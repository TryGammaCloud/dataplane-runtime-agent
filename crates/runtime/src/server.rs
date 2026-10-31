//! Guest local Unix protocol server and optional development-only vsock bridge.
use crate::attestation::AttestationCoordinator;
use crate::dev_vsock;
use crate::identity::OwnerIdentity;
use crate::manager::Manager;
use crate::network_policy::NetworkPolicy;
use crate::product;
use crate::security::Policy;
use crate::session::SessionManager;
use crate::telemetry::TelemetryCollector;
use gammacloud_protocol::{GuestState, Request, RequestEnvelope};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

struct RuntimeContext {
    manager: Manager,
    session_manager: SessionManager,
    #[allow(
        dead_code,
        reason = "Stored identity awaits verified command authorization."
    )]
    owner_identity: Option<OwnerIdentity>,
    attestation: AttestationCoordinator,
    network_policy: NetworkPolicy,
    #[allow(dead_code, reason = "Collector awaits resource sampling integration.")]
    telemetry: TelemetryCollector,
}

impl RuntimeContext {
    fn new(log_dir: PathBuf, product: product::Product) -> std::io::Result<Self> {
        let owner_identity = OwnerIdentity::from_env().ok();
        let mut session_manager = SessionManager::new();
        if let Some(identity) = owner_identity.clone() {
            let _ = session_manager.create("runtime-session", identity, Duration::from_secs(3600));
        }
        let network_policy = NetworkPolicy::from_env().unwrap_or_else(|_| NetworkPolicy::new());
        Ok(Self {
            manager: Manager::new(log_dir, Policy::from_env()?, product),
            session_manager,
            owner_identity,
            attestation: AttestationCoordinator::new(),
            network_policy,
            telemetry: TelemetryCollector::new(64),
        })
    }

    fn authorized(&self, stream: &std::os::unix::net::UnixStream) -> std::io::Result<bool> {
        if !self.manager.authorize(stream)? {
            return Ok(false);
        }
        if self.network_policy.require_attestation
            && self.attestation.state != crate::attestation::AttestationState::Verified
            && std::env::var("GAMMACLOUD_REQUIRE_ATTESTATION").as_deref() == Ok("1")
        {
            return Ok(false);
        }
        Ok(true)
    }

    fn status_line(&self) -> String {
        let attestation = match self.attestation.state {
            crate::attestation::AttestationState::Verified => "verified",
            crate::attestation::AttestationState::Pending => "pending",
            crate::attestation::AttestationState::Rejected => "rejected",
            crate::attestation::AttestationState::Unverified => "unverified",
        };
        let session_count = self.session_manager.list_active().len();
        format!("state=ready attestation={attestation} confidential=false sessions={session_count}")
    }
}

pub fn serve() -> std::io::Result<()> {
    let path = std::env::var("GAMMACLOUD_RUNTIME_SOCKET")
        .unwrap_or_else(|_| "/run/gammacloud/runtime.sock".into());
    let socket = Path::new(&path);
    if let Some(parent) = socket.parent() {
        fs::create_dir_all(parent)?;
    }
    if socket.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "socket exists; refusing to remove an unknown endpoint",
        ));
    }
    let listener = UnixListener::bind(socket)?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
    let log_dir = std::env::var("GAMMACLOUD_RUNTIME_LOG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/run/gammacloud/workloads"));
    let result = serve_listener(&listener, socket, log_dir);
    let _ = fs::remove_file(socket);
    result
}
fn serve_listener(listener: &UnixListener, socket: &Path, log_dir: PathBuf) -> std::io::Result<()> {
    let product_profile = product::load()?;
    let mut runtime = RuntimeContext::new(log_dir, product_profile)?;
    // SECURITY: The bridge is an unauthenticated development-only transport.
    dev_vsock::spawn(socket.to_path_buf())?;
    println!(
        "gammacloud-runtime state={} attestation=unverified confidential=false",
        GuestState::Ready.as_str()
    );
    for incoming in listener.incoming() {
        let mut stream = incoming?;
        if !runtime.authorized(&stream)? {
            stream.write_all(b"ERR unauthorized-peer\n")?;
            continue;
        }
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        let mut request = String::new();
        BufReader::new(&stream).take(257).read_line(&mut request)?;

        let envelope = RequestEnvelope::parse(&request);
        let response = match &envelope {
            Ok(envelope) => match envelope.request {
                Request::Health => "OK\n".into(),
                Request::Status => format!("{}\n", runtime.status_line()),
                Request::Shutdown => {
                    let _ = runtime.attestation.reject();
                    "state=stopping\n".into()
                }
                Request::Start { profile } => runtime.manager.start(profile)?,
                Request::WorkloadStatus { id } => runtime.manager.status(id)?,
                Request::WorkloadLogs { id } => runtime.manager.logs(id)?,
                Request::Stop { id } => runtime.manager.stop(id)?,
            },
            Err(err) => format!("ERR {err}\n"),
        };
        stream.write_all(response.as_bytes())?;
        if matches!(&envelope, Ok(envelope) if matches!(envelope.request, Request::Shutdown)) {
            break;
        }
    }
    runtime.manager.shutdown();
    println!("gammacloud-runtime state={}", GuestState::Stopped.as_str());
    Ok(())
}
