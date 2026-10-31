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
        let mut stream = match incoming {
            Ok(stream) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        match handle_connection(&mut runtime, &mut stream) {
            Ok(true) => break,
            Ok(false) => {}
            // Never log request contents or OS error details that may contain paths.
            Err(_) => eprintln!("gammacloud-runtime event=connection-failed"),
        }
    }
    runtime.manager.shutdown();
    println!("gammacloud-runtime state={}", GuestState::Stopped.as_str());
    Ok(())
}

/// Handles one development connection; only an authorized SHUTDOWN stops service.
fn handle_connection(
    runtime: &mut RuntimeContext,
    stream: &mut std::os::unix::net::UnixStream,
) -> std::io::Result<bool> {
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    if !runtime.authorized(stream)? {
        stream.write_all(b"ERR unauthorized-peer\n")?;
        return Ok(false);
    }
    let mut request = String::new();
    // At most 256 wire-content bytes plus CRLF; reject truncated frames.
    BufReader::new(&*stream).take(258).read_line(&mut request)?;
    if !request.ends_with('\n') || request.trim_end_matches(['\r', '\n']).len() > 256 {
        stream.write_all(b"ERR invalid-request\n")?;
        return Ok(false);
    }
    let envelope = match RequestEnvelope::parse(&request) {
        Ok(envelope) => envelope,
        Err(error) => {
            stream.write_all(format!("ERR {error}\n").as_bytes())?;
            return Ok(false);
        }
    };
    let shutdown = matches!(envelope.request, Request::Shutdown);
    let response = match envelope.request {
        Request::Health => Ok("OK\n".into()),
        Request::Status => Ok(format!("{}\n", runtime.status_line())),
        Request::Shutdown => {
            let _ = runtime.attestation.reject();
            Ok("state=stopping\n".into())
        }
        Request::Start { profile } => runtime.manager.start(profile),
        Request::WorkloadStatus { id } => runtime.manager.status(id),
        Request::WorkloadLogs { id } => runtime.manager.logs(id),
        Request::Stop { id } => runtime.manager.stop(id),
    }
    .unwrap_or_else(|_| "ERR operation-failed\n".into());
    let result = stream.write_all(response.as_bytes());
    // A disconnected caller must not cancel an already authorized shutdown.
    if shutdown {
        return Ok(true);
    }
    result?;
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;

    fn runtime() -> RuntimeContext {
        RuntimeContext::new(
            PathBuf::from("/dev/null/workloads"),
            product::Product::Sandbox,
        )
        .unwrap()
    }

    fn exchange(runtime: &mut RuntimeContext, request: &[u8]) -> (bool, String) {
        let (mut server, mut client) = UnixStream::pair().unwrap();
        client.write_all(request).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let shutdown = handle_connection(runtime, &mut server).unwrap();
        drop(server);
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        (shutdown, response)
    }

    #[test]
    fn incomplete_and_oversized_frames_do_not_execute() {
        let mut runtime = runtime();
        assert_eq!(
            exchange(&mut runtime, b"SHUTDOWN").1,
            "ERR invalid-request\n"
        );
        let mut oversized = vec![b' '; 257];
        oversized.extend_from_slice(b"SHUTDOWN\n");
        assert!(!exchange(&mut runtime, &oversized).0);
        assert_eq!(exchange(&mut runtime, b"HEALTH\n"), (false, "OK\n".into()));
    }

    #[test]
    fn operation_failure_keeps_runtime_available() {
        let mut runtime = runtime();
        assert_eq!(
            exchange(&mut runtime, b"START smoke\n").1,
            "ERR operation-failed\n"
        );
        assert_eq!(exchange(&mut runtime, b"V1 HEALTH\n").1, "OK\n");
    }

    #[test]
    fn shutdown_survives_failed_acknowledgement() {
        let mut runtime = runtime();
        let (mut server, mut client) = UnixStream::pair().unwrap();
        client.write_all(b"SHUTDOWN\n").unwrap();
        client.shutdown(Shutdown::Both).unwrap();
        assert!(handle_connection(&mut runtime, &mut server).unwrap());
    }

    #[test]
    fn invalid_utf8_only_fails_its_connection() {
        let mut runtime = runtime();
        let (mut server, mut client) = UnixStream::pair().unwrap();
        client.write_all(b"\xff\n").unwrap();
        assert!(handle_connection(&mut runtime, &mut server).is_err());
        assert_eq!(exchange(&mut runtime, b"HEALTH\r\n").1, "OK\n");
    }
}
