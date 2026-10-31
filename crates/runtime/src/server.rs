//! Guest local Unix protocol server and optional development-only vsock bridge.
use crate::attestation::AttestationCoordinator;
use crate::authorization::{Admission, Authorization};
use crate::dev_vsock;
use crate::identity::OwnerIdentity;
use crate::lifecycle;
use crate::manager::Manager;
use crate::network_policy::NetworkPolicy;
use crate::product;
use crate::security::Policy;
use crate::session::SessionManager;
use crate::telemetry::TelemetryCollector;
use gammacloud_protocol::structured::{Operation, Response, SignedEnvelope};
use gammacloud_protocol::{GuestState, Request, RequestEnvelope};
use std::fs;
#[cfg(test)]
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

struct RuntimeContext {
    authorization: Option<Authorization>,
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
        let authorization = Authorization::load()?;
        let owner_identity = if authorization.is_none() {
            OwnerIdentity::from_env().ok()
        } else {
            None
        };
        let mut session_manager = SessionManager::new();
        if let Some(identity) = owner_identity.clone() {
            let _ = session_manager.create("runtime-session", identity, Duration::from_secs(3600));
        }
        let network_policy = NetworkPolicy::from_env().unwrap_or_else(|_| NetworkPolicy::new());
        Ok(Self {
            authorization,
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
        if self.authorization.is_none()
            && self.network_policy.require_attestation
            && self.attestation.state != crate::attestation::AttestationState::Verified
            && std::env::var("GAMMACLOUD_REQUIRE_ATTESTATION").as_deref() == Ok("1")
        {
            return Ok(false);
        }
        Ok(true)
    }

    fn status_line(&self) -> String {
        let attestation = if let Some(authorization) = &self.authorization {
            if authorization.attested() {
                "decision-verified"
            } else {
                "unverified"
            }
        } else {
            match self.attestation.state {
                crate::attestation::AttestationState::Verified => "verified",
                crate::attestation::AttestationState::Pending => "pending",
                crate::attestation::AttestationState::Rejected => "rejected",
                crate::attestation::AttestationState::Unverified => "unverified",
            }
        };
        let session_count = self.session_manager.list_active().len();
        let boot = self
            .authorization
            .as_ref()
            .map(|a| format!(" boot_nonce={}", a.boot_nonce()))
            .unwrap_or_default();
        format!("state=ready attestation={attestation} confidential=false sessions={session_count}{boot}")
    }
}

impl RuntimeContext {
    fn signed_request(&mut self, raw: &str) -> (String, bool) {
        let encode = |response: Response| {
            format!(
                "{}\n",
                serde_json::to_string(&response).expect("response serialization")
            )
        };
        let Some(authorization) = self.authorization.as_mut() else {
            return (
                encode(Response::error("", "signed_mode_unavailable")),
                false,
            );
        };
        let envelope: SignedEnvelope = match serde_json::from_str(raw) {
            Ok(envelope) => envelope,
            Err(_) => return (encode(Response::error("", "invalid_envelope")), false),
        };
        let request = match authorization.admit(&envelope) {
            Ok(Admission::Execute(request)) => request,
            Ok(Admission::Cached(response)) => return (encode(response), false),
            Err(code) => return (encode(Response::error("", code)), false),
        };
        let identity_result = authorization.identity_operation(&request);
        let mut shutdown = false;
        let result: Result<String, &str> = match identity_result {
            Err(code) => Err(code),
            Ok(true) => {
                if matches!(request.operation, Operation::Revoke) {
                    self.manager.shutdown();
                }
                Ok("identity_updated".into())
            }
            Ok(false) => match &request.operation {
                Operation::Health => Ok("OK".into()),
                Operation::Status => Ok(self.status_line()),
                Operation::Start { profile } => {
                    let profile = match profile.as_str() {
                        "smoke" => Some(gammacloud_protocol::Profile::Smoke),
                        "sleep" => Some(gammacloud_protocol::Profile::Sleep),
                        "worker" => Some(gammacloud_protocol::Profile::Worker),
                        _ => None,
                    };
                    profile.ok_or("profile_denied").and_then(|profile| {
                        self.manager.start(profile).map_err(|_| "operation_failed")
                    })
                }
                Operation::Execute { manifest } => {
                    match self
                        .authorization
                        .as_ref()
                        .and_then(|a| a.execution_template(&manifest.template))
                        .cloned()
                    {
                        Some(template) => self
                            .manager
                            .execute(manifest, &template)
                            .map_err(|_| "isolation_or_execution_failed"),
                        None => Err("template_denied"),
                    }
                }
                Operation::WorkloadStatus { id } => {
                    self.manager.status(*id).map_err(|_| "operation_failed")
                }
                Operation::WorkloadLogs { id } => {
                    self.manager.logs(*id).map_err(|_| "operation_failed")
                }
                Operation::Stop { id } => self.manager.stop(*id).map_err(|_| "operation_failed"),
                Operation::Shutdown => {
                    shutdown = true;
                    Ok("state=stopping".into())
                }
                _ => Err("operation_denied"),
            },
        };
        let response = match result {
            Ok(result) if result.starts_with("ERR ") => Response::error(
                &request.request_id,
                result.trim().trim_start_matches("ERR "),
            ),
            Ok(result) => Response::success(&request.request_id, result),
            Err(code) => Response::error(&request.request_id, code),
        };
        let response = if self
            .authorization
            .as_ref()
            .unwrap()
            .finish(&request, &response)
            .is_err()
        {
            Response::error(&request.request_id, "outcome_unknown")
        } else {
            response
        };
        (encode(response), shutdown)
    }
}

pub fn serve() -> std::io::Result<()> {
    let _signals = lifecycle::Signals::install()?;
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

    let log_dir = std::env::var("GAMMACLOUD_RUNTIME_LOG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/run/gammacloud/workloads"));
    let result = (|| {
        fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        serve_listener(&listener, socket, log_dir)
    })();
    let _ = fs::remove_file(socket);
    result
}
fn serve_listener(listener: &UnixListener, socket: &Path, log_dir: PathBuf) -> std::io::Result<()> {
    let product_profile = product::load()?;
    let mut runtime = RuntimeContext::new(log_dir, product_profile)?;
    // SECURITY: The bridge is an unauthenticated development-only transport.
    if runtime.authorization.is_some() {
        if std::env::var("GAMMACLOUD_DEV_VSOCK_BRIDGE").as_deref() == Ok("1") {
            return Err(std::io::Error::other(
                "development bridge forbidden with signed policy",
            ));
        }
    } else {
        dev_vsock::spawn(socket.to_path_buf())?;
    }
    println!(
        "gammacloud-runtime state={} attestation=unverified confidential=false",
        GuestState::Ready.as_str()
    );
    while !lifecycle::stopping() {
        if let Err(error) = lifecycle::wait(
            listener.as_raw_fd(),
            libc::POLLIN,
            lifecycle::connection_deadline(),
        ) {
            if matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted
            ) {
                continue;
            }
            return Err(error);
        }
        let mut stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) =>
            {
                continue
            }
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
    stream.set_nonblocking(true)?;
    let deadline = lifecycle::connection_deadline();
    if !runtime.authorized(stream)? {
        lifecycle::write_response(stream, b"ERR unauthorized-peer\n", deadline)?;
        return Ok(false);
    }
    let request = lifecycle::read_frame(stream, deadline)?;
    if request.starts_with('{') {
        if !request.ends_with('\n')
            || request.len() > gammacloud_protocol::structured::MAX_FRAME_BYTES
        {
            lifecycle::write_response(stream, b"ERR invalid-request\n", deadline)?;
            return Ok(false);
        }
        let (response, shutdown) = runtime.signed_request(&request);
        let result = lifecycle::write_response(stream, response.as_bytes(), deadline);
        if shutdown {
            return Ok(true);
        }
        result?;
        return Ok(false);
    }
    if !request.ends_with('\n') || request.trim_end_matches(['\r', '\n']).len() > 256 {
        lifecycle::write_response(stream, b"ERR invalid-request\n", deadline)?;
        return Ok(false);
    }
    let envelope = match RequestEnvelope::parse(&request) {
        Ok(envelope) => envelope,
        Err(error) => {
            lifecycle::write_response(stream, format!("ERR {error}\n").as_bytes(), deadline)?;
            return Ok(false);
        }
    };
    if runtime.authorization.is_some()
        && !matches!(envelope.request, Request::Health | Request::Status)
    {
        lifecycle::write_response(stream, b"ERR signed-authorization-required\n", deadline)?;
        return Ok(false);
    }
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
    let result = lifecycle::write_response(stream, response.as_bytes(), deadline);
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
    use std::io::{BufRead, BufReader};
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
        // The protocol frames responses with LF, not EOF. Closing a rejected
        // oversized request can reset the socket while unread request bytes remain.
        assert!(BufReader::new(client).read_line(&mut response).unwrap() > 0);
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
        assert_eq!(
            exchange(&mut runtime, &oversized),
            (false, "ERR invalid-request\n".into())
        );
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
