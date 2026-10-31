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
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

struct RuntimeContext {
    authorization: Option<Authorization>,
    terminals: crate::terminal::Terminals,
    models: crate::inference::Models,
    last_export: std::time::Instant,
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
        let mut manager = Manager::new(log_dir, Policy::from_env()?, product);
        if authorization.is_some() {
            manager.enable_recovery()?;
        }
        Ok(Self {
            authorization,
            terminals: Default::default(),
            models: Default::default(),
            manager,
            last_export: std::time::Instant::now(),
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
    fn open_terminal(
        &mut self,
        manifest: &gammacloud_protocol::structured::ExecutionManifest,
        ttl: u64,
        request: &SignedEnvelope,
    ) -> Result<String, &'static str> {
        let authorization = self.authorization.as_ref().unwrap();
        if !authorization.attested() {
            return Err("attestation_required");
        }
        let template = authorization
            .execution_template(&manifest.template)
            .ok_or("template_denied")?;
        let volume = template
            .volume_id
            .as_ref()
            .and_then(|id| authorization.volume_policy(id));
        if volume.is_none() {
            return Err("workspace_required");
        }
        self.terminals
            .open(
                &mut self.manager,
                manifest,
                template,
                volume,
                ttl,
                crate::isolated::LaunchAuthorization::new(
                    request,
                    authorization
                        .current_decision()
                        .ok_or("attestation_required")?,
                    manifest,
                )
                .map_err(|_| "invalid_manifest")?,
            )
            .map_err(|_| "session_open_failed")
    }

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
                if matches!(
                    request.operation,
                    Operation::Revoke | Operation::Rotate { .. }
                ) {
                    self.terminals.close_all(&mut self.manager);
                    self.manager.shutdown();
                }
                Ok("identity_updated".into())
            }
            Ok(false) => {
                match &request.operation {
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
                    Operation::SessionOpen {
                        manifest,
                        ttl_seconds,
                    } => self.open_terminal(manifest, *ttl_seconds, &envelope),
                    Operation::AgentLaunch {
                        name,
                        manifest,
                        ttl_seconds,
                    } => {
                        let profile = self
                            .authorization
                            .as_ref()
                            .unwrap()
                            .agent_profile(name)
                            .cloned();
                        match profile {
                        Some(profile) if !profile.version.is_empty() && crate::development_agent::DevelopmentAgentKind::from_name(name).is_ok() => {
                            let mut manifest = manifest.clone(); manifest.template = profile.template;
                            self.open_terminal(&manifest, *ttl_seconds, &envelope)
                        }
                        _ => Err("agent_denied"),
                    }
                    }
                    Operation::SessionRead { id, cursor } => self
                        .terminals
                        .read(id, *cursor)
                        .map_err(|_| "session_read_failed"),
                    Operation::SessionWrite {
                        id,
                        sequence,
                        data_hex,
                    } => self
                        .terminals
                        .write(id, *sequence, data_hex)
                        .map_err(|_| "session_write_failed"),
                    Operation::SessionResize { id, rows, columns } => self
                        .terminals
                        .resize(id, *rows, *columns)
                        .map_err(|_| "session_resize_failed"),
                    Operation::SessionClose { id } => self
                        .terminals
                        .close(&mut self.manager, id)
                        .map_err(|_| "session_close_failed"),
                    Operation::VolumeUnlock { id } => {
                        let authorization = self.authorization.as_ref().unwrap();
                        match (
                            authorization.volume_policy(id),
                            authorization.current_decision(),
                        ) {
                            (Some(policy), Some(decision)) => {
                                crate::storage::unlock(id, policy, &envelope, decision)
                                    .map(|_| "mounted".into())
                                    .map_err(|_| "volume_activation_failed")
                            }
                            _ => Err("volume_or_attestation_unavailable"),
                        }
                    }
                    Operation::VolumeRotate { id } => {
                        let authorization = self.authorization.as_ref().unwrap();
                        match (
                            authorization.volume_policy(id),
                            authorization.current_decision(),
                        ) {
                            (Some(policy), Some(decision)) => {
                                crate::storage::rotate(id, policy, &envelope, decision)
                                    .map(|_| "replacement_key_added".into())
                                    .map_err(|_| "key_rotation_failed")
                            }
                            _ => Err("volume_or_attestation_unavailable"),
                        }
                    }
                    Operation::VolumeLock { id } => {
                        // Workloads must release their mounts before a non-lazy unmount.
                        self.manager.shutdown();
                        self.authorization
                            .as_ref()
                            .unwrap()
                            .volume_policy(id)
                            .ok_or("volume_denied")
                            .and_then(|policy| {
                                crate::storage::lock(id, policy)
                                    .map(|_| "locked".into())
                                    .map_err(|_| "volume_busy_or_lock_failed")
                            })
                    }
                    Operation::VolumeStatus { id } => self
                        .authorization
                        .as_ref()
                        .unwrap()
                        .volume_policy(id)
                        .ok_or("volume_denied")
                        .map(|policy| {
                            if crate::storage::ready(id, policy).is_ok() {
                                "mounted".into()
                            } else {
                                "locked_or_unavailable".into()
                            }
                        }),
                    Operation::Files {
                        volume_id,
                        operation,
                    } => {
                        let authorization = self.authorization.as_ref().unwrap();
                        if !authorization.attested() {
                            Err("attestation_required")
                        } else {
                            authorization
                                .volume_policy(volume_id)
                                .ok_or("volume_denied")
                                .and_then(|policy| {
                                    crate::storage::files(volume_id, policy, operation)
                                        .map_err(|_| "filesystem_operation_failed")
                                })
                        }
                    }
                    Operation::Metrics => serde_json::to_string(&serde_json::json!({"jobs":self.manager.samples(),"sessions":self.terminals.len(),"volume_used_bytes":self.authorization.as_ref().unwrap().volume_usage(),"gpu":crate::observability::gpu()})).map_err(|_| "metrics_unavailable"),
                    Operation::RequestOutcome { id } => self.authorization.as_ref().unwrap().outcome(id),
                    Operation::ModelStart { manifest } => (|| {
                        let authorization = self.authorization.as_ref().unwrap();
                        let template = authorization
                            .execution_template(&manifest.execution.template)
                            .ok_or("template_denied")?;
                        let context = crate::isolated::LaunchAuthorization::new(
                            &envelope,
                            authorization
                                .current_decision()
                                .ok_or("attestation_required")?,
                            manifest,
                        )
                        .map_err(|_| "invalid_manifest")?;
                        self.models
                            .start(&mut self.manager, manifest, template, context)
                            .map_err(|_| "model_start_failed")
                    })(),
                    Operation::ModelStatus { id } => self
                        .models
                        .status(&mut self.manager, id)
                        .map_err(|_| "model_status_failed"),
                    Operation::ModelStop { id } => self
                        .models
                        .stop(&mut self.manager, id)
                        .map_err(|_| "model_stop_failed"),
                    Operation::Execute { manifest } => (|| {
                        let authorization = self.authorization.as_ref().unwrap();
                        let template = authorization
                            .execution_template(&manifest.template)
                            .ok_or("template_denied")?;
                        let volume = template
                            .volume_id
                            .as_ref()
                            .and_then(|id| authorization.volume_policy(id));
                        let context = crate::isolated::LaunchAuthorization::new(
                            &envelope,
                            authorization
                                .current_decision()
                                .ok_or("attestation_required")?,
                            manifest,
                        )
                        .map_err(|_| "invalid_manifest")?;
                        self.manager
                            .execute(manifest, template, volume, None, context)
                            .map_err(|_| "isolation_or_execution_failed")
                    })(),
                    Operation::WorkloadStatus { id } => {
                        self.manager.status(*id).map_err(|_| "operation_failed")
                    }
                    Operation::WorkloadLogs { id } => {
                        self.manager.logs(*id).map_err(|_| "operation_failed")
                    }
                    Operation::Stop { id } => {
                        self.manager.stop(*id).map_err(|_| "operation_failed")
                    }
                    Operation::Shutdown => {
                        shutdown = true;
                        Ok("state=stopping".into())
                    }
                    _ => Err("operation_denied"),
                }
            }
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
        runtime.terminals.expire(&mut runtime.manager);
        if runtime.last_export.elapsed() >= Duration::from_secs(10) {
            runtime.last_export = std::time::Instant::now();
            if let Some(authorization) = runtime
                .authorization
                .as_ref()
                .filter(|authorization| authorization.export_telemetry())
            {
                let _ = crate::observability::export(
                    &runtime.manager.samples(),
                    runtime.terminals.len(),
                    &authorization.volume_usage(),
                    crate::observability::gpu().as_deref(),
                );
            }
        }
        if runtime
            .authorization
            .as_mut()
            .is_some_and(|authorization| authorization.expire_decision())
        {
            runtime.terminals.close_all(&mut runtime.manager);
            runtime.manager.shutdown();
        }
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
