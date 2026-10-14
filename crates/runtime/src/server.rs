//! Guest local Unix protocol server and optional development-only vsock bridge.
use crate::dev_vsock;
use crate::manager::Manager;
use crate::product;
use crate::security::Policy;
use gammacloud_protocol::{parse_request, GuestState, Request};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub fn serve() -> std::io::Result<()> {
    let path = std::env::var("GAMMACLOUD_RUNTIME_SOCKET")
        .unwrap_or_else(|_| "/run/gammacloud/runtime.sock".into());
    let socket = Path::new(&path);
    if let Some(parent) = socket.parent() { fs::create_dir_all(parent)?; }
    if socket.exists() {
        return Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists,
            "socket exists; refusing to remove an unknown endpoint"));
    }
    let listener = UnixListener::bind(socket)?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
    let log_dir = std::env::var("GAMMACLOUD_RUNTIME_LOG_DIR")
        .map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/run/gammacloud/workloads"));
    let result = serve_listener(&listener, socket, log_dir);
    let _ = fs::remove_file(socket);
    result
}
fn serve_listener(listener: &UnixListener, socket: &Path, log_dir: PathBuf) -> std::io::Result<()> {
    let mut manager = Manager::new(log_dir, Policy::from_env()?, product::load()?);
    // SECURITY: The bridge is an unauthenticated development-only transport.
    dev_vsock::spawn(socket.to_path_buf())?;
    println!("gammacloud-runtime state={} attestation=unverified confidential=false", GuestState::Ready.as_str());
    for incoming in listener.incoming() {
        let mut stream = incoming?;
        if !manager.authorize(&stream)? {
            stream.write_all(b"ERR unauthorized-peer\n")?;
            continue;
        }
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        let mut request = String::new();
        BufReader::new(&stream).take(257).read_line(&mut request)?;
        let response = match parse_request(&request) {
            Ok(Request::Health) => "OK\n".into(),
            Ok(Request::Status) => "state=ready attestation=unverified confidential=false\n".into(),
            Ok(Request::Shutdown) => "state=stopping\n".into(),
            Ok(Request::Start { profile }) => manager.start(profile)?,
            Ok(Request::WorkloadStatus { id }) => manager.status(id)?,
            Ok(Request::WorkloadLogs { id }) => manager.logs(id)?,
            Ok(Request::Stop { id }) => manager.stop(id)?,
            Err(err) => format!("ERR {err}\n"),
        };
        stream.write_all(response.as_bytes())?;
        if matches!(parse_request(&request), Ok(Request::Shutdown)) { break; }
    }
    manager.shutdown();
    println!("gammacloud-runtime state={}", GuestState::Stopped.as_str());
    Ok(())
}
