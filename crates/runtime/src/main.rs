use gammacloud_protocol::GuestState;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn main() -> std::io::Result<()> {
    // Local development control plane only. Never exposes a network port.
    let path = std::env::var("GAMMACLOUD_RUNTIME_SOCKET")
        .unwrap_or_else(|_| "/run/gammacloud/runtime.sock".to_owned());
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
    let stopping = Arc::new(AtomicBool::new(false));
    println!(
        "gammacloud-runtime state={} attestation=unverified confidential=false",
        GuestState::Ready.as_str()
    );
    for stream in listener.incoming() {
        let mut stream = stream?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
        let mut request = String::new();
        BufReader::new(&stream).read_line(&mut request)?;
        let response = match request.trim_end() {
            "HEALTH" => "OK\n",
            "STATUS" => "state=ready attestation=unverified confidential=false\n",
            "SHUTDOWN" => {
                stopping.store(true, Ordering::SeqCst);
                "state=stopping\n"
            }
            _ => "ERR unsupported-command\n",
        };
        stream.write_all(response.as_bytes())?;
        if stopping.load(Ordering::SeqCst) {
            break;
        }
    }
    fs::remove_file(socket)?;
    println!("gammacloud-runtime state={}", GuestState::Stopped.as_str());
    Ok(())
}
