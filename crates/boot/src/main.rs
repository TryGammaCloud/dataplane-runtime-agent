use gammacloud_protocol::GuestState;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

fn main() -> std::io::Result<()> {
    // Boot readiness is local only; hardware attestation remains unverified.
    let socket = std::env::var("GAMMACLOUD_RUNTIME_SOCKET")
        .unwrap_or_else(|_| "/run/gammacloud/runtime.sock".to_owned());
    println!(
        "gammacloud-boot state={} attestation=unverified confidential=false",
        GuestState::Starting.as_str()
    );
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.write_all(b"HEALTH\n")?;
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response)?;
    if response != "OK\n" {
        return Err(std::io::Error::other("runtime health check failed"));
    }
    println!(
        "gammacloud-boot state={} attestation=unverified confidential=false",
        GuestState::Ready.as_str()
    );
    Ok(())
}
