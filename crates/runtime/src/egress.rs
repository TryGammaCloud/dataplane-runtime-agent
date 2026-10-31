//! Mandatory per-workload CONNECT gateway outside the private network namespace.
//! TLS remains end-to-end; gateway logs never contain requests or credentials.
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

#[cfg(test)]
use crate::network_policy::Destination;
use crate::network_policy::NetworkPolicy as EgressPolicy;

fn rejected() -> io::Error {
    io::Error::other("egress denied")
}

fn public_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_multicast()
                || ip.is_unspecified()
                || ip.octets()[0] == 0
                || ip.octets()[0] >= 240
                || (ip.octets()[0] == 100 && ip.octets()[1] & 0xc0 == 64))
        }
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(|ip| public_address(IpAddr::V4(ip)))
            .unwrap_or_else(|| {
                !(ip.is_loopback()
                    || ip.is_unspecified()
                    || ip.is_multicast()
                    || ip.segments()[0] & 0xfe00 == 0xfc00
                    || ip.segments()[0] & 0xffc0 == 0xfe80)
            }),
    }
}

fn target(header: &[u8], policy: &EgressPolicy) -> io::Result<(String, u16)> {
    let text = std::str::from_utf8(header).map_err(|_| rejected())?;
    let line = text.split("\r\n").next().ok_or_else(rejected)?;
    let words: Vec<&str> = line.split(' ').collect();
    if words.len() != 3 || words[0] != "CONNECT" || words[2] != "HTTP/1.1" {
        return Err(rejected());
    }
    let (host, port) = words[1].rsplit_once(':').ok_or_else(rejected)?;
    let host = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host)
        .to_ascii_lowercase();
    let port: u16 = port.parse().map_err(|_| rejected())?;
    if host.is_empty()
        || host.len() > 253
        || host.ends_with('.')
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b':')
        || port == 0
    {
        return Err(rejected());
    }
    if !policy
        .destinations
        .iter()
        .any(|allowed| allowed.host == host && allowed.port == port)
    {
        return Err(rejected());
    }
    Ok((host, port))
}

fn header<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut bytes = Vec::new();
    while bytes.len() < 4096 && Instant::now() < deadline {
        let mut byte = [0];
        match reader.read(&mut byte) {
            Ok(0) => return Err(rejected()),
            Ok(_) => bytes.push(byte[0]),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue
            }
            Err(error) => return Err(error),
        }
        if bytes.ends_with(b"\r\n\r\n") {
            return Ok(bytes);
        }
    }
    Err(rejected())
}

fn copy_until<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    deadline: Instant,
    stop: Arc<AtomicBool>,
    connection: Arc<AtomicBool>,
) {
    let mut buffer = [0; 8192];
    while Instant::now() < deadline
        && !stop.load(Ordering::Relaxed)
        && !connection.load(Ordering::Relaxed)
    {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                if writer.write_all(&buffer[..count]).is_err() {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue
            }
            Err(_) => break,
        }
    }
    connection.store(true, Ordering::Relaxed);
}

pub struct Gateway {
    pub path: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Gateway {
    pub fn start(policy: EgressPolicy, uid: u32, lifetime: Duration) -> io::Result<Self> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        let directory = PathBuf::from("/run/gammacloud/egress");
        if !directory.exists() {
            fs::DirBuilder::new().mode(0o700).create(&directory)?;
        }
        let metadata = fs::symlink_metadata(&directory)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
            return Err(rejected());
        }
        let mut random = [0; 16];
        File::open("/dev/urandom")?.read_exact(&mut random)?;
        let path = directory.join(format!("{}.sock", crate::authorization::hex(&random)));
        let listener = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666))?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let deadline = Instant::now() + lifetime;
        let thread = std::thread::spawn(move || {
            let active = Arc::new(AtomicUsize::new(0));
            let mut workers = Vec::new();
            while Instant::now() < deadline && !stopping.load(Ordering::Relaxed) {
                workers.retain(|worker: &std::thread::JoinHandle<()>| !worker.is_finished());
                match listener.accept() {
                    Ok((mut client, _)) => {
                        if active.load(Ordering::Relaxed) >= 8 {
                            continue;
                        }
                        let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
                        let mut length = std::mem::size_of_val(&credentials) as libc::socklen_t;
                        if unsafe {
                            libc::getsockopt(
                                client.as_raw_fd(),
                                libc::SOL_SOCKET,
                                libc::SO_PEERCRED,
                                &mut credentials as *mut _ as *mut _,
                                &mut length,
                            )
                        } != 0
                            || credentials.uid != uid
                        {
                            continue;
                        }
                        let policy = policy.clone();
                        let stop = stopping.clone();
                        let active = active.clone();
                        active.fetch_add(1, Ordering::Relaxed);
                        workers.push(std::thread::spawn(move || {
                            let _ = (|| -> io::Result<()> {
                                client.set_read_timeout(Some(Duration::from_millis(500)))?;
                                client.set_write_timeout(Some(Duration::from_millis(500)))?;
                                let (host, port) = target(&header(&mut client)?, &policy)?;
                                let addresses: Vec<_> = policy
                                    .destinations
                                    .iter()
                                    .find(|entry| entry.host == host && entry.port == port)
                                    .ok_or_else(rejected)?
                                    .addresses
                                    .iter()
                                    .take(16)
                                    .copied()
                                    .filter(|address| {
                                        policy.allow_private_addresses || public_address(*address)
                                    })
                                    .map(|ip| std::net::SocketAddr::new(ip, port))
                                    .collect();
                                // Resolve once, validate actual IPs, then connect to that exact address.
                                let remote = addresses
                                    .iter()
                                    .take_while(|_| {
                                        !stop.load(Ordering::Relaxed) && Instant::now() < deadline
                                    })
                                    .find_map(|address| {
                                        TcpStream::connect_timeout(address, Duration::from_secs(1))
                                            .ok()
                                    })
                                    .ok_or_else(rejected)?;
                                remote.set_read_timeout(Some(Duration::from_millis(500)))?;
                                remote.set_write_timeout(Some(Duration::from_millis(500)))?;
                                client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
                                let connection = Arc::new(AtomicBool::new(false));
                                let reader = client.try_clone()?;
                                let writer = remote.try_clone()?;
                                let stop2 = stop.clone();
                                let connection2 = connection.clone();
                                let upstream = std::thread::spawn(move || {
                                    copy_until(reader, writer, deadline, stop2, connection2)
                                });
                                copy_until(remote, client, deadline, stop, connection);
                                let _ = upstream.join();
                                Ok(())
                            })();
                            active.fetch_sub(1, Ordering::Relaxed);
                        }));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(20))
                    }
                    Err(_) => break,
                }
            }
            stopping.store(true, Ordering::Relaxed);
            for worker in workers {
                let _ = worker.join();
            }
        });
        Ok(Self {
            path,
            stop,
            thread: Some(thread),
        })
    }
}
impl Drop for Gateway {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = fs::remove_file(&self.path);
    }
}

/// Runs unprivileged inside the workload namespace; all traffic goes to its bound socket.
pub fn sidecar(lifetime: u64) -> io::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", 18443))?;
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + Duration::from_secs(lifetime);
    let active = Arc::new(AtomicUsize::new(0));
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((client, _)) if active.load(Ordering::Relaxed) < 8 => {
                let active = active.clone();
                active.fetch_add(1, Ordering::Relaxed);
                std::thread::spawn(move || {
                    let _ = (|| -> io::Result<()> {
                        let gateway = UnixStream::connect("/run/gammacloud/egress.sock")?;
                        client.set_read_timeout(Some(Duration::from_millis(500)))?;
                        client.set_write_timeout(Some(Duration::from_millis(500)))?;
                        gateway.set_read_timeout(Some(Duration::from_millis(500)))?;
                        gateway.set_write_timeout(Some(Duration::from_millis(500)))?;
                        let stop = Arc::new(AtomicBool::new(false));
                        let connection = Arc::new(AtomicBool::new(false));
                        let reader = client.try_clone()?;
                        let writer = gateway.try_clone()?;
                        let stop2 = stop.clone();
                        let connection2 = connection.clone();
                        let upstream = std::thread::spawn(move || {
                            copy_until(reader, writer, deadline, stop2, connection2)
                        });
                        copy_until(gateway, client, deadline, stop, connection);
                        let _ = upstream.join();
                        Ok(())
                    })();
                    active.fetch_sub(1, Ordering::Relaxed);
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20))
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn connect_policy_matches_exact_host_and_port() {
        let policy = EgressPolicy {
            destinations: vec![Destination {
                host: "api.gamma.local".into(),
                port: 443,
                addresses: vec!["203.0.113.1".parse().unwrap()],
            }],
            allow_private_addresses: false,
        };
        assert!(target(b"CONNECT api.gamma.local:443 HTTP/1.1\r\n\r\n", &policy).is_ok());
        assert!(target(
            b"CONNECT api.gamma.local.evil:443 HTTP/1.1\r\n\r\n",
            &policy
        )
        .is_err());
        assert!(target(b"CONNECT api.gamma.local:80 HTTP/1.1\r\n\r\n", &policy).is_err());
        assert!(!public_address("169.254.169.254".parse().unwrap()));
        assert!(!public_address("::ffff:127.0.0.1".parse().unwrap()));
    }
}
