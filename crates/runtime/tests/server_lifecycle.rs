//! Guest-local integration scenarios, prepared for later execution (no privileged VM).
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Runtime {
    child: Child,
    directory: PathBuf,
    socket: PathBuf,
}
impl Runtime {
    fn start() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "gc-server-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let socket = directory.join("runtime.sock");
        fs::write(directory.join("profile"), "sandbox\n").unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_gammacloud-runtime"))
            .env_clear()
            .env("GAMMACLOUD_RUNTIME_SOCKET", &socket)
            .env("GAMMACLOUD_RUNTIME_LOG_DIR", directory.join("logs"))
            .env("GAMMACLOUD_PRODUCT_PROFILE_FILE", directory.join("profile"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut runtime = Self {
            child,
            directory,
            socket,
        };
        let deadline = Instant::now() + Duration::from_secs(3);
        while !runtime.socket.exists() {
            assert!(
                runtime.child.try_wait().unwrap().is_none(),
                "runtime exited before readiness"
            );
            assert!(Instant::now() < deadline, "startup timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(runtime.request(b"HEALTH\n"), "OK\n");
        runtime
    }
    fn request(&self, request: &[u8]) -> String {
        let mut stream = UnixStream::connect(&self.socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(request).unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }
    fn wait(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(8);
        while self.child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "shutdown timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Runtime {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn invalid_client_does_not_kill_listener() {
    let runtime = Runtime::start();
    assert_eq!(runtime.request(b"SHUTDOWN"), "ERR invalid-request\n");
    assert_eq!(runtime.request(b"HEALTH\n"), "OK\n");
}

#[test]
fn slow_client_cannot_reset_total_deadline() {
    let runtime = Runtime::start();
    let mut client = UnixStream::connect(&runtime.socket).unwrap();
    client.write_all(b"HE").unwrap();
    std::thread::sleep(Duration::from_millis(3200));
    assert_eq!(runtime.request(b"HEALTH\n"), "OK\n");
}

#[test]
fn sigterm_during_partial_request_cleans_children_and_socket() {
    let mut runtime = Runtime::start();
    assert!(runtime.request(b"START sleep\n").starts_with("OK id="));
    let child_file = format!(
        "/proc/{}/task/{}/children",
        runtime.child.id(),
        runtime.child.id()
    );
    let children: Vec<u32> = fs::read_to_string(child_file)
        .unwrap()
        .split_whitespace()
        .map(|pid| pid.parse().unwrap())
        .collect();
    assert!(!children.is_empty());
    let mut client = UnixStream::connect(&runtime.socket).unwrap();
    client.write_all(b"STA").unwrap();
    assert_eq!(
        unsafe { libc::kill(runtime.child.id() as i32, libc::SIGTERM) },
        0
    );
    runtime.wait();
    assert!(!runtime.socket.exists());
    for pid in children {
        assert!(!PathBuf::from(format!("/proc/{pid}")).exists());
    }
}
