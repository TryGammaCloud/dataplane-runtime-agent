//! Guest-local development workload manager.
//!
//! # Trust boundary
//!
//! This Unix socket is not a host-to-guest authenticated transport.
//! Development guests report attestation=unverified and confidential=false.
mod dev_vsock;
mod product;
mod security;
use gammacloud_protocol::{parse_request, GuestState, Profile, Request};
use security::{kill_process_group, Policy};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const MAX_WORKLOADS: usize = 16;
const MAX_LOG_BYTES: u64 = 4096;

/// Tracks a spawned development process and its bounded log files.
struct Workload {
    child: Child,
    profile: Profile,
    stdout: PathBuf,
    stderr: PathBuf,
    exit_code: Option<i32>,
}
/// Owns the guest-local workload lifecycle and authorization policy.
struct Manager {
    jobs: BTreeMap<u64, Workload>,
    next_id: u64,
    log_dir: PathBuf,
    policy: Policy,
    product: product::Product,
}
impl Manager {
    fn new(log_dir: PathBuf, policy: Policy, product: product::Product) -> Self {
        Self {
            jobs: BTreeMap::new(),
            next_id: 1,
            log_dir,
            policy,
            product,
        }
    }
    /// Starts an allowlisted profile with policy limits applied before spawn.
    ///
    /// # Errors
    ///
    /// Returns an error if log creation, policy setup or spawning fails.
    fn start(&mut self, profile: Profile) -> std::io::Result<String> {
        if !self.product.allows_workload() {
            return Ok("ERR workload-not-allowed-for-product\n".into());
        }
        if self.jobs.len() >= MAX_WORKLOADS {
            return Ok("ERR capacity-exceeded\n".into());
        }
        fs::create_dir_all(&self.log_dir)?;
        fs::set_permissions(&self.log_dir, fs::Permissions::from_mode(0o700))?;
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("id exhausted"))?;
        let stdout = self.log_dir.join(format!("{id}.stdout"));
        let stderr = self.log_dir.join(format!("{id}.stderr"));
        let out = File::create(&stdout)?;
        let err = File::create(&stderr)?;
        // SECURITY: Only image-controlled executables may be launched.
        // Never accept caller-controlled paths or command-line arguments.
        let mut cmd = match profile {
            Profile::Smoke => {
                let mut c = Command::new("/usr/bin/printf");
                c.arg("GAMMACLOUD_WORKLOAD_OK\n");
                c
            }
            Profile::Sleep => {
                let mut c = Command::new("/usr/bin/sleep");
                c.arg("30");
                c
            }
            Profile::Worker => Command::new("/opt/gammacloud/workloads/worker"),
        };
        self.policy.configure(&mut cmd);
        let child = cmd
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()?;
        self.jobs.insert(
            id,
            Workload {
                child,
                profile,
                stdout,
                stderr,
                exit_code: None,
            },
        );
        Ok(format!("OK id={id} profile={}\n", profile.as_str()))
    }
    fn refresh(job: &mut Workload) -> std::io::Result<()> {
        if job.exit_code.is_none() {
            if let Some(status) = job.child.try_wait()? {
                job.exit_code = Some(status.code().unwrap_or(-1));
            }
        }
        Ok(())
    }
    fn status(&mut self, id: u64) -> std::io::Result<String> {
        let Some(job) = self.jobs.get_mut(&id) else {
            return Ok("ERR unknown-id\n".into());
        };
        Self::refresh(job)?;
        let state = if job.exit_code.is_some() {
            "exited"
        } else {
            "running"
        };
        Ok(format!(
            "OK id={id} profile={} state={state} exit_code={}\n",
            job.profile.as_str(),
            job.exit_code
                .map_or_else(|| "none".to_string(), |c| c.to_string())
        ))
    }
    fn logs(&self, id: u64) -> std::io::Result<String> {
        let Some(job) = self.jobs.get(&id) else {
            return Ok("ERR unknown-id\n".into());
        };
        fn read_bounded(path: &Path) -> std::io::Result<String> {
            let mut bytes = Vec::new();
            File::open(path)?
                .take(MAX_LOG_BYTES)
                .read_to_end(&mut bytes)?;
            Ok(String::from_utf8_lossy(&bytes)
                .replace('\n', "\\n")
                .replace('\r', "\\r"))
        }
        Ok(format!(
            "OK stdout={} stderr={}\n",
            read_bounded(&job.stdout)?,
            read_bounded(&job.stderr)?
        ))
    }
    fn stop(&mut self, id: u64) -> std::io::Result<String> {
        let Some(job) = self.jobs.get_mut(&id) else {
            return Ok("ERR unknown-id\n".into());
        };
        Self::refresh(job)?;
        if job.exit_code.is_none() {
            kill_process_group(job.child.id())?;
            let status = job.child.wait()?;
            job.exit_code = Some(status.code().unwrap_or(-1));
        }
        Ok(format!("OK id={id} state=exited\n"))
    }
    /// Attempts to terminate and reap every tracked active workload.
    fn shutdown(&mut self) {
        for job in self.jobs.values_mut() {
            if job.exit_code.is_none() {
                let _ = kill_process_group(job.child.id());
                let _ = job.child.wait();
            }
        }
    }
}
fn main() -> std::io::Result<()> {
    // Development-only local Unix socket. This is NOT a remotely authenticated channel.
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
    // SECURITY: The vsock bridge is opt-in and development-only.
    // It does not authenticate the host or verify guest attestation.
    dev_vsock::spawn(socket.to_path_buf())?;
    let mut manager = Manager::new(log_dir, Policy::from_env()?, product::load()?);
    println!(
        "gammacloud-runtime state={} attestation=unverified confidential=false",
        GuestState::Ready.as_str()
    );
    let mut stopping = false;
    for incoming in listener.incoming() {
        let mut stream = incoming?;
        if !manager.policy.authorize(&stream)? {
            stream.write_all(b"ERR unauthorized-peer\n")?;
            continue;
        }
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        let mut request = String::new();
        // Bound the request before allocating unbounded memory.
        BufReader::new(&stream).take(257).read_line(&mut request)?;
        let response = match parse_request(&request) {
            Ok(Request::Health) => "OK\n".into(),
            Ok(Request::Status) => "state=ready attestation=unverified confidential=false\n".into(),
            Ok(Request::Shutdown) => {
                stopping = true;
                "state=stopping\n".into()
            }
            Ok(Request::Start { profile }) => manager.start(profile)?,
            Ok(Request::WorkloadStatus { id }) => manager.status(id)?,
            Ok(Request::WorkloadLogs { id }) => manager.logs(id)?,
            Ok(Request::Stop { id }) => manager.stop(id)?,
            Err(err) => format!("ERR {err}\n"),
        };
        stream.write_all(response.as_bytes())?;
        if stopping {
            break;
        }
    }
    manager.shutdown();
    fs::remove_file(socket)?;
    println!("gammacloud-runtime state={}", GuestState::Stopped.as_str());
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn models_rejects_execution() {
        let dir = std::env::temp_dir();
        let mut manager = Manager::new(dir, Policy::from_env().unwrap(), product::Product::Models);
        assert_eq!(manager.start(Profile::Smoke).unwrap(), "ERR workload-not-allowed-for-product\\n");
    }
    #[test]
    fn lifecycle_and_allowlist() {
        let dir =
            std::env::temp_dir().join(format!("gammacloud-runtime-test-{}", std::process::id()));
        let mut manager = Manager::new(dir.clone(), Policy::from_env().unwrap(), product::Product::Sandbox);
        let start = manager.start(Profile::Smoke).unwrap();
        assert!(start.contains("id=1"));
        let status = manager.status(1).unwrap();
        assert!(status.contains("profile=smoke"));
        let logs = manager.logs(1).unwrap();
        assert!(logs.starts_with("OK stdout="));
        assert!(manager.stop(1).unwrap().contains("state=exited"));
        assert_eq!(manager.status(999).unwrap(), "ERR unknown-id\n");
        manager.shutdown();
        fs::remove_dir_all(dir).unwrap();
    }
}
