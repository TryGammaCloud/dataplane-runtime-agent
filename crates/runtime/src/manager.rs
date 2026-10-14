//! Fixed-profile development process lifecycle; no arbitrary execution.
use crate::product;
use crate::security::{kill_process_group, Policy};
use gammacloud_protocol::Profile;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

const MAX_WORKLOADS: usize = 16;
const MAX_LOG_BYTES: u64 = 4096;

struct Workload {
    child: Child,
    profile: Profile,
    stdout: PathBuf,
    stderr: PathBuf,
    exit_code: Option<i32>,
}
pub struct Manager {
    jobs: BTreeMap<u64, Workload>,
    next_id: u64,
    log_dir: PathBuf,
    policy: Policy,
    product: product::Product,
}
impl Manager {
    pub fn new(log_dir: PathBuf, policy: Policy, product: product::Product) -> Self {
        Self {
            jobs: BTreeMap::new(),
            next_id: 1,
            log_dir,
            policy,
            product,
        }
    }
    pub fn authorize(&self, stream: &std::os::unix::net::UnixStream) -> std::io::Result<bool> {
        self.policy.authorize(stream)
    }
    pub fn start(&mut self, profile: Profile) -> std::io::Result<String> {
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
        // Executable paths are immutable image-owned Nix store paths when packaged.
        // The development fallback permits bare-host Rust tests.
        let mut cmd = match profile {
            Profile::Smoke => {
                let mut c =
                    Command::new(option_env!("GAMMACLOUD_PRINTF_BIN").unwrap_or("/usr/bin/printf"));
                c.arg("GAMMACLOUD_WORKLOAD_OK\n");
                c
            }
            Profile::Sleep => {
                let mut c =
                    Command::new(option_env!("GAMMACLOUD_SLEEP_BIN").unwrap_or("/usr/bin/sleep"));
                c.arg("30");
                c
            }
            Profile::Worker => Command::new(
                option_env!("GAMMACLOUD_WORKER_BIN").unwrap_or("/opt/gammacloud/workloads/worker"),
            ),
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
    pub fn status(&mut self, id: u64) -> std::io::Result<String> {
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
    pub fn logs(&self, id: u64) -> std::io::Result<String> {
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
    pub fn stop(&mut self, id: u64) -> std::io::Result<String> {
        let Some(job) = self.jobs.get_mut(&id) else { return Ok("ERR unknown-id\n".into()); };
        Self::refresh(job)?;
        if job.exit_code.is_none() {
            kill_process_group(job.child.id())?;
            let status = job.child.wait()?;
            job.exit_code = Some(status.code().unwrap_or(-1));
        }
        Ok(format!("OK id={id} state=exited\n"))
    }
    pub fn shutdown(&mut self) {
        for job in self.jobs.values_mut() {
            if job.exit_code.is_none() {
                let _ = kill_process_group(job.child.id());
                let _ = job.child.wait();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn models_rejects_execution() {
        let dir = std::env::temp_dir();
        let mut manager = Manager::new(dir, Policy::from_env().unwrap(), product::Product::Models);
        assert_eq!(
            manager.start(Profile::Smoke).unwrap(),
            "ERR workload-not-allowed-for-product\n"
        );
    }
    #[test]
    fn lifecycle_and_allowlist() {
        let dir =
            std::env::temp_dir().join(format!("gammacloud-runtime-test-{}", std::process::id()));
        let mut manager = Manager::new(
            dir.clone(),
            Policy::from_env().unwrap(),
            product::Product::Sandbox,
        );
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
