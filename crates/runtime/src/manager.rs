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
    profile: String,
    unit: Option<String>,
    gateway: Option<crate::egress::Gateway>,
    credential_descriptors: Vec<std::os::fd::OwnedFd>,
    stdout: PathBuf,
    stderr: PathBuf,
    exit_code: Option<i32>,
    started_at: std::time::Instant,
    lease: Option<crate::lease::Lease>,
}
pub struct Manager {
    jobs: BTreeMap<u64, Workload>,
    next_id: u64,
    log_dir: PathBuf,
    policy: Policy,
    product: product::Product,
    registry: Option<crate::recovery::Registry>,
}
impl Manager {
    pub fn new(log_dir: PathBuf, policy: Policy, product: product::Product) -> Self {
        Self {
            jobs: BTreeMap::new(),
            next_id: 1,
            log_dir,
            policy,
            product,
            registry: None,
        }
    }
    pub fn enable_recovery(&mut self) -> std::io::Result<()> {
        self.registry = Some(crate::recovery::Registry::open()?);
        Ok(())
    }
    pub fn samples(&self) -> Vec<crate::observability::Sample> {
        self.jobs
            .iter()
            .map(|(id, job)| {
                crate::observability::sample(
                    *id,
                    job.started_at
                        .elapsed()
                        .as_millis()
                        .min(u128::from(u64::MAX)) as u64,
                    job.unit.as_deref(),
                )
            })
            .collect()
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
                profile: profile.as_str().into(),
                unit: None,
                gateway: None,
                credential_descriptors: Vec::new(),
                stdout,
                stderr,
                exit_code: None,
                started_at: std::time::Instant::now(),
                lease: None,
            },
        );
        Ok(format!("OK id={id} profile={}\n", profile.as_str()))
    }
    /// Starts only an authorized immutable template with mandatory OS isolation.
    pub fn execute(
        &mut self,
        manifest: &gammacloud_protocol::structured::ExecutionManifest,
        template: &crate::isolated::ExecutionTemplate,
        volume: Option<&crate::storage::VolumePolicy>,
        terminal: Option<File>,
        authorization: crate::isolated::LaunchAuthorization<'_>,
    ) -> std::io::Result<String> {
        if !matches!(
            self.product,
            product::Product::Sandbox | product::Product::Models
        ) {
            return Ok("ERR workload-not-allowed-for-product\n".into());
        }
        if self.jobs.len() >= MAX_WORKLOADS {
            return Ok("ERR capacity-exceeded\n".into());
        }
        crate::isolated::validate(manifest, template)?;
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("id exhausted"))?;
        let mut nonce = [0; 16];
        File::open("/dev/urandom")?.read_exact(&mut nonce)?;
        let unit = format!(
            "gammacloud-job-{}.service",
            crate::authorization::hex(&nonce)
        );
        let decision: gammacloud_protocol::structured::AttestationDecision =
            serde_json::from_str(&authorization.decision.payload)
                .map_err(|_| std::io::Error::other("decision unavailable"))?;
        if decision.workload_digest != authorization.workload_digest {
            return Err(std::io::Error::other("workload decision mismatch"));
        }
        let remaining = decision.expires_at.saturating_sub(
            crate::authorization::now().map_err(|_| std::io::Error::other("clock unavailable"))?,
        );
        if remaining == 0 {
            return Err(std::io::Error::other("decision expired"));
        }
        let lease_deadline = std::time::Instant::now() + std::time::Duration::from_secs(remaining);
        let mut deadline_boot_nanos =
            crate::lifecycle::boot_nanos()?.saturating_add(remaining.saturating_mul(1_000_000_000));
        let mut effective = manifest.clone();
        effective.timeout_seconds = effective.timeout_seconds.min(remaining);
        let mut credential_descriptors = Vec::new();
        let mut credential_paths = Vec::new();
        use std::os::fd::AsRawFd;
        for (name, policy) in &template.credentials {
            if name.is_empty()
                || name.len() > 64
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                || policy.lifetime_seconds == 0
                || policy.lifetime_seconds > 300
            {
                return Err(std::io::Error::other("credential policy invalid"));
            }
            effective.timeout_seconds = effective.timeout_seconds.min(policy.lifetime_seconds);
            deadline_boot_nanos = deadline_boot_nanos.min(
                crate::lifecycle::boot_nanos()?
                    .saturating_add(policy.lifetime_seconds.saturating_mul(1_000_000_000)),
            );
            let fd = crate::storage::credential_descriptor(
                &policy.reference,
                &policy.scope,
                &authorization,
            )?;
            credential_paths.push((
                name.clone(),
                format!("/proc/{}/fd/{}", std::process::id(), fd.as_raw_fd()),
            ));
            credential_descriptors.push(fd);
        }
        let gateway = if template.egress.destinations.is_empty() {
            None
        } else {
            Some(crate::egress::Gateway::start(
                template.egress.clone(),
                template.uid,
                std::time::Duration::from_secs(effective.timeout_seconds),
            )?)
        };
        let mut command = crate::isolated::command(
            &effective,
            template,
            crate::isolated::LaunchOptions {
                unit: &unit,
                volume,
                interactive: terminal.is_some(),
                gateway: gateway.as_ref().map(|gateway| gateway.path.as_path()),
                credentials: &credential_paths,
                deadline_boot_nanos,
            },
        )?;
        fs::create_dir_all(&self.log_dir)?;
        fs::set_permissions(&self.log_dir, fs::Permissions::from_mode(0o700))?;
        let stdout = self.log_dir.join(format!("{id}.stdout"));
        let stderr = self.log_dir.join(format!("{id}.stderr"));
        // The wrapper forwards output to these files; cap its file writes on disk.
        use std::os::unix::process::CommandExt;
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                let limit = libc::rlimit {
                    rlim_cur: 1_048_576,
                    rlim_max: 1_048_576,
                };
                if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        if let Some(terminal) = terminal {
            command
                .stdin(Stdio::from(terminal.try_clone()?))
                .stdout(Stdio::from(terminal.try_clone()?))
                .stderr(Stdio::from(terminal));
        } else {
            command
                .stdin(Stdio::null())
                .stdout(Stdio::from(File::create(&stdout)?))
                .stderr(Stdio::from(File::create(&stderr)?));
        }
        if let Some(registry) = &self.registry {
            registry.track(&unit, &authorization.workload_digest)?;
        }
        let parent = unsafe { libc::getpid() };
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                    || libc::getppid() != parent
                {
                    return Err(std::io::Error::other("runtime parent unavailable"));
                }
                Ok(())
            });
        }
        let monotonic_remaining =
            deadline_boot_nanos.saturating_sub(crate::lifecycle::boot_nanos()?);
        if monotonic_remaining == 0 {
            return Err(std::io::Error::other("launch lease expired"));
        }
        let deadline = lease_deadline
            .min(std::time::Instant::now() + std::time::Duration::from_nanos(monotonic_remaining));
        let child = command.spawn()?;
        let lease = Some(crate::lease::Lease::start(unit.clone(), deadline));
        self.jobs.insert(
            id,
            Workload {
                child,
                profile: manifest.template.clone(),
                unit: Some(unit),
                gateway,
                credential_descriptors,
                stdout,
                stderr,
                exit_code: None,
                started_at: std::time::Instant::now(),
                lease,
            },
        );
        Ok(format!("OK id={id} state=starting\n"))
    }

    pub fn product(&self) -> product::Product {
        self.product
    }

    pub fn unit(&self, id: u64) -> Option<&str> {
        self.jobs.get(&id).and_then(|job| job.unit.as_deref())
    }

    pub fn latest_id(&self) -> Option<u64> {
        self.jobs.last_key_value().map(|(id, _)| *id)
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
        let Some(job) = self.jobs.get_mut(&id) else {
            return Ok("ERR unknown-id\n".into());
        };
        Self::refresh(job)?;
        if let Some(unit) = &job.unit {
            crate::isolated::control(unit, "stop")?;
        }
        if job.exit_code.is_none() {
            kill_process_group(job.child.id())?;
            let status = job.child.wait()?;
            job.exit_code = Some(status.code().unwrap_or(-1));
        }
        job.lease.take();
        job.gateway.take();
        job.credential_descriptors.clear();
        if let (Some(registry), Some(unit)) = (&self.registry, &job.unit) {
            registry.complete(unit)?;
        }
        Ok(format!("OK id={id} state=exited\n"))
    }
    pub fn shutdown(&mut self) {
        for job in self.jobs.values_mut() {
            job.lease.take();
            job.gateway.take();
            job.credential_descriptors.clear();
            if let Some(unit) = &job.unit {
                if crate::isolated::control(unit, "stop").is_ok() {
                    if let Some(registry) = &self.registry {
                        let _ = registry.complete(unit);
                    }
                }
            }
            if job.exit_code.is_none() {
                let _ = kill_process_group(job.child.id());
                if let Ok(status) = job.child.wait() {
                    job.exit_code = Some(status.code().unwrap_or(-1));
                }
            }
        }
    }
}

// LIFECYCLE: Also clean managed children on listener errors and unwinding.
// SIGKILL/process abort and descendants that escape the group require OS isolation.
impl Drop for Manager {
    fn drop(&mut self) {
        self.shutdown();
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
