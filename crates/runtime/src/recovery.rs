//! Durable registry of owned systemd services; restart recovery stops before admission.
//! No argv, file content, credentials or model prompts are persisted here.
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    unit: String,
    manifest_digest: String,
    recorded_at: u64,
}

pub struct Registry {
    directory: PathBuf,
}
fn rejected() -> io::Error {
    io::Error::other("service recovery failed")
}
fn valid(unit: &str) -> bool {
    unit.strip_prefix("gammacloud-job-")
        .and_then(|s| s.strip_suffix(".service"))
        .is_some_and(|id| {
            id.len() == 32
                && id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

impl Registry {
    pub fn open() -> io::Result<Self> {
        let directory = PathBuf::from("/var/lib/gammacloud/runtime/services");
        if !directory.exists() {
            fs::DirBuilder::new().mode(0o700).create(&directory)?;
        }
        let metadata = fs::symlink_metadata(&directory)?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(rejected());
        }
        let registry = Self { directory };
        let entries: Vec<_> = fs::read_dir(&registry.directory)?.collect::<io::Result<_>>()?;
        if entries.len() > 1024 {
            return Err(rejected());
        }
        for entry in entries {
            // An incomplete atomic write is harmless: it precedes the tracked spawn.
            if entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "pending")
            {
                fs::remove_file(entry.path())?;
                continue;
            }
            let bytes = crate::authorization::trusted_read(&entry.path(), 4096)?;
            let record: Record = serde_json::from_slice(&bytes).map_err(|_| rejected())?;
            if !valid(&record.unit) || entry.file_name() != record.unit.as_str() {
                return Err(rejected());
            }
            let state = crate::subprocess::output(
                Command::new(crate::isolated::SYSTEMCTL)
                    .env_clear()
                    .args(["show", "--property=LoadState", "--value", &record.unit])
                    .stdin(Stdio::null()),
                Duration::from_secs(2),
                256,
            )?;
            if state != b"not-found\n" {
                crate::isolated::control(&record.unit, "stop")?;
            }
            registry.complete(&record.unit)?;
            eprintln!("gammacloud-runtime event=service-reconciled");
        }
        Ok(registry)
    }
    pub fn track(&self, unit: &str, digest: &str) -> io::Result<()> {
        if !valid(unit) {
            return Err(rejected());
        }
        let record = Record {
            unit: unit.into(),
            manifest_digest: digest.into(),
            recorded_at: crate::authorization::now().map_err(|_| rejected())?,
        };
        crate::authorization::atomic_write(
            &self.directory.join(unit),
            &serde_json::to_vec(&record).map_err(|_| rejected())?,
        )
    }
    pub fn complete(&self, unit: &str) -> io::Result<()> {
        if !valid(unit) {
            return Err(rejected());
        }
        match fs::remove_file(self.directory.join(unit)) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        File::open(&self.directory)?.sync_all()
    }
}

#[cfg(test)]
mod tests {
    use super::valid;
    #[test]
    fn recovery_cannot_target_unrelated_services() {
        assert!(valid(
            "gammacloud-job-0123456789abcdef0123456789abcdef.service"
        ));
        assert!(!valid("sshd.service"));
        assert!(!valid("gammacloud-job-../sshd.service"));
    }
}
