//! OS-backed isolated execution through transient systemd services.
//! The OS owns immutable templates; untrusted manifests cannot weaken protections.
use crate::authorization::hex;
use gammacloud_protocol::structured::ExecutionManifest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const SYSTEMD_RUN: &str = "/run/current-system/sw/bin/systemd-run";
pub const SYSTEMCTL: &str = "/run/current-system/sw/bin/systemctl";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionTemplate {
    pub executable: String,
    pub sha256: String,
    pub root_directory: String,
    pub uid: u32,
    pub gid: u32,
    pub max_memory_mib: u64,
    pub max_cpu_percent: u32,
    pub max_pids: u32,
    pub max_timeout_seconds: u64,
    #[serde(default)]
    pub volume_id: Option<String>,
    #[serde(default)]
    pub egress: crate::egress::EgressPolicy,
    #[serde(default)]
    pub credentials: BTreeMap<String, CredentialPolicy>,
    #[serde(default)]
    pub model_directory: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialPolicy {
    pub reference: String,
    pub scope: String,
    pub lifetime_seconds: u64,
}

pub struct LaunchAuthorization<'a> {
    pub request: &'a gammacloud_protocol::structured::SignedEnvelope,
    pub decision: &'a gammacloud_protocol::structured::SignedEnvelope,
    pub workload_digest: String,
}

impl<'a> LaunchAuthorization<'a> {
    pub fn new<T: Serialize>(
        request: &'a gammacloud_protocol::structured::SignedEnvelope,
        decision: &'a gammacloud_protocol::structured::SignedEnvelope,
        manifest: &T,
    ) -> io::Result<Self> {
        let bytes = serde_json::to_vec(manifest)
            .map_err(|_| io::Error::other("manifest serialization failed"))?;
        Ok(Self {
            request,
            decision,
            workload_digest: hex(&Sha256::digest(bytes)),
        })
    }
}

pub type Templates = BTreeMap<String, ExecutionTemplate>;

pub fn validate(manifest: &ExecutionManifest, template: &ExecutionTemplate) -> io::Result<()> {
    let invalid = || io::Error::other("execution policy rejected");
    if template.uid == 0
        || template.gid == 0
        || !template.executable.starts_with("/nix/store/")
        || !template
            .root_directory
            .starts_with("/srv/gammacloud/roots/")
    {
        return Err(invalid());
    }
    if manifest.memory_mib < 32
        || manifest.memory_mib > template.max_memory_mib
        || manifest.cpu_percent == 0
        || manifest.cpu_percent > template.max_cpu_percent
        || manifest.max_pids == 0
        || manifest.max_pids > template.max_pids
        || manifest.timeout_seconds == 0
        || manifest.timeout_seconds > template.max_timeout_seconds
    {
        return Err(invalid());
    }
    if manifest.arguments.len() > 128
        || manifest
            .arguments
            .iter()
            .any(|s| s.len() > 4096 || s.contains('\0'))
        || !manifest.working_directory.starts_with('/')
        || Path::new(&manifest.working_directory)
            .components()
            .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(invalid());
    }
    if manifest.environment.iter().any(|(key, value)| {
        !["TERM", "LANG", "LC_ALL"].contains(&key.as_str())
            || value.len() > 256
            || value.chars().any(char::is_control)
    }) {
        return Err(invalid());
    }
    Ok(())
}

/// Checks actual guest facilities before submitting any customer command.
fn preflight(template: &ExecutionTemplate) -> io::Result<()> {
    let unavailable = || io::Error::other("isolation backend unavailable");
    if unsafe { libc::geteuid() } != 0 || !Path::new("/run/systemd/system").is_dir() {
        return Err(unavailable());
    }
    let controllers = fs::read_to_string("/sys/fs/cgroup/cgroup.controllers")?;
    if ["cpu", "memory", "pids"]
        .iter()
        .any(|c| !controllers.split_whitespace().any(|found| found == *c))
    {
        return Err(unavailable());
    }
    for namespace in ["mnt", "pid", "net", "user"] {
        fs::metadata(format!("/proc/self/ns/{namespace}"))?;
    }
    fs::read_to_string("/proc/sys/kernel/seccomp/actions_avail")?;
    for path in [SYSTEMD_RUN, SYSTEMCTL] {
        let metadata = fs::metadata(path)?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(unavailable());
        }
    }
    let root = Path::new(&template.root_directory);
    if fs::canonicalize(root)? != root || !root.is_dir() {
        return Err(unavailable());
    }
    let metadata = root.metadata()?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(unavailable());
    }
    let path = Path::new(&template.executable);
    if fs::canonicalize(path)? != path {
        return Err(unavailable());
    }
    let metadata = path.metadata()?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(unavailable());
    }
    let mut digest = Sha256::new();
    let mut file = File::open(path)?;
    let mut buffer = [0; 65_536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    if hex(&digest.finalize()) != template.sha256 {
        return Err(unavailable());
    }
    Ok(())
}

pub struct LaunchOptions<'a> {
    pub unit: &'a str,
    pub volume: Option<&'a crate::storage::VolumePolicy>,
    pub interactive: bool,
    pub gateway: Option<&'a std::path::Path>,
    pub credentials: &'a [(String, String)],
    pub deadline_boot_nanos: u64,
}

pub fn command(
    manifest: &ExecutionManifest,
    template: &ExecutionTemplate,
    options: LaunchOptions<'_>,
) -> io::Result<Command> {
    let LaunchOptions {
        unit,
        volume,
        interactive,
        gateway,
        credentials,
        deadline_boot_nanos,
    } = options;
    validate(manifest, template)?;
    preflight(template)?;
    if template.volume_id.is_some() != volume.is_some() {
        return Err(io::Error::other("workspace unavailable"));
    }
    if let Some(volume) = volume {
        if volume.uid != template.uid || volume.gid != template.gid {
            return Err(io::Error::other("workspace identity mismatch"));
        }
        crate::storage::ready(template.volume_id.as_ref().unwrap(), volume)?;
    }
    let mut command = Command::new(SYSTEMD_RUN);
    command.env_clear().args([
        "--quiet",
        "--wait",
        "--service-type=exec",
        "--expand-environment=no",
        "--description=GammaCloud isolated workload",
    ]);
    command.arg(if interactive { "--pty" } else { "--pipe" });
    command.arg(format!("--unit={unit}"));
    for property in [
        "BindsTo=gammacloud-runtime.service".into(),
        "After=gammacloud-runtime.service".into(),
        "NoNewPrivileges=yes".into(),
        "CapabilityBoundingSet=".into(),
        "AmbientCapabilities=".into(),
        "PrivateNetwork=yes".into(),
        "PrivateTmp=yes".into(),
        "PrivateDevices=yes".into(),
        "PrivateUsers=yes".into(),
        "PrivatePIDs=yes".into(),
        "SupplementaryGroups=".into(),
        "ProtectSystem=strict".into(),
        "ProtectHome=yes".into(),
        "ProtectKernelTunables=yes".into(),
        "ProtectKernelModules=yes".into(),
        "ProtectKernelLogs=yes".into(),
        "ProtectControlGroups=yes".into(),
        "RestrictSUIDSGID=yes".into(),
        "RestrictRealtime=yes".into(),
        "RestrictNamespaces=yes".into(),
        "LockPersonality=yes".into(),
        "RemoveIPC=yes".into(),
        "SystemCallArchitectures=native".into(),
        "SystemCallFilter=@system-service".into(),
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6".into(),
        "KillMode=control-group".into(),
        "TimeoutStopSec=5s".into(),
        "SendSIGKILL=yes".into(),
        "LimitCORE=0".into(),
        "MemorySwapMax=0".into(),
        "MemoryAccounting=yes".into(),
        "CPUAccounting=yes".into(),
        "TasksAccounting=yes".into(),
        "MountAPIVFS=yes".into(),
        "BindReadOnlyPaths=/nix/store".into(),
        format!("User={}", template.uid),
        format!("Group={}", template.gid),
        format!("RootDirectory={}", template.root_directory),
        format!("WorkingDirectory={}", manifest.working_directory),
        format!("MemoryMax={}M", manifest.memory_mib),
        format!("CPUQuota={}%", manifest.cpu_percent),
        format!("TasksMax={}", manifest.max_pids),
        format!("RuntimeMaxSec={}s", manifest.timeout_seconds),
    ] {
        command.arg(format!("--property={property}"));
    }
    if let Some(volume) = volume {
        command.arg(format!(
            "--property=BindPaths={}/workspace:/workspace",
            volume.mount_path
        ));
        command.arg("--property=ReadWritePaths=/workspace");
    }
    if let Some(path) = gateway {
        command.arg(format!(
            "--property=BindReadOnlyPaths={}:/run/gammacloud/egress.sock",
            path.display()
        ));
        command.arg("--setenv=HTTPS_PROXY=http://127.0.0.1:18443");
        command.arg("--setenv=ALL_PROXY=http://127.0.0.1:18443");
    }
    if let Some(directory) = &template.model_directory {
        command.arg(format!("--property=BindReadOnlyPaths={directory}:/models"));
    }
    for (name, path) in credentials {
        command.arg(format!("--property=LoadCredential={name}:{path}"));
    }
    for (key, value) in &manifest.environment {
        command.arg(format!("--setenv={key}={value}"));
    }
    let guard_executable = fs::canonicalize(std::env::current_exe()?)?;
    if !guard_executable.starts_with("/nix/store") {
        return Err(io::Error::other("guard must be OS packaged"));
    }
    let root = fs::metadata(&template.root_directory)?;
    let guard = crate::exec_guard::Guard {
        executable: template.executable.clone(),
        digest: template.sha256.clone(),
        arguments: manifest.arguments.clone(),
        uid: template.uid,
        gid: template.gid,
        memory_bytes: manifest
            .memory_mib
            .checked_mul(1_048_576)
            .ok_or_else(|| io::Error::other("memory overflow"))?,
        cpu_percent: manifest.cpu_percent,
        max_pids: manifest.max_pids,
        original_namespaces: ["mnt", "pid", "net", "user"]
            .iter()
            .map(|name| {
                Ok((
                    name.to_string(),
                    fs::read_link(format!("/proc/self/ns/{name}"))?
                        .to_string_lossy()
                        .into_owned(),
                ))
            })
            .collect::<io::Result<_>>()?,
        root_device: root.dev(),
        root_inode: root.ino(),
        egress_lifetime: gateway.map(|_| manifest.timeout_seconds),
        deadline_boot_nanos,
    };
    command
        .arg("--")
        .arg(guard_executable)
        .arg("--isolated-child")
        .arg(
            serde_json::to_string(&guard)
                .map_err(|_| io::Error::other("guard serialization failed"))?,
        );
    Ok(command)
}

/// Bounded systemctl calls never log command output (which can contain arguments).
pub fn control(unit: &str, verb: &str) -> io::Result<()> {
    let mut child = Command::new(SYSTEMCTL)
        .env_clear()
        .args([verb, unit])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(6);
    loop {
        if let Some(status) = child.try_wait()? {
            return if status.success() {
                Ok(())
            } else {
                Err(io::Error::other("service operation failed"))
            };
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::ErrorKind::TimedOut.into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manifests_cannot_weaken_identity_or_resource_policy() {
        let mut template = ExecutionTemplate {
            executable: "/nix/store/approved/bin/tool".into(),
            sha256: "digest".into(),
            root_directory: "/srv/gammacloud/roots/base".into(),
            uid: 1000,
            gid: 1000,
            max_memory_mib: 128,
            max_cpu_percent: 100,
            max_pids: 32,
            max_timeout_seconds: 30,
            volume_id: None,
            egress: Default::default(),
            credentials: Default::default(),
            model_directory: None,
        };
        let mut manifest = ExecutionManifest {
            template: "base".into(),
            arguments: vec![],
            environment: BTreeMap::new(),
            working_directory: "/".into(),
            memory_mib: 64,
            cpu_percent: 50,
            max_pids: 16,
            timeout_seconds: 10,
        };
        assert!(validate(&manifest, &template).is_ok());
        template.uid = 0;
        assert!(validate(&manifest, &template).is_err());
        template.uid = 1000;
        manifest
            .environment
            .insert("LD_PRELOAD".into(), "/tmp/evil".into());
        assert!(validate(&manifest, &template).is_err());
        manifest.environment.clear();
        manifest.memory_mib = 129;
        assert!(validate(&manifest, &template).is_err());
    }
}
