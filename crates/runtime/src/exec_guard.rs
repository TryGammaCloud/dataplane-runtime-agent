//! In-sandbox verification before an authorized executable is entered.
//! systemd can gracefully omit unsupported protections; this guard rejects them.
use crate::authorization::hex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Guard {
    pub executable: String,
    pub digest: String,
    pub arguments: Vec<String>,
    pub uid: u32,
    pub gid: u32,
    pub memory_bytes: u64,
    pub cpu_percent: u32,
    pub max_pids: u32,
    pub original_namespaces: Vec<(String, String)>,
    pub root_device: u64,
    pub root_inode: u64,
    pub egress_lifetime: Option<u64>,
    pub deadline_boot_nanos: u64,
}

fn denied() -> io::Error {
    io::Error::other("mandatory isolation verification failed")
}

pub fn run(raw: &str) -> io::Result<()> {
    let guard: Guard = serde_json::from_str(raw).map_err(|_| denied())?;
    if guard.uid == 0
        || unsafe { libc::geteuid() } != guard.uid
        || unsafe { libc::getegid() } != guard.gid
    {
        return Err(denied());
    }
    let status = fs::read_to_string("/proc/self/status")?;
    for line in [
        "NoNewPrivs:\t1",
        "Seccomp:\t2",
        "CapEff:\t0000000000000000",
        "CapPrm:\t0000000000000000",
        "CapBnd:\t0000000000000000",
    ] {
        if !status.lines().any(|found| found == line) {
            return Err(denied());
        }
    }
    if guard.original_namespaces.len() != 4 {
        return Err(denied());
    }
    for (name, original) in &guard.original_namespaces {
        if !["mnt", "pid", "net", "user"].contains(&name.as_str()) {
            return Err(denied());
        }
        if fs::read_link(format!("/proc/self/ns/{name}"))?.to_string_lossy() == *original {
            return Err(denied());
        }
    }
    let root = fs::metadata("/")?;
    if root.dev() != guard.root_device || root.ino() != guard.root_inode {
        return Err(denied());
    }
    let group_count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if group_count < 0 {
        return Err(denied());
    }
    let mut groups = vec![0; group_count as usize];
    if unsafe { libc::getgroups(group_count, groups.as_mut_ptr()) } < 0
        || groups.iter().any(|group| *group != guard.gid)
    {
        return Err(denied());
    }
    let cgroup = fs::read_to_string("/proc/self/cgroup")?;
    let relative = cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::/"))
        .ok_or_else(denied)?;
    let base = Path::new("/sys/fs/cgroup").join(relative);
    let number = |name: &str| -> io::Result<u64> {
        fs::read_to_string(base.join(name))?
            .trim()
            .parse()
            .map_err(|_| denied())
    };
    if number("memory.max")? > guard.memory_bytes
        || number("memory.swap.max")? != 0
        || number("pids.max")? > u64::from(guard.max_pids)
    {
        return Err(denied());
    }
    let cpu = fs::read_to_string(base.join("cpu.max"))?;
    let values: Vec<u64> = cpu
        .split_whitespace()
        .map(|v| v.parse().map_err(|_| denied()))
        .collect::<io::Result<_>>()?;
    if values.len() != 2
        || values[0].saturating_mul(100) > u64::from(guard.cpu_percent).saturating_mul(values[1])
    {
        return Err(denied());
    }
    let mut digest = Sha256::new();
    let mut file = File::open(&guard.executable)?;
    let mut buffer = [0; 65_536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    if hex(&digest.finalize()) != guard.digest {
        return Err(denied());
    }
    for path in ["/", "/nix/store", "/sys/fs/cgroup"] {
        let path = std::ffi::CString::new(path).map_err(|_| denied())?;
        let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(path.as_ptr(), &mut stats) } != 0
            || stats.f_flag & libc::ST_RDONLY == 0
        {
            return Err(denied());
        }
    }
    crate::seccomp::install()?;
    if let Some(lifetime) = guard.egress_lifetime {
        let mut child = Command::new(std::env::current_exe()?)
            .arg("--egress-sidecar")
            .arg(lifetime.to_string())
            .spawn()?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if child.try_wait()?.is_some() {
                return Err(denied());
            }
            if std::net::TcpStream::connect_timeout(
                &"127.0.0.1:18443".parse().map_err(|_| denied())?,
                std::time::Duration::from_millis(10),
            )
            .is_ok()
            {
                break;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(denied());
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    if crate::lifecycle::boot_nanos()? >= guard.deadline_boot_nanos {
        return Err(denied());
    }
    // Exec preserves the verified namespaces, cgroup, credentials and seccomp filter.
    Err(Command::new(&guard.executable)
        .args(&guard.arguments)
        .exec())
}
