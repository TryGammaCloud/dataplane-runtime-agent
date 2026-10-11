//! Linux-only local access policy and per-process resource limits.
//! This does not authenticate a remote host or prove SEV-SNP attestation.
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::process::Command;

#[repr(C)]
struct UCred { pid: i32, uid: u32, gid: u32 }
#[repr(C)]
struct RLimit { current: u64, maximum: u64 }
unsafe extern "C" {
    fn getsockopt(fd: i32, level: i32, name: i32, value: *mut UCred, length: *mut u32) -> i32;
    fn geteuid() -> u32;
    fn setrlimit(resource: i32, limit: *const RLimit) -> i32;
    fn setsid() -> i32;
    fn kill(pid: i32, signal: i32) -> i32;
}
const SOL_SOCKET: i32 = 1;
const SO_PEERCRED: i32 = 17;
const RLIMIT_CPU: i32 = 0;
const RLIMIT_AS: i32 = 9;
const SIGKILL: i32 = 9;

pub struct Policy { allowed_uid: u32, max_memory_bytes: u64, max_cpu_seconds: u64 }
impl Policy {
    pub fn from_env() -> io::Result<Self> {
        let uid = unsafe { geteuid() };
        let allowed_uid = std::env::var("GAMMACLOUD_RUNTIME_ALLOWED_UID")
            .map(|s| s.parse::<u32>().map_err(|_| io::Error::other("invalid allowed UID")))
            .unwrap_or(Ok(uid))?;
        let memory_mib = std::env::var("GAMMACLOUD_WORKLOAD_MEMORY_MIB")
            .map(|s| s.parse::<u64>().map_err(|_| io::Error::other("invalid memory limit")))
            .unwrap_or(Ok(256))?;
        let cpu_seconds = std::env::var("GAMMACLOUD_WORKLOAD_CPU_SECONDS")
            .map(|s| s.parse::<u64>().map_err(|_| io::Error::other("invalid CPU limit")))
            .unwrap_or(Ok(10))?;
        if !(32..=4096).contains(&memory_mib) || !(1..=300).contains(&cpu_seconds) {
            return Err(io::Error::other("resource limit outside policy bounds"));
        }
        Ok(Self { allowed_uid, max_memory_bytes: memory_mib * 1024 * 1024, max_cpu_seconds: cpu_seconds })
    }
    pub fn authorize(&self, stream: &UnixStream) -> io::Result<bool> {
        let mut cred = UCred { pid: 0, uid: 0, gid: 0 };
        let mut size = std::mem::size_of::<UCred>() as u32;
        let rc = unsafe { getsockopt(stream.as_raw_fd(), SOL_SOCKET, SO_PEERCRED, &mut cred, &mut size) };
        if rc != 0 { return Err(io::Error::last_os_error()); }
        if size as usize != std::mem::size_of::<UCred>() { return Err(io::Error::other("invalid peer credentials")); }
        Ok(cred.uid == self.allowed_uid)
    }
    pub fn configure(&self, cmd: &mut Command) {
        use std::os::unix::process::CommandExt;
        let memory = self.max_memory_bytes;
        let cpu = self.max_cpu_seconds;
        unsafe {
            cmd.pre_exec(move || {
                if setsid() == -1 { return Err(io::Error::last_os_error()); }
                let memory_limit = RLimit { current: memory, maximum: memory };
                let cpu_limit = RLimit { current: cpu, maximum: cpu };
                if setrlimit(RLIMIT_AS, &memory_limit) == -1 { return Err(io::Error::last_os_error()); }
                if setrlimit(RLIMIT_CPU, &cpu_limit) == -1 { return Err(io::Error::last_os_error()); }
                Ok(())
            });
        }
    }
}
pub fn kill_process_group(pid: u32) -> io::Result<()> {
    let id = i32::try_from(pid).map_err(|_| io::Error::other("invalid process id"))?;
    if unsafe { kill(-id, SIGKILL) } == -1 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(3) { return Err(err); }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_peer_identity() {
        let (a, _b) = UnixStream::pair().unwrap();
        let policy = Policy::from_env().unwrap();
        assert!(policy.authorize(&a).unwrap());
    }
}
