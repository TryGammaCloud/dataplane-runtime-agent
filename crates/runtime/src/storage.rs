//! Guest volume activation and descriptor-relative workspace operations.
//! Disk keys arrive only as sealed descriptors from an image-provisioned broker.
use gammacloud_protocol::structured::{FileOperation, SignedEnvelope};
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path};
use std::process::{Command, Stdio};
use std::time::Duration;

const CRYPTSETUP: &str = "/run/current-system/sw/bin/cryptsetup";
const BLKID: &str = "/run/current-system/sw/bin/blkid";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumePolicy {
    pub device: String,
    pub luks_uuid: String,
    pub filesystem_uuid: String,
    pub mount_path: String,
    pub uid: u32,
    pub gid: u32,
    pub quota_bytes: u64,
    pub quota_inodes: u64,
}

fn denied() -> io::Error {
    io::Error::other("storage policy rejected")
}
fn cstring(value: &str) -> io::Result<CString> {
    CString::new(value).map_err(|_| denied())
}

fn validate(id: &str, policy: &VolumePolicy) -> io::Result<()> {
    if id.is_empty()
        || id.len() > 48
        || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        || !policy.device.starts_with("/dev/disk/by-id/")
        || !policy.mount_path.starts_with("/srv/gammacloud/volumes/")
        || policy.uid == 0
        || policy.gid == 0
        || policy.quota_bytes < 4096
        || policy.quota_inodes == 0
    {
        return Err(denied());
    }
    for path in [&policy.device, &policy.mount_path] {
        if Path::new(path)
            .components()
            .any(|c| matches!(c, Component::ParentDir))
        {
            return Err(denied());
        }
    }
    Ok(())
}

fn uuid(device: &str) -> io::Result<String> {
    let output = crate::subprocess::output(
        Command::new(BLKID)
            .env_clear()
            .args(["-p", "-s", "UUID", "-o", "value", "--", device])
            .stdin(Stdio::null()),
        Duration::from_secs(2),
        256,
    )?;
    String::from_utf8(output)
        .map(|s| s.trim().to_owned())
        .map_err(|_| denied())
}

/// Broker must independently validate the signed request and verifier decision.
fn key_descriptor(
    id: &str,
    request: &SignedEnvelope,
    decision: &SignedEnvelope,
    key_version: &str,
) -> io::Result<OwnedFd> {
    let mut stream = UnixStream::connect("/run/gammacloud/key-release.sock")?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&credentials) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credentials as *mut _ as *mut _,
            &mut length,
        )
    } < 0
        || credentials.uid != 0
    {
        return Err(denied());
    }
    let bytes = serde_json::to_vec(&serde_json::json!({"version": 1, "volume_id": id, "key_version": key_version, "request": request, "decision": decision})).map_err(|_| denied())?;
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&bytes)?;
    let mut status = [0; 1];
    let mut iov = libc::iovec {
        iov_base: status.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 16];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&control);
    let count = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    let mut descriptors = Vec::new();
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header.is_null() {
        unsafe {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let size = (*header)
                    .cmsg_len
                    .saturating_sub(libc::CMSG_LEN(0) as usize)
                    / std::mem::size_of::<i32>();
                for index in 0..size {
                    descriptors.push(OwnedFd::from_raw_fd(
                        *(libc::CMSG_DATA(header) as *const i32).add(index),
                    ));
                }
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    if count != 1
        || status != [1]
        || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
        || descriptors.len() != 1
    {
        return Err(denied());
    }
    let fd = descriptors.pop().unwrap();
    let seals = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
    let required = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    let metadata = File::from(fd.try_clone()?).metadata()?;
    if seals < 0 || seals & required != required || !(16..=4096).contains(&metadata.len()) {
        return Err(denied());
    }
    Ok(fd)
}

pub fn ready(id: &str, policy: &VolumePolicy) -> io::Result<File> {
    validate(id, policy)?;
    let root = Path::new(&policy.mount_path);
    if fs::canonicalize(root)? != root {
        return Err(denied());
    }
    let mapper = fs::metadata(format!("/dev/mapper/gc-{id}"))?;
    let metadata = root.metadata()?;
    if !mapper.file_type().is_block_device() || metadata.dev() != mapper.rdev() {
        return Err(denied());
    }
    let root = File::open(root)?;
    quota(&root, policy, false)?;
    Ok(root)
}

fn quota(root: &File, policy: &VolumePolicy, set: bool) -> io::Result<()> {
    let mut limits: libc::dqblk = unsafe { std::mem::zeroed() };
    limits.dqb_bhardlimit = policy.quota_bytes / 1024;
    limits.dqb_ihardlimit = policy.quota_inodes;
    limits.dqb_valid = libc::QIF_LIMITS;
    let operation = if set {
        libc::Q_SETQUOTA
    } else {
        libc::Q_GETQUOTA
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_quotactl_fd,
            root.as_raw_fd(),
            libc::QCMD(operation, libc::USRQUOTA),
            policy.uid,
            &mut limits,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if !set
        && (limits.dqb_bhardlimit == 0
            || limits.dqb_bhardlimit > policy.quota_bytes / 1024
            || limits.dqb_ihardlimit == 0
            || limits.dqb_ihardlimit > policy.quota_inodes)
    {
        return Err(denied());
    }
    Ok(())
}

pub fn unlock(
    id: &str,
    policy: &VolumePolicy,
    request: &SignedEnvelope,
    decision: &SignedEnvelope,
) -> io::Result<()> {
    validate(id, policy)?;
    if ready(id, policy).is_ok() {
        return Ok(());
    }
    if !fs::metadata(&policy.device)?.file_type().is_block_device()
        || uuid(&policy.device)? != policy.luks_uuid
    {
        return Err(denied());
    }
    let key = key_descriptor(id, request, decision, "current")?;
    let fd = key.as_raw_fd();
    let mapping = format!("gc-{id}");
    let mapper = format!("/dev/mapper/{mapping}");
    if !Path::new(&mapper).exists() {
        let mut command = Command::new(CRYPTSETUP);
        command
            .env_clear()
            .args([
                "open",
                "--type",
                "luks2",
                "--key-file",
                &format!("/proc/self/fd/{fd}"),
                "--",
                &policy.device,
                &mapping,
            ])
            .stdin(Stdio::null());
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        crate::subprocess::output(&mut command, Duration::from_secs(30), 1024)?;
    }
    if uuid(&mapper)? != policy.filesystem_uuid {
        return Err(denied());
    }
    let mount_path = Path::new(&policy.mount_path);
    if fs::canonicalize(mount_path)? != mount_path {
        return Err(denied());
    }
    let metadata = mount_path.metadata()?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(denied());
    }
    let source = cstring(&mapper)?;
    let target = cstring(&policy.mount_path)?;
    let filesystem = cstring("ext4")?;
    let options = cstring("usrquota")?;
    if unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            filesystem.as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            options.as_ptr().cast(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        let root = File::open(mount_path)?;
        quota(&root, policy, true)?;
        let path = cstring("workspace")?;
        if unsafe { libc::mkdirat(root.as_raw_fd(), path.as_ptr(), 0o700) } != 0
            && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
        {
            return Err(io::Error::last_os_error());
        }
        let workspace = open_beneath(&root, "workspace", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        if unsafe { libc::fchown(workspace.as_raw_fd(), policy.uid, policy.gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        ready(id, policy).map(|_| ())
    })();
    if result.is_err() {
        unsafe { libc::umount2(target.as_ptr(), 0) };
    }
    result
}

pub fn lock(id: &str, policy: &VolumePolicy) -> io::Result<()> {
    validate(id, policy)?;
    let target = cstring(&policy.mount_path)?;
    if ready(id, policy).is_ok() && unsafe { libc::umount2(target.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // No lazy unmount: a busy workspace must remain explicitly busy.
    crate::subprocess::output(
        Command::new(CRYPTSETUP)
            .env_clear()
            .args(["close", "--", &format!("gc-{id}")])
            .stdin(Stdio::null()),
        Duration::from_secs(5),
        1024,
    )
    .map(|_| ())
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn open_beneath(root: &File, path: &str, flags: i32, mode: u32) -> io::Result<File> {
    let path = Path::new(path);
    if path.is_absolute()
        || path.as_os_str().is_empty()
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
        || path.components().count() > 32
    {
        return Err(denied());
    }
    let path = cstring(path.to_str().ok_or_else(denied)?)?;
    // RESOLVE_BENEATH | NO_SYMLINKS | NO_MAGICLINKS | NO_XDEV.
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK) as u64,
        mode: u64::from(mode),
        resolve: 0x08 | 0x04 | 0x02 | 0x01,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            path.as_ptr(),
            &how,
            std::mem::size_of_val(&how),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd as i32) })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChildOperation {
    operation: FileOperation,
}

/// Runs file operations as the volume UID so kernel user quotas apply to all writes.
pub fn files(id: &str, policy: &VolumePolicy, operation: &FileOperation) -> io::Result<String> {
    let volume = ready(id, policy)?;
    let workspace = open_beneath(&volume, "workspace", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    let fd = workspace.as_raw_fd();
    let body = serde_json::to_vec(&ChildOperation {
        operation: operation.clone(),
    })
    .map_err(|_| denied())?;
    let name = cstring("gammacloud-file-operation")?;
    let input_fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    if input_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut input = unsafe { File::from_raw_fd(input_fd) };
    input.write_all(&body)?;
    use std::io::{Seek, SeekFrom};
    input.seek(SeekFrom::Start(0))?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .env_clear()
        .arg("--workspace-child")
        .arg(fd.to_string())
        .stdin(Stdio::from(input));
    let uid = policy.uid;
    let gid = policy.gid;
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) < 0
                || libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(gid) != 0
                || libc::setuid(uid) != 0
            {
                return Err(io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = crate::subprocess::output(&mut command, Duration::from_secs(2), 32_768)?;
    String::from_utf8(output).map_err(|_| denied())
}

pub fn file_child(fd: i32) -> io::Result<()> {
    if fd < 3 || unsafe { libc::geteuid() } == 0 {
        return Err(denied());
    }
    let root = unsafe { File::from_raw_fd(fd) };
    let mut bytes = Vec::new();
    std::io::stdin().take(32_769).read_to_end(&mut bytes)?;
    if bytes.len() > 32_768 {
        return Err(denied());
    }
    let request: ChildOperation = serde_json::from_slice(&bytes).map_err(|_| denied())?;
    let parent = |path: &str| -> io::Result<(File, CString)> {
        let path = Path::new(path);
        let name = path
            .file_name()
            .and_then(|p| p.to_str())
            .ok_or_else(denied)?;
        if path
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err(denied());
        }
        let directory = path.parent().filter(|p| !p.as_os_str().is_empty());
        Ok((
            match directory {
                Some(path) => open_beneath(
                    &root,
                    path.to_str().ok_or_else(denied)?,
                    libc::O_RDONLY | libc::O_DIRECTORY,
                    0,
                )?,
                None => root.try_clone()?,
            },
            cstring(name)?,
        ))
    };
    match request.operation {
        FileOperation::Read { path } => {
            let file = open_beneath(&root, &path, libc::O_RDONLY, 0)?;
            if !file.metadata()?.is_file() || file.metadata()?.len() > 16_384 {
                return Err(denied());
            }
            let mut bytes = Vec::new();
            file.take(16_385).read_to_end(&mut bytes)?;
            if bytes.len() > 16_384 {
                return Err(denied());
            }
            let text = String::from_utf8(bytes).map_err(|_| denied())?;
            std::io::stdout().write_all(text.as_bytes())?;
        }
        FileOperation::Write { path, data } => {
            if data.len() > 16_384 {
                return Err(denied());
            }
            // New files only: no partial overwrite on error or retry ambiguity.
            let mut file = open_beneath(
                &root,
                &path,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )?;
            file.write_all(data.as_bytes())?;
            file.sync_all()?;
        }
        FileOperation::Mkdir { path } => {
            let (parent, name) = parent(&path)?;
            if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        FileOperation::Remove { path, directory } => {
            let (parent, name) = parent(&path)?;
            if unsafe {
                libc::unlinkat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    if directory { libc::AT_REMOVEDIR } else { 0 },
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        FileOperation::Chmod { path, mode } => {
            if mode & !0o700 != 0 {
                return Err(denied());
            }
            let file = open_beneath(&root, &path, libc::O_RDONLY, 0)?;
            if unsafe { libc::fchmod(file.as_raw_fd(), mode) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

/// Adds a broker-authorized replacement key; never destroys an existing key slot.
pub fn rotate(
    id: &str,
    policy: &VolumePolicy,
    request: &SignedEnvelope,
    decision: &SignedEnvelope,
) -> io::Result<()> {
    validate(id, policy)?;
    if uuid(&policy.device)? != policy.luks_uuid {
        return Err(denied());
    }
    let current = key_descriptor(id, request, decision, "current")?;
    let next = key_descriptor(id, request, decision, "next")?;
    let old_fd = current.as_raw_fd();
    let new_fd = next.as_raw_fd();
    let mut command = Command::new(CRYPTSETUP);
    command
        .env_clear()
        .args([
            "luksAddKey",
            "--batch-mode",
            "--key-file",
            &format!("/proc/self/fd/{old_fd}"),
            "--",
            &policy.device,
            &format!("/proc/self/fd/{new_fd}"),
        ])
        .stdin(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(old_fd, libc::F_SETFD, 0) < 0
                || libc::fcntl(new_fd, libc::F_SETFD, 0) < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    crate::subprocess::output(&mut command, Duration::from_secs(30), 1024).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn descriptor_resolution_refuses_parent_and_symlink_escapes() {
        let root = std::env::temp_dir().join(format!("gc-paths-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        std::os::unix::fs::symlink("/etc", root.join("escape")).unwrap();
        let directory = File::open(&root).unwrap();
        assert!(open_beneath(&directory, "../etc/passwd", libc::O_RDONLY, 0).is_err());
        assert!(open_beneath(&directory, "escape/passwd", libc::O_RDONLY, 0).is_err());
        assert!(open_beneath(&directory, "/etc/passwd", libc::O_RDONLY, 0).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
