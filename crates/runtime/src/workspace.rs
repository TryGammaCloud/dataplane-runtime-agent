//! All filesystem traversal is descriptor-relative and enforced by Linux openat2.
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::{Component, Path};
fn denied() -> io::Error {
    io::Error::other("workspace path denied")
}
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

pub fn open_beneath(root: &File, path: &str, flags: i32, mode: u32) -> io::Result<File> {
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
    let path = CString::new(path.to_str().ok_or_else(denied)?).map_err(|_| denied())?;
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

/// All path ancestors must be immutable to workload UIDs, including parent directories.
pub fn trusted_path(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute() || std::fs::canonicalize(path)? != path {
        return Err(denied());
    }
    for ancestor in path.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor)?;
        if metadata.file_type().is_symlink() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0
        {
            return Err(denied());
        }
    }
    Ok(())
}
