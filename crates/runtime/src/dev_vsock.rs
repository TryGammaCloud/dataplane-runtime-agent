//! Explicitly enabled, unauthenticated development-only vsock bridge.
//!
//! # Security
//!
//! This bridge is NOT suitable for confidential production workloads.
//! The guest must be disposable, contain no customer secrets and report
//! attestation=unverified. A vsock CID is not an authenticated identity.

use std::io::{self, Read, Write};
use std::mem::size_of;
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

const AF_VSOCK: i32 = 40;
const SOCK_STREAM: i32 = 1;
const VMADDR_CID_ANY: u32 = 0xffff_ffff;
const PORT: u32 = 4050;
const MAX_REQUEST: usize = 257;
const MAX_RESPONSE: usize = 16384;

#[repr(C)]
struct SockAddrVm {
    family: u16,
    reserved: u16,
    port: u32,
    cid: u32,
    flags: u8,
    zero: [u8; 3],
}

unsafe extern "C" {
    fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
    fn bind(fd: i32, address: *const SockAddrVm, len: u32) -> i32;
    fn listen(fd: i32, backlog: i32) -> i32;
    fn accept(fd: i32, address: *mut u8, len: *mut u32) -> i32;
    fn close(fd: i32) -> i32;
}

/// Starts a detached development bridge to the guest-local Unix socket.
///
/// # Security
///
/// Must only be enabled in an explicitly unverified development guest.
/// The local Unix socket still enforces its own UID policy.
pub fn spawn(local_socket: PathBuf) -> io::Result<()> {
    // SECURITY: No implicit enablement; never expose a production listener.
    if std::env::var("GAMMACLOUD_DEV_VSOCK_BRIDGE").as_deref() != Ok("1") {
        return Ok(());
    }
    let fd = unsafe { socket(AF_VSOCK, SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let address = SockAddrVm {
        family: AF_VSOCK as u16,
        reserved: 0,
        port: PORT,
        cid: VMADDR_CID_ANY,
        flags: 0,
        zero: [0; 3],
    };
    let result = unsafe {
        bind(
            fd,
            &address,
            u32::try_from(size_of::<SockAddrVm>()).expect("fixed sockaddr size"),
        )
    };
    if result != 0 || unsafe { listen(fd, 8) } != 0 {
        let error = io::Error::last_os_error();
        unsafe { close(fd) };
        return Err(error);
    }
    std::thread::spawn(move || {
        // LIFECYCLE: The process owns the listener; it closes on runtime exit.
        let listener = unsafe { std::fs::File::from_raw_fd(fd) };
        loop {
            let client = unsafe { accept(std::os::fd::AsRawFd::as_raw_fd(&listener), std::ptr::null_mut(), std::ptr::null_mut()) };
            if client < 0 {
                break;
            }
            let mut stream = unsafe { std::fs::File::from_raw_fd(client) };
            let result = forward(&mut stream, &local_socket);
            if result.is_err() {
                let _ = stream.write_all(b"ERR development-bridge-failed\n");
            }
        }
    });
    Ok(())
}

/// Forwards one bounded request and response to the local runtime endpoint.
fn forward(client: &mut std::fs::File, local_socket: &PathBuf) -> io::Result<()> {
    let mut request = Vec::new();
    let mut byte = [0u8; 1];
    while request.len() < MAX_REQUEST {
        if client.read(&mut byte)? == 0 {
            return Err(io::Error::other("client disconnected"));
        }
        request.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    if request.last() != Some(&b'\n') || request.len() > 256 {
        return Err(io::Error::other("invalid request length"));
    }
    let mut local = UnixStream::connect(local_socket)?;
    local.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    local.write_all(&request)?;
    let mut response = Vec::new();
    while response.len() < MAX_RESPONSE {
        if local.read(&mut byte)? == 0 {
            break;
        }
        response.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    if response.last() != Some(&b'\n') {
        return Err(io::Error::other("invalid runtime response"));
    }
    client.write_all(&response)
}
