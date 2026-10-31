//! Linux shutdown notification and bounded, cancellable socket operations.
//! Signal handlers only store an atomic flag; cleanup happens on the main thread.
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static STOPPING: AtomicBool = AtomicBool::new(false);

extern "C" fn request_stop(_: libc::c_int) {
    STOPPING.store(true, Ordering::Relaxed);
}

pub fn stopping() -> bool {
    STOPPING.load(Ordering::Relaxed)
}

/// Restores previous handlers when the runtime leaves its serving scope.
pub struct Signals {
    previous: Vec<(libc::c_int, libc::sigaction)>,
}

impl Signals {
    /// Installs SIGTERM/SIGINT handlers before the runtime starts bridge threads.
    pub fn install() -> io::Result<Self> {
        STOPPING.store(false, Ordering::Relaxed);
        let mut guard = Self {
            previous: Vec::new(),
        };
        for signal in [libc::SIGTERM, libc::SIGINT] {
            // SAFETY: sigaction is initialized before use; no Rust references enter C.
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = request_stop as *const () as usize;
            unsafe { libc::sigemptyset(&mut action.sa_mask) };
            if unsafe { libc::sigaction(signal, &action, &mut previous) } == -1 {
                return Err(io::Error::last_os_error());
            }
            guard.previous.push((signal, previous));
        }
        Ok(guard)
    }
}

impl Drop for Signals {
    fn drop(&mut self) {
        for (signal, previous) in self.previous.iter().rev() {
            unsafe { libc::sigaction(*signal, previous, std::ptr::null_mut()) };
        }
    }
}

/// Waits in short intervals so shutdown does not depend on client activity.
pub fn wait(fd: RawFd, events: i16, deadline: Instant) -> io::Result<()> {
    loop {
        if stopping() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "runtime stopping",
            ));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "connection deadline",
            ));
        }
        let mut descriptor = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let millis = remaining.as_millis().clamp(1, 100) as i32;
        let result = unsafe { libc::poll(&mut descriptor, 1, millis) };
        if result > 0 {
            if descriptor.revents & libc::POLLNVAL != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid descriptor",
                ));
            }
            return Ok(());
        }
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

/// Reads exactly one bounded frame against a total deadline, including slow senders.
pub fn read_frame(stream: &mut UnixStream, deadline: Instant) -> io::Result<String> {
    let mut bytes = Vec::new();
    while bytes.len() < gammacloud_protocol::structured::MAX_FRAME_BYTES + 2 {
        wait(stream.as_raw_fd(), libc::POLLIN, deadline)?;
        let mut byte = [0];
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                bytes.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                continue
            }
            Err(error) => return Err(error),
        }
    }
    String::from_utf8(bytes).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid utf8"))
}

pub fn write_response(stream: &mut UnixStream, bytes: &[u8], deadline: Instant) -> io::Result<()> {
    let mut remaining = bytes;
    while !remaining.is_empty() {
        wait(stream.as_raw_fd(), libc::POLLOUT, deadline)?;
        match stream.write(remaining) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => remaining = &remaining[count..],
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                continue
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub fn connection_deadline() -> Instant {
    Instant::now() + Duration::from_secs(3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_frame_cannot_extend_total_deadline() {
        let (mut server, mut client) = UnixStream::pair().unwrap();
        server.set_nonblocking(true).unwrap();
        client.write_all(b"HE").unwrap();
        let error =
            read_frame(&mut server, Instant::now() + Duration::from_millis(10)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}
