//! Bounded helper execution; captured output is never logged by this module.
use crate::security::kill_process_group;
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub fn output(command: &mut Command, timeout: Duration, maximum: usize) -> io::Result<Vec<u8>> {
    command.stdout(Stdio::piped()).stderr(Stdio::null());
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    let mut pipe = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("helper pipe missing"))?;
    let flags = unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        let _ = kill_process_group(child.id());
        let _ = child.wait();
        return Err(io::Error::last_os_error());
    }
    let deadline = Instant::now() + timeout;
    let mut bytes = Vec::new();
    let result = loop {
        let mut buffer = [0; 4096];
        match pipe.read(&mut buffer) {
            Ok(count) => {
                bytes.extend_from_slice(&buffer[..count]);
                if bytes.len() > maximum {
                    break Err(io::Error::other("helper output limit"));
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => break Err(error),
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    break Err(io::Error::other("helper failed"));
                }
                // Drain bytes left in the pipe after the helper exited.
                loop {
                    match pipe.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(count) => {
                            bytes.extend_from_slice(&buffer[..count]);
                            if bytes.len() > maximum {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                break if bytes.len() <= maximum {
                    Ok(bytes)
                } else {
                    Err(io::Error::other("helper output limit"))
                };
            }
            Ok(None) => {}
            Err(error) => break Err(error),
        }
        if Instant::now() >= deadline || crate::lifecycle::stopping() {
            break Err(io::ErrorKind::TimedOut.into());
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    if result.is_err() {
        let _ = kill_process_group(child.id());
        let _ = child.wait();
    }
    result
}
