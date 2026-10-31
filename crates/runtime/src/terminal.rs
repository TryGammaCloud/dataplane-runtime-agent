//! Bounded PTY sessions bound to the current signed owner lifecycle.
use crate::authorization::hex;
use crate::isolated::ExecutionTemplate;
use crate::manager::Manager;
use crate::storage::VolumePolicy;
use gammacloud_protocol::structured::ExecutionManifest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::time::{Duration, Instant};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProfile {
    pub template: String,
    pub version: String,
}

struct Terminal {
    master: File,
    job: u64,
    expires: Instant,
    idle: Instant,
    buffer: VecDeque<u8>,
    base: u64,
    emitted: u64,
    next_sequence: u64,
    last_input: Option<(u64, String, usize)>,
    closed: bool,
}

#[derive(Default)]
pub struct Terminals {
    sessions: BTreeMap<String, Terminal>,
}

fn rejected() -> io::Error {
    io::Error::other("terminal operation rejected")
}

impl Terminals {
    pub fn open(
        &mut self,
        manager: &mut Manager,
        manifest: &ExecutionManifest,
        template: &ExecutionTemplate,
        volume: Option<&VolumePolicy>,
        ttl_seconds: u64,
    ) -> io::Result<String> {
        self.expire(manager);
        if self.sessions.len() >= 8
            || ttl_seconds == 0
            || ttl_seconds > manifest.timeout_seconds
            || ttl_seconds > 3600
        {
            return Err(rejected());
        }
        let mut master = -1;
        let mut slave = -1;
        let size = libc::winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        if unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                &size,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        for fd in [master.as_raw_fd(), slave.as_raw_fd()] {
            if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        if unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let response = manager.execute(manifest, template, volume, Some(slave))?;
        if response.starts_with("ERR ") {
            return Err(rejected());
        }
        let job = manager.latest_id().ok_or_else(rejected)?;
        let mut nonce = [0; 16];
        File::open("/dev/urandom")?.read_exact(&mut nonce)?;
        let id = hex(&nonce);
        self.sessions.insert(
            id.clone(),
            Terminal {
                master,
                job,
                expires: Instant::now() + Duration::from_secs(ttl_seconds),
                idle: Instant::now(),
                buffer: VecDeque::new(),
                base: 0,
                emitted: 0,
                next_sequence: 0,
                last_input: None,
                closed: false,
            },
        );
        eprintln!("gammacloud-runtime event=session-opened");
        Ok(serde_json::json!({"id":id,"job_id":job,"next_sequence":0,"cursor":0}).to_string())
    }

    pub fn expire(&mut self, manager: &mut Manager) {
        let now = Instant::now();
        let expired: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, session)| {
                now >= session.expires
                    || now.duration_since(session.idle) >= Duration::from_secs(120)
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            let _ = self.close(manager, &id);
        }
    }

    pub fn close(&mut self, manager: &mut Manager, id: &str) -> io::Result<String> {
        if let Some(session) = self.sessions.remove(id) {
            manager.stop(session.job)?;
            eprintln!("gammacloud-runtime event=session-closed");
        }
        Ok("closed".into())
    }

    pub fn close_all(&mut self, manager: &mut Manager) {
        let ids: Vec<String> = self.sessions.keys().cloned().collect();
        for id in ids {
            let _ = self.close(manager, &id);
        }
    }

    pub fn read(&mut self, id: &str, cursor: u64) -> io::Result<String> {
        let session = self.sessions.get_mut(id).ok_or_else(rejected)?;
        if cursor < session.base || cursor > session.emitted {
            return Err(rejected());
        }
        for _ in session.base..cursor {
            session.buffer.pop_front();
        }
        session.base = cursor;
        session.idle = Instant::now();
        let mut buffer = [0; 4096];
        while session.buffer.len() + buffer.len() <= 1_048_576 {
            match session.master.read(&mut buffer) {
                Ok(0) => {
                    session.closed = true;
                    break;
                }
                Ok(count) => session.buffer.extend(&buffer[..count]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.raw_os_error() == Some(libc::EIO) => {
                    session.closed = true;
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        let bytes: Vec<u8> = session.buffer.iter().take(8192).copied().collect();
        let end = session
            .base
            .checked_add(bytes.len() as u64)
            .ok_or_else(rejected)?;
        session.emitted = session.emitted.max(end);
        Ok(serde_json::json!({"data_hex":hex(&bytes),"cursor":session.base,"next_cursor":end,"closed":session.closed}).to_string())
    }

    pub fn write(&mut self, id: &str, sequence: u64, data: &str) -> io::Result<String> {
        if data.len() > 16_384
            || data.len() & 1 != 0
            || !data.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(rejected());
        }
        let bytes: Vec<u8> = (0..data.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&data[i..i + 2], 16).map_err(|_| rejected()))
            .collect::<io::Result<_>>()?;
        let session = self.sessions.get_mut(id).ok_or_else(rejected)?;
        let digest = hex(&Sha256::digest(&bytes));
        if let Some((previous, hash, accepted)) = &session.last_input {
            if *previous == sequence && *hash == digest {
                return Ok(
                    serde_json::json!({"accepted":accepted,"next_sequence":session.next_sequence})
                        .to_string(),
                );
            }
        }
        if sequence != session.next_sequence || session.closed {
            return Err(rejected());
        }
        let accepted = match session.master.write(&bytes) {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => 0,
            Err(error) => return Err(error),
        };
        if accepted > 0 {
            session.next_sequence = session.next_sequence.checked_add(1).ok_or_else(rejected)?;
            session.last_input = Some((sequence, digest, accepted));
        }
        session.idle = Instant::now();
        Ok(
            serde_json::json!({"accepted":accepted,"next_sequence":session.next_sequence})
                .to_string(),
        )
    }

    pub fn resize(&mut self, id: &str, rows: u16, columns: u16) -> io::Result<String> {
        if !(1..=1000).contains(&rows) || !(1..=1000).contains(&columns) {
            return Err(rejected());
        }
        let session = self.sessions.get_mut(id).ok_or_else(rejected)?;
        let size = libc::winsize {
            ws_row: rows,
            ws_col: columns,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        if unsafe { libc::ioctl(session.master.as_raw_fd(), libc::TIOCSWINSZ, &size) } < 0 {
            return Err(io::Error::last_os_error());
        }
        session.idle = Instant::now();
        Ok("resized".into())
    }
}
