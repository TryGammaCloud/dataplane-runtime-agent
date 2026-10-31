//! Generic supervision of preinstalled inference engines and immutable weight files.
use crate::authorization::hex;
use crate::isolated::{ExecutionTemplate, LaunchAuthorization};
use crate::manager::Manager;
use gammacloud_protocol::structured::InferenceManifest;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path};
use std::process::{Command, Stdio};
use std::time::Duration;

struct Model {
    job: u64,
    port: u16,
    path: String,
}
#[derive(Default)]
pub struct Models {
    models: BTreeMap<String, Model>,
}
fn rejected() -> io::Error {
    io::Error::other("inference operation rejected")
}

impl Models {
    pub fn start(
        &mut self,
        manager: &mut Manager,
        manifest: &InferenceManifest,
        template: &ExecutionTemplate,
        authorization: LaunchAuthorization<'_>,
    ) -> io::Result<String> {
        if manager.product() != crate::product::Product::Models {
            return Err(rejected());
        }
        if self.models.len() >= 16
            || self.models.contains_key(&manifest.id)
            || manifest.id.is_empty()
            || manifest.id.len() > 64
            || manifest.artifacts.is_empty()
            || manifest.artifacts.len() > 1024
            || manifest.health_port == 0
            || !manifest.health_path.starts_with('/')
            || manifest.health_path.len() > 256
            || manifest
                .health_path
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(rejected());
        }
        let directory = template.model_directory.as_ref().ok_or_else(rejected)?;
        let root = Path::new(directory);
        if !root.starts_with("/srv/gammacloud/models") || fs::canonicalize(root)? != root {
            return Err(rejected());
        }
        let request: gammacloud_protocol::structured::AuthorizedRequest =
            serde_json::from_str(&authorization.request.payload).map_err(|_| rejected())?;
        for artifact in &manifest.artifacts {
            let relative = Path::new(&artifact.relative_path);
            if relative.is_absolute()
                || relative
                    .components()
                    .any(|c| !matches!(c, Component::Normal(_)))
            {
                return Err(rejected());
            }
            let path = root.join(relative);
            if fs::canonicalize(&path)? != path {
                return Err(rejected());
            }
            let metadata = path.metadata()?;
            if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(rejected());
            }
            let mut file = File::open(path)?;
            let mut digest = Sha256::new();
            let mut buffer = [0; 65_536];
            loop {
                if crate::lifecycle::stopping() {
                    return Err(rejected());
                }
                if crate::authorization::now().map_err(|_| rejected())? >= request.expires_at {
                    return Err(rejected());
                }
                let count = file.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                digest.update(&buffer[..count]);
            }
            if hex(&digest.finalize()) != artifact.sha256 {
                return Err(rejected());
            }
        }
        // Engine-specific paths/flags remain in its approved template and manifest.
        let response = manager.execute(&manifest.execution, template, None, None, authorization)?;
        if response.starts_with("ERR ") {
            return Err(rejected());
        }
        let job = manager.latest_id().ok_or_else(rejected)?;
        self.models.insert(
            manifest.id.clone(),
            Model {
                job,
                port: manifest.health_port,
                path: manifest.health_path.clone(),
            },
        );
        Ok(serde_json::json!({"id":manifest.id,"job_id":job,"state":"starting"}).to_string())
    }
    pub fn status(&self, manager: &mut Manager, id: &str) -> io::Result<String> {
        let model = self.models.get(id).ok_or_else(rejected)?;
        let job = manager.status(model.job)?;
        let ready = manager
            .unit(model.job)
            .is_some_and(|unit| probe(unit, model.port, &model.path).is_ok());
        Ok(serde_json::json!({"id":id,"ready":ready,"job":job}).to_string())
    }
    pub fn stop(&mut self, manager: &mut Manager, id: &str) -> io::Result<String> {
        if let Some(model) = self.models.remove(id) {
            manager.stop(model.job)?;
        }
        Ok("stopped".into())
    }
}

fn probe(unit: &str, port: u16, path: &str) -> io::Result<()> {
    let output = crate::subprocess::output(
        Command::new(crate::isolated::SYSTEMCTL)
            .env_clear()
            .args(["show", "--value", "--property=MainPID", unit])
            .stdin(Stdio::null()),
        Duration::from_secs(1),
        128,
    )?;
    let pid: u32 = std::str::from_utf8(&output)
        .map_err(|_| rejected())?
        .trim()
        .parse()
        .map_err(|_| rejected())?;
    if pid == 0 {
        return Err(rejected());
    }
    let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    if !cgroup.lines().any(|line| {
        line.strip_prefix("0::")
            .is_some_and(|group| group.split('/').any(|component| component == unit))
    }) {
        return Err(rejected());
    }
    let namespace = File::open(format!("/proc/{pid}/ns/net"))?;
    let fd = namespace.as_raw_fd();
    let mut command = Command::new(std::env::current_exe()?);
    command
        .env_clear()
        .arg("--health-probe")
        .arg(fd.to_string())
        .arg(port.to_string())
        .arg(path)
        .stdin(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    crate::subprocess::output(&mut command, Duration::from_secs(2), 128).map(|_| ())
}

pub fn health_child(fd: i32, port: u16, path: &str) -> io::Result<()> {
    if fd < 3
        || port == 0
        || !path.starts_with('/')
        || path.len() > 256
        || path.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(rejected());
    }
    let namespace = unsafe { File::from_raw_fd(fd) };
    if unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let mut connection = TcpStream::connect_timeout(&address, Duration::from_millis(500))?;
    connection.set_read_timeout(Some(Duration::from_millis(500)))?;
    connection.set_write_timeout(Some(Duration::from_millis(500)))?;
    connection.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes(),
    )?;
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    let mut response = Vec::new();
    while response.len() < 256 && std::time::Instant::now() < deadline {
        let mut byte = [0];
        if connection.read(&mut byte)? == 0 {
            return Err(rejected());
        }
        response.push(byte[0]);
        if response.ends_with(b"\r\n") {
            break;
        }
    }
    let first = std::str::from_utf8(&response).map_err(|_| rejected())?;
    let words: Vec<&str> = first.split_whitespace().collect();
    if words.len() < 2
        || !["HTTP/1.1", "HTTP/1.0"].contains(&words[0])
        || words[1].len() != 3
        || words[1]
            .parse::<u16>()
            .map_or(true, |status| !(200..300).contains(&status))
    {
        return Err(rejected());
    }
    Ok(())
}
