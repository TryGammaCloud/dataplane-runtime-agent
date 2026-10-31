//! Real resource sampling and optional local OTLP/HTTP JSON export.
//! Only numeric counters and technical identifiers enter exported metrics.
use serde::Serialize;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Component, Path};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Serialize)]
pub struct Sample {
    pub job_id: u64,
    pub elapsed_ms: u64,
    pub cpu_usec: Option<u64>,
    pub memory_bytes: Option<u64>,
    pub memory_peak_bytes: Option<u64>,
    pub pids: Option<u64>,
}

pub fn sample(job_id: u64, elapsed_ms: u64, unit: Option<&str>) -> Sample {
    let mut sample = Sample {
        job_id,
        elapsed_ms,
        cpu_usec: None,
        memory_bytes: None,
        memory_peak_bytes: None,
        pids: None,
    };
    let Some(unit) = unit else {
        return sample;
    };
    if !unit.starts_with("gammacloud-job-") || unit.contains('/') {
        return sample;
    }
    let base = Path::new("/sys/fs/cgroup/system.slice").join(unit);
    let number = |name: &str| {
        fs::read_to_string(base.join(name))
            .ok()
            .and_then(|s| s.trim().parse().ok())
    };
    sample.memory_bytes = number("memory.current");
    sample.memory_peak_bytes = number("memory.peak");
    sample.pids = number("pids.current");
    sample.cpu_usec = fs::read_to_string(base.join("cpu.stat"))
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                line.strip_prefix("usage_usec ")
                    .and_then(|s| s.parse().ok())
            })
        });
    sample
}

pub fn disk_bytes(path: &str) -> io::Result<u64> {
    if !Path::new(path).is_absolute()
        || Path::new(path)
            .components()
            .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(io::Error::other("invalid volume path"));
    }
    let path = std::ffi::CString::new(path).map_err(|_| io::Error::other("invalid volume path"))?;
    let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut stats) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stats
        .f_blocks
        .saturating_sub(stats.f_bfree)
        .saturating_mul(stats.f_frsize))
}

pub fn gpu() -> Option<Vec<(u64, u64)>> {
    let binary = Path::new("/run/current-system/sw/bin/nvidia-smi");
    if !binary.is_file() {
        return None;
    }
    let output = crate::subprocess::output(
        std::process::Command::new(binary)
            .env_clear()
            .args([
                "--query-gpu=utilization.gpu,memory.used",
                "--format=csv,noheader,nounits",
            ])
            .stdin(std::process::Stdio::null()),
        Duration::from_millis(500),
        4096,
    )
    .ok()?;
    std::str::from_utf8(&output)
        .ok()?
        .lines()
        .map(|line| {
            let (utilization, memory) = line.split_once(',')?;
            Some((
                utilization.trim().parse().ok()?,
                memory.trim().parse::<u64>().ok()?.checked_mul(1_048_576)?,
            ))
        })
        .collect()
}

pub fn export(
    samples: &[Sample],
    sessions: usize,
    volumes: &[u64],
    gpu: Option<&[(u64, u64)]>,
) -> io::Result<()> {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::other("clock unavailable"))?
        .as_nanos()
        .to_string();
    let mut metrics = Vec::new();
    let mut record = |name: &str, value: u64, job: Option<u64>| {
        let attributes = job
            .map(|id| vec![serde_json::json!({"key":"job.id","value":{"intValue":id.to_string()}})])
            .unwrap_or_default();
        metrics.push(serde_json::json!({"name":name,"gauge":{"dataPoints":[{"timeUnixNano":time,"asInt":value.to_string(),"attributes":attributes}]}}));
    };
    for sample in samples {
        record("runtime.elapsed_ms", sample.elapsed_ms, Some(sample.job_id));
        for (name, value) in [
            ("runtime.cpu_usec", sample.cpu_usec),
            ("runtime.memory_bytes", sample.memory_bytes),
            ("runtime.memory_peak_bytes", sample.memory_peak_bytes),
            ("runtime.pids", sample.pids),
        ] {
            if let Some(value) = value {
                record(name, value, Some(sample.job_id));
            }
        }
    }
    record("runtime.sessions", sessions as u64, None);
    record(
        "runtime.disk_used_bytes",
        volumes.iter().copied().fold(0u64, u64::saturating_add),
        None,
    );
    if let Some(devices) = gpu {
        record("runtime.gpu_count", devices.len() as u64, None);
        for (index, (utilization, bytes)) in devices.iter().enumerate() {
            record(
                "runtime.gpu_utilization_percent",
                *utilization,
                Some(index as u64),
            );
            record("runtime.gpu_memory_bytes", *bytes, Some(index as u64));
        }
    }
    let body = serde_json::to_vec(
        &serde_json::json!({"resourceMetrics":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"gammacloud-runtime"}}]},"scopeMetrics":[{"scope":{"name":"gammacloud.runtime"},"metrics":metrics}]}]}),
    )?;
    let mut stream = UnixStream::connect("/run/gammacloud/otel.sock")?;
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
    } != 0
        || credentials.uid != 0
    {
        return Err(io::Error::other("untrusted collector"));
    }
    stream.set_read_timeout(Some(Duration::from_millis(200)))?;
    stream.set_write_timeout(Some(Duration::from_millis(200)))?;
    stream.write_all(format!("POST /v1/metrics HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes())?;
    stream.write_all(&body)?;
    let mut response = [0; 128];
    let count = stream.read(&mut response)?;
    if !response[..count].starts_with(b"HTTP/1.1 2") {
        return Err(io::Error::other("telemetry export failed"));
    }
    Ok(())
}
