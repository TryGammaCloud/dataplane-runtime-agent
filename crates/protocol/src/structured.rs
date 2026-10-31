//! Signed operation schema. Sign exact UTF-8 payload bytes, never reserialized JSON.
use serde::{Deserialize, Serialize};

pub const VERSION: u16 = 2;
pub const MAX_FRAME_BYTES: usize = 65_536;
pub const REQUEST_DOMAIN: &[u8] = b"gammacloud.runtime.request.v2\0";
pub const DECISION_DOMAIN: &[u8] = b"gammacloud.runtime.attestation.v2\0";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEnvelope {
    pub payload: String,
    pub signature: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedRequest {
    pub version: u16,
    pub request_id: String,
    pub organization_id: String,
    pub project_id: String,
    pub sandbox_id: String,
    pub guest_id: String,
    pub boot_nonce: String,
    pub policy_version: String,
    pub owner_epoch: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub operation: Operation,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Enroll {
        owner_public_key: String,
        workload_identity: String,
    },
    Rotate {
        new_public_key: String,
        new_key_proof: String,
    },
    Revoke,
    Attest {
        decision: SignedEnvelope,
    },
    Health,
    Status,
    Start {
        profile: String,
    },
    VolumeUnlock {
        id: String,
    },
    VolumeRotate {
        id: String,
    },
    VolumeLock {
        id: String,
    },
    VolumeStatus {
        id: String,
    },
    Files {
        volume_id: String,
        operation: FileOperation,
    },
    SessionOpen {
        manifest: ExecutionManifest,
        ttl_seconds: u64,
    },
    SessionRead {
        id: String,
        cursor: u64,
    },
    SessionWrite {
        id: String,
        sequence: u64,
        data_hex: String,
    },
    SessionResize {
        id: String,
        rows: u16,
        columns: u16,
    },
    SessionClose {
        id: String,
    },
    AgentLaunch {
        name: String,
        manifest: ExecutionManifest,
        ttl_seconds: u64,
    },
    Evidence {
        challenge: String,
    },
    Metrics,
    RequestOutcome {
        id: String,
    },
    ModelStart {
        manifest: InferenceManifest,
    },
    ModelStatus {
        id: String,
    },
    ModelStop {
        id: String,
    },
    Execute {
        manifest: ExecutionManifest,
    },
    WorkloadStatus {
        id: u64,
    },
    WorkloadLogs {
        id: u64,
    },
    Stop {
        id: u64,
    },
    Shutdown,
}

impl Operation {
    pub fn permission(&self) -> &'static str {
        match self {
            Self::Enroll { .. } => "enroll",
            Self::Rotate { .. } => "rotate",
            Self::Revoke => "revoke",
            Self::Attest { .. } => "attest",
            Self::Health => "health",
            Self::Status => "status",
            Self::Start { .. } => "start",
            Self::Execute { .. } => "execute",
            Self::ModelStart { .. } => "model_start",
            Self::Metrics => "metrics",
            Self::Evidence { .. } => "evidence",
            Self::RequestOutcome { .. } => "request_outcome",
            Self::ModelStatus { .. } => "model_status",
            Self::ModelStop { .. } => "model_stop",
            Self::SessionOpen { .. } => "session_open",
            Self::SessionRead { .. } => "session_read",
            Self::SessionWrite { .. } => "session_write",
            Self::SessionResize { .. } => "session_resize",
            Self::SessionClose { .. } => "session_close",
            Self::AgentLaunch { .. } => "agent_launch",
            Self::VolumeUnlock { .. } => "volume_unlock",
            Self::VolumeLock { .. } => "volume_lock",
            Self::VolumeRotate { .. } => "volume_rotate",
            Self::VolumeStatus { .. } => "volume_status",
            Self::Files { .. } => "files",
            Self::WorkloadStatus { .. } => "workload_status",
            Self::WorkloadLogs { .. } => "workload_logs",
            Self::Stop { .. } => "stop",
            Self::Shutdown => "shutdown",
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationDecision {
    pub guest_id: String,
    pub boot_nonce: String,
    pub owner_public_key: String,
    pub image_digest: String,
    pub workload_digest: String,
    pub workload_identity: String,
    pub policy_version: String,
    pub owner_epoch: u64,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub version: u16,
    pub request_id: String,
    pub ok: bool,
    pub code: String,
    pub result: String,
}

impl Response {
    pub fn error(id: &str, code: &str) -> Self {
        Self {
            version: VERSION,
            request_id: id.into(),
            ok: false,
            code: code.into(),
            result: String::new(),
        }
    }
    pub fn success(id: &str, result: String) -> Self {
        Self {
            version: VERSION,
            request_id: id.into(),
            ok: true,
            code: "ok".into(),
            result,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionManifest {
    pub template: String,
    pub arguments: Vec<String>,
    pub environment: std::collections::BTreeMap<String, String>,
    pub working_directory: String,
    pub memory_mib: u64,
    pub cpu_percent: u32,
    pub max_pids: u32,
    pub timeout_seconds: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum FileOperation {
    Read { path: String },
    Write { path: String, data: String },
    Mkdir { path: String },
    Remove { path: String, directory: bool },
    Chmod { path: String, mode: u32 },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelArtifact {
    pub relative_path: String,
    pub sha256: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceManifest {
    pub id: String,
    pub execution: ExecutionManifest,
    pub artifacts: Vec<ModelArtifact>,
    pub health_port: u16,
    pub health_path: String,
}
