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
        workload_digest: String,
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
    pub challenge: String,
    pub evidence_digest: String,
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

/// Stable machine-readable error category; `code` retains the precise diagnostic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    Unauthorized,
    InvalidRequest,
    Conflict,
    Unavailable,
    Internal,
}

impl ErrorKind {
    fn from_code(code: &str) -> Self {
        match code {
            "invalid_signature"
            | "invalid_public_key"
            | "owner_unavailable"
            | "stale_owner_epoch"
            | "attestation_required"
            | "fresh_evidence_required"
            | "decision_binding_mismatch"
            | "evidence_binding_mismatch"
            | "binding_mismatch"
            | "request_expired"
            | "clock_rollback"
            | "isolated_execution_required" => Self::Unauthorized,
            "request_id_conflict" | "outcome_unknown" | "owner_already_bound" => Self::Conflict,
            _ if code.ends_with("_denied") => Self::Unauthorized,
            _ if code.starts_with("invalid_")
                || code == "unsupported_version"
                || code.ends_with("_too_large") =>
            {
                Self::InvalidRequest
            }
            _ if code.ends_with("_unavailable") || code == "journal_full" => Self::Unavailable,
            _ => Self::Internal,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub version: u16,
    pub request_id: String,
    pub ok: bool,
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<ErrorKind>,
    pub result: String,
}

impl Response {
    pub fn bounded(self) -> Self {
        match serde_json::to_vec(&self) {
            Ok(bytes) if bytes.len() < MAX_FRAME_BYTES => self,
            _ => Self::error(&self.request_id, "response_too_large"),
        }
    }

    pub fn error(id: &str, code: &str) -> Self {
        Self {
            version: VERSION,
            request_id: id.into(),
            ok: false,
            code: code.into(),
            error_kind: Some(ErrorKind::from_code(code)),
            result: String::new(),
        }
    }
    pub fn success(id: &str, result: String) -> Self {
        Self {
            version: VERSION,
            request_id: id.into(),
            ok: true,
            code: "ok".into(),
            error_kind: None,
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

#[cfg(test)]
mod response_tests {
    use super::*;

    #[test]
    fn errors_have_stable_typed_categories_and_bounded_frames() {
        assert_eq!(
            Response::error("id", "attestation_required").error_kind,
            Some(ErrorKind::Unauthorized)
        );
        assert_eq!(
            Response::error("id", "request_id_conflict").error_kind,
            Some(ErrorKind::Conflict)
        );
        assert_eq!(
            Response::error("id", "evidence_unavailable").error_kind,
            Some(ErrorKind::Unavailable)
        );
        let response = Response::success("id", "x".repeat(MAX_FRAME_BYTES)).bounded();
        assert_eq!(response.code, "response_too_large");
        assert!(serde_json::to_vec(&response).unwrap().len() < MAX_FRAME_BYTES);
    }
}
