//! Signed request authorization with durable owner binding and replay reservations.
//! Trust roots must be provisioned by the measured OS, never by host metadata.
//! Persistence resists process crashes, not rollback of operator-controlled disks.
use ed25519_dalek::{Signature, VerifyingKey};
use gammacloud_protocol::structured::{
    self, AttestationDecision, AuthorizedRequest, Operation, Response, SignedEnvelope,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_RESERVATIONS: usize = 16_384;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustPolicy {
    pub organization_id: String,
    pub project_id: String,
    pub sandbox_id: String,
    pub guest_id: String,
    pub image_digest: String,
    pub policy_version: String,
    pub enrollment_public_key: String,
    pub verifier_public_key: String,
    pub permissions: BTreeSet<String>,
    pub require_attestation_for_start: bool,
    #[serde(default)]
    pub execution_templates: crate::isolated::Templates,
    #[serde(default)]
    pub development_agents: std::collections::BTreeMap<String, crate::terminal::AgentProfile>,
    #[serde(default)]
    pub volumes: std::collections::BTreeMap<String, crate::storage::VolumePolicy>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerBinding {
    public_key: String,
    workload_identity: String,
    epoch: u64,
    revoked: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reservation {
    digest: String,
    response: Option<Response>,
}

pub enum Admission {
    Execute(Box<AuthorizedRequest>),
    Cached(Response),
}

pub struct Authorization {
    policy: TrustPolicy,
    owner: Option<OwnerBinding>,
    boot_nonce: String,
    state: PathBuf,
    verified_until: u64,
    decision: Option<SignedEnvelope>,
    journal_lock: File,
}

fn error() -> io::Error {
    io::Error::other("authorization state unavailable")
}

pub fn now() -> Result<u64, &'static str> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "clock_unavailable")
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode<const N: usize>(value: &str) -> Result<[u8; N], &'static str> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid_encoding");
    }
    let mut bytes = [0; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid_encoding")?;
    }
    Ok(bytes)
}

pub fn verify(key: &str, domain: &[u8], envelope: &SignedEnvelope) -> Result<(), &'static str> {
    let key = VerifyingKey::from_bytes(&decode::<32>(key)?).map_err(|_| "invalid_key")?;
    let signature = Signature::from_bytes(&decode::<64>(&envelope.signature)?);
    let mut message = Vec::from(domain);
    message.extend_from_slice(envelope.payload.as_bytes());
    key.verify_strict(&message, &signature)
        .map_err(|_| "invalid_signature")
}

fn trusted_read(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
        || metadata.len() > maximum
    {
        return Err(error());
    }
    let mut data = Vec::new();
    file.take(maximum + 1).read_to_end(&mut data)?;
    if data.len() as u64 > maximum {
        return Err(error());
    }
    Ok(data)
}

fn atomic_write(path: &Path, data: &[u8]) -> io::Result<()> {
    let temporary = path.with_extension("pending");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(data)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(path.parent().ok_or_else(error)?)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

impl Authorization {
    /// A missing policy preserves development mode; a malformed policy fails startup.
    pub fn load() -> io::Result<Option<Self>> {
        let path = Path::new("/etc/gammacloud/runtime-policy.json");
        match fs::symlink_metadata(path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
            Ok(_) => {}
        }
        if unsafe { libc::geteuid() } != 0 {
            return Err(error());
        }
        for parent in ["/etc", "/etc/gammacloud", "/var", "/var/lib"] {
            let metadata = fs::symlink_metadata(parent)?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(error());
            }
        }
        let state_parent = Path::new("/var/lib/gammacloud");
        if !state_parent.exists() {
            fs::DirBuilder::new().mode(0o700).create(state_parent)?;
        }
        let metadata = fs::symlink_metadata(state_parent)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(error());
        }
        let policy: TrustPolicy =
            serde_json::from_slice(&trusted_read(path, 32_768)?).map_err(|_| error())?;
        Self::open(policy, PathBuf::from("/var/lib/gammacloud/runtime")).map(Some)
    }

    fn open(policy: TrustPolicy, state: PathBuf) -> io::Result<Self> {
        if [
            &policy.organization_id,
            &policy.project_id,
            &policy.sandbox_id,
            &policy.guest_id,
            &policy.image_digest,
            &policy.policy_version,
        ]
        .iter()
        .any(|v| v.trim().is_empty())
        {
            return Err(error());
        }
        decode::<32>(&policy.enrollment_public_key).map_err(|_| error())?;
        decode::<32>(&policy.verifier_public_key).map_err(|_| error())?;
        if !state.exists() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&state)?;
        }
        let metadata = fs::symlink_metadata(&state)?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(error());
        }
        let journal_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(state.join("lock"))?;
        if unsafe {
            libc::flock(
                std::os::fd::AsRawFd::as_raw_fd(&journal_lock),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        } != 0
        {
            return Err(error());
        }
        let owner = match trusted_read(&state.join("owner.json"), 16_384) {
            Ok(data) => Some(serde_json::from_slice(&data).map_err(|_| error())?),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        let journal = state.join("requests");
        if !journal.exists() {
            fs::DirBuilder::new().mode(0o700).create(&journal)?;
        }
        let metadata = fs::symlink_metadata(&journal)?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(error());
        }
        let mut nonce = [0; 32];
        File::open("/dev/urandom")?.read_exact(&mut nonce)?;
        Ok(Self {
            policy,
            owner,
            boot_nonce: hex(&nonce),
            state,
            verified_until: 0,
            decision: None,
            journal_lock,
        })
    }

    pub fn agent_profile(&self, name: &str) -> Option<&crate::terminal::AgentProfile> {
        self.policy.development_agents.get(name)
    }

    pub fn volume_policy(&self, id: &str) -> Option<&crate::storage::VolumePolicy> {
        self.policy.volumes.get(id)
    }
    pub fn current_decision(&self) -> Option<&SignedEnvelope> {
        self.decision.as_ref().filter(|_| self.attested())
    }

    pub fn execution_template(&self, name: &str) -> Option<&crate::isolated::ExecutionTemplate> {
        self.policy.execution_templates.get(name)
    }

    pub fn expire_decision(&mut self) -> bool {
        if self.verified_until != 0 && !self.attested() {
            self.verified_until = 0;
            self.decision = None;
            return true;
        }
        false
    }

    pub fn boot_nonce(&self) -> &str {
        &self.boot_nonce
    }
    pub fn attested(&self) -> bool {
        now().is_ok_and(|time| time < self.verified_until)
    }

    pub fn admit(&mut self, envelope: &SignedEnvelope) -> Result<Admission, &'static str> {
        if envelope.payload.len() > structured::MAX_FRAME_BYTES / 2 {
            return Err("request_too_large");
        }
        let request: AuthorizedRequest =
            serde_json::from_str(&envelope.payload).map_err(|_| "invalid_request")?;
        if request.version != structured::VERSION {
            return Err("unsupported_version");
        }
        if request.request_id.is_empty()
            || request.request_id.len() > 64
            || !request
                .request_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err("invalid_request_id");
        }
        let time = now()?;
        if request.issued_at > time
            || request.expires_at <= time
            || request.expires_at.saturating_sub(request.issued_at) > 300
        {
            return Err("request_expired");
        }
        if request.organization_id != self.policy.organization_id
            || request.project_id != self.policy.project_id
            || request.sandbox_id != self.policy.sandbox_id
            || request.guest_id != self.policy.guest_id
            || request.boot_nonce != self.boot_nonce
            || request.policy_version != self.policy.policy_version
        {
            return Err("binding_mismatch");
        }
        let authority = matches!(
            request.operation,
            Operation::Enroll { .. } | Operation::Revoke
        );
        let key = if authority {
            &self.policy.enrollment_public_key
        } else {
            let owner = self
                .owner
                .as_ref()
                .filter(|owner| !owner.revoked)
                .ok_or("owner_unavailable")?;
            if request.owner_epoch != owner.epoch {
                return Err("stale_owner_epoch");
            }
            &owner.public_key
        };
        verify(key, structured::REQUEST_DOMAIN, envelope)?;
        if !self
            .policy
            .permissions
            .contains(request.operation.permission())
        {
            return Err("operation_denied");
        }
        if matches!(
            request.operation,
            Operation::Start { .. } | Operation::Execute { .. }
        ) && self.policy.require_attestation_for_start
            && !self.attested()
        {
            return Err("attestation_required");
        }
        let path = self.state.join("requests").join(&request.request_id);
        let digest = hex(&Sha256::digest(envelope.payload.as_bytes()));
        match trusted_read(&path, 65_536) {
            Ok(data) => {
                let record: Reservation =
                    serde_json::from_slice(&data).map_err(|_| "state_unavailable")?;
                if record.digest != digest {
                    return Err("request_id_conflict");
                }
                return Ok(Admission::Cached(record.response.unwrap_or_else(|| {
                    Response::error(&request.request_id, "outcome_unknown")
                })));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err("state_unavailable"),
        }
        if fs::read_dir(self.state.join("requests"))
            .map_err(|_| "state_unavailable")?
            .count()
            >= MAX_RESERVATIONS
        {
            return Err("journal_full");
        }
        let record = serde_json::to_vec(&Reservation {
            digest,
            response: None,
        })
        .map_err(|_| "state_unavailable")?;
        // Reserve before effects; a crash can produce uncertainty, never automatic replay.
        atomic_write(&path, &record).map_err(|_| "state_unavailable")?;
        Ok(Admission::Execute(Box::new(request)))
    }

    pub fn finish(
        &self,
        request: &AuthorizedRequest,
        response: &Response,
    ) -> Result<(), &'static str> {
        let path = self.state.join("requests").join(&request.request_id);
        let mut record: Reservation =
            serde_json::from_slice(&trusted_read(&path, 65_536).map_err(|_| "state_unavailable")?)
                .map_err(|_| "state_unavailable")?;
        record.response = Some(
            if matches!(
                request.operation,
                Operation::WorkloadLogs { .. }
                    | Operation::Files { .. }
                    | Operation::SessionRead { .. }
            ) {
                Response::error(&request.request_id, "result_not_retained")
            } else {
                response.clone()
            },
        );
        atomic_write(
            &path,
            &serde_json::to_vec(&record).map_err(|_| "state_unavailable")?,
        )
        .map_err(|_| "state_unavailable")
    }

    fn save_owner(&mut self, owner: OwnerBinding) -> Result<(), &'static str> {
        atomic_write(
            &self.state.join("owner.json"),
            &serde_json::to_vec(&owner).map_err(|_| "state_unavailable")?,
        )
        .map_err(|_| "state_unavailable")?;
        self.owner = Some(owner);
        self.verified_until = 0;
        self.decision = None;
        Ok(())
    }

    pub fn identity_operation(
        &mut self,
        request: &AuthorizedRequest,
    ) -> Result<bool, &'static str> {
        match &request.operation {
            Operation::Enroll {
                owner_public_key,
                workload_identity,
            } => {
                if self.owner.is_some() {
                    return Err("owner_already_bound");
                }
                VerifyingKey::from_bytes(&decode::<32>(owner_public_key)?)
                    .map_err(|_| "invalid_key")?;
                if workload_identity.is_empty() || request.owner_epoch != 1 {
                    return Err("invalid_enrollment");
                }
                self.save_owner(OwnerBinding {
                    public_key: owner_public_key.clone(),
                    workload_identity: workload_identity.clone(),
                    epoch: 1,
                    revoked: false,
                })?;
            }
            Operation::Rotate {
                new_public_key,
                new_key_proof,
            } => {
                let mut owner = self.owner.clone().ok_or("owner_unavailable")?;
                let payload = serde_json::to_string(&(
                    &self.policy.organization_id,
                    &self.policy.project_id,
                    &self.policy.sandbox_id,
                    &owner.public_key,
                    new_public_key,
                    owner.epoch,
                ))
                .map_err(|_| "invalid_rotation")?;
                verify(
                    new_public_key,
                    b"gammacloud.runtime.rotation.v2\0",
                    &SignedEnvelope {
                        payload,
                        signature: new_key_proof.clone(),
                    },
                )?;
                owner.public_key = new_public_key.clone();
                owner.epoch = owner.epoch.checked_add(1).ok_or("epoch_exhausted")?;
                self.save_owner(owner)?;
            }
            Operation::Revoke => {
                let mut owner = self.owner.clone().ok_or("owner_unavailable")?;
                if request.owner_epoch <= owner.epoch {
                    return Err("stale_owner_epoch");
                }
                owner.epoch = request.owner_epoch;
                owner.revoked = true;
                self.save_owner(owner)?;
            }
            Operation::Attest { decision } => {
                verify(
                    &self.policy.verifier_public_key,
                    structured::DECISION_DOMAIN,
                    decision,
                )?;
                let decision: AttestationDecision =
                    serde_json::from_str(&decision.payload).map_err(|_| "invalid_decision")?;
                let owner = self.owner.as_ref().ok_or("owner_unavailable")?;
                let time = now()?;
                if decision.guest_id != self.policy.guest_id
                    || decision.boot_nonce != self.boot_nonce
                    || decision.owner_public_key != owner.public_key
                    || decision.image_digest != self.policy.image_digest
                    || decision.workload_identity != owner.workload_identity
                    || decision.policy_version != self.policy.policy_version
                    || decision.owner_epoch != owner.epoch
                    || decision.issued_at > time
                    || decision.expires_at <= time
                    || decision.expires_at.saturating_sub(decision.issued_at) > 300
                {
                    return Err("decision_binding_mismatch");
                }
                self.verified_until = decision.expires_at;
                if let Operation::Attest { decision } = &request.operation {
                    self.decision = Some(decision.clone());
                }
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
}

impl Drop for Authorization {
    fn drop(&mut self) {
        // Keep the exclusive lock alive for the entire authorization lifecycle.
        let _ = self.journal_lock.sync_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        authorization: Authorization,
        authority: SigningKey,
        owner: SigningKey,
    }
    impl Fixture {
        fn new() -> Self {
            let authority = SigningKey::from_bytes(&[1; 32]);
            let owner = SigningKey::from_bytes(&[2; 32]);
            let state = std::env::temp_dir().join(format!(
                "gc-auth-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let policy = TrustPolicy {
                organization_id: "org".into(),
                project_id: "project".into(),
                sandbox_id: "sandbox".into(),
                guest_id: "guest".into(),
                image_digest: "sha256:expected".into(),
                policy_version: "v1".into(),
                enrollment_public_key: hex(authority.verifying_key().as_bytes()),
                verifier_public_key: hex(SigningKey::from_bytes(&[3; 32])
                    .verifying_key()
                    .as_bytes()),
                permissions: ["enroll", "revoke", "rotate", "attest", "start", "status"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
                require_attestation_for_start: true,
                execution_templates: Default::default(),
                volumes: Default::default(),
                development_agents: Default::default(),
            };
            Self {
                authorization: Authorization::open(policy, state).unwrap(),
                authority,
                owner,
            }
        }
        fn request(&self, id: &str, operation: Operation) -> AuthorizedRequest {
            let time = now().unwrap();
            AuthorizedRequest {
                version: 2,
                request_id: id.into(),
                organization_id: "org".into(),
                project_id: "project".into(),
                sandbox_id: "sandbox".into(),
                guest_id: "guest".into(),
                boot_nonce: self.authorization.boot_nonce.clone(),
                policy_version: "v1".into(),
                owner_epoch: 1,
                issued_at: time,
                expires_at: time + 60,
                operation,
            }
        }
        fn signed(request: &AuthorizedRequest, key: &SigningKey) -> SignedEnvelope {
            let payload = serde_json::to_string(request).unwrap();
            let mut bytes = Vec::from(structured::REQUEST_DOMAIN);
            bytes.extend_from_slice(payload.as_bytes());
            SignedEnvelope {
                payload,
                signature: hex(&key.sign(&bytes).to_bytes()),
            }
        }
        fn enroll(&mut self) {
            let request = self.request(
                "enroll",
                Operation::Enroll {
                    owner_public_key: hex(self.owner.verifying_key().as_bytes()),
                    workload_identity: "workload".into(),
                },
            );
            let envelope = Self::signed(&request, &self.authority);
            assert!(matches!(
                self.authorization.admit(&envelope),
                Ok(Admission::Execute(_))
            ));
            assert!(self.authorization.identity_operation(&request).unwrap());
            self.authorization
                .finish(&request, &Response::success("enroll", "bound".into()))
                .unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.authorization.state);
        }
    }

    #[test]
    fn signatures_resource_binding_and_expiry_are_enforced() {
        let mut f = Fixture::new();
        f.enroll();
        let request = f.request("status", Operation::Status);
        assert!(f
            .authorization
            .admit(&Fixture::signed(&request, &f.authority))
            .is_err());
        let mut wrong = request.clone();
        wrong.boot_nonce = "other-boot".into();
        assert!(f
            .authorization
            .admit(&Fixture::signed(&wrong, &f.owner))
            .is_err());
        let mut expired = request;
        expired.expires_at = now().unwrap();
        assert!(f
            .authorization
            .admit(&Fixture::signed(&expired, &f.owner))
            .is_err());
    }

    #[test]
    fn duplicate_requests_return_results_and_reserved_requests_are_uncertain() {
        let mut f = Fixture::new();
        f.enroll();
        let request = f.request("status", Operation::Status);
        let envelope = Fixture::signed(&request, &f.owner);
        assert!(matches!(
            f.authorization.admit(&envelope),
            Ok(Admission::Execute(_))
        ));
        assert!(
            matches!(f.authorization.admit(&envelope), Ok(Admission::Cached(response)) if response.code == "outcome_unknown")
        );
        f.authorization
            .finish(&request, &Response::success("status", "ready".into()))
            .unwrap();
        assert!(
            matches!(f.authorization.admit(&envelope), Ok(Admission::Cached(response)) if response.result == "ready")
        );
        let mut conflict = request;
        conflict.operation = Operation::Revoke;
        // Authority-signed conflicting reuse still cannot execute a second effect.
        assert!(matches!(
            f.authorization
                .admit(&Fixture::signed(&conflict, &f.authority)),
            Err("request_id_conflict")
        ));
    }

    #[test]
    fn enrollment_cannot_replace_bound_owner_and_start_requires_a_decision() {
        let mut f = Fixture::new();
        f.enroll();
        let rebind = f.request(
            "rebind",
            Operation::Enroll {
                owner_public_key: hex(f.authority.verifying_key().as_bytes()),
                workload_identity: "other".into(),
            },
        );
        assert_eq!(
            f.authorization.identity_operation(&rebind),
            Err("owner_already_bound")
        );
        let start = f.request(
            "start",
            Operation::Start {
                profile: "smoke".into(),
            },
        );
        assert!(matches!(
            f.authorization.admit(&Fixture::signed(&start, &f.owner)),
            Err("attestation_required")
        ));
    }

    #[test]
    fn verifier_signature_and_binding_are_required() {
        let mut f = Fixture::new();
        f.enroll();
        let time = now().unwrap();
        let decision = AttestationDecision {
            guest_id: "guest".into(),
            boot_nonce: f.authorization.boot_nonce.clone(),
            owner_public_key: hex(f.owner.verifying_key().as_bytes()),
            image_digest: "sha256:expected".into(),
            workload_digest: "sha256:expected-workload".into(),
            workload_identity: "workload".into(),
            policy_version: "v1".into(),
            owner_epoch: 1,
            issued_at: time,
            expires_at: time + 60,
        };
        let payload = serde_json::to_string(&decision).unwrap();
        let mut message = Vec::from(structured::DECISION_DOMAIN);
        message.extend_from_slice(payload.as_bytes());
        let forged = SignedEnvelope {
            payload: payload.clone(),
            signature: hex(&f.owner.sign(&message).to_bytes()),
        };
        let request = f.request("attest", Operation::Attest { decision: forged });
        assert!(f.authorization.identity_operation(&request).is_err());
        assert!(!f.authorization.attested());
        let verifier = SigningKey::from_bytes(&[3; 32]);
        let request = f.request(
            "attest-real",
            Operation::Attest {
                decision: SignedEnvelope {
                    payload,
                    signature: hex(&verifier.sign(&message).to_bytes()),
                },
            },
        );
        f.authorization.identity_operation(&request).unwrap();
        assert!(f.authorization.attested());
    }

    #[test]
    fn revocation_rejects_previous_owner() {
        let mut f = Fixture::new();
        f.enroll();
        let mut revoke = f.request("revoke", Operation::Revoke);
        revoke.owner_epoch = 2;
        assert!(matches!(
            f.authorization
                .admit(&Fixture::signed(&revoke, &f.authority)),
            Ok(Admission::Execute(_))
        ));
        f.authorization.identity_operation(&revoke).unwrap();
        let request = f.request("after-revoke", Operation::Status);
        assert!(matches!(
            f.authorization.admit(&Fixture::signed(&request, &f.owner)),
            Err("owner_unavailable")
        ));
    }
}
