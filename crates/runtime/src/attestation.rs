#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationState {
    Unverified,
    Pending,
    Verified,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationEvidence {
    pub vm_id: String,
    pub image_digest: String,
    pub policy_version: String,
    pub measurement: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretLease {
    pub secret_name: String,
    pub reason: String,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationCoordinator {
    pub state: AttestationState,
    pub evidence: Option<AttestationEvidence>,
    pub secret_lease: Option<SecretLease>,
}

impl AttestationCoordinator {
    pub fn new() -> Self {
        Self {
            state: AttestationState::Unverified,
            evidence: None,
            secret_lease: None,
        }
    }

    pub fn record_evidence(
        &mut self,
        vm_id: impl Into<String>,
        image_digest: impl Into<String>,
        policy_version: impl Into<String>,
        measurement: impl Into<String>,
    ) -> Result<(), String> {
        let vm_id = vm_id.into();
        if vm_id.trim().is_empty() {
            return Err("vm_id is required".into());
        }
        self.evidence = Some(AttestationEvidence {
            vm_id,
            image_digest: image_digest.into(),
            policy_version: policy_version.into(),
            measurement: measurement.into(),
        });
        self.state = AttestationState::Pending;
        Ok(())
    }

    pub fn accept(&mut self) -> Result<(), String> {
        if self.evidence.is_none() {
            return Err("cannot verify without evidence".into());
        }
        self.state = AttestationState::Verified;
        Ok(())
    }

    pub fn reject(&mut self) -> Result<(), String> {
        self.state = AttestationState::Rejected;
        self.secret_lease = None;
        Ok(())
    }

    pub fn grant_secret(
        &mut self,
        secret_name: impl Into<String>,
        reason: impl Into<String>,
        expires_at: u64,
    ) -> Result<(), String> {
        if self.state != AttestationState::Verified {
            return Err("secrets are only released after successful attestation".into());
        }
        self.secret_lease = Some(SecretLease {
            secret_name: secret_name.into(),
            reason: reason.into(),
            expires_at,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{AttestationCoordinator, AttestationState};

    #[test]
    fn attestation_requires_evidence_before_accept() {
        let mut coordinator = AttestationCoordinator::new();
        assert!(coordinator.accept().is_err());
    }

    #[test]
    fn secret_is_released_only_after_verification() {
        let mut coordinator = AttestationCoordinator::new();
        coordinator
            .record_evidence("vm-42", "sha256:abc", "v1", "measurement-123")
            .unwrap();
        coordinator.accept().unwrap();
        coordinator
            .grant_secret("db-password", "runtime bootstrap", 1234)
            .unwrap();
        assert_eq!(coordinator.state, AttestationState::Verified);
        assert!(coordinator.secret_lease.is_some());
    }
}
