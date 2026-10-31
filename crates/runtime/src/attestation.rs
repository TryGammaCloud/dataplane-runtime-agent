//! Authoritative, boot-local attestation state. Evidence alone never grants authority.
use gammacloud_protocol::structured::{AttestationDecision, SignedEnvelope};
use std::time::{Duration, Instant};

struct Evidence {
    challenge: String,
    digest: String,
    workload: String,
    collected_at: u64,
    deadline: Instant,
}

#[derive(Default)]
pub struct AttestationCoordinator {
    evidence: Option<Evidence>,
    decision: Option<SignedEnvelope>,
    expires_at: u64,
    deadline: Option<Instant>,
}

impl AttestationCoordinator {
    pub fn invalidate(&mut self) {
        self.decision = None;
        self.expires_at = 0;
        self.deadline = None;
        self.evidence = None;
    }

    // Called only after the local SNP collector succeeds; not exposed by the wire protocol.
    pub fn record_evidence(&mut self, challenge: &str, digest: String, workload: &str, now: u64) {
        self.invalidate();
        self.evidence = Some(Evidence {
            challenge: challenge.into(),
            digest,
            workload: workload.into(),
            collected_at: now,
            deadline: Instant::now() + Duration::from_secs(60),
        });
    }

    pub fn verify_decision(
        &mut self,
        key: &str,
        envelope: &SignedEnvelope,
        now: u64,
    ) -> Result<(), &'static str> {
        // Verify first: malformed/forged submissions cannot overwrite existing authority.
        crate::authorization::verify(
            key,
            gammacloud_protocol::structured::DECISION_DOMAIN,
            envelope,
        )?;
        let decision: AttestationDecision =
            serde_json::from_str(&envelope.payload).map_err(|_| "invalid_decision")?;
        let evidence = self.evidence.as_ref().ok_or("fresh_evidence_required")?;
        if Instant::now() >= evidence.deadline
            || now < evidence.collected_at
            || decision.challenge != evidence.challenge
            || decision.evidence_digest != evidence.digest
            || decision.workload_digest != evidence.workload
            || decision.issued_at < evidence.collected_at
            || decision.issued_at > now
            || decision.expires_at <= now
            || decision.expires_at.saturating_sub(decision.issued_at) > 300
        {
            return Err("evidence_binding_mismatch");
        }
        // Consume evidence: a second decision cannot extend this proof's lease.
        self.evidence = None;
        self.deadline = Some(Instant::now() + Duration::from_secs(decision.expires_at - now));
        self.expires_at = decision.expires_at;
        self.decision = Some(envelope.clone());
        Ok(())
    }

    pub fn current(&self, now: u64) -> Option<&SignedEnvelope> {
        self.decision.as_ref().filter(|_| {
            now < self.expires_at
                && self
                    .deadline
                    .is_some_and(|deadline| Instant::now() < deadline)
        })
    }

    pub fn expire(&mut self, now: Option<u64>) -> bool {
        if self.decision.is_some() && now.and_then(|time| self.current(time)).is_none() {
            self.invalidate();
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use gammacloud_protocol::structured::DECISION_DOMAIN;

    // Synthetic proof bindings exercise authorization only, never claim hardware verification.
    fn fixture() -> (AttestationCoordinator, SigningKey, AttestationDecision) {
        let mut coordinator = AttestationCoordinator::default();
        coordinator.record_evidence("challenge", "proof-digest".into(), "manifest", 100);
        let decision = AttestationDecision {
            challenge: "challenge".into(),
            evidence_digest: "proof-digest".into(),
            guest_id: "guest".into(),
            boot_nonce: "boot".into(),
            owner_public_key: "owner".into(),
            image_digest: "image".into(),
            workload_digest: "manifest".into(),
            workload_identity: "workload".into(),
            policy_version: "policy".into(),
            owner_epoch: 1,
            issued_at: 100,
            expires_at: 150,
        };
        (coordinator, SigningKey::from_bytes(&[9; 32]), decision)
    }
    fn signed(key: &SigningKey, decision: &AttestationDecision) -> SignedEnvelope {
        let payload = serde_json::to_string(decision).unwrap();
        let mut bytes = DECISION_DOMAIN.to_vec();
        bytes.extend_from_slice(payload.as_bytes());
        SignedEnvelope {
            payload,
            signature: crate::authorization::hex(&key.sign(&bytes).to_bytes()),
        }
    }
    #[test]
    fn evidence_requires_verifier_and_is_consumed_once() {
        let (mut coordinator, key, decision) = fixture();
        assert!(coordinator.current(100).is_none());
        let public_key = crate::authorization::hex(key.verifying_key().as_bytes());
        let envelope = signed(&key, &decision);
        let wrong = SigningKey::from_bytes(&[10; 32]);
        assert!(coordinator
            .verify_decision(
                &crate::authorization::hex(wrong.verifying_key().as_bytes()),
                &envelope,
                100
            )
            .is_err());
        coordinator
            .verify_decision(&public_key, &envelope, 100)
            .unwrap();
        assert!(coordinator.current(100).is_some());
        assert!(coordinator
            .verify_decision(&public_key, &envelope, 100)
            .is_err());
        assert!(coordinator.expire(Some(150)));
        assert!(coordinator.current(150).is_none());
    }
    #[test]
    fn signed_decisions_cannot_replace_proof_challenge_or_workload() {
        for field in 0..3 {
            let (mut coordinator, key, mut decision) = fixture();
            match field {
                0 => decision.challenge = "other".into(),
                1 => decision.evidence_digest = "other".into(),
                _ => decision.workload_digest = "other".into(),
            }
            assert!(coordinator
                .verify_decision(
                    &crate::authorization::hex(key.verifying_key().as_bytes()),
                    &signed(&key, &decision),
                    100
                )
                .is_err());
            assert!(coordinator.current(100).is_none());
        }
    }
    #[test]
    fn stale_proof_and_clock_rollback_fail_closed() {
        let (mut coordinator, key, decision) = fixture();
        let public_key = crate::authorization::hex(key.verifying_key().as_bytes());
        let envelope = signed(&key, &decision);
        assert!(coordinator
            .verify_decision(&public_key, &envelope, 99)
            .is_err());
        coordinator.evidence.as_mut().unwrap().deadline = Instant::now();
        assert!(coordinator
            .verify_decision(&public_key, &envelope, 100)
            .is_err());
        assert!(coordinator.current(100).is_none());
    }
}
