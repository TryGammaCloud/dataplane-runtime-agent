use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPolicy {
    pub allowlist: BTreeSet<String>,
    pub deny_by_default: bool,
    pub require_attestation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialLease {
    pub name: String,
    pub scope: String,
    pub expires_at: u64,
    pub provider: String,
}

impl NetworkPolicy {
    pub fn new() -> Self {
        Self {
            allowlist: BTreeSet::new(),
            deny_by_default: true,
            require_attestation: true,
        }
    }

    pub fn add_allowed_destination(&mut self, destination: impl Into<String>) {
        self.allowlist.insert(destination.into());
    }

    pub fn authorize(&self, destination: &str) -> Result<(), String> {
        if self.deny_by_default && self.allowlist.is_empty() {
            return Err(format!("destination {destination} is not allowed by policy"));
        }
        if !self.allowlist.is_empty() && !self.allowlist.iter().any(|allowed| destination.starts_with(allowed)) {
            return Err(format!("destination {destination} is not in the egress allowlist"));
        }
        Ok(())
    }
}

impl CredentialLease {
    pub fn new(name: impl Into<String>, scope: impl Into<String>, expires_at: u64, provider: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            scope: scope.into(),
            expires_at,
            provider: provider.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CredentialLease, NetworkPolicy};

    #[test]
    fn network_policy_rejects_unlisted_destination() {
        let mut policy = NetworkPolicy::new();
        policy.add_allowed_destination("api.gamma.local");
        assert!(policy.authorize("example.com").is_err());
        assert!(policy.authorize("api.gamma.local/v1/models").is_ok());
    }

    #[test]
    fn credential_lease_tracks_scope() {
        let lease = CredentialLease::new("db-token", "sandbox", 42, "vault");
        assert_eq!(lease.scope, "sandbox");
        assert_eq!(lease.provider, "vault");
    }
}
