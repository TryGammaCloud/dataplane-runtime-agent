use std::env;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerIdentity {
    pub organization_id: String,
    pub project_id: String,
    pub sandbox_id: String,
    pub owner_public_key: String,
    pub workload_identity: String,
    pub session_id: String,
    pub policy_version: String,
}

impl OwnerIdentity {
    pub fn from_env() -> Result<Self, String> {
        let organization_id = env::var("GAMMACLOUD_ORG_ID").unwrap_or_else(|_| "dev-org".to_owned());
        let project_id = env::var("GAMMACLOUD_PROJECT_ID").unwrap_or_else(|_| "dev-project".to_owned());
        let sandbox_id = env::var("GAMMACLOUD_SANDBOX_ID").unwrap_or_else(|_| "dev-sandbox".to_owned());
        let owner_public_key = env::var("GAMMACLOUD_OWNER_PUBLIC_KEY")
            .unwrap_or_else(|_| "local-development-identity".to_owned());
        let workload_identity = env::var("GAMMACLOUD_WORKLOAD_IDENTITY")
            .unwrap_or_else(|_| "local-workload".to_owned());
        let session_id = env::var("GAMMACLOUD_SESSION_ID").unwrap_or_else(|_| "dev-session".to_owned());
        let policy_version = env::var("GAMMACLOUD_POLICY_VERSION").unwrap_or_else(|_| "dev-policy-v1".to_owned());

        let identity = Self {
            organization_id,
            project_id,
            sandbox_id,
            owner_public_key,
            workload_identity,
            session_id,
            policy_version,
        };
        identity.validate()?
;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.organization_id.trim().is_empty() {
            return Err("organization_id is required".into());
        }
        if self.project_id.trim().is_empty() {
            return Err("project_id is required".into());
        }
        if self.sandbox_id.trim().is_empty() {
            return Err("sandbox_id is required".into());
        }
        if self.owner_public_key.trim().is_empty() {
            return Err("owner_public_key is required".into());
        }
        if self.workload_identity.trim().is_empty() {
            return Err("workload_identity is required".into());
        }
        if self.session_id.trim().is_empty() {
            return Err("session_id is required".into());
        }
        Ok(())
    }

    pub fn verify_new_owner(&self, proposed: &OwnerIdentity) -> Result<(), String> {
        if proposed.organization_id != self.organization_id {
            return Err("organization_id mismatch".into());
        }
        if proposed.project_id != self.project_id {
            return Err("project_id mismatch".into());
        }
        if proposed.sandbox_id != self.sandbox_id {
            return Err("sandbox_id mismatch".into());
        }
        if !self.owner_public_key.is_empty() && self.owner_public_key != proposed.owner_public_key {
            return Err("owner_public_key is already bound to a different identity".into());
        }
        Ok(())
    }

    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = session_id.into();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::OwnerIdentity;

    #[test]
    fn owner_identity_requires_nonempty_fields() {
        let identity = OwnerIdentity {
            organization_id: "org".to_string(),
            project_id: "project".to_string(),
            sandbox_id: "sandbox".to_string(),
            owner_public_key: "ssh-rsa AAAA".to_string(),
            workload_identity: "workload".to_string(),
            session_id: "session".to_string(),
            policy_version: "v1".to_string(),
        };

        assert!(identity.validate().is_ok());
    }

    #[test]
    fn owner_identity_rejects_rebinding() {
        let current = OwnerIdentity {
            organization_id: "org".to_string(),
            project_id: "project".to_string(),
            sandbox_id: "sandbox".to_string(),
            owner_public_key: "ssh-rsa current".to_string(),
            workload_identity: "workload".to_string(),
            session_id: "session".to_string(),
            policy_version: "v1".to_string(),
        };

        let next = OwnerIdentity {
            organization_id: "org".to_string(),
            project_id: "project".to_string(),
            sandbox_id: "sandbox".to_string(),
            owner_public_key: "ssh-rsa other".to_string(),
            workload_identity: "workload".to_string(),
            session_id: "session-2".to_string(),
            policy_version: "v1".to_string(),
        };

        assert!(current.verify_new_owner(&next).is_err());
    }
}
