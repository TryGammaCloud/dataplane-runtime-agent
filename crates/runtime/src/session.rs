use crate::identity::OwnerIdentity;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Active,
    Idle,
    Expired,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: String,
    pub owner: OwnerIdentity,
    pub state: SessionState,
    pub created_at: u64,
    pub expires_at: u64,
    pub pty_enabled: bool,
}

impl Session {
    pub fn new(id: impl Into<String>, owner: OwnerIdentity, ttl: Duration) -> Result<Self, String> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| "system clock is before unix epoch".to_string())?
            .as_secs();
        let expires_at = now + ttl.as_secs();

        let id = id.into();
        if id.trim().is_empty() {
            return Err("session id cannot be empty".into());
        }

        Ok(Self {
            id,
            owner,
            state: SessionState::Active,
            created_at: now,
            expires_at,
            pty_enabled: true,
        })
    }

    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at || self.state == SessionState::Expired || self.state == SessionState::Closed
    }
}

#[derive(Debug, Default)]
pub struct SessionManager {
    sessions: HashMap<String, Session>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create(
        &mut self,
        id: impl Into<String>,
        owner: OwnerIdentity,
        ttl: Duration,
    ) -> Result<Session, String> {
        let session = Session::new(id, owner, ttl)?;
        self.sessions.insert(session.id.clone(), session.clone());
        Ok(session)
    }

    pub fn close(&mut self, id: &str) -> Result<(), String> {
        let Some(session) = self.sessions.get_mut(id) else {
            return Err(format!("unknown session: {id}"));
        };
        session.state = SessionState::Closed;
        Ok(())
    }

    pub fn list_active(&self) -> Vec<Session> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        self.sessions
            .values()
            .filter(|session| !session.is_expired(now))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionManager, SessionState};
    use crate::identity::OwnerIdentity;
    use std::time::Duration;

    #[test]
    fn session_can_be_created_and_closed() {
        let owner = OwnerIdentity {
            organization_id: "org".to_string(),
            project_id: "project".to_string(),
            sandbox_id: "sandbox".to_string(),
            owner_public_key: "ssh-rsa AAAA".to_string(),
            workload_identity: "workload".to_string(),
            session_id: "session-1".to_string(),
            policy_version: "v1".to_string(),
        };

        let mut sessions = SessionManager::new();
        let session = sessions.create("session-1", owner, Duration::from_secs(60)).unwrap();
        assert_eq!(session.state, SessionState::Active);
        sessions.close("session-1").unwrap();
        assert_eq!(sessions.list_active().len(), 0);
    }

    #[test]
    fn session_rejects_empty_identifier() {
        let owner = OwnerIdentity {
            organization_id: "org".to_string(),
            project_id: "project".to_string(),
            sandbox_id: "sandbox".to_string(),
            owner_public_key: "ssh-rsa AAAA".to_string(),
            workload_identity: "workload".to_string(),
            session_id: "session-1".to_string(),
            policy_version: "v1".to_string(),
        };

        let mut sessions = SessionManager::new();
        assert!(sessions.create("", owner, Duration::from_secs(5)).is_err());
    }
}
