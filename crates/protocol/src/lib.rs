//! Development-only guest lifecycle protocol. No attestation claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestState {
    Starting,
    Ready,
    Stopping,
    Stopped,
}

impl GuestState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Ready => "ready",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn states_have_stable_names() {
        assert_eq!(GuestState::Starting.as_str(), "starting");
        assert_eq!(GuestState::Ready.as_str(), "ready");
    }
}
