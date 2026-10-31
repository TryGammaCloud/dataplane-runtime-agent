//! Typed, guest-local development protocol v1.
//!
//! This protocol does not provide remote authentication or attestation.
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
#[derive(Debug, Clone, PartialEq, Eq)]
/// Commands accepted by the guest-local development runtime.
pub enum Request {
    Health,
    Status,
    Shutdown,
    Start { profile: Profile },
    WorkloadStatus { id: u64 },
    WorkloadLogs { id: u64 },
    Stop { id: u64 },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Fixed executable profiles; callers cannot supply arbitrary commands.
pub enum Profile {
    Smoke,
    Sleep,
    Worker,
}
impl Profile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Smoke => "smoke",
            Self::Sleep => "sleep",
            Self::Worker => "worker",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestEnvelope {
    pub version: u8,
    pub request: Request,
}

impl RequestEnvelope {
    /// Parse a versioned or legacy request using the same payload grammar.
    pub fn parse(line: &str) -> Result<Self, &'static str> {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.starts_with("V1 ") {
            let payload = trimmed.strip_prefix("V1 ").unwrap_or(trimmed);
            return Ok(Self {
                version: 1,
                request: parse_request(payload)?,
            });
        }
        Ok(Self {
            version: 1,
            request: parse_request(trimmed)?,
        })
    }
}

/// Parses a bounded ASCII command without accepting arbitrary executables.
///
/// # Errors
///
/// Rejects invalid lengths, non-ASCII input and unsupported commands.
pub fn parse_request(line: &str) -> Result<Request, &'static str> {
    if line.len() > 256 || !line.is_ascii() {
        return Err("invalid-request");
    }
    let tokens: Vec<_> = line.split_whitespace().collect();
    match tokens.as_slice() {
        ["HEALTH"] => Ok(Request::Health),
        ["STATUS"] => Ok(Request::Status),
        ["SHUTDOWN"] => Ok(Request::Shutdown),
        ["START", "smoke"] => Ok(Request::Start {
            profile: Profile::Smoke,
        }),
        ["START", "sleep"] => Ok(Request::Start {
            profile: Profile::Sleep,
        }),
        ["START", "worker"] => Ok(Request::Start {
            profile: Profile::Worker,
        }),
        ["WORKLOAD_STATUS", id] => Ok(Request::WorkloadStatus {
            id: id.parse().map_err(|_| "invalid-id")?,
        }),
        ["WORKLOAD_LOGS", id] => Ok(Request::WorkloadLogs {
            id: id.parse().map_err(|_| "invalid-id")?,
        }),
        ["STOP", id] => Ok(Request::Stop {
            id: id.parse().map_err(|_| "invalid-id")?,
        }),
        _ => Err("unsupported-command"),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn states_have_stable_names() {
        assert_eq!(GuestState::Ready.as_str(), "ready");
    }
    #[test]
    fn parses_workload_commands() {
        assert_eq!(
            parse_request("START smoke\n"),
            Ok(Request::Start {
                profile: Profile::Smoke
            })
        );
        assert_eq!(parse_request("STOP 42"), Ok(Request::Stop { id: 42 }));
        assert_eq!(
            parse_request("WORKLOAD_STATUS 42"),
            Ok(Request::WorkloadStatus { id: 42 })
        );
        assert_eq!(
            parse_request("WORKLOAD_LOGS 42"),
            Ok(Request::WorkloadLogs { id: 42 })
        );
        assert_eq!(
            RequestEnvelope::parse("V1 START smoke").unwrap(),
            RequestEnvelope {
                version: 1,
                request: Request::Start {
                    profile: Profile::Smoke
                },
            }
        );
    }
    #[test]
    fn rejects_untrusted_commands() {
        assert!(parse_request("START /bin/sh").is_err());
        assert!(parse_request("START smoke extra").is_err());
        assert!(parse_request(&"a".repeat(257)).is_err());
    }
}

pub mod structured;
