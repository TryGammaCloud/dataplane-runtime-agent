use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevelopmentAgentKind {
    OpenCode,
    Codex,
    ClaudeCode,
    QwenCode,
    Goose,
}

impl DevelopmentAgentKind {
    pub fn from_name(name: &str) -> Result<Self, String> {
        match name.trim().to_ascii_lowercase().as_str() {
            "opencode" => Ok(Self::OpenCode),
            "codex" => Ok(Self::Codex),
            "claudecode" | "claude-code" => Ok(Self::ClaudeCode),
            "qwen" | "qwen-code" => Ok(Self::QwenCode),
            "goose" => Ok(Self::Goose),
            _ => Err(format!("unsupported development agent: {name}")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenCode => "opencode",
            Self::Codex => "codex",
            Self::ClaudeCode => "claude-code",
            Self::QwenCode => "qwen-code",
            Self::Goose => "goose",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevelopmentAgent {
    pub kind: DevelopmentAgentKind,
    pub enabled: bool,
    pub version: String,
}

#[derive(Debug, Default)]
pub struct DevelopmentAgentCatalog {
    agents: BTreeMap<String, DevelopmentAgent>,
}

impl DevelopmentAgentCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, kind: DevelopmentAgentKind, version: impl Into<String>, enabled: bool) {
        let version = version.into();
        self.agents.insert(kind.as_str().to_string(), DevelopmentAgent { kind, enabled, version });
    }

    pub fn get(&self, name: &str) -> Option<&DevelopmentAgent> {
        let key = name.trim().to_ascii_lowercase();
        self.agents.get(&key)
    }

    pub fn supported_names(&self) -> Vec<String> {
        self.agents.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{DevelopmentAgentCatalog, DevelopmentAgentKind};

    #[test]
    fn resolves_supported_agent_types() {
        assert_eq!(DevelopmentAgentKind::from_name("codex").unwrap(), DevelopmentAgentKind::Codex);
        assert_eq!(DevelopmentAgentKind::from_name("ClaudeCode").unwrap(), DevelopmentAgentKind::ClaudeCode);
        assert!(DevelopmentAgentKind::from_name("unknown-agent").is_err());
    }

    #[test]
    fn catalog_tracks_enabled_agents() {
        let mut catalog = DevelopmentAgentCatalog::new();
        catalog.register(DevelopmentAgentKind::OpenCode, "1.0.0", true);
        assert!(catalog.get("opencode").is_some());
        assert_eq!(catalog.supported_names().len(), 1);
    }
}
