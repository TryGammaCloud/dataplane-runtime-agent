//! Image-provisioned launch profiles; binaries are never downloaded by this module.
use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProfile {
    pub template: String,
    pub version: String,
}

pub type DevelopmentAgentCatalog = std::collections::BTreeMap<String, AgentProfile>;
