//! Policy enforced by the private namespace and CONNECT gateway, never environment allowlists.
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub host: String,
    pub port: u16,
    pub addresses: Vec<IpAddr>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    pub destinations: Vec<Destination>,
    #[serde(default)]
    pub allow_private_addresses: bool,
}
