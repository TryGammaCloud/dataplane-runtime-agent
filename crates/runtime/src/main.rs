//! GammaCloud development guest service entrypoint.
#[allow(
    dead_code,
    reason = "Attestation interfaces await integration with a trusted external verifier."
)]
mod attestation;
mod dev_vsock;
#[allow(
    dead_code,
    reason = "Agent catalog interfaces await workload launcher integration."
)]
mod development_agent;
#[allow(
    dead_code,
    reason = "Owner rotation and session binding interfaces await verified enrollment."
)]
mod identity;
mod lifecycle;
mod manager;
#[allow(
    dead_code,
    reason = "Inference interfaces await integration with a preinstalled engine."
)]
mod model_runtime;
#[allow(
    dead_code,
    reason = "Policy interfaces are declarative until egress enforcement is integrated."
)]
mod network_policy;
mod product;
#[allow(
    dead_code,
    reason = "Reconciliation interfaces await persistent state and process discovery."
)]
mod resilience;
mod security;
mod server;
#[allow(
    dead_code,
    reason = "Interactive session transitions await PTY and protocol integration."
)]
mod session;
#[allow(
    dead_code,
    reason = "Telemetry interfaces await resource sampling and export integration."
)]
mod telemetry;
#[allow(
    dead_code,
    reason = "Workspace interfaces await filesystem and volume lifecycle integration."
)]
mod workspace;

fn main() -> std::io::Result<()> {
    server::serve()
}
