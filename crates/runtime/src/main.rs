//! GammaCloud development guest service entrypoint.
mod attestation;
mod dev_vsock;
mod development_agent;
mod identity;
mod manager;
mod model_runtime;
mod network_policy;
mod product;
mod resilience;
mod security;
mod server;
mod session;
mod telemetry;
mod workspace;

fn main() -> std::io::Result<()> {
    server::serve()
}
