//! GammaCloud development guest service entrypoint.
#[allow(
    dead_code,
    reason = "Attestation interfaces await integration with a trusted external verifier."
)]
mod attestation;
mod authorization;
mod dev_vsock;
#[allow(
    dead_code,
    reason = "Agent catalog interfaces await workload launcher integration."
)]
mod development_agent;
mod egress;
mod exec_guard;
#[allow(
    dead_code,
    reason = "Owner rotation and session binding interfaces await verified enrollment."
)]
mod identity;
mod inference;
mod isolated;
mod lease;
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
mod observability;
mod product;
mod recovery;
#[allow(
    dead_code,
    reason = "Reconciliation interfaces await persistent state and process discovery."
)]
mod resilience;
mod seccomp;
mod security;
mod server;
#[allow(
    dead_code,
    reason = "Interactive session transitions await PTY and protocol integration."
)]
mod session;
mod storage;
mod subprocess;
#[allow(
    dead_code,
    reason = "Telemetry interfaces await resource sampling and export integration."
)]
mod telemetry;
mod terminal;
#[allow(
    dead_code,
    reason = "Workspace interfaces await filesystem and volume lifecycle integration."
)]
mod workspace;

fn main() -> std::io::Result<()> {
    let arguments: Vec<String> = std::env::args().collect();
    if arguments.get(1).map(String::as_str) == Some("--isolated-child") {
        if arguments.len() != 3 {
            return Err(std::io::Error::other("invalid guard invocation"));
        }
        return exec_guard::run(&arguments[2]);
    }
    if arguments.get(1).map(String::as_str) == Some("--health-probe") {
        if arguments.len() != 5 {
            return Err(std::io::Error::other("invalid probe invocation"));
        }
        return inference::health_child(
            arguments[2]
                .parse()
                .map_err(|_| std::io::Error::other("invalid descriptor"))?,
            arguments[3]
                .parse()
                .map_err(|_| std::io::Error::other("invalid port"))?,
            &arguments[4],
        );
    }
    if arguments.get(1).map(String::as_str) == Some("--egress-sidecar") {
        if arguments.len() != 3 || unsafe { libc::geteuid() } == 0 {
            return Err(std::io::Error::other("invalid sidecar invocation"));
        }
        return egress::sidecar(
            arguments[2]
                .parse()
                .map_err(|_| std::io::Error::other("invalid lifetime"))?,
        );
    }
    if arguments.get(1).map(String::as_str) == Some("--workspace-child") {
        if arguments.len() != 3 {
            return Err(std::io::Error::other("invalid workspace invocation"));
        }
        return storage::file_child(
            arguments[2]
                .parse()
                .map_err(|_| std::io::Error::other("invalid descriptor"))?,
        );
    }
    if arguments.len() != 1 {
        return Err(std::io::Error::other("unsupported arguments"));
    }
    server::serve()
}
