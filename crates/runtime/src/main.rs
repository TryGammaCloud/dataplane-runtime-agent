//! Unified GammaCloud Sandbox/Models runtime and development guest entrypoint.
mod attestation;
mod authorization;
mod dev_vsock;
mod development_agent;
mod egress;
mod exec_guard;
mod identity;
mod inference;
mod isolated;
mod lease;
mod lifecycle;
mod manager;
mod model_runtime;
mod network_policy;
mod observability;
mod product;
mod recovery;
mod resilience;
mod seccomp;
mod security;
mod server;
mod session;
mod snp;
mod storage;
mod subprocess;
mod telemetry;
mod terminal;
mod workspace;

fn main() -> std::io::Result<()> {
    let arguments: Vec<String> = std::env::args().collect();
    if arguments.get(1).map(String::as_str) == Some("--isolated-child") {
        if arguments.len() != 3 {
            return Err(std::io::Error::other("invalid guard invocation"));
        }
        return exec_guard::run(&arguments[2]);
    }
    if arguments.get(1).map(String::as_str) == Some("--snp-evidence") {
        if arguments.len() != 3 {
            return Err(std::io::Error::other("invalid evidence invocation"));
        }
        println!("{}", snp::collect(&arguments[2])?);
        return Ok(());
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
