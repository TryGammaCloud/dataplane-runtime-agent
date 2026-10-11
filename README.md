# GammaCloud Data Plane Runtime Agent

Rust software running **inside** each GammaCloud guest VM/CVM, distinct from the host-side `dataplane-node-agent` and image builder `dataplane-os`.

## Current development protocol v1

Local Unix socket `/run/gammacloud/runtime.sock` (mode 0600). Requests are newline-delimited and responses are single-line. The socket is **not** a host-to-guest transport and is **not** an attested or remotely authenticated API.

| Request | Result |
|---|---|
| `HEALTH` | `OK` |
| `STATUS` | `state=ready attestation=unverified confidential=false` |
| `START smoke` | Start a fixed `printf` smoke-test profile |
| `START sleep` | Start a fixed 30-second sleep profile |
| `START worker` | Execute a preinstalled `/opt/gammacloud/workloads/worker` binary (admin-controlled, not client-supplied) |
| `WORKLOAD_STATUS <id>` | Profile, running/exited state and exit code |
| `WORKLOAD_LOGS <id>` | Bounded stdout/stderr (4 KiB each), escaped |
| `STOP <id>` | Terminate and reap the process |
| `SHUTDOWN` | Terminate remaining processes and stop runtime |

No arbitrary executable, shell, command arguments, environment variables or secrets are accepted. The fixed `worker` executable must be provisioned by a trusted OS image; do not allow customer writes to this path. Up to 16 jobs can be started per runtime lifetime; completed jobs remain queryable until shutdown. This development prototype enforces local Linux peer UID checks (`SO_PEERCRED`), per-process CPU-time and virtual-address-space limits (`setrlimit`), and kills the workload process group on STOP/SHUTDOWN. It does **not** implement cgroups, wall-clock timeouts, namespaces/seccomp, filesystem isolation, persistence, authenticated host-to-guest transport, SEV-SNP attestation, or customer workload execution. `RLIMIT_AS` is not a replacement for a cgroup memory controller. It is **not production-safe for untrusted code**.

## Build and test

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --release --locked
```

To test manually, run `gammacloud-runtime` with `GAMMACLOUD_RUNTIME_SOCKET` and `GAMMACLOUD_RUNTIME_LOG_DIR` pointing to an isolated writable directory. Use `socat - UNIX-CONNECT:<socket>` to send protocol lines.

## Local policy configuration

The runtime defaults to the effective UID of the runtime process. Override with `GAMMACLOUD_RUNTIME_ALLOWED_UID` (decimal UID) to allow a different local principal. `GAMMACLOUD_WORKLOAD_MEMORY_MIB` defaults to 256 MiB (range 32–4096) and `GAMMACLOUD_WORKLOAD_CPU_SECONDS` defaults to 10 CPU seconds (range 1–300). Invalid policy settings fail startup. Keep the Unix socket owner/mode locked down; peer UID authorization does **not** establish host identity over vsock or network.

## Trust boundaries

- `gammacloud-boot`: local guest readiness today; later guest identity and evidence acquisition.
- `gammacloud-runtime`: fixed-profile development process lifecycle today; later policy-constrained execution.
- SEV-SNP evidence must be verified by a trusted service **outside the guest** using fresh evidence and policy.
- No customer secrets or privileged workloads before successful remote attestation and policy evaluation.
- Host agent provisions VMs, networks and disks; it must not impersonate the guest runtime.
- A development VM must never claim production confidentiality.

## Next steps

1. Attestation-bound authenticated host-to-guest transport (vsock) and signed workload authorization. Local UID policy is not sufficient.
2. cgroups v2, namespaces, seccomp, enforced wall-clock timeouts, bounded retention and workload identity.
3. Workload packages, volume/persistence interfaces and audit logs.
4. Hardware SEV-SNP attestation, measured release and secrets gating.
5. Pin and integrate a reviewed runtime release into `dataplane-os`.
