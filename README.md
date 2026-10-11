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
| `WORKLOAD_STATUS <id>` | Profile, running/exited state and exit code |
| `WORKLOAD_LOGS <id>` | Bounded stdout/stderr (4 KiB each), escaped |
| `STOP <id>` | Terminate and reap the process |
| `SHUTDOWN` | Terminate remaining processes and stop runtime |

No arbitrary executable, shell, command arguments, environment variables or secrets are accepted. Up to 16 jobs can be started per runtime lifetime; completed jobs remain queryable until shutdown. This intentionally limited development prototype does **not** implement resource isolation, cgroups, persistence, an authenticated remote channel, SEV-SNP attestation, or customer workload execution.

## Build and test

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --release --locked
```

To test manually, run `gammacloud-runtime` with `GAMMACLOUD_RUNTIME_SOCKET` and `GAMMACLOUD_RUNTIME_LOG_DIR` pointing to an isolated writable directory. Use `socat - UNIX-CONNECT:<socket>` to send protocol lines.

## Trust boundaries

- `gammacloud-boot`: local guest readiness today; later guest identity and evidence acquisition.
- `gammacloud-runtime`: fixed-profile development process lifecycle today; later policy-constrained execution.
- SEV-SNP evidence must be verified by a trusted service **outside the guest** using fresh evidence and policy.
- No customer secrets or privileged workloads before successful remote attestation and policy evaluation.
- Host agent provisions VMs, networks and disks; it must not impersonate the guest runtime.
- A development VM must never claim production confidentiality.

## Next steps

1. Authenticated host-to-guest transport and explicit execution policy.
2. Process sandboxing, cgroups, timeouts, bounded retention and workload identity.
3. Workload packages, volume/persistence interfaces and audit logs.
4. Hardware SEV-SNP attestation, measured release and secrets gating.
5. Pin and integrate a reviewed runtime release into `dataplane-os`.
