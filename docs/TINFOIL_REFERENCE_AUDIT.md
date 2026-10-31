# Tinfoil reference audit

Read-only source review on 2026-10-31. No upstream code was executed.

## Revisions inspected

| Repository | Commit | Scope |
|---|---|---|
| confidential-agent-sandbox | `0ae82d1722d9faccfd2a13d83b1a85ec69edb45d` | Go API, entrypoint, image/configuration and guest helper scripts |
| confidential-sandbox-gpu | `2c4db132d527a6ae67e009af20d14b0ca2ab65e0` | GPU workload declaration |
| tinfoil-webapp-sandbox | `54ed5493b58bcb9d72f9ed274f2583a8762ebf4d` | Static preview origin, browser message/CSP contracts |

## Agent sandbox: mechanisms actually present

- [main.go](https://github.com/tinfoilsh/confidential-agent-sandbox/blob/0ae82d1722d9faccfd2a13d83b1a85ec69edb45d/main.go)
  starts health and owner/attestation HTTP services, bounds header reads, handles
  SIGTERM/SIGINT and drains HTTP servers. The owner API is disabled without an
  owner key described by this system as measured launch configuration.
- [owner.go](https://github.com/tinfoilsh/confidential-agent-sandbox/blob/0ae82d1722d9faccfd2a13d83b1a85ec69edb45d/owner.go)
  verifies domain-separated Ed25519 requests over exact signed bytes, binds
  protocol/resource/method/path/body, checks request age and reserves nonces before
  dispatch. A bounded live nonce table refuses admission when full. EHBP middleware
  and an attested per-boot X25519 key provide the encrypted owner channel through
  an external library/CVM mechanism; this file does not implement hardware proof.
- [workspace.go](https://github.com/tinfoilsh/confidential-agent-sandbox/blob/0ae82d1722d9faccfd2a13d83b1a85ec69edb45d/workspace.go)
  checks enrollment inputs, refuses replacement of an installed Monitor identity,
  atomically installs identity/pin files and sends a disk key on helper stdin.
  Unlock has a ten-minute context. Enrollment of the same identity can update the
  Monitor pin. This is not a general owner rotation/revocation service.
- [shell.go](https://github.com/tinfoilsh/confidential-agent-sandbox/blob/0ae82d1722d9faccfd2a13d83b1a85ec69edb45d/shell.go)
  implements PTYs, bounded sessions and output buffers, polling/cursors, sequenced
  input, terminal size limits and idle expiry. Shell admission requires workspace
  readiness and uses the sandbox account through `runuser`.
- [attestation.go](https://github.com/tinfoilsh/confidential-agent-sandbox/blob/0ae82d1722d9faccfd2a13d83b1a85ec69edb45d/attestation.go)
  proxies a bounded attestation document from `/tinfoil/attestation.sock`, without
  forwarding client credentials or following redirects. Evidence generation and
  verification are not implemented by this proxy.
- [entrypoint.sh](https://github.com/tinfoilsh/confidential-agent-sandbox/blob/0ae82d1722d9faccfd2a13d83b1a85ec69edb45d/entrypoint.sh)
  distinguishes local mode, prepares ephemeral credentials, waits for an unlocked
  writable ext4 workspace, establishes persistent overlays and starts systemd.
  Its mounts and administrative capabilities are VM-wide; they are not a template
  for per-customer process isolation inside a shared guest.
- [workspace-unlock](https://github.com/tinfoilsh/confidential-agent-sandbox/blob/0ae82d1722d9faccfd2a13d83b1a85ec69edb45d/rootfs/usr/local/bin/workspace-unlock)
  talks to a CVM volume worker over a Unix socket and checks the real mount state.
  The worker that implements disk encryption/initialization belongs outside this
  repository. The wrapper is not a LUKS implementation.

## Monitor, SSH and tools

The agent repository contains a substantial [Monitor client](https://github.com/tinfoilsh/confidential-agent-sandbox/blob/0ae82d1722d9faccfd2a13d83b1a85ec69edb45d/rootfs/usr/local/bin/monitor):
SSH tunnel setup with pinned host keys, connection discovery, local HTTP/MCP
forwarding and TUN routing through sing-box. The client can install a Monitor CA.
Monitor's remote policy engine, account credentials and substitution service are
external. Client-side routing alone is not proof of enforced egress containment;
the workload declaration also describes host/CVM restrictions.

The [configuration seeder](https://github.com/tinfoilsh/confidential-agent-sandbox/blob/0ae82d1722d9faccfd2a13d83b1a85ec69edb45d/rootfs/usr/local/libexec/seed-agent-config)
installs provider templates and virtual `.monitor` endpoints while preserving user
choices. Real service credentials are held on the Monitor side; substitution keys
are not service API secrets. The Dockerfile and pinned toolchain pack supply tools;
the Go service does not implement their AI behavior. SSH authorized keys derive
from the declared measured owner, with host keys supplied through CVM attested-key
facilities. GammaCloud must establish its own measured/signed provisioning contract;
copying these environment variables would not reproduce that trust boundary.

## GPU repository

The [configuration](https://github.com/tinfoilsh/confidential-sandbox-gpu/blob/2c4db132d527a6ae67e009af20d14b0ca2ab65e0/tinfoil-config.yml)
declares eight GPUs, CPU/RAM resources, persistent workspace/toolchain overlays and
shim paths. It explicitly attributes owner enrollment and tunneled-port handling to
`tinfoilsh/cvmimage-sandbox`. There is no local `main.go`, GPU inference controller,
PTY implementation or hardware verifier to port from this repository.

## Webapp repository

The [README](https://github.com/tinfoilsh/tinfoil-webapp-sandbox/blob/54ed5493b58bcb9d72f9ed274f2583a8762ebf4d/README.md)
and [headers](https://github.com/tinfoilsh/tinfoil-webapp-sandbox/blob/54ed5493b58bcb9d72f9ed274f2583a8762ebf4d/vercel.json)
describe a static browser preview origin using CSP and iframe sandboxing. The
preview protocol binds parent-window messages to a nonce and instance ID. The map
page has separate origin/network rules. This is browser isolation, not a guest
runtime, encrypted volume service or confidential VM attestation implementation.

## Consequences for GammaCloud

Reuse the design principles of exact signed requests, explicit resource bindings,
bounded replay state, workspace readiness and supervised sessions. Keep disk/key
services, evidence verification and inference engines behind explicit contracts.
Do not claim that the three repositories provide all those external components.
