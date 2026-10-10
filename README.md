# GammaCloud Data Plane Runtime Agent

Rust software running **inside** each GammaCloud guest VM/CVM. It is distinct from the host-side `dataplane-node-agent` and from the NixOS image builder `dataplane-os`.

## Trust boundaries

- `gammacloud-boot` (future): guest startup, workload configuration, guest identity and attestation evidence acquisition.
- `gammacloud-runtime` (future): constrained workload execution, lifecycle and guest-facing health/status API.
- Hardware AMD SEV-SNP attestation must be verified by a trusted verifier **outside the guest**, using fresh evidence and a policy; booting a VM is not proof of confidential execution.
- No customer secrets or privileged workloads before successful remote attestation and authorized policy evaluation. Development VMs must never claim production confidentiality.
- The host agent provisions VMs, networks and disks; it must not impersonate the guest runtime.

## Development milestones

1. Rust workspace with `gammacloud-boot` and `gammacloud-runtime` binaries, shared protocol/types and unit tests.
2. Guest boot status, local readiness and safe shutdown (development VM, no attestation claim).
3. Authenticated host-to-guest channel and explicit execution policy; no arbitrary unauthenticated command execution.
4. Isolated workload lifecycle, logs, resource limits and persistence interfaces.
5. SEV-SNP attestation binding, measured release and secrets gating, followed by NixOS image integration.

See [Tinfoil CVM reference](https://github.com/TryGammaCloud/cvmimage/tree/main/tinfoil) for architectural inspiration (`cmd/boot` and `cmd/shim`), not a drop-in security guarantee.
