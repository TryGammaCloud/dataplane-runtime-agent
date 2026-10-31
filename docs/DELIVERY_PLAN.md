# Runtime delivery plan

## Baseline

Baseline: merged runtime scaffolding on `main` at `9f55d96`.
The runtime remains a development service: Unix UID authorization, fixed
executables, per-process rlimits and an optional unauthenticated vsock bridge.
Declared capabilities are design intentions unless backed by an operational path.

## Delivery rules

- Keep the Rust workspace and the existing development commands compatible.
- Create focused PRs against `main`; do not merge dependent work automatically.
- Every PR states behavior, failure modes, integration dependencies and validation.
- Prepare regression tests but do not execute test suites during this mission.
  Formatting, Clippy and documentation checks may run; CI results must be reported
  separately from local validation.
- Do not build NixOS, deploy, or publish release artifacts.
- Never enable arbitrary execution or customer secrets on scaffolding guarantees.

## Ordered increments

| Increment | Tasks | Deliverable and acceptance criteria | Dependencies |
|---|---|---|---|
| Connection resilience | T03, T15 | Malformed, disconnected or timed-out clients cannot terminate the listener. Responses are bounded by time. Shutdown still cleans managed processes if its acknowledgement fails. | Current Unix protocol |
| Process lifecycle | T05, T06, T15 | Define signal handling, child/group cleanup, retention and wall-clock deadlines. Prepare regression scenarios for descendant processes and repeated cleanup. | Connection resilience; Linux lifecycle review |
| Reference audit and contracts | T01, T02, T16 | Review the three named Tinfoil repositories at recorded commits. Attribute external Monitor/verifier features accurately. Specify OS, Node, verifier and inference ownership. | Read-only upstream analysis |
| Protocol and enrollment | T03, T04 | Structured responses, request IDs, deadlines and idempotency semantics. Verified enrollment binds owner and policy durably, with rotation/revocation rules. Reject forged, expired and replayed authorizations. | Agreed trust and key provisioning contracts |
| Attestation decisions | T10 | Validate independent verifier decisions bound to fresh evidence, guest, image, workload and expiry. A host boolean or a local state transition cannot release secrets. | Verifier contract; cryptographic review; hardware evidence acquisition |
| Isolated execution | T05, T06 | Authorized manifests launch under enforced UID/GID, cgroups, namespaces, capability and seccomp policies. Missing mandatory protection prevents launch. | Authorization; OS provisioning contract |
| Workspace and volumes | T08, T09 | File operations resist traversal and symlink escapes. Enforce permissions/quotas and volume states. No workspace access before authorized unlock/mount; no logged keys. | Isolation; independent key-release policy; attached device contract |
| Sessions and tools | T07, T12 | Authorized sessions own PTYs and processes, handle disconnection/expiry, and launch OS-packaged agents through approved profiles. | Identity; isolation; workspace |
| Egress and credentials | T11 | Enforce destinations on actual workload traffic. Scoped temporary credentials expire/revoke and do not enter ordinary tool configuration. | Network enforcement and credential broker contracts |
| Inference supervision | T13 | Verify authorized artifacts, coordinate weights, launch a preinstalled engine, probe health and stop cleanly. Keep engine-specific configuration outside the runtime. | Authorization; isolation; dataplane-inference contract |
| Telemetry and restart recovery | T14, T15 | Collect real resource measurements and safe lifecycle events. Reconcile persisted desired state with live processes, cgroups and mounts after interruption. | Operational lifecycle and storage |

## Integration ownership to specify

- OS: installed binaries, service identities, kernel features, mount roots and packaging.
- Node Agent: VM lifecycle, virtual devices and transport; no authority to self-assert
  attestation success or impersonate an owner.
- Independent verifier/key service: evidence evaluation, signed decisions, freshness,
  revocation and conditional key release.
- Runtime: guest-side authorization, enforcement, supervision and reconciliation.
- Inference repository: engine packages and specialized configuration.

## Validation gates

Prepare unit tests for parsing, policy refusals, expiration and transitions; Linux
integration scenarios for sockets, children, cgroups, PTYs and mounts; and separate
hardware scenarios for SEV-SNP evidence and conditional secret release.
Passing lint or CI is not evidence of production confidentiality. Record unexecuted
checks and unavailable hardware explicitly in each PR.
