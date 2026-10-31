# Runtime integration contracts — proposed v1

These are proposed interfaces to implement and review, not a claim that OS, Node
Agent, verifier or inference services already support them. Existing development
commands remain separate from production authorization.

| Component | Owns | Must not establish trust through |
|---|---|---|
| OS image | Immutable runtime/tool binaries, policy trust roots, UID/GID, cgroup delegation, kernel features, device/mount configuration | An unverified host metadata boolean |
| Node Agent | VM lifecycle, virtual disk attachment, network/vsock routing and retries | CID alone, owner impersonation or self-asserted attestation |
| Runtime | Guest authorization, bounded execution, workspace/session lifecycle, supervision and safe resource reporting | Environment-derived owner authority |
| Independent verifier | Fresh evidence validation and signed decisions bound to expected image/guest/workload/policy | Node Agent's approval |
| Key/credential service | Conditional, scoped, expiring release to an authenticated guest channel | Keys returned in host-visible plaintext |
| dataplane-inference | Engine package, arguments, model layout and readiness contract | A model-specific server reimplemented in Runtime |

## Authorization and communication

Use a versioned structured envelope with request ID, explicit operation/resource,
issued-at/deadline, policy revision and authenticated issuer. Sign exact payload
bytes with domain separation. Bind organization, project, sandbox, guest boot and
workload identity. Reject unknown versions/fields, invalid signatures, stale policy,
expired operations and oversized frames before effects. Responses retain request ID
and a stable error code; never echo credentials, filesystem content or OS errors.

Reserve mutating request IDs durably before effects. Repeated identical requests
return the stored result; reuse with different content is a conflict. A crash
between effect and durable result yields an explicit uncertain outcome, never an
automatic duplicate execution. Retention must not evict still-replayable IDs.

Signed requests authenticate operations but do not encrypt transport. Production
secret delivery also requires a channel whose guest key is bound to attestation.
The development vsock bridge must not become a secret transport by implication.

## Owner lifecycle and attestation

An image-provisioned enrollment authority signs the initial binding. Persist that
binding before accepting owner commands. Rotation requires current-owner consent
and new-key proof; revocation requires an authorized authority decision and a
monotonically advancing epoch. Persistent state on operator-controlled storage
needs an external anti-rollback anchor; filesystem persistence alone is insufficient.

The verifier decision binds a fresh runtime challenge and guest public key, expected
image/workload digests, policy version, permissions and expiration. Runtime validates
the decision against a pinned verifier key. Raw SNP report collection requires the
actual guest device/API and hardware validation; no local `accept()` substitutes
for it. Revocation invalidates cached authorizations and secret leases.

## Workload, storage and session lifecycle

Admission: verified identity → allowed operation → ready workspace → resource and
isolation installation → spawn → readiness. Failure before spawn means no child;
failure after spawn means bounded teardown. Elevated privileges require a separate
explicit reviewed policy; ordinary manifests cannot opt out of isolation.

OS supplies a delegated cgroup v2 subtree and non-root identities. Runtime enforces
memory/CPU/PID limits, namespace/capability/seccomp policy and real deadlines. The
workload may not write its cgroup controller or runtime socket/state.

Node attaches devices; Runtime checks expected identifiers before activation. The
volume moves through detected/locked/unlocking/mounted/error states. Mount readiness
is checked against the kernel, not a boolean supplied by Node. Key release requires
verifier authorization. Keys travel via protected descriptors/channel, never argv
or logs. No formatting, destructive reset or key removal is implicit in a retry.
Workspace APIs use directory-descriptor-relative operations that reject traversal,
symlink/mount escapes and unauthorized writes. Kernel quotas must cover all writers.

Sessions bind owner, workload and workspace; PTYs have bounded input/output, expiry,
resize limits and explicit disconnect behavior. Closing/revoking the session tears
down its process group/cgroup. OS packages approved tools and SSH; Runtime supplies
only authorized profiles and keys, never downloads executable agents at runtime.

## Network, inference and telemetry

Enforcement belongs in a workload network namespace or a mandatory guest gateway,
with no direct-route fallback. Policy binds exact destinations and workloads, and
handles DNS rebinding, IP literals, ports and redirects explicitly. A credential
broker injects scoped credentials at the gateway; ordinary tool files contain
only public endpoints and non-secret references. Unavailable enforcement denies
workload admission rather than silently allowing unrestricted traffic.

Inference manifests identify an approved engine executable and weight digests,
resource requests and a loopback health endpoint. Runtime verifies local artifacts,
supervises the engine and reports ready only after an actual bounded probe.

Export CPU/RAM/PID/disk/runtime/session counters and technical lifecycle events,
with bounded buffers. GPU reporting is optional and explicitly unavailable without
an installed collector. No prompts, tokens, secret values, file content or customer
command arguments are telemetry. Billing remains external.

## Acceptance evidence

Every implementation PR links its contract subsection and records exercised versus
prepared tests. Required scenarios include tampered/expired/replayed requests,
owner replacement, failed isolation, locked volumes, symlink escapes, denied egress,
PTY expiry, failed engine readiness, SIGTERM and restart reconciliation. SNP/key
release evidence requires an independent verifier and appropriate hardware.
