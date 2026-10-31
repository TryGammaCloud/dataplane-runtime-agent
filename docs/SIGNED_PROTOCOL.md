# Signed protocol v2 — experimental integration

## Activation and trust

An OS-provisioned `/etc/gammacloud/runtime-policy.json` enables signed mode. It must
be a regular root-owned file without group/world write access; its parent directories
must also be trusted. Invalid configuration fails startup. The example in
`examples/runtime-policy.json` deliberately contains invalid placeholder keys.

Missing policy retains the explicitly insecure development protocol. With a policy,
legacy HEALTH/STATUS remain discovery operations; all other operations require a
signature. The development vsock bridge is forbidden in signed mode. No production
remote transport or encrypted secret channel is claimed by this increment.

The policy pins separate Ed25519 enrollment and verifier public keys, resource IDs,
expected image digest, permissions and whether starting fixed profiles requires a
verifier decision. Owner authority never comes from environment variables in this
mode. OS provisioning must bind the file to the approved image/launch measurement;
root ownership alone does not authenticate an operator-supplied image.

## Wire format

One UTF-8 JSON object followed by LF (maximum 65,536 bytes including LF):

```json
{"payload":"<exact JSON request bytes as a string>","signature":"<128 lowercase hex characters>"}
```

The Ed25519 signature covers `gammacloud.runtime.request.v2\0` followed by the exact
UTF-8 payload bytes. JSON field reordering/whitespace changes require a new signature.
The payload follows `gammacloud_protocol::structured::AuthorizedRequest`: version 2,
request ID, organization/project/sandbox/guest IDs, boot nonce, policy version,
owner epoch, issued-at/expires-at Unix seconds and a tagged `operation`.
Unknown fields are rejected. Requests cannot be future-dated and live at most 300
seconds. Request IDs contain 1–64 ASCII letters, digits, underscores or hyphens.
STATUS exposes a fresh random boot nonce; it is a challenge, not a secret or proof.

Responses contain version, request ID, ok, stable code and result. They are not
signed/encrypted; clients must not infer attested server identity from them. Invalid
or unauthorized payloads return an empty request ID because that ID is not trusted.

## Owner and verifier operations

- `enroll`: authority-signed, initial epoch 1, Ed25519 owner public key and workload
  identity. A bound or revoked owner cannot be replaced by another enrollment.
- `rotate`: current-owner-signed at the current epoch, plus new-key proof. The proof
  signs `gammacloud.runtime.rotation.v2\0` followed by the compact JSON array
  `[organization_id,project_id,sandbox_id,old_public_key,new_public_key,current_epoch]`.
  Successful rotation increments the epoch and invalidates cached attestation.
- `revoke`: enrollment-authority-signed with a strictly larger epoch. It persists
  revocation, invalidates attestation and stops managed workloads. Re-enrollment
  after revocation is deliberately unsupported; recovery requires a separate policy.
- `attest`: owner-signed request carrying an independent signed decision. The inner
  signature domain is `gammacloud.runtime.attestation.v2\0`; the exact payload binds
  guest, boot nonce, owner key, image digest, workload identity, policy, epoch and
  validity interval. The decision lifetime is at most 300 seconds.

Other operations are health/status, fixed-profile start, workload status/logs, stop
and shutdown, with a separate policy permission for each. Arbitrary execution remains
unavailable. The old local `AttestationCoordinator::accept()` has been removed.
A signed decision does not establish hardware correctness unless the external
verifier actually validates SNP evidence. No disk keys or credentials cross this API.

## Crash/replay semantics

`/var/lib/gammacloud/runtime` is guest-private (0700), with an exclusive process lock,
atomic owner updates and a fsynced request reservation before effects. Results are
persisted after effects. An identical admitted request returns its stored result;
a changed payload with the same ID is a conflict. A reservation with no result
returns `outcome_unknown`; the runtime never retries that effect automatically.
Expiration and current authorization are checked before cached responses are returned.

The journal retains at most 16,384 files and refuses admission when full. Automatic
compaction is deliberately absent until a replay-safe policy is defined. The boot
nonce changes after restart, requiring fresh signatures; IDs remain reserved.
An interrupted temporary write can require operator recovery; failures deny effects.
Disk persistence does not provide rollback resistance against an operator restoring
an old disk snapshot. Production needs an external monotonic binding/revocation anchor.

## Validation and remaining work

Prepared tests cover signature/resource/expiry refusals, owner replacement, durable
reservations/results, ID conflicts, verifier signature checking and owner revocation.
Tests were compiled by Clippy, not executed. Formatting and Clippy passed locally.
Hardware acquisition, independent verifier integration, attested channel encryption,
external anti-rollback, and cgroups isolation remain separate acceptance gates.

## Subsequent implementation increments

Later PRs add execute, volume/files, session/agent, model, metrics/outcome and raw
evidence operations to the same signed envelope. See their dedicated contracts and
IMPLEMENTATION_STATUS.md. Independent decisions additionally bind `workload_digest`
(the exact normalized manifest serialization, documented in INFERENCE_CONTRACT.md).
Leases use monotonic deadlines as well as Unix expiry; observed wall-clock rollback
denies authorization. Persisted owner bindings also carry a resource digest, so
state cannot silently migrate to another organization/project/sandbox/guest.
The evolving experimental state schema intentionally rejects incompatible old state;
no production migration or disk anti-rollback guarantee is supplied.

Responses are bounded after JSON serialization, including escaping. File/log/terminal
and outcome-query payloads are not retained as journal results. The example lists
available permissions but has no execution templates, volumes or installed tools;
placeholder trust keys must not be used as a real configuration.
