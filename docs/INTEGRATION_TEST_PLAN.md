# Deferred integration validation

Tests are prepared, not executed locally during this mission. Unit tests cover
signed requests, replay/outcome handling, owner revocation, verifier signatures,
manifest restrictions, descriptor path escapes, destination matching and SNP ABI.
`crates/runtime/tests/server_lifecycle.rs` adds unprivileged guest-local process tests
for invalid frames, total read deadlines and SIGTERM cleanup of children/socket.

| Environment | Scenarios | Required evidence |
|---|---|---|
| Ordinary Linux | Protocol versions, malformed UTF-8/truncated/oversized frames, disconnect/read timeout, SIGTERM/SIGINT during idle/read/write | Listener survives client failure; authorized shutdown and socket cleanup |
| Policy fixture | Tampered signatures, wrong resource/boot/epoch, future/expired request, missing permission, duplicate/concurrent IDs, pending result after crash | No unauthorized effect and no duplicate launch; bounded results |
| Persistent guest state | Enrollment restart, second owner, rotation proof, revocation, changed resource binding, backward clock | Durable binding; old authority rejected; no local anti-rollback claim |
| NixOS VM with systemd >=257 | Missing namespaces/seccomp/controllers, immutable digest mismatch, root UID request, memory/PID pressure, wall deadline, forked descendants | Guard denies before target exec when mandatory protection fails; cgroup cleanup |
| Encrypted scratch volume | Wrong device/LUKS/fs UUID, missing broker, malformed/multiple/unsealed descriptors, quota unavailable/full, traversal/symlink/mount escape, busy unmount | Workspace inaccessible until authorized real mount; no key in logs/argv/config |
| Disposable key rotation fixture | Add replacement key, lost reply, retry with same ID, crash during update, explicit broker promotion | Old slot not removed implicitly; uncertain effects are reconciled |
| PTY guest | Sequence retry/partial write, cursor rewind/advance, resize bounds, buffer pressure, disconnect/reconnect, idle/TTL, failed stop | Bounded resources, no duplicated input, failed cleanup retains control handles |
| Controlled egress fixture | Exact host/port, suffix attack, private/mapped IPs, changed DNS, direct route attempts, parallel limit, gateway failure | Only approved pinned destinations reachable; no direct fallback |
| Credential broker fixture | Wrong scope/provider, forged/expired decision, wrong UID, expired lease, runtime crash | Protected credentials only, lease-bound teardown, no normal tool config secrets |
| Packaged inference engine | Wrong weight digest, wrong workload decision, delayed start, partial/invalid/slow health response, crash/stop, unavailable GPU | Actual load and HTTP readiness; no fabricated ready state |
| Restart fault injection | Kill before/after reservation, service submission and result commit; queued startup race; failed stop; runtime restart | Reconcile old owned services before admission; unknown results never auto-replayed |
| OTLP collector | Collector absent/slow/wrong peer UID, bad HTTP reply, memory pressure, missing GPU | Bounded best-effort export; numeric technical data only |
| SEV-SNP hardware | Fresh challenge/report-data, AMD chain/TCB/measurement, invalid firmware status, stale report, independent signed decision, attested key channel | Hardware evidence independently verified; no host boolean accepted |

Production acceptance requires recorded results on the exact reviewed commits and
image/kernel/systemd versions. Formatting, compilation and unit tests alone do not
satisfy hardware or isolation acceptance. Native SSH and GPU device access require
separate approved OS policies; neither is enabled merely by these PRs.
