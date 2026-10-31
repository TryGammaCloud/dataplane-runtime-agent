# Resource reporting and restart recovery

Signed `metrics` returns numeric CPU usage, memory current/peak, PID count, elapsed
runtime, active terminal count and mounted-volume disk usage. Isolated jobs read
actual cgroup v2 files; unavailable measurements are null rather than fabricated.
Optional GPU sampling uses the OS-packaged nvidia-smi with bounded numeric-only
output; missing collectors report unavailable. Development jobs without cgroups do
not claim cgroup consumption. Measurements are snapshots, not billing-grade usage.

An OS policy `export_telemetry: true` enables periodic OTLP/HTTP JSON metric export to
root-authenticated `/run/gammacloud/otel.sock`. No prompts, file contents, credentials,
customer argv or raw helper errors enter exports. Failed export is best effort;
there is no unbounded queue or dependency on a reachable external collector. The OS
collector owns downstream delivery/authentication. Commercial pricing remains outside
Runtime. Lifecycle logs contain fixed event names only.

Before submitting a systemd service, the runtime fsyncs a service registry entry
containing only its generated unit name, manifest digest and observation time.
Signed-mode startup reconciles entries before command admission: stop remembered
services, remove only successfully reconciled records, and fail startup on ambiguous
state. Unit names are validated so a corrupted record cannot name arbitrary OS
services. Pending writes precede spawn and can be removed during startup.

The service binds to `gammacloud-runtime.service`; its wrapper also has a parent-death
signal. OS must keep the runtime under that service and preserve state across runtime
restarts. Workloads are stopped on recovery, never silently resumed with old authority.
PTYs are ephemeral and closed; mounted volumes are checked against kernel/device/
quota state before reuse. A new random boot nonce invalidates old signed requests.
New attestation is required before new isolated execution or workspace access.

Request reservations/results remain durable. Signed `request_outcome` can inspect
an earlier ID without replaying its effect. A missing completion is `outcome_unknown`.
File/log/terminal contents are deliberately not retained; their replay result is
`result_not_retained`. Old successful results can refer to jobs that recovery stopped;
clients must reconcile status before deciding what to launch next.

Authorization rejects backward wall-clock movement observed within a boot. Verifier
leases also have monotonic deadlines. An independent lease thread stops services even
if the main loop is busy, and the in-service guard rejects launches after the absolute
boot-time deadline. Systemd enforces its runtime/teardown limits as another bound.
Disk snapshot rollback remains outside this local journal's guarantees and needs an
external epoch/revocation authority before production.

OS integration prerequisites: writable private StateDirectory for
`/var/lib/gammacloud/runtime` (the existing development ProtectSystem=strict unit does
not supply it), packaged helpers, cgroup controllers and reviewed service properties.
These are contracts, not OS source changes or a successful deployment.

Validation: formatting, Clippy and compilation checks; no test suites executed.
Prepared tests include strict registry-unit validation. Remaining integration cases:
crash before/after spawn and result commit, queued service start during crash,
SIGKILL/restart, failed service stop, stale owner policy, clock rollback, quota/mount
reconciliation, collector absence and GPU absence. No production recovery or hardware
confidentiality guarantee is asserted without those demonstrations.
