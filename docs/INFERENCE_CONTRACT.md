# Generic inference engine contract

Signed `model_start` accepts an ID, an approved execution manifest, weight artifacts
(relative path and SHA-256), and a loopback HTTP health port/path. Only the Models
product admits model starts. The OS template specifies the immutable engine binary
and a `model_directory` under `/srv/gammacloud/models/`, bound read-only at `/models`.
Runtime checks canonical paths, ownership, permissions and actual weight bytes
before launch. Artifact preparation/download/attachment belongs to the model supply
pipeline; an unavailable local artifact fails admission instead of being invented.

The verifier decision now also carries `workload_digest`: lowercase SHA-256 hex of
the compact serde JSON manifest. For execute/session/agent operations this covers the
normalized ExecutionManifest (after selecting an approved agent template); for model
start it covers the entire InferenceManifest, including weight digests and health
configuration. The checked manifest is bound to the signed guest/image/owner/boot/
policy decision. A decision for another workload cannot launch this one. Effective
runtime limits may only shorten the approved manifest's lifetime.

Runtime supervises the preinstalled engine using the shared isolated execution
backend. Start reports `starting` with a job ID. `model_status` probes the actual
engine's loopback health endpoint in its network namespace through a bounded helper;
only an HTTP 2xx response reports ready. It also returns current process status.
`model_stop`, revocation, expiry and shutdown stop the service cgroup. Runtime does
not implement inference requests, tokenization, vLLM or model-specific argument logic.

The dataplane-inference repository must define/pin engine packages, compatible CLI
arguments, weight layout, required GPU devices if any, and readiness semantics. The
current strict template does not expose GPUs; GPU/device policy requires separate
review and real hardware validation. No arbitrary privileged device access is enabled.

Validation: formatting and Clippy compile all targets. No engine, VM or test suite
was run. Required scenarios: missing/tampered weights, wrong manifest decision,
engine crash, failed/slow health, stop during startup, model-ID conflicts and resource
pressure. The runtime supplies real supervision/probing code but no successful model
load is claimed until an actual packaged engine and guest image exercise the path.
