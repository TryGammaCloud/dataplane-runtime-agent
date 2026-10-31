# Interactive sessions and packaged agents

Signed operations now create/read/write/resize/close real PTY sessions. A session
requires a current verifier decision, an approved execution template and a mounted,
quota-controlled workspace. The same isolated systemd service and in-guest guard
apply as for noninteractive execution. No direct `/bin/sh` fallback exists.

At most eight sessions are live. Each uses a random 128-bit ID, an explicit TTL up
to the manifest runtime limit (and 3600 seconds), and a 120-second idle timeout.
The listener periodically expires sessions; owner rotation, revocation and verifier
decision expiry stop sessions and managed services. Terminal disconnection does not
immediately destroy a session: the owner can reconnect within its idle/TTL window.
Explicit close stops the job's cgroup and closes the PTY. Session output is never a
technical log event or a replay-journal payload.

Reads accept an acknowledged byte cursor. Output is retained in a bounded 1 MiB
buffer until acknowledged, with at most 8 KiB returned per poll as hex bytes. Once
full, kernel PTY backpressure applies. Writes use a monotonically advancing sequence,
hex bytes up to 8 KiB and an explicit accepted-byte count. A repeated last sequence
with identical input does not inject the same bytes twice. Short writes require the
caller to submit remaining bytes at the returned sequence. Resize bounds rows and
columns to 1–1000. Workload status exposes the associated job exit code.

`development_agents` in the trusted policy maps approved tool names to `{template,
version}`. `agent_launch` selects that template instead of trusting a caller-supplied
executable. Supported names resolve through the existing OpenCode/Codex/Claude Code/
Qwen Code/Goose catalog. The OS installs/version-pins tools and public provider
configuration. A GammaModels-compatible endpoint can be configured in that approved
template root; no service credential is written by the session API. Runtime does
not implement these tools or download them.

Native SSH provisioning is still a separate OS integration: no unverified SSH key
installation endpoint has been exposed. The PTY API is usable over the authorized
local channel; production remote access still needs the attestation-bound encrypted
transport described in the protocol contract.

Validation: code and test targets compile through Clippy; tests are not executed.
VM scenarios to validate: PTY resize and terminal input, slow readers, buffer limits,
short/repeated input, disconnect/reconnect, expiry, owner rotation and service cleanup.
The backend requires actual NixOS-packaged runtime/tools/systemd and unlocked volumes;
no end-to-end shell success is claimed on the development host.
