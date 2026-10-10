# Development guest lifecycle (NOT production confidential computing)

Run from the repository root on Linux:

```bash
cargo fmt --all
cargo test --workspace
cargo build --workspace
export GAMMACLOUD_RUNTIME_SOCKET="$(mktemp -u /tmp/gammacloud-runtime.XXXXXX.sock)"
cargo run -p gammacloud-runtime &
RUNTIME_PID=$!
sleep 1
cargo run -p gammacloud-boot
python3 - <<'PY'
import os, socket
s=socket.socket(socket.AF_UNIX)
s.connect(os.environ["GAMMACLOUD_RUNTIME_SOCKET"])
s.sendall(b"STATUS\n")
print(s.recv(512).decode().strip())
s.close()
s=socket.socket(socket.AF_UNIX)
s.connect(os.environ["GAMMACLOUD_RUNTIME_SOCKET"])
s.sendall(b"SHUTDOWN\n")
print(s.recv(512).decode().strip())
s.close()
PY
wait "$RUNTIME_PID"
```

The socket is local, owner-only (0600), and is not a host-to-guest transport.
Do **not** mount it into untrusted workload containers. Local access to the
socket grants shutdown capability. There is no remote authentication, TLS,
workload execution, SEV-SNP attestation, or secrets release in this iteration.
The boot binary probes an already running runtime; process supervision and
NixOS systemd integration are future work.
