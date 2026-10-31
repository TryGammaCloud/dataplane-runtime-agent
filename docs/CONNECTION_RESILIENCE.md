# Development connection resilience

Each Unix connection handles one newline-terminated request. Wire content is
limited to 256 bytes, including an optional `V1 ` prefix, with LF or CRLF framing.
Incomplete, oversized and invalid UTF-8 requests do not execute commands.

Nonblocking reads and writes share a three-second total connection deadline.
Slow senders cannot reset it. SIGTERM/SIGINT set an atomic notification; poll waits
check it at most every 100 ms so the main thread can stop admission and clean up.
The listener remains sequential; concurrent admission control remains future work.

Connection failures are contained at the listener boundary. Workload operation
errors return `ERR operation-failed` without exposing OS error details. An accepted
`SHUTDOWN` still stops service if its response cannot be delivered.

Dropping the manager attempts process-group termination and reaps managed children,
including on listener errors or ordinary unwinding. Cleanup records exit status so
repeated shutdown does not signal already cleaned groups. This does not cover
SIGKILL, aborts or descendants escaping the process group. Cgroups and restart
reconciliation remain separate work. Previous signal handlers are restored on exit.

## Prepared regression checks

Unit scenarios cover a partial frame exhausting its total deadline,
incomplete/oversized frames, invalid UTF-8, operation failure
followed by health, and shutdown with a disconnected client. They are compiled by
Clippy but were not executed during this mission.

Additional Linux integration scenarios to execute later:

- Let a read time out, then verify another client can query health.
- Disconnect during a response, then verify the listener remains available.
- Drop a manager with an active fixed-profile child; verify termination and reaping.
- Repeat explicit cleanup followed by drop; verify no unrelated group is signalled.
- Send SIGTERM and SIGINT while idle and during an incomplete request; verify
  socket removal and managed child cleanup. SIGKILL is intentionally excluded.
- Verify unauthorized peers cannot execute shutdown or start operations.

Local validation: formatting, Clippy with warnings denied, and diff whitespace
checks. No test suite, NixOS build, deployment or release publication was run.
