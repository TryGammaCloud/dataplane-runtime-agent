# Authorized isolated execution — experimental OS backend

The signed `execute` operation selects an immutable `execution_templates` entry in
the OS trust policy. The caller supplies arguments, a filtered environment, working
directory and CPU/RAM/PID/runtime limits within that template's bounds. Empty or
missing template policy denies execution. Existing development smoke profiles remain.

The backend submits a transient **system** service through the NixOS-packaged
systemd-run binary. It configures cgroup limits, non-root UID/GID, empty capabilities,
no-new-privileges, separate mount/user/PID/network namespaces, a read-only root and
Nix store, private temporary directories/devices, seccomp, and a maximum lifetime.
All network traffic is initially denied by the private network namespace.
Elevated-privilege manifests are unsupported and rejected.

Systemd may omit unsupported sandboxing features. Consequently the runtime enters
its own `--isolated-child` guard inside the service before executing the customer
binary. The guard checks real namespace identities, UID/GID/groups, root inode,
NoNewPrivs, seccomp mode, empty effective/permitted/bounding capabilities, kernel
cgroup memory/swap/CPU/PID limits and the executable SHA-256. Failed verification
prevents the target executable from running. It does not prove kernel integrity.

OS requirements: systemd >=257 with seccomp support, unified cgroups v2 controllers,
Linux namespaces, and the runtime executable in an immutable Nix closure. Template
roots under `/srv/gammacloud/roots/` must be image-owned, contain the needed mount
points and expose the service's cgroup files read-only for guard checks. Template
executables must be immutable canonical `/nix/store/` paths with approved digests.
No fallback to an unisolated process exists when these requirements are missing.

Templates have `executable`, `sha256`, `root_directory`, nonzero `uid`/`gid`, and
`max_memory_mib`, `max_cpu_percent`, `max_pids`, `max_timeout_seconds` fields. Their
names and all configuration must be approved in the measured policy. Writable
persistent workspaces and networking are separate integrations; neither is enabled
by this increment. `TERM`, `LANG` and `LC_ALL` are the only caller environment keys.

The manager tracks the service unit separately from the systemd-run wrapper. STOP,
revocation and shutdown stop the service's whole cgroup, then reap the wrapper.
The wrapper caps each regular output file at 1 MiB. Admission reports `starting`,
not application readiness; engine-specific health probes remain separate.

Validation: formatting and Clippy with warnings denied pass. Resource/identity/env
refusal tests are prepared and compiled, not executed. Required VM scenarios include
missing systemd features, unsupported namespaces/seccomp, failed digest, memory/PID
pressure, timeout, escaped process groups and child cleanup. Until these have been
exercised on the actual guest image, this backend is experimental and not production
validated. OS and Node repositories are not modified by this PR.

References: [systemd.exec](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html),
[resource control](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html),
[systemd-run](https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html).
