# Enforced egress and temporary credentials

Every isolated workload retains a private network namespace. No default route to
outside services is introduced. An optional per-template `egress` policy creates a
private Unix CONNECT gateway outside that namespace and binds only its socket into
the service. An unprivileged sidecar exposes an HTTP CONNECT proxy on namespace-local
127.0.0.1:18443. Runtime sets HTTPS_PROXY/ALL_PROXY to that proxy; ignoring those
variables does not provide a direct-route bypass. Direct TCP traffic remains confined
to the private namespace.

`egress.destinations` contains exact `{host,port,addresses}` entries. Each address is
an explicitly approved IP; Runtime does not perform DNS resolution. This avoids
unbounded resolver waits and DNS rebinding. Hosts are compared exactly, never by
prefix. Private/loopback/link-local addresses are refused unless the trusted policy
explicitly sets `allow_private_addresses`. Changed destination addresses require an
approved policy update. Gateway sockets are individually bound into each service;
SO_PEERCRED must match the approved workload UID. Gateway admission is limited to
eight connections per workload, bounded headers and explicit lifetimes. TLS stays
end-to-end; no full Monitor server or TLS interception is implemented.

Template `credentials` maps a credential filename to `{reference,scope,lifetime_seconds}`.
A guest-local broker independently validates the original signed request and current
verifier decision, then returns a sealed descriptor (same SCM_RIGHTS protocol as
volume keys, with `purpose=credential`, reference in `volume_id` and scope in
`key_version`). No value is read into argv, environment or ordinary tool config.
Systemd LoadCredential copies the descriptor into the service's protected runtime
credential directory. Tools must support credential files or an OS-packaged adapter.
The runtime limit is shortened to both the verifier decision and credential lease
lifetime. Revocation/expiry tears down the service; there is no automatic renewal.

The broker must authorize scope/provider and the requested lease independently; the
runtime does not mint service tokens. Without the broker, credential-bearing
workloads fail admission. LoadCredential source descriptors stay alive until service
cleanup and are closed on stop/shutdown. Broker integration and expiry tests remain
required; no successful remote key release is claimed.

Prepared tests cover exact host/port matching and rejection of private/mapped-private
addresses. Formatting and Clippy pass; no tests or networking services are executed
by this mission. VM integration must verify direct-route denial, proxy startup,
concurrent limits, shutdown, template separation, TLS validation and credential
lifetime. The backend remains experimental pending those checks.
