# Code quality and annotations

Rust workspace standards:
- Four-space indentation, `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`.
- Use `//! ` for module intent and `///` for exported structs, enums, traits, functions and protocol messages.
- Describe protocol versioning, request/response semantics, error behavior and workload state transitions.
- Explain **why** a decision was made, not obvious control flow.
- Mark guest trust boundaries, dev-only unauthenticated vsock behavior, and unverified attestation clearly.
- Add tests for new protocol commands, invalid input and process lifecycle behavior.

Do not confuse documentation or linting with security certification.
