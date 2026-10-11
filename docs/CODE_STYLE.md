# GammaCloud code style and documentation

This convention applies to all new and modified source files in this repository.

## Formatting

- Use **four spaces** for indentation. Never align code with manual tabs.
- Rust: run `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings`.
- Python: follow PEP 8; use four spaces and standard-library-compatible type hints.
- Keep functions focused, names descriptive, and error handling explicit. Do not reformat unrelated code in feature changes.

## Documentation comments

- **Rust `//!`**: document module purpose, boundaries and invariants at the top of each module.
- **Rust `///`**: document public types/functions and non-obvious internal APIs; include `# Security`, `# Errors` and `# Panics` only when applicable.
- **Python docstrings**: use module and function docstrings explaining arguments, return values, exceptions and security properties when relevant.
- **Inline comments**: explain *why* a decision exists or what invariant must be preserved, not what the next line obviously does.
- Use uppercase comment labels sparingly and consistently: `SECURITY:`, `POLICY:`, `LIFECYCLE:`, `RESOURCE LIMITS:`, `COMPATIBILITY:`.
- Keep comments accurate when behavior changes. Never claim hardware attestation, confidentiality or production safety without verified evidence.
- Write source comments in **English**; product/project communications may be in French.

## Examples

Rust:

```rust
//! Guest-side execution policy.
//! A local Unix identity check does not authenticate a remote host.

/// Validates the caller before allowing a local operation.
///
/// # Security
///
/// The caller UID is only a guest-local authorization signal.
fn authorize_local_peer(&self, peer_uid: u32) -> bool {
    // SECURITY: Reject every principal not explicitly permitted by policy.
    peer_uid == self.allowed_uid
}
```

Python:

```python
def verify_release(reference: str) -> None:
    """Reject unsigned or unapproved release references.

    Raises:
        ValueError: If the reference is not allowed by local policy.

    Security:
        Image-signature verification is not hardware attestation.
    """
    # POLICY: Never resolve a mutable tag when an immutable digest is required.
    validate_digest(reference)
```

## Review checklist

1. Formatting, linting and tests are green on the exact PR head commit.
2. Security-sensitive functions document trust boundaries and failure modes.
3. No misleading claims about SEV-SNP, remote identity or secret release.
4. Comments match actual behavior and tests cover changed logic.
5. A passing CI run does not substitute for security or integration review.
