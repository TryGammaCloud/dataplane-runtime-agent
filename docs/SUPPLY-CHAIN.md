# Runtime supply-chain evidence

The release workflow builds both Rust binaries, creates a SHA-256 manifest and SPDX SBOM, and requests GitHub OIDC-backed build-provenance and SBOM attestations for the release tarball.

The archive is currently a GitHub Actions artifact with 30-day retention, not a durable public release. This is a development pipeline, not a reproducible build or hardware attestation. The SBOM scanner may not enumerate every Rust dependency.

A verifier must check the artifact digest, signer workflow identity and an explicitly approved source commit. GitHub attestation alone is not proof that a CVM is executing this binary. Production requires a separate hardware report and an authorized measurement policy.
