# Raw SEV-SNP evidence adapter — hardware validation pending

Signed `evidence` accepts a verifier-provided 32-byte challenge encoded as lowercase
hex. Runtime builds a deterministic JSON context binding the challenge to
organization/project/sandbox/guest, current boot nonce, owner key/epoch, declared
image digest, workload identity and policy version. REPORT_DATA is SHA-512 of the
context prefixed by `gammacloud.runtime.snp-evidence.v1\0`.

A bounded helper opens the actual Linux `/dev/sev-guest` character device and issues
SNP_GET_REPORT with message version 1 and VMPL 0. The adapter follows the Linux UAPI
request/response/ioctl layouts, with zeroed reserved fields. Driver/firmware errors
produce `evidence_unavailable`; no environment or host boolean can fabricate success.
The raw 4000-byte response and report-data bytes are returned as hex with
`verified:false`. The independent verifier must parse the firmware response, validate
AMD signature/certificate chain, TCB/policy/measurement and challenge/report-data
binding before issuing a decision. The runtime does not reinterpret ioctl success
as valid hardware attestation.

This adapter is implemented but has **not** been exercised on SEV-SNP hardware. ABI
size/context-binding tests are prepared and compiled, not executed. Non-SNP guests
fail when the device is unavailable. Certificate retrieval, AMD endorsement policy
and attested channel encryption belong to independent verification/channel services.
Declared image strings in report data are context claims, not substitutes for the
hardware launch measurement. No secret is released by evidence collection itself.

Sources: [Linux guest API](https://docs.kernel.org/virt/coco/sev-guest.html) and
[Linux UAPI header](https://github.com/torvalds/linux/blob/master/include/uapi/linux/sev-guest.h).
