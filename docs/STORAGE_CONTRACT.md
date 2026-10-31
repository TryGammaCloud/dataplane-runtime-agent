# Volume and workspace operations — experimental Linux backend

The signed policy may define `volumes`, indexed by ID, with expected `device`
(`/dev/disk/by-id/…`), `luks_uuid`, `filesystem_uuid`, `mount_path`
(`/srv/gammacloud/volumes/…`), non-root `uid`/`gid`, `quota_bytes` and `quota_inodes`.
Devices and mountpoints are provisioned externally; no implicit formatting occurs.

Signed operations `volume_unlock`, `volume_lock`, `volume_status`, `volume_rotate`
and `files` have separate permissions. Unlock and rotation require a current signed
verifier decision. Unlock verifies device identity, requests a sealed key descriptor,
opens LUKS2 through cryptsetup, verifies the inner filesystem UUID, mounts ext4 with
nosuid/nodev/noexec, configures kernel user quotas and creates an owner workspace.
A quota/mount failure prevents workspace availability. A busy unmount is an error;
there is no lazy unmount. Rotation adds a replacement key slot and never removes an
old key implicitly; external broker key promotion/retirement needs its own procedure.

## Local key broker integration

`/run/gammacloud/key-release.sock` must be served by a trusted guest-local root
service. Runtime verifies SO_PEERCRED and sends a four-byte big-endian JSON length,
then `{version:1,volume_id,key_version,request,decision}`. The latter two values are
the exact signed envelopes; `key_version` is `current` or `next`. Broker must
independently validate signatures, resource scope, current policy/revocation and
expiry, and acquire keys through an attestation-bound confidential channel.

Reply: byte 1 plus exactly one SCM_RIGHTS memfd descriptor containing 16–4096 key
bytes, sealed against write/grow/shrink and further seal changes. Other replies are
refused. Runtime never reads key bytes into a string, argv, environment or normal
file. The cryptsetup child inherits only the required key descriptors and receives
`/proc/self/fd/N` paths. Helper output and errors are not logged.

The broker and real SNP verification are external dependencies, not implemented or
simulated by Runtime. Without the broker, unlock fails closed. Signed decisions do
not replace the broker's independent policy evaluation.

## Workspace APIs

File operations use openat2 with BENEATH, NO_SYMLINKS, NO_MAGICLINKS and NO_XDEV;
unsupported kernels fail rather than falling back to lexical checks. Paths are
relative with at most 32 normal components. Read/write are UTF-8 and limited to
16 KiB per file/request. Writes create new files only (0600), directories are 0700,
chmod permits owner bits only, and deletion is nonrecursive. Symlinks can be removed
without following them; neither root deletion nor recursive destruction is exposed.

An internal helper executes file operations as the volume UID/GID with cleared
supplementary groups so kernel quotas cover API and workload writes. File contents
are returned only to the authorized caller, never logged or retained in the replay
journal. Replays of file-result requests return `result_not_retained` without
repeating effects. Runtime makes no claim of encrypted transport for the local API.

An execution template can name `volume_id`; its UID/GID must match. The backend
checks real mounted-device identity and quota state before binding only its workspace
into the isolated service at `/workspace`. Unavailable volumes prevent launch.

## Integration validation still required

OS must package cryptsetup/blkid, create trusted mountpoints, supply ext4 volumes with
kernel user quota support and install the guest-local key broker. No OS/Node source
was modified or built. Code passes formatting/Clippy; symlink/traversal tests are
prepared and compiled, not executed. Device unlock, quota pressure, busy unmount,
key rotation, recovery with already-open mappings and power-loss behavior require
VM tests. Existing mappings/UUIDs must be reviewed as part of device reconciliation.
