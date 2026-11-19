# WP2 lifecycle component — qualification boundary

The lifecycle adapter reserves every native mutation durably before calling the
custodied Engine. A returned CID is persisted before post-create validation; a
lost response without a durable CID stays UNKNOWN and cannot be rediscovered by
name or created again. First-process proof and restart restoration bind that CID.
Predecessors stay retained, stopped/detached/renamed before replacement creation.

The generated key is resolved only in memory from its own proven inode. Private
journal metadata includes final mtime/ctime as well as ownership/mode/size, so an
in-place change followed by restoring0400 does not replace the generated value.
No value or credential hash is emitted in journal evidence or public proof.

This is still a component: current DB/Owner/generation admission, image import,
Gateway HTTP, issuer and complete immutable entrypoint need full Ports integration.
The new tests use real Ed25519 role signatures and real private CAS/key custody,
with synthetic Engine responses; existing actual Docker comparison/namespace
qualification remains separate. No full G2 or runtime authority is claimed.

Local syntax checks passed. Native UID tests in the restricted CLOUD workspace
stopped at fchown(10002,10002) with EINVAL; that environment cannot qualify numeric
key ownership. The unchanged fail-closed check is exercised on the existing real
root GitHub runner. No local ownership check was mocked or relaxed to obtain PASS.
