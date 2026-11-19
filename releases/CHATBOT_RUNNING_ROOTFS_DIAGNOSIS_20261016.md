> Completed: the operator returned the bounded read-only diagnostic. See
> [the qualified running-rootfs recovery](CHATBOT_RUNNING_ROOTFS_RECOVERY_20261016.md)
> for the eight-entry result and new pinned handoff. This document retains the
> original diagnostic instructions as history.

# Running Registry rootfs mismatch: next action is read-only diagnosis

The VPS run of the backup recovery launcher from
`c6548b77d43ede821fe3ecd4b11bc5852db3eacf`, using runtime source
`eab913b879827c029d77fb5702e94b20aef386c7`, stopped before review and new
runtime authority with `PAUSED_INDEPENDENT_RETAINED_IMAGE_SEAL_DRIFT`.
The safe traceback identifies `current_paused_native`, line 195. Source
inspection confirms that this is the exact full image seal comparison.

The expected retained-mount seal was qualified before Java started. The newly
running Registry uses the same image and mount profile, but its filesystem
view after startup requires direct comparison. Startup writes are a hypothesis,
not a diagnosis or
permission to ignore differences. The previous 416 general tests, targeted
database tests and real token-mount tests did not reproduce this full running
Java rootfs comparison. They remain valid for their scopes, but they did not
prove target acceptance. The runtime recovery launcher must not be repeated
until this mismatch is understood and a separately qualified correction exists.

The diagnostic reader is pinned at
`a06e8c29d04a34ee2dd00989adfa218b0206686e`:
`scripts/read-chatbot-running-rootfs-diff-20261016.py`, SHA-256
`eb583060238dfb4a8685befde5895dbb187e39bf6b80c122aeabf79c0cc18fe8`.
The launcher downloads those exact bytes, checks their hash again as root and
executes a private root-owned copy with isolated Python. Its only filesystem
writes are its own temporary reader copy and diagnostic log. It does not issue
new runtime authority, touch retained records, stop/restart/pause the Registry,
call SQL/IAM, request tokens or repeat the dump probe.

The reader verifies the fixed review, authority, bundle, ten-effect Registry
journal, cancelled worker and five cumulative grants, other retained journals
and four original backup files. It checks that the new continuation claim is
still absent. It independently verifies the same running process and complete
OCI against the retained evidence. It scans the host image view, after excluding
private bind exposure, using the unchanged, hash-pinned v1 sealer functions.

The independent expected manifest is the 9302-entry retained-mount qualification
from run `38784418792`, artifact `11997695755`. The artifact and entries hashes
are verified, and replaying the entry stream reproduces the original retained
seal. No expected entry comes from this target. Two scans share a 180-second
budget; the reader has a 240-second outer deadline and no automatic retry.

Output distinguishes additions, removals, contents, mode, ownership, hardlink
count, symlinks and xattrs. Only names present in the independent CI manifest
may be printed. New target names, content hashes, contents, symlink targets and
xattr values remain private. Samples are capped at 60 while total counts are
retained. The two scans also report stability; no difference is accepted as a
new baseline. Backup and journal bytes and the native generation are checked
again before `END`. A changing file can safely stop the reader; that is useful
diagnostic evidence, not permission to relax custody or ignore the file.

Qualification: [run 38831063445](https://github.com/GioNob/ouf-deploy/actions/runs/38831063445),
job `116749699817`, **14 tests passed, zero skips**. Tests use the real frozen
sealer, private files, mutation and redaction checks, and a real hardened running
process. Target Docker/runc receipts in composition tests are explicitly
synthetic. The qualification has no VPS access and does not prove the target's
cause. The next required evidence is the output of the diagnostic launcher:
`scripts/launch-chatbot-running-rootfs-diff-20261016.sh`.

Continue autonomously after that output: identify the exact delta, distinguish
unexplained image/configuration drift from independently reproducible startup
effects, and qualify a specific correction. Preserve all prior signatures,
ten applied phases, five grant attempts, backups and the failed MCP claim. No
seal replacement with the observed hash, generic exclusions, old authority
extension, replay, reset, restore or new runtime mutation is authorized by this
diagnosis. `AGENTS.md` and resilience policy v3 remain applicable. A future
changed execution plan still requires its own complete fresh HUMAN review.
