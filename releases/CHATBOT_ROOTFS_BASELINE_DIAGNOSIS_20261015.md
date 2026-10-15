# Frozen Registry rootfs baseline diagnosis — 2026-10-15

The owner target readback at19:43 CEST completed all checks without mutation.
Candidate24d36d23 independently derives the exact COMPLETE observed OCI. The36
environment rows have the same names and values and now the same order; fresh
network namespace expectation and kernel sandbox binding pass. This fixes the
previous expected-policy defect on the actual target, without accepting it.

The next independent image seal differs:9302 entries and1719645735 bytes were
read from the host image view; no credential/token bind content was read. The
original seal and native journals were retained. This digest alone cannot
identify whether content, directory topology, mode, ownership, links or xattrs
differ. No rootfs policy may be weakened or replaced with the target digest.

Code inspection shows the package seal was generated using the CLASSIC Docker
MergedDir, while target runtime uses containerd overlayfs. Prior project
diagnostics documented directory link-count differences between filesystems;
that history is a hypothesis here, not evidence about this image.

The new CI workflow uses the exact retained semantic part artifact11907831957
from original successful run38584614991, archive digest5d28e55ca5541efadec4b93a6396c8f84d21e6db92766b785b1cd8c3fd10db09.
It does not rebuild images. Two disposable Docker29.8.1 engines (classic and
containerd) load these image bytes, create the same four synthetic mount
targets, start only the nonroot pre-Java shell gate, pause, and compute the
unchanged original v1 seal twice. Each canonical entry is retained in a CI
artifact for diagnosis. No JVM release, target operation or acceptance occurs.

Four local tests prove exact sealer stream replay, immutable original code
verification, file drift detection and artifact hash rejection before output.
Native CI results must be inspected before interpreting the target difference.
This is a bounded experiment (15min/job,180s/scan), not a new target launcher.

The target remains transitionv13/nextPhase6 with six APPLIED effects and unsigned
ATTEST IN_FLIGHT, same paused PID3484588, cumulative2 grants and cancelled worker.
Its old finite authority has expired. No current paused-attestation recovery
profile is implemented; do not replay any earlier installer or remove claims.

## Native outcome

Run38781095495 at source36861be786b5fcae853b116a35d406bf961705cb
completed both real image-store jobs successfully. Each ran the four source/
stream tests and sealed the original image twice. Both EXACT v1 seals match
the original package:9301 entries,1719645735 bytes,
510f56436da3e36b700b244e5e2476db9d4984216866e412b0484f951bfdb8a2.
The store-only explanation is REFUTED for these tested inputs; no normalization
or seal-policy change is warranted. Target count9302 differs by a net one entry,
with equal byte total; that does not prove that only one field/entry differs.

The new fixed read-only reader scripts/read-chatbot-rootfs-entry-diff-20261015.py
embeds the complete independent CI entry manifest. Before comparing it with
target records, it replays the exact original ordered v1 stream and requires
equality with the retained reviewed package seal. The unchanged original
sealer captures target entry records without exclusions. It compares every
entry/field, reports total counts with at most40 public metadata/path samples,
and suppresses content, hashes, xattr values and link targets. Host subordinate
mounts and exposure of private bind inodes are denied before content scan.
No signing/approval/grant/runtime recovery is attempted. Eight local reader
cases passed, including the entire main handoff (two I/O boundaries mocked),
real original sealer/capture and private-view refusal (procfs mocked because
not present in this workspace), exact full CI manifest replay, drift/privacy,
baseline tamper and sample truncation. These are not target/E2E acceptance.

Initial native experiment809e95e1 failed at the pre-Docker test fixture because
GitHub runner-owned ancestors correctly failed the sealer's root-owned path
requirement.36861be7 moves those tests into a root-owned disposable fixture;
the trust check and original sealer remain unchanged. Both native profiles
then passed. Preserve this failed experiment as development history.

Reader CI run38782162247/job116584868336 at exact source84271d380d414a2fe211ac78f71c28b06d9e0e11 passed all8 cases, zero skips. The published reader was fetched and compared with the local exact bytes (SHA256dbdcd40d90a2c5294623bc8777c1584d01a8704477e85004a1de362dad25c1bb). No target difference is yet inferred from these tests.
