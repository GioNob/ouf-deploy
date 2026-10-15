# Next chatbot/VPS action — 2026-10-15

Latest target evidence: evidence/chatbot-rootfs-entry-target-20261015.json.
The candidate exact OCI passes. Rootfs differences are fully classified:8,
all mount placeholders/ancestors and one directory link counter. The package
CI qualifier used different mount TARGETS from the reviewed retained request.
No shared image content drift is reported; no exclusions are allowed.

Read releases/CHATBOT_RETAINED_MOUNT_ROOTFS_FIX_20261015.md and
evidence/chatbot-retained-mount-rootfs-qualification-20261015.json.
Independent native CI38784418792/sourcea535e987 PASS with original image,
exact retained mount targets, same pre-Java gate and unchanged original sealer.
Its complete entry differences reproduce all8 target public projections.
Retained mount seal:9302entries,1719645735bytes,
a73d7520737345d67030baaa2405478b3784fc84060f6ec6ccc6109f98ac2f11.
Original package seal510f5643 remains retained, never overwritten.

Next target action is ONLY scripts/read-chatbot-retained-rootfs-proposal-20261015.py
from qualified source3b22669289c82e03d57743b48cf8be9e5e73ae9f. It binds the reviewed four readonly targets
and compares full OCI plus every image entry and exact new independent v1 seal.
It requires sudo only; no IAM/device/APPROVO, no private credential/token content,
signing, DB call, grant, journal/policy overwrite or runtime operation.

Current target state unchanged: six APPLIED, ATTEST IN_FLIGHT/v13, no signature
claim, same paused generation, cumulative2 grants/cancelled worker. Old authority
expired and old global continuation claim reserved. Do not replay old launcher.
Governed paused-attestation recovery is still NOT implemented: preserve all six
effects, backups/fence, original history/claims, account new worker after2, bind
changed recipe under fresh HUMAN finite approval and persistent fencing.
Actual full private frame/token/peer acceptance and CSV chatbot E2E unproven.

Reader CI38785161756/job116595159120 PASS:10 tests,0 skips; published bytes
verified. SHA25640df05f3522f5213a74e83fd2621bba314dea3b5c6a7f530bf2415fff36d8276.
Copyable VPS command: releases/read-chatbot-retained-rootfs-proposal-20261015.sh.
Await RETAINED_MOUNT_PROPOSAL candidateExactRootfsSeal and END. The historical
QUALIFIED_IMAGE_ROOTFS still compares against the old package mount profile;
its false is intentionally preserved and is distinct from the new proposal.
