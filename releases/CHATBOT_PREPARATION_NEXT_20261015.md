# Next chatbot/VPS action — 2026-10-15, mounted-token recovery

The latest complete target metadata reader PASS is retained in
 evidence/chatbot-mounted-recovery-target-20261015.json.
It binds failed sourceb7d24c57/review2380132a/authority8c59697f and context
/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-d3ef7a038a6b587dde883e802080cb393732be9c4399f98e43a1a3ff6b3b2c2f.
Unitouf-file-cohort-d3ef7a038a6b587dde883e802080cb39.service is stopped/not-found.
Transition8cfb3760/v15: six APPLIED, ATTEST IN_FLIGHT, prior failed-intent marker
intact. Worker978c661b CANCELLED/attempts1/publication1/prior2/cumulative3;
session2c64588a; admissionc456b40b BLOCKED/v3. Claim e440b996 remains reserved.
Node contains only frame-policy, no issuance/acceptance. Same paused PID3484588,
container790c6274/restarts0. Four later journals have zero effects/backups.
Old authority was not expired at read; its stopped executor/cancelled worker
and blocked admission are preserved, never revived or extended.

Root cause is proven: the mount observer passed read-deadline(up to30s)+mount
minimum30s as token expiry, which cannot meet actual owner minimum90s. Core
lifetime fix c4fdc34f687553f1b02fcb79576a1e6562d395d0 passed six CI gates. It uses
retained publication expiry on BOTH clocks and unchanged actual online IAM.
Seven joined native readonly-mount/installed-owner/TLS tests pass; no lowering
of minimum90s, artificial expiry, publication, renewal or counter reset.

Fixed governed recovery v2 is implemented at source
e74cfc009fba1c142dc168fa86610358fd268842 on
codex/retained-inspection-channel-20261015 (draft PR31, no merge).
It preserves both previous failed intents and all six effects, old journal
and both old claims, backup/DB fence, exact image and native generation.
New fixed O_EXCL/inode/flock claim, current complete HUMAN review and a signed
worker sessionv3 retain prior3; first new TLS grant must become cumulative4.
No old worker/token adoption; no CREATE/STAGE/SIGUSR1, image import, retirement,
first grant, credential rotation or backup/fence replay. Full independent OCI/
rootfs preflight precedes IAM/device/terminal interaction. Existing complete
frame, token, peer, node-signing and later native application checks stay required.

Qualification PENDING at this checkpoint: all six same-source runs must PASS.
Runs:38796920463 cohort,38796920407 IAM,38796920559 Docker29.8.1,
38796920447 owner,38796920495 HUMAN/Ed25519,38796920382 legacy retirement.
Earlier sourcef66e69ca had actual fourth TLS grant/mounted admission PASS but
failed its complete-review TEST FIXTURE missing old-owner reference; it must
not be delivered. e74cfc00 fixes that reference and runs the six native v3 cases
before the long suites, including actual complete review compilation.
No runtime code/capsule changed by that test-only correction.

Exact candidate capsule0188d923fe197a6102097abc8b3af26a94e0175923a23fcca008801acd0b9e3d
117files/99runtime modules. LauncherSHA
72323604029b4ede41211a579e138ef6fcda03f8e396d1b67bdf251130118595.
Pinned operational wrapper is prepared locally as
scripts/launch-chatbot-mount-recovery-20261015.sh, SHA
929b278ef98f96c45560409347be586fa1f9ca1dea575c696ca0fca9f3edc751.
Publish it and the final qualification only after six gates pass; do not give
a target command while any gate is red/pending. User has no further readback
to perform now. Existing user downloaded qualified ZIP must be reused.

No new runtime authority issued by this development. E2E still unproven. After
actual cohort readiness use TEATRI_SEMANTIC_REUSE_REVIEW_20261014.md for actual
source HUMAN approval, COMMIT rather than ACK, UDP lineage, fresh chatbot search
and same-content canonical NOOP/reuse; preserve existing Cinema baseline.
