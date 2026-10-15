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
f2e70ae8ccce848eff3fed3d9b95f535af8b3e18 on
codex/retained-inspection-channel-20261015 (draft PR31, no merge).
It preserves both previous failed intents and all six effects, old journal
and both old claims, backup/DB fence, exact image and native generation.
New fixed O_EXCL/inode/flock claim, current complete HUMAN review and a signed
worker sessionv3 retain prior3; first new TLS grant must become cumulative4.
No old worker/token adoption; no CREATE/STAGE/SIGUSR1, image import, retirement,
first grant, credential rotation or backup/fence replay. Full independent OCI/
rootfs preflight precedes IAM/device/terminal interaction. Existing complete
frame, token, peer, node-signing and later native application checks stay required.

Qualification BLOCKED: source f2e70ae8ccce848eff3fed3d9b95f535af8b3e18 has six
GitHub job failures WITHOUT RUNNER START (runner_id0/empty steps, no logs).
Cohort run38798031552/job116639479918; check-run has one annotation, but this
connector cannot read the /check-runs/.../annotations endpoint. Its summary/
text fields are null. The actual reason is NOT established. Billing/quota is
possible but must not be asserted without the annotation. No rerun requested,
no spending/settings/visibility changes and no target runtime command delivered.

Earlier source e74cfc00: actual joined mount/owner/TLS step PASS and all six
native v3 worker/history/fourth-grant/full-review cases PASS. Five companion
checks PASS. Whole cohort run38796920463 failed ONE legacy terminal-summary
fixture using synthetic-postgrant rather than the actual supported profile.
Source f2e70ae8 changes ONLY that test: uses actual old profile and adds the new
three-grant summary case; all9 terminal tests PASS locally. All production
capsule/launcher bytes remain identical to e74cfc00. The complete cohort must
still finish before runtime delivery; no claim of all-six-gate qualification.
Earlier f66e69ca failed another test fixture's missing old-owner reference,
corrected at e74cfc00. Never deliver either failed source as qualified.

Next required user intervention: open the specific GitHub job and report its
single annotation: https://github.com/GioNob/ouf-deploy/actions/runs/38798031552/job/116639479918.
No VPS action or new IAM/device/HUMAN approval is requested. After the runner
block is understood/resolved, qualify the exact f2e70ae8 source; use existing
rerun-job capability with bounded deliberate requests, not new source changes
or repeated target attempts to work around unavailable CI.

Local extra validation: complete closed-source imports3 PASS, launcher14 PASS,
signed two-failure recovery5 PASS, legacy paused recovery9 PASS, postgrant9 PASS,
terminal9 PASS. Additional selected local suites pass; native systemd journal
and missing peer-source cases are environment limitations, NOT locally passed:
process-native(no systemd journal); target-selection(missing pinned picker);
Gateway/Gateway-runtime(missing peer compiler); authorization(missing peer env).
Hosted qualification remains necessary for those and actual group custody.

Exact candidate capsule0188d923fe197a6102097abc8b3af26a94e0175923a23fcca008801acd0b9e3d
117files/99runtime modules. LauncherSHA
72323604029b4ede41211a579e138ef6fcda03f8e396d1b67bdf251130118595.
Pinned operational wrapper is prepared locally as
scripts/launch-chatbot-mount-recovery-20261015.sh, SHA
c3e0e5975535d8c420d1a68035a85db663b7ad0ec85f4fc9a68d2a3b82761fd1.
Publish it and the final qualification only after six gates pass; do not give
a target command while any gate is red/pending. User has no further readback
to perform now. Existing user downloaded qualified ZIP must be reused.

No new runtime authority issued by this development. E2E still unproven. After
actual cohort readiness use TEATRI_SEMANTIC_REUSE_REVIEW_20261014.md for actual
source HUMAN approval, COMMIT rather than ACK, UDP lineage, fresh chatbot search
and same-content canonical NOOP/reuse; preserve existing Cinema baseline.
