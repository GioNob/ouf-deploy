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

Fixed governed recovery v2 is implemented at current source
43819bc04dc40daaf119a2098945405f42d7bc6f on
codex/retained-inspection-channel-20261015 (draft PR31, no merge).
It preserves both previous failed intents and all six effects, old journal
and both old claims, backup/DB fence, exact image and native generation.
New fixed O_EXCL/inode/flock claim, current complete HUMAN review and a signed
worker sessionv3 retain prior3; first new TLS grant must become cumulative4.
No old worker/token adoption; no CREATE/STAGE/SIGUSR1, image import, retirement,
first grant, credential rotation or backup/fence replay. Full independent OCI/
rootfs preflight precedes IAM/device/terminal interaction. Existing complete
frame, token, peer, node-signing and later native application checks stay required.

Qualification COMPLETE on source43819bc04dc40daaf119a2098945405f42d7bc6f.
All six native GitHub CI gates PASS on attempt2, each deliberately rerun ONCE
after owner made repository public. Full logs read, zero skips:
- Cohort38799875475/job116648805489:356tests/48suites.
- IAM38799875567/job116648945842:250tests/33suites plus actual disposable Keycloak.
- Installation38799875577/job116648950234:70tests/8suites.
- Docker29.8.1 38799875436/job116648955937:25tests/4suites.
- HUMAN authority38799875533/job116648964216:66tests/9suites.
- Retirement38799875681/job116648967135:44tests/4suites.
Joined actual readonly mount/signed owner/TLS, third-history/fourth-grant/full
v3 review, both failed-intent preservation, original native DB migration/dump,
Gateway replacement and ACK/COMMIT/canonical NOOP fixtures pass.
These fixture results are NOT actual target private-frame/CSV acceptance.

Source43819bc0 changes ONLY six workflows relative to f2e70ae8: five formerly
unrestricted push triggers now target main only; native authority was already
main-only. All jobs, commands, permissions and path filters are identical.
Per-workflow/PR concurrency cancels superseded qualification. Local YAML/job/
permission/path comparisons PASS. No required check removed. Production
capsule/launcher bytes unchanged. All117 capsule file hashes checked locally.

Prior f2e70ae8/initial43819bc0 jobs were rejected before runner assignment.
The user supplied GitHub's account payment/spending-limit annotation, then
chose public visibility. Public visibility and all six actual runner starts
were verified. No billing limit/payment/visibility setting was changed by the
agent. The exact original annotation and failed dispatches remain in evidence.
No native VPS execution, new grant or authority issued during development.

Public-disclosure review remains LIMITED:1550 tracked blobs;259 local tracked
files scanned with known key/GitHub/AWS-token patterns, zero matches. Generated
local disposable test keys are untracked. No complete history/artifact audit;
do not certify all public history secret-free.

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

Next action: deliver the published exact wrapper to the user for ONE actual
VPS invocation. Source43819bc0 is qualified by all six native CI gates. Wrapper
SHA378fc7e4bbac39be2c213e841fda06590b02b91b899d5a34a4a74092dfca8100
pins source43819bc0, launcherSHA72323604 and capsuleSHA0188d923; reuses existing
ZIP144699ab. On VPS it validates exact retained history and full native OCI/
rootfs BEFORE administrative/device/terminal interactions. Explain four possible
operator steps (sudo, Keycloak admin if needed, fresh device code, exact APPROVO
review). Later application-domain HUMAN links are printed explicitly. Preserve
private run.log and finite detached process evidence if the phone disconnects.
No new readback, first-grant/replacement replay or automatic rerun is requested.
At this checkpoint user execution is NOT confirmed; do not assume it occurred.

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
378fc7e4bbac39be2c213e841fda06590b02b91b899d5a34a4a74092dfca8100.
Wrapper and final qualification are now published after all six gates pass.
The user has no further diagnostic readback to perform now. Existing downloaded
qualified ZIP must be reused. No target command execution confirmed.

No new runtime authority issued by this development. E2E still unproven. After
actual cohort readiness use TEATRI_SEMANTIC_REUSE_REVIEW_20261014.md for actual
source HUMAN approval, COMMIT rather than ACK, UDP lineage, fresh chatbot search
and same-content canonical NOOP/reuse; preserve existing Cinema baseline.
