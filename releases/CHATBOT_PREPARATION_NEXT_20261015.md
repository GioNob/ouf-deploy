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

Qualification BLOCKED by a confirmed GitHub account billing/spending-limit gate.
The user supplied the exact GitHub annotation for source f2e70ae8:
"The job was not started because recent account payments have failed or your
spending limit needs to be increased. Please check the 'Billing & plans'
section in your settings". This does NOT distinguish payment failure from
quota/budget exhaustion. That candidate's six jobs never started a runner.

Current source43819bc04dc40daaf119a2098945405f42d7bc6f changes ONLY six CI workflows:
five formerly unrestricted push triggers are restricted to main; the existing
main-only native-authority trigger stays main-only. All six retain identical
jobs, test commands, permissions, pull-request paths and push paths. Each now
cancels superseded runs of the same workflow/PR (or branch). Structural YAML
and exact job/permissions/path comparisons PASS locally. No required test is
removed. The PR-triggered six checks failed at dispatch while the repository
was still private; no manual rerun was requested. Current whole-cohort
qualification remains incomplete. Capsule/launcher/production bytes unchanged.

The user chose to make the repository public. Visibility last observed private;
the agent has NOT changed visibility, payment details, budgets or spending caps.
Official GitHub docs state standard hosted runner usage is free for public
repositories; larger runners remain billed. These six use ubuntu-24.04 standard
runners. All five pinned peer repositories are already public. A payment lock
can still require account intervention; do not promise visibility alone fixes it.
No target runtime command delivered and no new VPS authority/mutations.

Public-disclosure review is LIMITED: tree has1550 tracked blobs;259 locally
readable tracked files scanned with known private-key/GitHub/AWS token patterns,
zero matches. Generated disposable local test keys are UNTRACKED. No full
repository/history/artifact disclosure audit was performed; do not certify the
repository secret-free or alter its visibility on that basis.

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

Next action: read repository visibility after the user's change. If public,
rerun the current cohort check once to establish runner availability, then
qualify the remaining required checks on the SAME current source. If dispatch
still reports the account billing gate, stop reruns and report that exact gate.
No new source edits solely to cause reruns; no VPS test as a substitute for CI.
No new IAM/device/HUMAN approval or diagnostic command is requested now.

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
