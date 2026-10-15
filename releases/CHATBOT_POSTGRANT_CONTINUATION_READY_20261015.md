# Post-grant continuation — native qualification, 2026-10-15

The source candidate is **qualified in the listed native test environments**.
It is ready for current VPS preflight and a new exact HUMAN review. No new
target command has been executed from this workspace. CSV/chatbot E2E and
permanent runtime acceptance remain unproven.

Source: `0525c4186a5613000905ba4dfae6766827ad9f06` in
`codex/retained-inspection-channel-20261015`, draft/unmerged PR31. The release
is pinned to that commit; no moving branch is executed.

Capsule115: `c228da198b608f6bf8461bf73dfc283c59334aaa80b2f0308be09c010df43fce`.
Delivery launcher: `788b7381ab642effce7786b0ca5b07a575cc01069df51c7e13c584ddf18fbce3`.
Operator wrapper: `a0e3653a43c7bf9be1f0ccd886144f5f6036065ada1106cc954ffc2b0505017d`.

## Correction after the earlier qualified candidate

The previous source `2a122f1144579fe03d57c14e35452a8fbf6e0547` stopped on the
VPS at POSTGRANT_RETAINED_HISTORY_PREFLIGHT, before IAM and runtime authority.
The complete private bundle exceeded the independent IAM snapshot helper's
512KiB protocol limit. The retained-history reader now honors its explicit
8MiB artifact bound, preserving root custody, file mode, no-follow and stable
read checks. The separate IAM protocol remains unchanged. The actual complete
compiler bundle reproduces the previous failure and passes with this fix;
seven additional reader regressions cover bounds, custody, drift and JSON.
The earlier test set missed that compiler-to-reader boundary. See
`releases/CHATBOT_POSTGRANT_SNAPSHOT_BOUND_FIX_20261015.md` for the scope.

## Completed checks on the same source

| Qualification | Result | Run |
| --- | --- | --- |
| Complete native cohort, including7 continuation worker/review tests |319tests /42suites /0skip PASS|[38765374763](https://github.com/GioNob/ouf-deploy/actions/runs/38765374763)|
| Docker29.8.1 /overlayfs /systemd and real PostgreSQL contracts |25tests /4suites /0skip PASS|[38765374706](https://github.com/GioNob/ouf-deploy/actions/runs/38765374706)|
| Independent owner installer and closed imports |70tests /8suites /0skip PASS|[38765374890](https://github.com/GioNob/ouf-deploy/actions/runs/38765374890)|
| Online IAM /disposable real Keycloak |237tests /31suites /0skip PASS|[38765374883](https://github.com/GioNob/ouf-deploy/actions/runs/38765374883)|
| Native HUMAN authority and Ed25519 |PASS|[38765374785](https://github.com/GioNob/ouf-deploy/actions/runs/38765374785)|
| Governed legacy retirement |PASS|[38765374829](https://github.com/GioNob/ouf-deploy/actions/runs/38765374829)|

The new tests cover a spent first grant and cancelled zero-renewal worker,
fresh accounted TLS publication before admission, current HUMAN revocation,
partial initialization without reset, immutable predecessor history, copied
Registry history with current dual-role authority, no CREATE replay, global
reservation fencing, current source closure, complete review compilation and
real terminal approval. The shared owner installation module was restored
byte-for-byte; the new continuation belongs only to the full cohort closure.

Docker qualification additionally checks actual paused rootfs/proc inode,
runc ID/PID/bundle, nonroot/read-only/no-capabilities OCI policy and four exact
recursive read-only binds. It exercises native create/start/pause/unpause,
one SIGUSR1, HTTP readiness, restart-policy update, networks and retained rename.
Its HTTP program substitutes for Spring; non-Docker attestation/admission
boundaries remain explicitly simulated. Tests are not actual target acceptance.

## Current operator action

Use `scripts/launch-chatbot-postgrant-20261015.sh` from this evidence checkpoint.
The wrapper first selects the existing portable gh, checks the exact downloaded
launcher SHA, and reuses the qualified ZIP already on the VPS. It preserves the
current GitHub login. Its stdout/stderr is saved privately as `run.log` in the
new `ouf-postgrant-launch.*` directory. It does not install another gh or request
access credentials in chat.

The authenticated preparation now chooses the pinned post-grant path before
package extraction. It verifies the old expired/stopped process, fixed review,
consumed first grant, cancelled worker, current created Registry, five images,
APISIX generation, stopped producers, database/OID/closed admission/zero sessions,
backup archive, existing output inode and masked legacy writer before IAM login.
If these facts drifted, it stops before requesting IAM/browser/terminal approval.
The outer delivery still requires sudo to inspect protected facts. Existing IAM
sessions are reused when valid; otherwise its normal administrative and device
login prompts remain necessary. The final exact `APPROVO <new hash>` belongs to
the newly compiled complete review; no historical approval is reused.

Runtime continuation preserves all old journals/claims, credential, backup,
the four APPLIED phases and original Registry context/name. It reconciles the
already-created container without a new CREATE or image import. A distinct
worker starts with one retained cumulative grant and requires a newly accounted
grant to become active. No first-grant replay, credential rotation, DB rollback,
budget reset or automatic authority renewal is supplied. The finite window is
at most3600seconds with at most128 new worker grant attempts.

## After target execution

Inspect the safe live result and its retained status. COHORT_READY, health or
completed migrations do not prove CSV E2E. Actual target OCI/peer admission,
application health and service migrations must pass before the owner CSV flow.
Then use the preserved Teatri semantic proposal and HUMAN approvals, demonstrate
the source commit and fresh chatbot retrieval, and the governed same-content
MATCH/NOOP reuse. Preserve the existing8 Cinema ACTIVE baseline. No claim that
the remaining target path is guaranteed to succeed is made by these tests.

Full machine evidence is in
`evidence/chatbot-postgrant-continuation-qualification-20261015.json`. The earlier
draft continuation checkpoint and development failures remain preserved.
