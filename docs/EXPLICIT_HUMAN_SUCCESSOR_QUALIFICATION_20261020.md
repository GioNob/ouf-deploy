# Expired READY HUMAN successor: qualification candidate

This separate pre-runtime package handles an expired, unambiguous READY session
without replaying the completed Owner7/publication7 actions or the old login
recovery claim. The current installation's retained count is 278/288; these
numbers are reviewed history inputs, never reusable installation defaults.

The current Matrix1.7/Blueprint0.3 baseline and repository AGENTS govern this
work: development authorization does not grant runtime HUMAN/THS authority;
expired authority cannot be extended automatically. This candidate introduces
no call from the existing native executor and does not change its 114 sources.

## Contract

The public review selects one retained root-custodied private journal, its exact
binding, source closure and completed owner plan/result history. It requires an
expired READY window on both recorded clocks and an expired recorded bearer.
It neither opens the predecessor bearer file nor copies credentials. Journal
content remains private; credential values and credential hashes are not
printed. Every installation identity, path, issuer and scope comes from the
reviewed input. No host discovery or issuer fallback is permitted.

Only a fresh, explicit terminal decision can initialize one separate finite
7200-second session. The fixed predecessor claim is consumed before directory
creation. A crash leaves the claim consumed and requires reconciliation. The
predecessor journal and cumulative maximum are retained; the successor starts
at the actual retained count, never zero. Initialization itself sends no OAuth
request and issues no runtime authority.

Each explicit foreground step dispatches at most one HTTP request, reserving
its cumulative attempt before transport. Discovery, device start, one confirmed
poll and provider userinfo are separate steps. Every poll requires a current
confirmation bound to that exact durable challenge. There is no loop, sleep,
background login, automatic refresh or renewal. Explicit transient reads retain
bounded retry state; ambiguous authentication POST outcomes and permanent or
identity failures block. The minimum successful path consumes four attempts.

## Qualification and remaining gates

Local tests cover predecessor custody/history, unchanged cumulative limits,
one-use claims and crash retention, no credential copying, explicit poll
confirmation, provider revocation, missing scopes, changed provider principal,
counter/window drift and a real verified-TLS synthetic provider using the
existing transport. The resulting READY journal is exercised with the concrete
native read-only HUMAN reader. The CI workflow runs the same finite fixtures on
Python3.12 and3.13.5 in root custody.

These are synthetic qualification fixtures, not target IAM authentication,
THS approval, DB admission, runtime rollout or release acceptance. The package
has no approved authentication launcher or target consent. The separate
`scripts/launch-human-successor-read-20261020.sh` delivers only the six-source
read-only inspection. Its embedded policy module contains just CLIENT/SCOPES/
PROFILE constants, and its boot module just reads the Linux boot identifier.
No authentication, journal writer, initializer or signing implementation is
included. The embedded installation case binds the already retained packet,
inputs, owner plan and completed result. It derives the session directory from
that exact completed plan, rather than assuming a sibling directory layout.
The launcher verifies the pinned script before sudo; root rechecks the bounded
file and digest and executes those verified bytes in isolated memory. Target
artifacts are not changed. A local private download/log directory is retained.
Failure exposes only a fixed checkpoint and an allowlisted static reason code.
No login or new window is authorized by running this diagnostic.
Technical phases remain8/8; functional milestones remain4/6; G3 stays open.

Authorization PET1.5 §§0,6 and the actor/HUMAN-only guards were consulted.
The product HUMAN flow prescribed in §6 is Authorization Code+PKCE through a
trusted client/BFF or THS. The existing `ouf-human-admin` device path reused in
these fixtures is an installation operator recovery profile; this work does
not claim product PKCE, federation or THS acceptance from it, create users,
change IAM client configuration, or turn terminal consent into THS approval.

CI success, VPS readiness and CSV end-to-end acceptance are distinct evidence
classes. The operator reports roughly30% first-pass VPS success after CI from
experience. This is not a measured OUF statistic and is not used as an automatic
effort multiplier. Diagnose target failures without resetting state or replaying
consumed claims; record target diagnosis and corrections separately from CI.


## Target STOP: full selection reconciliation

At2026-10-20T14:38:43Z the operator supplied STOP_RECONCILE at
EXPIRED_READY_PUBLIC_HISTORY, reason EXACT_RETAINED_HUMAN_SELECTION_REQUIRED.
The previous diagnostic did not mutate the target, initialize a session or call
OAuth. Preserve that launcher, context and log; do not rerun it.

The inspection constructed only issuer/tenant/subject while the original
HumanSession binding hashes the complete authorization selection. Inspection
of the original target_selection and completed ingestion_owner_recovery.entry
source proves the producer used original.authorization.plan.selection, which
also includes origin, Docker binding, Keycloak container, realm and clients.
The three-field fixtures missed this shape. The exact hash guard rejected the
projection correctly; it must remain unchanged.

The distinct read-only reconciliation follows the completed plan's exact
authorityDirectory (also required to equal the pinned plan file's directory),
reads its root-custodied case.json and the originalBinding document, verifies
the original bytes, prepared-inputs schema and same Engine, then requires the
FULL selection digest to equal the selectionHash in the already pinned Owner7
plan. It also checks issuer/tenant/subject equality. The capsule cannot select
a different origin/client profile by merely changing its originalBinding: the
independent completed plan hash anchors the required full selection digest.
All files are rechecked for custody/drift before returning. No new fallback,
normalization, discovery, hash bypass or authentication is introduced.

New artifacts: scripts/reconcile-human-successor-selection-20261020.py and
scripts/launch-human-successor-selection-reconcile-20261020.sh. The original
reader and launcher remain byte-for-byte retained. The new result schema is
ouf.human-expired-ready-successor-selection-reconcile.v1 and records the
predecessor reason. Full eight-field selection, reduced-projection rejection
and a changed-original-profile attack now have explicit fixture coverage.
CI remains qualification; current VPS reconciliation is still required.
