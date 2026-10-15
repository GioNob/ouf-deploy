# Governed mount-owner lifetime reprocessing — 2026-10-15

The fixed latest target reader completed with stable records and no unavailable
checks. Review2380132a/sourceb7d24c57 action is stopped, worker CANCELLED after
one new publication: prior2 +attempt1 =cumulative3. Admission is BLOCKED/v3.
Transition8cfb3760/v15 retains six APPLIED effects and failed unsigned ATTEST.
Its earlier failed intent marker is intact. Node contains only frame-policy;
no issuance claim or accepted attestation receipt. Same paused PID3484588,
container790c6274/restarts0. No later application/migration/Gateway effects.
See evidence/chatbot-mounted-recovery-target-20261015.json.

The lifetime fix at c4fdc34f687553f1b02fcb79576a1e6562d395d0 passed all six
same-source gates, including actual readonly mounts and actual signed owner
with TLS introspection. The owner minimum90seconds is unchanged. The witness
uses current worker wall/monotonic publication expiry and issuer admission,
never read-deadline+mount-minimum as fabricated token expiry.

This candidate adds a fixed v2 unsigned reprocessing profile from the exact
latest review/authority/transition/worker/session/admission/claim hashes. The
complete historical chain is reread without execution and hash-bound. The old
v1 successor is verified with its exact original signed scope and marker.
Six native effect payloads must match both generations. Later stage journals
must equal the reader's exact pins and have zero effects/backups/migrations.
Any node issuance or acceptance record rejects this unsigned-only recovery.

A distinct fixed O_EXCL/inode/flock claim fences one fresh invocation. Both
older claims remain reserved. The prior executor must be stopped, its worker
CANCELLED and admission BLOCKED even if its original finite window has not
elapsed. A new exact HUMAN approval opens one distinct finite session; no old
authority/decision/TTL is extended or rewritten. New active journalv16 starts
at phase7. Its v2 marker retains BOTH prior failed intents and the prior full
reprocessing marker, bound to old journal/proof/new authority/changed intent.
No CREATE/STAGE/SIGUSR1, import, retirement, first-grant or backup/fence replay.

New signed worker sessionv3 starts attempts0/prior3/cumulative3. Its first new
TLS grant must be cumulative4. The independent installed owner validates exact
cancelled predecessor worker/session copies, first-grant reference, schemas,
prior2 +attempt1 =3 lineage and immutable logical scope. Observer admission
uses actual retained publication lifetime. It cannot adopt an old active
worker/token. Legacy sessionsv1/v2 preserve their prior semantics and counts.

Tests cover real role signatures, durable CAS, both failed-intent markers,
revocation, duplicate launch/inode fencing and real TLS v3 worker history.
A complete review/source-closure compilation is exercised before runtime.
Native attestation effects in Executor tests remain synthetic; target full
private frame/peer acceptance and application/CSV readiness are still unproven.
Qualification is PENDING at this immutable implementation checkpoint. Do not
deliver a runtime command until all same-source required CI gates pass.
