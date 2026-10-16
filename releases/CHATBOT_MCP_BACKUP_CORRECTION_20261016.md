# MCP backup role correction and retained recovery boundary

The operator's readback confirms three complete retained archives and an empty
claimed MCP archive. The single diagnostic dump with the workload role exited
1 with `INSUFFICIENT_PRIVILEGE`, zero dump bytes and 584 stderr bytes. No MCP
migration has started. The original journal and archives were unchanged.

| Module | State | Bytes |
| --- | --- | ---: |
| UDP | COMPLETE | 247357 |
| Onboarding | COMPLETE | 325831 |
| Ingestion | COMPLETE | 94318 |
| MCP | CLAIMED | 0 |

The affected journal hash is
`2c55b26774660d1e56d6855b5425c18b2cc26a6ab09da463fe324229b744094c`.

## Implemented candidate correction

`databases.py` previously used the workload user for every full database dump.
MCP separates protected operational evidence from the workload's privileges;
a role that can run the application and read its migration history is not
necessarily entitled to dump every table. PostgreSQL's `--no-owner` and
`--no-acl` options do not grant missing source read privileges. See the official
[pg_dump documentation](https://www.postgresql.org/docs/17/app-pgdump.html).

The new `compile_mcp_backup_reader()` explicitly derives a changed plan from
the old plan and a read-only administrative preflight. It selects the existing
administrator already named in the reviewed MCP administration scope. The
new plan retains every application database/user binding and binds the old
plan hash, exact MCP database OID, proposed backup user and preflight. It must
be included in a fresh HUMAN-reviewed aggregate action before runtime use.

The backup owner validates the changed plan, repeats the role/database/read-only
preflight and checks current signed authority and PostgreSQL generation before
creating the archive. Other database backups retain their original users.
There is no implicit fallback following an error and no GRANT, ownership change,
restore or weakening of application permissions. A historical `CLAIMED` archive
still blocks replay. This change alone does not resolve the old claim.

The dump reader now drains stderr concurrently with stdout, caps diagnostics at
64 KiB and emits only fixed failure categories. Unknown errors remain blocked;
no stderr text, identifiers or data are printed.

## Verification and deployment status

Local qualification: 22 signed database-owner tests and 8 fixed reader tests,
all passed with no skipped tests. The native workflow additionally exercises a
real restricted PostgreSQL role, proves its dump fails, then uses the actual
signed owner to produce and parse a complete administrative archive. It checks
that the application still lacks SELECT and that no migration/audit-role action
occurred. The authoritative workflow result is recorded separately in evidence.

This is a candidate component change on the exact runtime source lineage,
`e70ca5957772e170bc762dd937e1c46a40051f0a`. Existing launchers do not call its
new plan compiler. No regenerated capsule or runtime recovery launcher is
delivered by this change; it is not a deployment or CSV acceptance.

## Target checkpoint collected by the administrative preflight

The second operator readback confirms Registry `READY`, version 29, next phase
10, with all ten effects through `VERIFY_APPLICATION` applied. The actual
Registry container is running, not paused, with restart count zero. The worker
is `CANCELLED`, with five cumulative controlled grant attempts (four inherited),
and admission is `BLOCKED`. This is a later boundary than the signed-paused
recovery profile. The three completed archives and the empty MCP claim still
match their previous hashes; no MCP migration has started.

The administrative catalogue query then exited unsuccessfully, before any
administrative dump probe. Its old error handler discarded stderr, so this
target output does not identify the SQL error or prove that the administrator
cannot perform a dump. It also contains no final `END` unchanged-artifact check.
The records were read-only; no recovery or runtime authority was issued.

The reader correction places the privilege functions inside `CASE` guards.
PostgreSQL may reorder `WHERE` conditions, so a separate `relkind='S'` predicate
does not protect `has_sequence_privilege()` from receiving a table OID. SQL
errors now expose only an allowlisted SQLSTATE/category and byte count, never
stderr text. An in-container timeout also bounds a failed SQL connection.

The earlier 32-test qualification exercised the administrative archive through
the signed backup owner, but mocked this separate reader's SQL result. It did
not qualify the failing catalogue query. The added native test executes the
exact delivered reader against tables, a view, an index and sequences with
mixed grants, and exercises its administrative dump probe. Qualification of
this revision is recorded in a separate evidence file.

At source `500eab9d6ddad1e02865bb333ef66ce946ad58e0`, workflow run
`38826095544` passed 22 owner tests, 10 reader tests and 3 native tests with
zero skips. The native regression reproduces the old expression's SQLSTATE
`42809`, then verifies the corrected reader and its bounded administrative dump
probe succeed. This identifies a real defect in the old query; the target's
suppressed stderr means its exact SQLSTATE remains unknown until readback.

## Why the target administrative preflight was necessary

The existing signed recovery profile resumes a paused Registry before
attestation/admission. This attempt instead passed Registry verification and
completed three later backups. Reusing the previous profile would use the wrong
checkpoint. Its worker/grant count and Registry's state after cancellation were
not collected by the first backup reader; the second readback supplied them.
At that intermediate checkpoint, administrative dump capability was still
unproven because the SQL preflight stopped first. The corrected successful
preflight below closes that diagnostic gap.

The standalone `read-chatbot-mcp-backup-preflight-20261016.py` binds the exact
failed context, review, authority, source and reported database journal. It reads
Registry phase hashes, node records, cohort records and worker/session/admission
hashes and counters. It then validates the selected backup administrator with a
read-only catalogue query and performs one bounded administrative dump probe,
discarding its output. No application-role dump is repeated. It reports only
counts, booleans, states and hashes, and checks all retained archives/journal
again before declaring the read complete.

The next recovery must retain all historical phase effects and grant attempts,
the three complete backups and the empty failed MCP archive/claim. It needs
fresh native proof and a new explicit HUMAN decision for the changed source and
backup plan. The preflight does not grant that authority or implement adoption.
Do not run the previous recovery launcher or remove the old MCP claim/archive.

## Successful target preflight and successor candidate

The corrected reader at `500eab9d6ddad1e02865bb333ef66ce946ad58e0`
completed on the target. The administrator matches database OID 21560 and
produced 250874 bytes with exit 0 and no stderr. The application lacks SELECT
on two tables and no sequences; its privileges were unchanged. The final
check proves all retained archives and the database journal unchanged. This
probe was discarded and is not an accepted backup. See the success evidence.

The successor candidate adds an exact verified-Registry recovery profile.
It preserves all ten Registry effects, the signed/unsigned reprocessing
history, five controlled grants, the empty MCP archive/claim and three complete
archives. It copies those three archives into a new private directory under a
consumed continuation fence, with a durable copy claim and no automatic replay
after interrupted copying. A changed signed database plan authorizes one new
MCP dump with the existing administrator. No GRANT is added for backup.

The Registry is checked as the same running process, complete OCI and
independent rootfs, with fresh readiness and a current owner-admitted token
observed through its actual read-only mount. No new node attestation, database
admission, create, stage, unpause or SIGUSR1 is executed. The previous signature
remains historical evidence and its expiry is not extended. Only the final
producer release remains a possible future Registry effect after the full
cohort verifies. A distinct v5 worker session retains five predecessors; its
first new grant will be the sixth cumulative controlled attempt.

The candidate passed the qualifications recorded below, and a separate pinned
launcher is now released. The previous recovery launcher remains unsuitable.
The CSV/chatbot end-to-end acceptance remains unproven.

## Delivery qualification and operational handoff

Runtime source: `eab913b879827c029d77fb5702e94b20aef386c7`.
The preparation capsule SHA-256 is
`8e6b05b00dc1e0f62dccf9e6b9a4b34a98312b1b69c3a1a623ede0cdb7346b0b`.
The launcher uses this exact source, verifies the delivery script's hash and
reuses the original package archive, whose identity the inner launcher checks.
It selects the existing portable GitHub client before considering PATH.

The targeted workflow [38828474230](https://github.com/GioNob/ouf-deploy/actions/runs/38828474230)
passed 77 tests with zero skips on this source. Four tests use actual PostgreSQL:
the application dump is denied, the explicit administrative backup succeeds,
the complete payload parses, and the three old archives and failed claim remain
unchanged during signed successor adoption. The retained Registry archive is
checked separately from the current database fence; old fenced phases continue
to reject an open database or extra sessions. No backup privilege is granted
to the workload.

The running token-mount workflow [38827997111](https://github.com/GioNob/ouf-deploy/actions/runs/38827997111)
passed four tests on the preceding test-only commit. Its process observer,
mount observer and test file are byte-identical in the delivery source. The
fixture uses a real non-root process with empty capabilities and NoNewPrivs,
a real read-only mount and signed TLS owner. The Docker receipts are synthetic;
this qualification does not substitute for fresh target observation. Revocation
and generation drift deny acceptance.

The full delivery workflow [38828474141](https://github.com/GioNob/ouf-deploy/actions/runs/38828474141)
passed 416 tests across 56 suites with zero failures, errors or skips on the
exact delivery source. This includes the actual sixth TLS grant, complete v5
review compilation, revocation and reconciliation, previous session histories,
real service fencing, four-database archives and native owner acceptance joins.
The detailed qualification and source hashes are recorded in
`evidence/chatbot-verified-registry-backup-recovery-qualification-20261016.json`.
The 77 targeted tests overlap the general suite and are not an additional
77 distinct cases.

The operational launcher is
`scripts/launch-chatbot-backup-recovery-20261016.sh`.
Run it once as `oufadmin` in the interactive VPS terminal. The existing installer
performs read-only history/native checks before login and prepares the complete
new review before asking for `APPROVO <review-hash>`. This new HUMAN decision is
required by `AGENTS.md` and resilience policy v3: the changed backup plan/source
and finite session cannot inherit the expired authority. All old grant attempts
and incident history remain retained. The new session is bounded to 128 worker
attempts and 3600 seconds, with no automatic renewal. Its first successful new
grant is the sixth cumulative controlled attempt.

The action adopts the three complete cohort backups, permits one new MCP dump,
and continues the remaining cohort deployment through the existing owners.
It preserves the exact running Registry and its ten applied effects; only final
producer release may be a new Registry effect after full cohort verification.
An interrupted archive copy or ambiguous dump remains blocked for governed
reconciliation, without repeating the dump or resetting an incident budget.
The launcher records its log path. On any stop, retain that log and all journals;
the same consumed recovery must not be launched again.

Successful setup reports `COHORT_READY_FOR_ACTUAL_CHATBOT_CSV_ACCEPTANCE` and
keeps the finite session alive for the actual CSV interaction. A real owner
acceptance observation is still required before claiming chatbot end-to-end
success. The qualification and launcher publication themselves perform no VPS
mutation and issue no runtime authority.
