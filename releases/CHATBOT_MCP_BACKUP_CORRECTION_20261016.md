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

## Why target administrative verification is still necessary

The existing signed recovery profile resumes a paused Registry before
attestation/admission. This attempt instead passed Registry verification and
completed three later backups. Reusing the previous profile would use the wrong
checkpoint. Its worker/grant count and Registry's state after cancellation have
were not collected by the first backup reader; the second readback now supplies
them as described above. Administrative dump capability remains unproven on
the target because the SQL preflight stopped first.

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
