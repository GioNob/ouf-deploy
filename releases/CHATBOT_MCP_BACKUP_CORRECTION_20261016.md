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

## Why the remaining preflight is necessary

The existing signed recovery profile resumes a paused Registry before
attestation/admission. This attempt instead passed Registry verification and
completed three later backups. Reusing the previous profile would use the wrong
checkpoint. Its worker/grant count and Registry's state after cancellation have
not yet been collected by the first backup reader.

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
