# Backup failure diagnosis after signed recovery

The operator's 2026-10-15 output reached `backup_quiesced()` and failed in
`capture()` with `COHORT_DATABASE_DUMP_FAILED`. The four-database backup gate
has not completed. MCP migration and the later cohort replacements have not
been reached by this delivery path. CSV end-to-end acceptance remains unproven.

The delivered wrapper at `dd4cd1e6a567ff244dad729e32d78a7e2d0f61f2`
actually downloads and executes the capsule from
`e70ca5957772e170bc762dd937e1c46a40051f0a`. These are distinct source trees.
The diagnostic is an additive file on the evidence branch's history; it does
not replace runtime modules or recompile the signed capsule.

## Why another launch is not yet justified

The executed code writes a `CLAIMED` backup journal entry before starting
`pg_dump`, opens the archive exclusively, and discards the process stderr.
The observed reason means nonzero dump exit or at most 100 output bytes.
It does not identify which condition or the underlying PostgreSQL error.
A subsequent backup invocation rejects this unresolved claim. Removing the
archive or clearing the claim would discard evidence and is not reconciliation.

## Exact diagnostic scope

`scripts/read-chatbot-backup-failure-20261015.py` binds the exact supplied
review hash, authority hash, context, unit and executed source commit. It checks
root custody, the private bundle hash and prepared-input hash; bundle sources
are never executed. Only the stopped failed context is accepted. The reader
selects one `CLAIMED` entry in an otherwise complete backup prefix, requires
no MCP migration/audit-role action, hashes the retained archives, checks the
selected PostgreSQL generation and stopped producers, then runs one dump probe.

The probe uses the reviewed role/database and original `pg_dump` options.
It adds C locale and an in-container `timeout -s KILL 75` wrapper. If that
utility is absent, the probe fails without running pg_dump. The host CLI also
has an 85-second deadline. Output is discarded, with the reviewed archive-size
cap and a 64 KiB stderr cap. Only fixed error classifications, exit status and
byte counts are printed. The dump is not saved or accepted as a backup.

This is a read-only database probe, but it does consume read I/O and may briefly
hold pg_dump's ordinary read locks. It does not perform grants, IAM operations,
migrations, service lifecycle changes, journal writes, backup replacement,
restore, budget renewal or runtime authorization. A private temporary Docker
configuration directory is created and removed on the host.

After the probe it rechecks native generations, stopped delivery, the retained
journal/status and every retained archive. A success classification only means
the current probe exited zero with more than 100 bytes; it cannot reconstruct
the discarded historical stderr, validate a backup restore or resolve the claim.
An unknown error remains blocked and is not automatically retried.

## Qualification and next boundary

Thirteen tests pass locally with no skips, using real root-owned private files
and subprocess pipes. Tests cover pipe draining, byte/time limits, private-output
redaction, exact failure selection, source/authority bindings via the full entry
fixture, incomplete prefix rejection, migration exclusion, changed archives,
active delivery and PostgreSQL generation/producer guards. Docker, systemd and
PostgreSQL are explicit doubles; no VPS or native PostgreSQL result is claimed.

The operator must run this reader on the VPS and return its JSON output.
Only then can the correction and a governed reconciliation be bound to the
observed failure, preserving the old claim, partial archive, historical grants,
and any complete archives. Do not run the previous signed-recovery launcher.

Applicable constraints: `AGENTS.md`, resilience policy v3 (unknown outcomes,
bounded read-only diagnosis, retained evidence), L0 alignment matrix v1.7,
UDP PET v1.3 backup/migration safety, and Authorization PET v1.5 audit redaction.
