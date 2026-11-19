# Native PostgreSQL fixture: backup identifier correction

The second native run
[`41719760642`](https://github.com/GioNob/ouf-deploy/actions/runs/41719760642)
on `77215bee99bf52a476a1fcebc38b68ed5f4a8e81` reports **5 PASS, 2 ERROR,
zero skips**, so the overall result remains **FAIL**. The independent foundation
run `41719760718` passed all **50 tests**, with zero skips.

The passfile correction removed the previous libpq warning: retained ordinary
SQL stderr is empty and no retained stderr contains the password-file warning.
The adapter captured five actual PostgreSQL snapshots. The two pending-ACK
checks, mixed-generation rejection, SELECT/read-only enforcement and coherent
generation before/after atomic commit passed. The first failed run remains
preserved separately and is not reclassified.

Both remaining errors occur before body reconciliation. `NativeLab.reconcile`
passes `backup_id="native-fixture-0001"`, while the existing manifest constructor
requires every synthetic backup identifier to start with `lab-`. It correctly
raises `LAB_BACKUP_ID_REQUIRED`.

The implementation change is one literal:
`backup_id="lab-native-fixture-0001"`. No manifest guard, adapter, SQL,
seven-case acceptance count, cleanup rule or authority boundary changes.

A new offline test exercises the actual `NativeLab.reconcile` method through
the real manifest constructor and coordinator, using actual local body streams.
It checks both successful body/hash reconciliation and detection of a changed
body whose database metadata remains unchanged. It reproduces
`LAB_BACKUP_ID_REQUIRED` against the previous runner: **10 harness tests, one
ERROR**. With the literal corrected, the full local foundation suite is
**51 PASS**, including **10 harness contract tests** and **16 adapter tests**.
RED and GREEN logs are retained.

The second native negative ZIP is artifact `13272805054`, 107,903 bytes, SHA256
`cf3788bb59c6daa0f2ea4587fea63af6ce9208c63592b0363903a33335468629`.
All 89 manifest entries and source bindings were checked locally. It records
partial real-SQL progress, not successful body reconciliation or recovery.

This correction still requires a new hosted PostgreSQL run. No native seven-case
PASS, restore origin, writer fencing, PITR, RPO/RTO, runtime health, release
admission or target authority is claimed by this local correction.
