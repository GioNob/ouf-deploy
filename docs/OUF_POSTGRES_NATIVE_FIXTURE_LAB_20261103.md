# PostgreSQL native fixture laboratory — development only

This adds the first runnable real-PostgreSQL laboratory for the published
`tools/storage_recovery/postgres_fixture.py` adapter. The adapter, fixed SQL,
fixture schema, coordinator and historical SeaweedFS lab profile remain
unchanged. The separate workflow runs on an ephemeral hosted runner; it does
not address any OUF target or consume target authority.

## Exact input and pending execution

- PostgreSQL **17.11**, released 2026-08-13, source archive
  `https://ftp.postgresql.org/pub/source/v17.11/postgresql-17.11.tar.bz2`.
- SHA256 `dd27f2b3c59e73ed14aa3324901242bf69a032a6347805f274e6260322d42979`,
  observed from the matching `.sha256` file on the same official origin.
- Official release record: `https://www.postgresql.org/docs/release/17.11/`.
- The workflow verifies the archive before unpacking, builds native binaries,
  checks all four runtime version strings, and retains their actual SHA256s,
  compiler/tool versions, runner package list, configure/build logs and source
  hashes. No floating PostgreSQL package or image determines the tested version.
- Ubuntu build tools are runner packages, not independently pinned artifacts;
  this is not a reproducible-build or PostgreSQL image-admission claim.
- The current delivery has **9 offline harness tests PASS**. The **7 real
  PostgreSQL cases are PENDING hosted execution**. No native PostgreSQL
  execution, source build or successful fixture result is asserted locally.
- The standalone harness records `expectedSourceTarballSha256` and keeps
  `sourceArchiveVerifiedByHarness=false`: it checks executable version strings
  and hashes, while the workflow supplies the archive-check → build → binary
  evidence chain. A matching version string alone never proves source origin.

## What the real cases establish when they pass

| Case | Observation required |
| --- | --- |
| Snapshot and reconciliation | Fixed adapter reads actual fixture SQL tables; coordinator hashes real local file streams against those SQL hashes |
| Corrupt body | Same-size changed file with unchanged catalog/metadata produces `BODY_SHA256_MISMATCH` |
| Read-only access | SELECT-only adapter role cannot UPDATE (`42501`); owner cannot UPDATE inside `BEGIN READ ONLY` (`25006`); server has no TCP listener |
| Pending object ACK | A SQL row with `PENDING` is rejected before reconciliation |
| Pending ACK counter | A nonzero SQL generation counter is rejected |
| Mixed generations | A SQL object generation different from the selected generation is rejected |
| MVCC and atomic generation change | While another transaction holds uncommitted changes to both tables, the adapter sees the old coherent generation; after an explicit atomic committed change it sees the new generation and rejects the old expectation |

The MVCC case checks the writer is waiting in `PgSleep` both before and after
the adapter read. It then cancels that transaction and verifies its cancellation
error, followed by a separate atomic committed update of both tables. This is
not a test of writer lease/fence enforcement, a concurrent restore, or commit
ordering across PostgreSQL and an object store. PostgreSQL's fixed
`REPEATABLE READ READ ONLY` statement is exercised unchanged.

## Isolation, limits and retained failures

The runner requires an unprivileged OS account. It creates a new owner-only
temporary data/socket tree, enables no TCP listening, and grants the adapter
role only database CONNECT, schema USAGE and table SELECT. Local trust
authentication is confined by the private Unix socket directory in this
disposable laboratory. It is not a deployable authentication policy.

Process commands use argv without a shell, a fresh environment without inherited
PG credentials/options, finite deadlines, and temporary-file diagnostics rather
than blocking output pipes. The administrative harness accepts only its fixed
test SQL; output is rejected above 1 MiB per stream after command completion.
The published adapter retains its stricter streaming byte/time budgets. Native
server start/stop budgets are finite, forced cleanup after failed graceful stop
does not change failure into success. The hosted job is bounded to 20 minutes.

SQL inputs/stdout/stderr, actual server log, individual snapshot receipts,
reconciliation reports, binary/source hashes, test log and final receipt are
retained for 90 days, including failures. CI success requires exactly seven tests,
zero skips and clean server stop. A timeout or exception during normal stop still
attempts bounded immediate cleanup and leaves the run failed; a failed forced
cleanup never reports the server stopped. Attestation is attempted only after successful verification;
it binds evidence origin, not runtime admission or correctness beyond the tests.

## Claims deliberately left open

Object bodies are local fixture files, not S3 readbacks. The five manifest
artifacts and the supplied `postgres_dump` hash are explicitly synthetic
references: no dump is restored and no restore origin is proven. Fence rows are
observations; they do not fence writers. The fixture schema is not UDP or another
owner's schema. The historical profile's candidate lock is not promoted to the
current candidate generation.

Every receipt keeps `dumpRestoreOriginVerified`, `writerFenceEnforcedByAdapter`,
`livePostgresRecoveryQualified`, `seaweedfsExercised`, `pitrQualified`,
`rpoMeasured`, `rtoMeasured`, `runtimeHealthyClaimed`, `releaseAdmitted` and
`runtimeAuthorityIssued` false, and `targetOperations` zero. Real coordinated
restore, WAL/PITR, durable writer protocol, current-image binding and target
HUMAN/THS authorization remain separate MiniPET WP3 work. No gate or acceptance
test is closed by this scaffold. MinIO, consumed scopes and Teatri/Farmacie
results are unaffected.
