# PostgreSQL fixture passfile correction

The first real PostgreSQL native fixture run
[`41715990786`](https://github.com/GioNob/ouf-deploy/actions/runs/41715990786)
on `9ead15c56717c2e301eeb1a2bc1af38b007bfdb8` **FAILED**: seven native cases,
zero PASS, three assertion failures, four errors, zero skips, zero admitted
snapshots. The PostgreSQL 17.11 source build, startup and clean shutdown succeeded;
the nine offline harness checks passed. The failure remains preserved separately.

## Verified cause

The environment selected `PGPASSFILE=/dev/null`. Actual hosted libpq emitted
`WARNING: password file "/dev/null" is not a plain file` in each retained
administrative SQL stderr, including `lab-evidence/sql-001.stderr`. Every adapter
attempt failed with `POSTGRES_FIXTURE_DIAGNOSTIC_OUTPUT`: the adapter's strict
stderr check correctly refused an otherwise successful client process.

The full negative ZIP is retained with artifact ID `13269487925`, 101,408 bytes,
SHA256 `e2d210d4c1a90eee071a772f10d2c6ca079bc122cd7603308796a38f9626fadc`.
All 70 manifest entries and source hashes were checked locally. This is a
verified failure, not a pending first execution or a successful snapshot.

## Narrow correction

`empty_password_environment()` creates an empty regular password file with
explicit mode `0600` inside a private temporary directory with mode `0700`.
It supplies a fresh libpq environment without inherited credentials, connection
settings, service selection or options. The private file prevents libpq's
non-regular-file warning and fallback to the user's `.pgpass`.

The adapter and native harness use the same context manager. Its lifetime covers
the process attempt, termination and pipe cleanup, including startup failure,
nonzero exit, diagnostic stderr and timeout; the empty file and directory are
removed afterward. No credential is written. `--no-password`, the fixed
read-only SQL, byte/time budgets and unconditional rejection of stderr remain.
The native writer peer holds its separate private environment until it exits.

## Validation and remaining limits

The new process-peer regressions were first run against the published adapter:
the non-regular-file warning reproduced the rejection, and the cleanup assertions
failed against the persistent `/dev/null` path. The RED log is retained.

With the correction, the full local foundation suite reports **50 PASS**, zero
failures or skips: 16 adapter cases, nine native-harness contract cases, and 25
profile/manifest/coordinator cases. These include a real child process inspecting
file type, permissions and empty contents, plus cleanup checks on success,
warning, exit error, startup error and timeout. Existing warning rejection,
bounded output, process-group termination and environment-isolation tests pass.

The local peer is explicitly not libpq. A second hosted PostgreSQL execution is
still required to establish that the fix removes the actual warning and allows
all seven native cases to complete. No native PASS, PITR, restore-origin, writer
fence, runtime health, release admission or target authority is claimed here.
