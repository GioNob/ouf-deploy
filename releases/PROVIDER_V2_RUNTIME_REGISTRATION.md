# Register the provider admission runtime with no authorized candidate

## State and purpose

Provider private TLS is prepared in `semantic-provider-v2-trust-vf7B4SM5`; startup inputs are prepared in `semantic-provider-v2-inputs-XE7IwlGm`. Do not repeat those bootstraps. The independent target runtime catalogue contains only `runc` and `io.containerd.runc.v2`. Operator root observation confirms `/etc/docker/daemon.json` is absent, current command fingerprints, original guard hash and common lock. Root observation is operator evidence, not an independent runner read of protected files.

The next action registers `ouf-semantic-admitted-v2`, using the existing Gateway adapter v4 and its exact 19-file source closure at `ace683b1019f79adaace86796b67e463b93ec12e`. Its candidate allowlist is empty. Existing default runtime, workloads, candidate images, network rules, leases, original guard and installation authority keys are preserved.

## Exact bounded operator action

Bootstrap revision: `9668abd6abec533ba3d45af92e673ae797d6330a`.
Bootstrap SHA256: `b647ea7e2fd015b399b8ffa2a014145c784f65e7a6cb9f2c53ecd747e1ace9ec`.
Installer revision: `6b74365821a668479eac10c2364b29d5cbab5eff`.
Installer SHA256: `2ee5d624ec653e9cdaf1f1d4c4774735e5d151e0f5a3e41587d766d0be998924`.
Manifest SHA256: `6e0894c95eafcc1b50d2dc15e38918a3912297a063f6800f2da3dd6c69ffa8da`.

The existing GitHub CLI OAuth session downloads these exact bytes. A fresh root-private snapshot holds the closed source package, empty adapter configuration, planned daemon file, durable registration claim and eventual completion receipt. The installer revalidates the installed no-argument native guard helper before and after, and holds the existing common guard lock during publication/reload. It refuses a preexisting daemon file or runtime wrapper instead of adopting or overwriting it.

The only installed files are the owned runtime wrapper `/usr/local/sbin/ouf-semantic-admitted-v2` and `/etc/docker/daemon.json`, which contains only the new runtime entry. Before publication the actual dockerd validates the planned JSON and the actual adapter successfully executes runc's version request. A pidfd targets the already identified daemon for SIGHUP; there is no daemon restart, service change, runtime default change, image import, container lifecycle operation, firewall write, private-key read or provider request. The actual daemon PID/birth/binary, complete existing container IDs/PIDs/start times/states, default runtime and other registrations are rechecked. No globally atomic protection against unrelated external host writers is claimed.

Success is `EMPTY_RUNTIME_REGISTERED`, candidateCount=0 and startAuthorized=false. Registration alone does not configure a transaction, authorize an image, sign mandates, satisfy the existing target admission gates or enable national discovery. Next work: a new role-specific stopped candidate creation manifest/transaction, its installation authority/producers/admission consumers, actual guarded startup, then Semantic/MCP rollout and the national Teatri product flow.

## Failure and recovery

If publication or reload is uncertain, retain all private/installed evidence and do not rerun apply. The fsynced registration claim precedes both installed files; no automatic rollback, daemon restart or adoption is attempted. Diagnose exact file hashes, current runtime catalogue and recorded daemon/container state, then implement a bounded recovery for the observed phase. Preserve previous trust/input/authority/guard snapshots.

## Validation and limits

[CI 37724365989](https://github.com/GioNob/ouf-deploy/actions/runs/37724365989), job 113139046098, passed eight root-private publication/refusal tests and one real isolated Docker test, zero skips. The Docker test used a separate daemon/socket/storage/exec root and a real running BusyBox fixture. Registration via SIGHUP preserved its state and daemon PID; the real sealed adapter returned the actual runc version and refused an unstaged CID. Native guard custody and systemd PID discovery are simulated in this isolated test; the target action uses the actual installed helper and systemd. Bootstrap syntax is also checked locally and in CI. No target registration has been performed yet.

Initial test failures were retained: explicit non-default fixture daemon configuration had to exist at startup, the actual dockerd binary exceeded the original 64 MB command ceiling, and Docker quiet listing required --no-trunc for full IDs. Final code uses a bounded 256 MB dockerd read while preserving other command limits and verifies actual full container identities. The originally published bootstrap at `0bbe92d317b5dc12eef3e215823143048766d8ca` is withdrawn; it points to an uncorrected installer. Use only the fixed revision above.
