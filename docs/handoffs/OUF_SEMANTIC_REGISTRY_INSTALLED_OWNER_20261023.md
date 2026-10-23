# Registry recovery: exact installed owner and one-time finite initialization

The 502 remains OPEN. No VPS operation, grant, login, signal, authority issuance or source activation occurred. The source work below makes existing native recovery components usable with an explicitly selected installed owner; it does not establish which owner is currently admitted on the VPS.

Qualified source: `8758070e38dd38981e9f5740cb5896d287453be6`. [Workflow 39902242028](https://github.com/GioNob/ouf-deploy/actions/runs/39902242028) passed 100 tests with zero skips: 95 component/regression tests, three actual Docker generation tests and two PostgreSQL17 tests. Seven changed implementation/test files were read back exactly at that commit. Local core: 15 PASS.

## Changes

`installed_owner.py` reconstructs only the existing InstalledTokenOwner observer named by a separate signed `semanticRegistryRecoveryInstalledOwner` scope. The complete retained owner configuration, source-manifest custody, journal path and directory identity, context/generation, TLS trust and installed source must match. The unchanged actual owner checks its current HUMAN/dual-role signatures, source, legacy-writer fence, worker-session history and ACTIVE admission. The resolver neither scans for another owner nor starts/waits for a worker. Construction performs no token/credential read or IAM request.

An additional lease check rejects a previous boot, missing expiry evidence, expired wall/monotonic token windows or insufficient remaining validity. `ACTIVE` alone is insufficient. CurrentAdmission repeats this before database prerequisites and native effects; the installer checks it before creating its directory and before publishing its receipt. This is retained-window evidence, explicitly not online issuer admission. Actual online revocation/signature/audience/scope checks remain in the unchanged mounted-token owner witness before Java release.

`factory.py` now shares authenticated current-context/retained-history validation with the installer and exposes `build_from_reference`. It builds the actual observer from the exact signed reference and then the concrete NativePorts. The factory does not issue authority or select an owner by name/latest journal/historical association.

`installer.py` requires actual current factory, recovery, owner, read-budget and installation scopes. It initializes the canonical original-parent recovery directory, node directory, durable recovery ledger, separate native-read ledger and installation receipt. Root-only mkdir is the first one-attempt fence. Existing or partially initialized directories always stop: no adoption, cleanup, counter reset, alternate-parent retry or reinitialization. It grants no authority and dispatches no Docker/OAuth/application operation. Source/entry custody remains a separate required boundary.

## Qualification limits and corrected fixture

New owner tests use real Ed25519/private source custody, a real InstalledTokenOwner and an actual ScheduledRecovery/RenewalWorker publication against a disposable TLS IAM fixture. The fixture uses synthetic HUMAN approval and a substituted legacy-systemd fence. It is not the production governed/legacy worker-session history or target IAM. Source/manifest/trust drift, revoked/parked owners, changed journal references, previous boot and expired windows fail without a grant, network request or journal mutation by reconstruction.

Installer tests use actual signatures, the actual observer and private durable files, but substitute the factory context/retained-input layer. They verify create-once behavior, partial initialization preservation, refusal before directory creation on revocation and refusal without signed installation scope. They do not qualify the full production installer against current target inputs.

Run 39901992525 failed three positive tests because their inherited one-operation Recovery fixture left the scheduled expiry fields unset. Production lease rejection was retained. The fixture now uses the actual scheduled worker to persist the publication window; run 39902242028 passes. No expiry/boot check was weakened. Original shared observer/owner source files and completed caches remain unchanged.

## Required next input and remaining path

The private historical Registry dossier is not proof of the currently configured token owner. The exact current installation/journal reference must come from the current operator configuration or an explicitly selected current source. Do not silently pick the last historical worker or invent a new owner. A current path/reference is sufficient for selection; no token, secret or password should be requested in chat.

If that selected owner is parked, expired, exhausted or bound to a historical Registry generation, the resolver must stop. Any governed owner recovery/new grant needs its own concrete qualified path and actual current native authority; existing OAuth history 304/304 must not be reset or bypassed. Do not ask for premature login/token/window approval.

Still required: immutable current-context collection, sealed full source loader/capsule and executable delivery/launcher/issuer composition, plus qualification of the whole real Semantic JVM/OCI/rootfs/token/DB/Gateway path. There is no target recovery command ready yet. Existing repository workflows describe a self-hosted VPS read runner, but no current repair executor/session or usable runner was established or invoked here. The operator terminal remains the established execution channel.

The corrective target remains the exact stopped Registry behind the unchanged semantic route. Bare Docker start leaves its wait shell; Java needs fresh admitted generation custody and its own SIGUSR1 release. Full rootfs admission remains mandatory; old attestations/claims/signals and the historical running-JVM exception cannot admit the new PID. Final closure requires every original service-authenticated semantic reference to return the exact ACTIVE version with HTTP200; health alone is insufficient.

Preserve all dossiers/claims/receipts and failed/partial installations. Patch12/12, technical8/8, functional4/6, WP3/CSV-H-13, G3OPEN, nativeProfilePublishedfalse and releaseAcceptancefalse are unchanged. No automatic replay, budget/window reset, provider restoration or activation retry is authorized by these source tests. See the preceding native-path handoff for the complete retained incident evidence and normative references.
