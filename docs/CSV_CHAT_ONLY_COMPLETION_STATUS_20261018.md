# CSV chat-only completion: qualified components and remaining gates

Evidence update: 2026-10-18 Europe/Rome.

## Target evidence

The supplied recovery receipt proves functional stage 3: 13 committed rows, 13 distinct active objects, no remaining quarantine and all 13 upstream handoffs/lineage matched. Technical phases remain 8/8; functional milestones are 3/6. MCP urban object search independently returned 13 ACTIVE revision-1 objects, but empty property maps. This does not prove readable semantic properties or completion of stage 4.

Actual OUF MCP calls were used: system status HEALTHY; selected onboarding version ACTIVE; role catalogue readable. Ingestion status was denied by authorization (non-retryable); the current admin catalogue lacks ingestion.operations.read. A proposed role replacement preserved existing entries and added only that read capability, but was rejected by argument-schema validation before execution. No proposal, approval, permission publication or runtime mutation resulted. The caller's standing authorization to use MCP remains valid.

## Implemented, not installed

- UDP PR44: XSD string preservation.
- UDP PR45: preserve property profile through deferred THS decisions; CREATE_NEW and APPROVE integration coverage.
- [UDP PR46](https://github.com/GioNob/ouf-udp-object-resolution/pull/46), commit 0d40da05408a14db31d4d41af2372d6a71480291: distinguish transient publication reads from permanent denials; durable bounded retry episodes, jitter, Retry-After, elapsed and attempt limits, stale-lease fencing. V36 adds recovery metadata without releasing existing quarantines. [CI](https://github.com/GioNob/ouf-udp-object-resolution/actions/runs/39077784467) passed all four jobs: Java/PostgreSQL 265 tests, zero failures/errors, two existing skips; disaster recovery, supply chain and performance passed.
- [MCP PR71](https://github.com/GioNob/ouf-mcp-server/pull/71): complete common input properties in each permission union branch for clients that project branches independently. This is a portability fix candidate; its relationship to the observed connector validation rejection requires target verification after installation. No authorization semantics or direct HUMAN approval tool added.

MCP qualification is now green at 5124178d5856b564691ca4274817efd45a0bb991: all 13 PR workflows passed, including full normal/race tests, paired service checks, build, static analysis and vulnerability checks ([full CI](https://github.com/GioNob/ouf-mcp-server/actions/runs/39078524948), [PostgreSQL suite](https://github.com/GioNob/ouf-mcp-server/actions/runs/39078524941)). The lineage fixture now asserts ordinary startup cannot perform migration 13 and uses the existing bounded administrative primitive, verifying removal of temporary membership. The lifecycle fixture uses an independent manifest identity. No production migration or authority rules were weakened. PR71 is ready for review, not installed.

A subsequent actual MCP operations-summary call for the source returned HTTP 403 (connector classified INVALID_ARGUMENT). It was not retried. The admin role already includes operations.status.read, so this result alone does not establish which authorization layer rejected the call. Inspect through the supported owner path after the connector proposal contract is installed; do not broaden unrelated privileges speculatively.

## Remaining work and acceptance

1. MCP code qualification is complete. Install the qualified package and verify valid native permission proposals through the actual client; retain THS for real human decisions.
2. Provide continuous workload credential ownership under explicit native authority. The successful one-job recovery used a finite temporary grant and an owner intentionally stopped afterward. It is not a permanent credential lifecycle.
3. Complete dependency-wide circuit coordination and native chat-visible recovery for exhausted/permanent incidents. Per-job bounded retry alone does not satisfy these requirements.
4. Qualify and install the composed UDP/MCP package via the governed deployment path, including V36 compatibility and backup evidence. Existing noninteractive runner privilege failure remains unresolved; do not bypass it using containers or another root path.
5. Verify a deferred THS decision automatically reaches its rightful UDP outcome with provenance, no duplicate identities, no replay of unrelated jobs and readable properties. Test both new-object and existing-object paths, transient failures, restart, permanent denial and exhausted retries.
6. Publish the generic reconciliation profile through the native path only after checking scheduler consequences. Current profile activation remains unproven; no historical reimport is implicit.
7. Complete remaining functional milestones with the previously agreed evidence, including a separate chat, second CSV and preservation of prior objects.

No new source publication, historical re-ingestion, identity decision, target deployment or blanket retry was performed in this update. Full chat-only end-to-end is not yet proven.

## Release integration and runner delivery — 2026-10-18

MCP PR71 merged into its integration branch (52bbc121d39760c74a9b86cde17ab04af958d576). UDP PR46 and PR45 merged, followed by PR44 into feat/resolution-object-comparison-20261017 (e15e54bbe8df036aa44d7c9224928054b2bec4b8). The UDP intermediate merge tree was checked against the qualified source tree. Packaging still pins the exact CI-tested source commits rather than moving branch names.

[Candidate build/scan/attestation 39078879773](https://github.com/GioNob/ouf-deploy/actions/runs/39078879773) passed for both components. Aggregate artifact 12117443634, 351856568 bytes, ZIP digest sha256:b615d85bd6c23bcbc0364a95c0c7a1b02cf5da40775a28eed4116f3bc058f481. Publisher identity and all aggregate file checksums were verified on the existing VPS runner.

[Persistent delivery 39079129729](https://github.com/GioNob/ouf-deploy/actions/runs/39079129729) passed. Verified package directory: /home/oufadmin/ouf-deploy-runner/_work/ouf-deploy/ouf-chat-recovery-39079129729. This directory is outside runner temporary cleanup, private to the runner, and is NOT root custody or installation authority. Earlier temporary delivery 39079059327 was superseded for persistence. Neither delivery uses privileged commands or changes runtime services.

The existing no-argument root discovery helper was invoked through its existing sudo rule in [39079096885](https://github.com/GioNob/ouf-deploy/actions/runs/39079096885). It executed and returned OUF_DISCOVERY_PRIVILEGED_PREFLIGHT=BLOCKED READ_FAILED NO_RAW_OUTPUT=true. Therefore the current obstacle is not proven to be a blanket sudo denial: that fixed helper can execute but its protected read fails. General administrative deployment access remains unproven. No broader sudo command or alternate root path was attempted.

A bounded diagnostic for that installed helper is prepared in scripts/diagnose-installed-fixed-helper-20261018.py at ffd8064be4a0bb7698d4cfdfe39292c1c38a9f79, SHA256 fb4105323c5ed2836f0cf41efb01f9709bfb0b8494a8fc99e7f6a760a487f9bf. It requires isolated administrative execution, validates root-owned helper custody, suppresses helper stdout/stderr and payloads, and returns only helper hash, exception class and source-frame locations. No exception message or local variables are emitted. [Qualification 39079288553](https://github.com/GioNob/ouf-deploy/actions/runs/39079288553) passed real root-custody success/failure/redaction tests and rejection of writable helper code.

Physical operator action is now needed to run that exact diagnostic through interactive administrative authentication, because its execution is outside the existing fixed-helper sudo rule. This is not another request for repository/MCP permission. No runtime installation, policy publication or credential-owner restart is included. Use the diagnostic output to repair the supported administrative path before preparing a current private activation review. Do not replay the old 34->35 launcher: the next UDP transition is 35->36.

Technical status remains 8/8; functional status 3/6. Packaging and delivery do not establish target installation or chat-only E2E.

## Fixed-helper diagnostic result and masked observer failure

The operator supplied a read-only diagnostic receipt: installed helper SHA256 65c8caa661005a7bf4bfe7eb1c5f45932a32c3e024095db861882f6c52998618, ValueError at collect line 76, no runtime mutations. That hash exactly matches the v3 source. The pointer, selected receipt and observer loading completed; the final runtimeCustodyVerified gate rejected the report. The v2 collector catches the observer exception before v3 checks that gate, hiding the original location. The underlying native failure is not yet established.

The v2 diagnostic observes exception propagation at the sealed observer's observe boundary and reports only class and source frames, including a failure swallowed by the legacy collector. It pins the exact installed v3 helper hash, restores the prior tracing hook, retains the 90-second bound and all custody checks, and does not change helper/observer files, receipts, sudo policy or runtime authority. A direct helper replacement would also violate the observer's own pinned HELPER_V3_HASH; do not replace it as an isolated observability fix.

The previous operator diagnostic step is complete. The deeper diagnostic is required only because the original error is masked; its result must precede any claim about historical cohort drift or a runtime repair. Technical 8/8 and functional 3/6 remain unchanged.

Qualification passed: [run 39079625525](https://github.com/GioNob/ouf-deploy/actions/runs/39079625525), commit bce616e90b28c11bd178f318f429a15323004312, diagnostic SHA256 1839a7c9b9c65f491e49876b462c22cef3728223d5285c12e65c5df0768f18bf. Tests cover swallowed observer failure, successful reads, output redaction, tracing restoration, foreign-helper rejection and unsafe custody rejection. This is CI evidence, not a new target read. The operator command is updated to these immutable bytes. Execution still requires the existing interactive administrative path; no sudo rule was expanded.

## Root cause of obsolete helper failure — 2026-10-18

Operator diagnostic v2 reports MigrationDenied at transition-source.py inspect_candidates line 104, propagated through observe line 134. The repository implementation tools/semantic_guard_extension/install_provider_network_guard.py has the matching check: created, not running, PID zero and StartedAt beginning 0001; its reason is CANDIDATE_ALREADY_STARTED. The historical document releases/PROVIDER_R8_POST_START_READ_20261009.md already records successful start and explicitly excludes this pre-start observer from post-start verification. This is an obsolete observation contract, not evidence of application corruption or a new failed database migration. The observer source hash itself was not emitted by this diagnostic; attribution uses the matching class/function/line chain and existing documented history.

Do not modify this helper to accept started candidates, restart historical candidates, rerun R8, or use its failure as the current release gate. The earlier suggestion to repair the fixed helper is superseded. No further fixed-helper diagnostic is requested. The installed-read workflow now reads current UDP/MCP/Onboarding generations using existing runner read access only; it does not establish protected review custody, database migration state or installation authority. Current MCP system-status call returned HEALTHY, actionRequired false, partial false. The qualified candidate package remains delivered, not installed; technical 8/8, functional 3/6.
