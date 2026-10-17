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

MCP qualification found Go formatting (corrected from native gofmt output), plus integration failures in deployed-lineage migration 13 permissions and shared fixture manifest identity. The latter failures occur in unchanged test/source paths; inherited status has not yet been proven by a separate baseline run. Do not mark the MCP package qualified while they remain red.

## Remaining work and acceptance

1. Complete MCP qualification and verify valid native permission proposals through the actual client; retain THS for real human decisions.
2. Provide continuous workload credential ownership under explicit native authority. The successful one-job recovery used a finite temporary grant and an owner intentionally stopped afterward. It is not a permanent credential lifecycle.
3. Complete dependency-wide circuit coordination and native chat-visible recovery for exhausted/permanent incidents. Per-job bounded retry alone does not satisfy these requirements.
4. Qualify and install the composed UDP/MCP package via the governed deployment path, including V36 compatibility and backup evidence. Existing noninteractive runner privilege failure remains unresolved; do not bypass it using containers or another root path.
5. Verify a deferred THS decision automatically reaches its rightful UDP outcome with provenance, no duplicate identities, no replay of unrelated jobs and readable properties. Test both new-object and existing-object paths, transient failures, restart, permanent denial and exhausted retries.
6. Publish the generic reconciliation profile through the native path only after checking scheduler consequences. Current profile activation remains unproven; no historical reimport is implicit.
7. Complete remaining functional milestones with the previously agreed evidence, including a separate chat, second CSV and preservation of prior objects.

No new source publication, historical re-ingestion, identity decision, target deployment or blanket retry was performed in this update. Full chat-only end-to-end is not yet proven.
