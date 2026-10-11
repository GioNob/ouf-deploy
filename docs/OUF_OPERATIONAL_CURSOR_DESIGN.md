# Stable incident cursors and operator consultation — implementation decision

Status: owner publication/paging, MCP metadata/composition, delegated mediation and persistent control admission IMPLEMENTED AND CI QUALIFIED (Ingestion PR37; Gateway PR60/64/65; MCP PR53–58). Public HTTP/tool adapter PR58 is IMPLEMENTED AND CI QUALIFIED; Owner persistent publication bookmarks and hidden HTTP transport are IMPLEMENTED AND CI QUALIFIED (Ingestion PR38–39; Gateway PR66–68). Persistent global MCP vector, consultation confirmation and target qualification remain OPEN. This design follows [resilience policy v3](OUF_RESILIENCE_POLICY.md), [rollout plan](OUF_OPERATIONAL_RESILIENCE_PLAN.md), MCP PET1.4 §§33–34 and Ingestion PET1.3 Operational Awareness. Existing owners retain authority; no new central incident service or broker is introduced.

## Why observation time is insufficient

Ingestion PR36 persists all future incident changes, including metadata/reopening. It deliberately does not certify a snapshot cursor. A writer can timestamp a change and commit after a reader advanced its wall-clock boundary. An ordinary PostgreSQL sequence also allocates before commit: a late lower sequence would disappear behind a max(sequence) cursor. Neither is a safe proof of complete catch-up.

A short-term bounded timestamp query must overlap windows and deduplicate stable owner incident identities. It does not mark the operator's durable checkpoint complete. Critical current OPEN state is a separate read, independent of the historical window.

## Owner publication ledger

Persist an immutable transition snapshot and pending publication entry in the same transaction as the owner incident mutation. Preserve an owner-local incident version and original occurrence/observation times. Rollback publishes neither incident change nor entry. Existing rows enter as an explicit BASELINE, not reconstructed history.

A publisher in the existing owner runtime serializes publication per tenant/scope, acquires its publication lock before claiming pending entries, and allocates the public revision in the publication transaction. Pending scans select unprocessed entries, never only sequence > last sequence. Publication and mark-processed commit together; crash or rollback leaves work pending. Multiple publishers use persistent fencing and idempotent unique transition identity; older versions cannot replace a later version of the same incident.

The revision describes durable publication order, not a fabricated total order of real-world events across owners. Original times remain visible. Report unpublished backlog and coverage lag; stale publication cannot prove current HEALTHY. Retain transition history for the governed period and explicitly expose gaps/capacity pressure.

An alternative writer-serialized revision is valid only if every writer acquires a tenant revision lock before incident row locks and preserves one lock order. A per-row trigger that locks the tenant counter after locking an incident can deadlock with multi-incident transactions. Do not introduce that shortcut without migrating and qualifying all writers.

## Stable owner pages

An owner snapshot captures a committed publication high-watermark and selects latest incident versions at or below that watermark. Preserve immutable snapshots needed by live pages; later resolution, severity changes or reopening cannot remove or reorder an already captured page. Apply owner priority before page selection, with deterministic identity ties.

Use opaque random server-stored cursor tokens bound to principal, tenant, actor class, capability, typed filters, policy/scope version, priority profile and snapshot watermark. Tokens are not grants. Reauthorize every page and every projected row against fresh current policy. Expired snapshots, changed grants, retention gaps, unavailable owner and unsupported cursor versions produce explicit bounded errors/coverage metadata.

Version and qualify finite page/session limits, expiry, per-tenant/global active-session capacity, retained rows/bytes and cleanup. Limit physical scanning even when many candidates are hidden by authorization. A page that cannot complete its governed selection is partial; do not claim there are no more incidents. Never reveal hidden identifiers or protected counts in cursor/error payloads.

## Cross-owner MCP composition

Reuse summary/incidents/explain and Gateway-mediated producer calls. A global snapshot carries an opaque vector of owner positions and coverage; owners retain transition truth. MCP stores only bounded consultation/cursor metadata. Validate producer identity/schema and preserve unknown/partial/truncated evidence, including MCP's fixed self projection as in PR52.

Stable global priority needs a bounded k-way merge over authorized owner pages at their captured watermarks. Limiting arbitrary producer prefixes and sorting afterward cannot certify global priority. Refill only within the declared scan/time/result budget; incomplete selection remains explicit. Never reset an outage budget for each page or owner retry.

## Operator checkpoint and confirmation

Keep login, successfully delivered consultation, human acknowledgement and incident resolution distinct. Persist principal/tenant/scope-bound consultation metadata. A new page/query does not advance the checkpoint; canceled, failed, incomplete or unseen pages leave it unchanged.

A delivery receipt covers exact snapshot positions and known coverage. Confirmation uses expected-version compare-and-set and monotone positions; two concurrent conversations cannot rewind or skip unseen pages. The client must explicitly demonstrate the governed delivery/confirmation contract. If that proof is absent, leave the previous checkpoint and allow repeated catch-up.

Do not hide a metadata write inside READ authority. Any client confirmation mutation needs its own reviewed capability/operation-class contract, Gateway mediation, current owner authorization and finite idempotency semantics. It is not a HUMAN recovery grant and never acknowledges/resolves incidents or renews exhausted execution budgets.

## Required qualification before publication

Test late commit below an allocated sequence; pending publication after crash/rollback; concurrent publishers and stale fencing; old issue updates during paging; deterministic priority across pages; policy change/tenant replay/token expiry; more candidates than scan capacity; retention gap and publisher outage; concurrent consultation confirmation; canceled/failed delivery; urgent OPEN incidents predating the window. Test native owner PostgreSQL plus real Gateway/MCP contracts, and record deployment/grant limitations.

Until these tests pass, cursor and persistent 'since last consultation' remain OPEN. PR36 and PR52 close narrower timestamp/read-boundary gaps only. No target deploy, grants, notifications or R9/R10 replay is authorized by this design.


## Implemented foundations — 2026-10-11

Ingestion V17 qualifies pending publication under late commits, rollback and competing publishers, plus stable materialized owner pages and current resource decisions. Gateway reference qualifies SQLite commit-order history, atomic cause dedup and stable owner pages; its host authorization port defaults fail-closed. Both return opaque current/next tokens, stable snapshotRef, priority/cursor profiles, coverage lag/baseline gap and visible-items digest. These tokens are owner read snapshots, not persistent operator receipts. MCP PR53 carries correct producer resources and canonical query-bound nested keys against the current pairwise baselines.

The next composition stores only bounded owner position/coverage metadata in the existing MCP PostgreSQL store, refetches each owner page before using a saved offset, and invalidates changed visibility/digests. Persist neither producer payloads nor cached grants. Receipt writes require a separate governed capability and client delivery proof; until that proof is wired, the operator checkpoint remains unchanged. The alert reference outbox from Gateway PR63 is separate delivery state, not a consultation acknowledgement or incident authority.


## MCP metadata qualification

PR54 qualifies the principal-bound PostgreSQL owner-vector metadata store, immutable expiry and positions, finite capacities, concurrent append and unchanged replay in eight successful CI gates. It does not record client delivery or consultation. Bounded composition is being qualified in PR55; production Gateway delegated-context transport, public profile and whole-request budget composition remain explicit gates. See [adoption evidence](OUF_RESILIENCE_ADOPTION.md#cursor-mcp-persistenti-qualificati-composizione-in-sviluppo).


## Publication bookmarks and explicit consultation: next implementation contract

A thirty-minute page cursor cannot be an operator bookmark for an absence of weeks. Add distinct owner-local opaque publication bookmarks; preserve them independently of temporary captured-page rows. A bookmark is a read coverage position, never evidence of delivery, human acknowledgement, recovery authority or an incident resolution. Login never advances it.

Resume must select incidents changed after the bookmark's committed publication boundary, taking their latest version at the new committed watermark. Do not reuse observation timestamps or pre-commit sequence numbers as the lower boundary. This captures a late publication even when its occurrence time is old. For Ingestion the per-tenant publication clock/pending ledger is authoritative; SQLite commit-order revision is valid only for the current reference Gateway store. Current urgent OPEN state remains an independent read, so a long-standing important incident cannot disappear behind a history filter.

Bind long-lived bookmark metadata to stable owner/principal/tenant/resource scope and reviewed filter/priority semantics, not to login or conversation identifiers. Re-evaluate current collection/row authorization on resume. A new authentication session does not erase coverage, and a bookmark never preserves an old grant. Scope/policy changes need an explicit invalidation/rebase contract that preserves prior evidence and reports gaps; they cannot silently restart the history at now. Do not carry an old timestamp cutoff into revision-based resume and thereby hide late commits.

Each resumed snapshot stores its immutable parent bookmark. Only a complete, non-redacted, bounded coverage chain may produce a successor bookmark for that captured publication boundary. Unknown publication lag or retention coverage remains explicit. Finite metadata/page/row quotas and owner history floor must be versioned and independently qualified; expired/compacted coverage reports a gap instead of an empty successful catch-up. A finalized read position is still not an operator checkpoint.

MCP should persist only an opaque vector of owner parent/successor bookmarks, page digests and coverage lineage. Confirmation uses a separate reviewed COMMAND capability, current authorization, exact delivery/confirmation binding, idempotency and expected checkpoint version. The parent vector must equal the version actually consulted; owner-proven lineage must prevent rewind or skipped positions. A stale concurrent conversation receives a conflict and repeats validation; random UUID order or local wall-clock order is never used to compare progress.

The delivery integration must name a trusted client contract: exact principal/tenant, consultation ID, page/snapshot digest, delivered page chain and expiry, with cancellation/failure/unseen pages excluded. An MCP tool invocation, Gateway HUMAN delegation, generated response, provider receipt or model assertion does not prove the user saw a page. Until a concrete client confirmation path is implemented, keep consultationRecorded=false and the previous checkpoint unchanged. Acknowledging operational consultation never acknowledges/resolves an incident or renews a quarantined job's execution budget.

Required next tests: old-time late publication after a prior bookmark, restart/login after page expiry, scope/tenant/policy replay, owner lag/retention floor, complete versus redacted/failed/missing pages, finite history/metadata capacity and independent incident writes; then exact client receipt, cancellation, stale concurrent confirmation/CAS, idempotent retry and unchanged checkpoint on failure. Host SDK/HA/network and client delivery remain distinct target gates.


### Owner implementation qualification update — 2026-10-11

Ingestion PR38 is merged after18 native gates,47 focused PostgreSQL tests and163 full-module tests. Gateway PR67 is merged after330 Python passes/2 skips plus Authorization pairwise and real APISIX/OIDC. Both owners protect captured frame metadata and reuse an equivalent live bookmark when publication has not progressed; random UUID ordering is never a progress test. Ingestion uses committed tenant publication order, including an earlier private sequence committed late. These are private primitives, without HTTP bookmark opt-in or a global checkpoint. See [qualification evidence](../evidence/operational-publication-bookmarks-qualified-20261011.json).


### Governed owner transport qualified — 2026-10-11

Gateway PR68 qualifies342 Python tests/2 skips plus real APISIX/OIDC and Authorization pairwise. Ingestion PR39 qualifies18 gates,50 focused PostgreSQL and166 module tests. Owner-only closed coverage modes use explicit snapshot+coverage, cursor+coverage or resumeFrom+optional limit; all saved filters are inherited on resume, no timestamp/revision authority is introduced. Global MCP rejects these raw owner positions pending its own opaque-vector contract. Every read still requires current owner SDK decisions; request views do not share mutable authorization.
