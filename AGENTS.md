# CURRENT — live metadata matched; separate technical budget decision only

Corrected target reader PASS: exact replacement CID/PID/start and namespace matched, including recycled inode;18 Engine GETs,zero OAuth/effects. The old rollout remains stopped at nextStage18 with18 applied stages; no readiness/routes/DB/provider authority newly proven. Technical8/8,functional4/6,G0–G2PASS,G3OPEN. OAuth remains288/288; proposed292 ceiling is NOT yet granted.

PR48 prepares a separate explicit terminal decision for four additional technical requests, preserving exhausted history. CI39596994308 at85a30fb4af7ce0bfe74bd20acae3a0124d80f73c:20PASS on each Python3.12/3.13.5,zero skips. No login/window/provider request/runtime authority is implemented. Future provider authentication and runtime consent are separate; do not obtain a fresh token until the successor runtime is qualified. See docs/handoffs/OUF_TECHNICAL_OAUTH_BUDGET_EXTENSION_20261021.md. Previous instructions below are historical.

---

# CURRENT — corrected live namespace reader required, no runtime action

First input-reader STOP was caused by a bridge inode-inequality defect. Frozen GatewayNamespacePin already supports recycled namespace inode numbers with exact NEW CID/PID/start. See current roadmap and docs/handoffs/OUF_CLOUD_STAGE18_CONTINUATION_INPUTS_20261021.md. Corrected PR47 source84385614…,CI39594157172,19tests each Python/zero skips. Only the corrected pinned read-only reader is next; old launcher/log retained. No login,old step/reconcile/approve/initialize or budget reset. OAuth remains288/288;292proposal unapproved. Older instructions below are historical.

---

# CURRENT — stopped prefix reconciled; live continuation metadata only

Follow docs/handoffs/OUF_CLOUD_STAGE18_CONTINUATION_INPUTS_20261021.md. Owner snapshot confirms18APPLIED,no pending claim,same boot,expired authority. Next target action is the separately qualified read-only live metadata reader(PR47,1776f946…). No old step/reconcile/initialize/approve/login/window or budget reset. Proposed288→292 budget is NOT granted. Older instructions below are historical.

---

# CURRENT — stage18 partial rollout STOP, 21 October2026

The HUMAN open-window command below WAS subsequently executed once, all four provider steps completed at288/288, and explicit infrastructure authority was issued. Rollout stopped after18/28stages through both readiness gates: INSUFFICIENT_CURRENT_STAGE_WINDOW. Status RECONCILE_REQUIRED,nextStage18,readStateIDLE. Follow docs/handoffs/OUF_CLOUD_ROLLOUT_STAGE18_STOP_20261021.md and current roadmap header. Next target action is only the separately pinned offline reader; no replay/renewal/login/reset. The older transfer instructions below are historical.

---

# OUF project instructions

## Current chat transfer — 21October2026

Read [the restart handoff](docs/handoffs/OUF_CLOUD_CHAT_RESTART_BEFORE_HUMAN_WINDOW_HANDOFF_20261021.md) and [checkpoint](evidence/csv-e2e-chat-restart-checkpoint-20261021.json) first. Owner explicitly confirms the last open-window command was NOT executed. Latest completed target operation is the successful read-only supplementary preflight,284/288,four left,no new HUMAN window. After reading AGENTS/Mini-PET/original PET attachments/resilience policy, the new chat must present that exact pinned open-window command and terminal consent, not rerun prepare or start another diagnostic/authentication path. No automatic execution. Owner will attach original PETs; do not publish their archive/full text. This is a chat transfer, not a new runtime STOP or authorization.

## Active CSV/chatbot roadmap

Follow [the stable 8 technical phases and 6 functional milestones](docs/CHATBOT_CSV_ROADMAP.md). Keep its evidence/status current and include the current numbered phase and functional progress in user updates until completion. Internal launcher phases do not replace this roadmap. Distinguish execution-flow evidence, persisted target readback, CI qualification and end-to-end acceptance.

## Installation configuration and PET authority

Owner reaffirmation, 2026-10-18: consult the original current Matrix/PET baseline at the start of every sprint and every relevant coherence/acceptance decision. Record exact versions and sections actually consulted; never substitute a historical summary for unavailable originals or claim complete compliance from integrity checks. Cloud attachment integrity and normative precedence are recorded in evidence/pet-baseline-cloud-integrity-20261018.json (archive e63df67e8817eec38a9d4b3eb736b020f693b932f3360dc02f4555330f2201ce, all323 checksums PASS). Repository/MCP development authorization is standing; runtime HUMAN/THS authority remains separately enforced.

Owner reminder, 2026-10-16: keep every installation-dependent value in a validated, versioned installation/bootstrap profile: public/internal domains, DNS, service/admin endpoint references, scheme/ports, deployment-specific route hosts/prefixes/upstreams, issuer/audience/trust, secret references, host placement, network/subnet bindings, storage and runtime identity. Do not embed this municipality's values or assume one server, localhost reachability, a shared Docker network or shared filesystem across services.

Owner reaffirmation, 2026-10-20: this includes MAC addresses and interface identities for each Ente's machines and runtime networks. Derive addressing/allocation policy and explicit bindings from that Ente's validated installation profile; never ship a historical MAC, IP, network name or placement as a reusable default. For reconciliation of an existing deployment, preserve only observations authenticated against its approved runtime bindings. A Docker endpoint MAC is not implicitly the physical host interface MAC. Any conversion from legacy container-level MAC metadata to explicit per-network endpoint settings must prove equality with the observed endpoints, preserve their addresses, and remain a reviewed proposal. Fixed example addresses belong only to isolated test fixtures.

Preserve PET-defined API paths, capability identities and owner contracts. Resolve their environment-specific route bindings from approved configuration; do not make contract/security semantics arbitrary configuration. Validate endpoint references, reachability, TLS identities and independent egress allowlists. Never substitute a client-supplied URL or silently fall back to a local backend.

Use the current PET baseline in releases/PET_ROADMAP_RECONCILIATION_20261010.md, including Matrix1.7/Blueprint0.3, as normative design authority. Gateway mediates approved bindings; Authorization evaluates; service owners enforce; HUMAN decisions remain in THS. Follow the published resilience policy below, including jitter, durable cumulative budgets and ambiguity reconciliation.

Historical recovery scripts may bind exact retained IDs/hashes and the qualified current transport to avoid acting on the wrong installation. Label them installation-specific diagnostics; never promote their constants to reusable installer defaults or weaken those bindings to claim portability. General distributed deployment requires explicit authenticated transport adapters and qualification on an independent multi-host/multi-network profile. Record gaps honestly; documentation alone is not implementation evidence.

## Default resilience requirement

The project owner's decision of 2026-10-11 requires bounded resilient pause/resume by default throughout OUF. Follow [OUF resilience policy v3](https://github.com/GioNob/ouf-deploy/blob/main/docs/OUF_RESILIENCE_POLICY.md) and the module PET.

For explicitly transient failures, persist progress and retry state, pause dependent work, and retry with incremental backoff and jitter. Defaults: 5/15/60/300/900 seconds, up to20% jitter, maximum128 attempts and24hours per operation/incident, including attempt duration. Respect Retry-After; operation-specific finite profiles must be versioned and justified. Never hold shared locks/DB transactions during waits or reset budgets/checkpoints on restart.

Retries require read-only/idempotent operations or owner-proven deduplication using the same idempotency key. Ambiguous mutation outcomes require reconciliation. Permanent errors, explicit revocation, integrity/identity/configuration drift and unknown errors block automatic retry.

Keep the process observable while paused; separate liveness from readiness. Revoke/expire unproven traffic leases, and restore only with fresh evidence and valid authority/current generations. Never replay consumed activation claims, extend zero TTL, or bypass IAM/HUMAN/THS. Exhausted retry budgets remain paused for intervention, with deduplicated durable issues and no secret-bearing logs.

Verify hours-long outage/recovery, cancellation/revocation while paused, finite budgets and restart/reconciliation behavior. Record implementation limits and evidence in GitHub; documenting the rule is not proof that existing runtimes comply.

## Quarantine and governed recovery

Follow policy v3: isolate the smallest provably independent scope, preserve durable input/progress/evidence and leave independent services/jobs alive. Exhaustion stops automatic retries and keeps one persistent incident OPEN; scheduler/restarts/new job IDs do not bypass incident budgets. Advance checkpoints past quarantine only when the owner contract explicitly permits a durable terminal quarantine.

An authorized HUMAN may grant a NEW finite budget after exhaustion. Persist a new session with actor/reason/decisionRef/limits and the same logical operation/incident; retain exhausted history and cumulative attempts. Preserve operation idempotency across identical retries; changed intent/configuration is explicit governed reprocessing. Development delegation is not runtime HUMAN authority.

Use atomic expected-version transitions and persistent fencing: one active recovery per logical scope, no double operator launch or publication by stale workers. Ambiguous effects require reconciliation; new budget never overrides revocation, custody, grants, admission pressure or consumed claims.

Limit concurrency by dependency/source/tenant, protect control capacity, avoid retry multiplication, resume backlog gradually. Quarantine has bounded capacity/retention, owner/priority/age metrics, deduplicated issues and admission backpressure before saturation. No silent loss or unauthorized discard.

Verify human budget renewal after exhaustion, concurrent commands, stale/late workers, crash/effects/dedup across sessions, ordering and saturation. Record code evidence and unclosed integration limits in GitHub.

## Operational Awareness, incident correlation and alerts

Follow policy v3 and MCP PET1.4 §33. Separate incidents, events, affected jobs and notifications: one unavailable dependency with5,000 dependent objects is one owner incident with impact counts, not5,000 duplicate incidents. Correlate only proven equivalent causes within authorized scope; preserve owner identities.

Prioritize unresolved incidents by severity/action/verified impact before bounded selection, with deterministic ties; expose truncation and unavailable producers without false HEALTHY/NO_INCIDENTS. Persist operator catch-up checkpoints separately from login; do not mark unseen/failed pages as read or acknowledgement as resolved. Respect retention and disclose history gaps.

Detect systemic pressure using current windowed error rates, breadth, duration and capacity/queue age, not historical issue totals or operator absence. Scope circuits/backpressure, protect control capacity and use hysteresis plus gradual recovery.

Alerts are actionable, deduplicated and configuration-governed, with finite durable delivery budgets/outbox and safe payloads. Delivery/acknowledgement/recovery are distinct. Do not introduce a new incident authority or send real alerts merely while developing these capabilities. Qualify storm/catch-up/retention/capacity/concurrency/notification failure and record remaining deployment gaps.


## Existing VPS GitHub client

The current oufadmin VPS does not expose gh in PATH. Historical working deliveries use the existing portable executable at $HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh. Target commands must check this executable first, then optionally command -v gh, and fail before sudo or mutations if unavailable. Never assume raw curl can fetch this private repository anonymously. Preserve existing authentication; do not request or print tokens. This is a retained-host delivery binding, not a portable installation default.


## IAM administration through APIs

Owner instruction, 2026-10-20: do not ask the owner to visit the Keycloak console to inspect or edit IAM settings. Prepare and qualify the API path and use it within current authority. Do not delegate routine administrative discovery to the owner. If an operator terminal is the only qualified VPS execution channel, provide one exact pinned command with explicit expected output. If credentials or human consent are indispensable, prepare a separately explicit terminal/API step; never silently log in, refresh, reset budgets/windows, or replay claims. Passwords and token values must not enter chat, command arguments, environment, or logs. A supposedly read-only kcadm call can refresh automatically and is not an acceptable substitute for a no-refresh reader.


Owner clarification,2026-10-21: the console restriction concerns navigating administrative settings from a cellphone. Trusted HUMAN identity-provider authentication is not excluded. Keep administration API-only, distinguish sudo/IAM passwords, state each exact manual next step, and never infer consent to automatic authentication/window/budget renewal. Preserve the cumulative chain: retained HUMAN282 plus completed administrative283/284. The currently applied client-only1200second profile is not new runtime/THS authority. Follow the current roadmap/handoff rather than replaying old commands.
