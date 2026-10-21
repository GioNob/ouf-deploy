# Stage18 successor — exact retained installation

Technical8/8,functional4/6,G0–G2PASS,G3OPEN. Existing rollout stopped after18/28 applied stages. OAuth grant complete:288 consumed, cumulative ceiling292, four available AS OF GRANT; subsequent consumption is not observed. No current HUMAN window or runtime authority follows from that grant. Target preflight of this successor is still pending. This document describes qualified source behavior once CI passes, not production acceptance.

## Source and authority boundaries

Case: `releases/ingestion-rollout-stage18-successor-case-20261021.json`. It pins the full successful budget receipt, original budget case, native declaration and source hashes of both controllers/common bridge. Private persisted proposal/decision/claim must reproduce the receipt exactly; the public JSON alone grants no executable authority. Original journal/review hashes and all28 intents/logical operation stay fixed.

The HUMAN artifact has its own sealed124-module closure. All114 original native source hashes are checked unchanged within it. The runtime artifact embeds the original114-module source graph and loader unchanged, plus separately hashed stdlib-only continuation helpers. No installed application code fallback is permitted. Both artifacts verify isolated root execution and have a180second per-invocation deadline. All installation identities remain in this one-off versioned case/retained profiles; they are not portable defaults.

Originals consulted: Matrix1.7 §1; Authorization1.5 §§2.1/12.1; Ingestion1.3 §§94–95; resilience policy v3 §§14–16 (blob0a7068e9655084b412993b9e64ff898a6141b930). Gateway/Authorization/backend/THS ownership is unchanged. Development and technical OAuth consent do not approve domain HUMAN/THS operations.

## Complete manual sequence

Download and verify BOTH launchers before opening the login window. Keep their absolute paths, named below as HUMAN_LAUNCHER and RUNTIME_LAUNCHER. These names denote public launcher paths, never credentials. Every invocation retains a separate operator.log. Each launcher caches the exact public artifact beside itself; all later calls verify a new private copy's SHA256, descriptor/path metadata and byte stability before root execution. A changed/partial cache fails closed; no hidden redownload/retry or reset follows.

1. `bash RUNTIME_LAUNCHER preflight`, then `bash HUMAN_LAUNCHER prepare`. These check the private granted budget, exact expired no-pending18APPLIED prefix, frozen source/executable/stdlib closure, current role-policy window and original public-file seals. HUMAN prepare additionally reads the sealed old HUMAN journal to verify expired READY288 public history; it never uses its tokens or opens the old bearer file. Zero provider/Engine/DB/Gateway calls, no new window, authority or effects. Expected final status: `STAGE18_HUMAN_AND_RUNTIME_PREFLIGHT_NO_WINDOW`. Both artifact caches now exist. Return public JSON/log paths before proceeding.
2. Once preflight succeeds, `bash HUMAN_LAUNCHER open-window`. Operator must type the exact terminal phrase `APRO FINESTRA HUMAN <reviewHash>` after reviewing the limits. It consumes a one-use claim under the granted-budget directory and the original HUMAN lineage before creating a new7200second window. Starts at288/292 and copies no old access/refresh/published token. No provider request is sent here. A failed/partial creation remains fenced; no reopening.
3. Four separate invocations of `bash HUMAN_LAUNCHER step HUMAN_CONTROL_PATH`, each with the exact terminal confirmation. Requests are DISCOVERY, DEVICE_START, one DEVICE_POLL AFTER completing the device login in the browser, then USERINFO. Browser URL/code appear only in the local terminal. Provider identity must equal the original selection. No refresh/poll/retry loop exists. Ambiguity remains BLOCKED; pending or lost responses consume their reserved request. USERINFO reserve prevents a fifth request. READY must be292/292 and expose a private read-profile path with >930seconds token margin. The artifact inherits the existing bounded TLS/provider session implementation unchanged.
4. `bash RUNTIME_LAUNCHER review`. This creates a NEW deterministic sibling context/review and one-use review claim. It validates the freshly verified292 profile against the new window/grant/case and original principal/scopes. It copies the complete old native review, changes only the new execution context/HUMAN profile and explicitly granted current OAuth ceiling, and embeds the exact predecessor owner history plus grant/prefix proof. No original history, packet, stage intent, key/image or resource is rewritten. No runtime authority yet.
5. `bash RUNTIME_LAUNCHER approve`. Requires a separate fresh exact infrastructure terminal approval (`APPROVO <reviewHash>`), current HUMAN token margin>930seconds and valid original policy/executable closure. Existing dual-role issuance signs the new exact scope for at most900seconds. No THS/source/job/client-publication approval. It returns `STAGE18_AUTHORITY_ISSUED_EXPLICIT_IMPORT_REQUIRED`.
6. `bash RUNTIME_LAUNCHER import-prefix`. Requires the current signed authority and fresh HUMAN identity. A global one-use fence keyed by the OLD logical operation is created BEFORE writing the new journal. Exactly18 APPLIED records, all resource/evidence fields, original createdAt and cumulative native/read counters are copied. Only the new scope/authority/version/session clocks are distinct; this is no extension of the expired session. Never calls Runner.initialize or executes a native port. Expected `STAGE18_PREFIX_IMPORTED_NO_RUNTIME_EFFECTS`, nextStage18/readAttempts18. A partial import is retained and cannot be retried.
7. Ten explicit `bash RUNTIME_LAUNCHER step` invocations, one stage per command, in this order:

| Stage index | Native stage |
|---|---|
|18|REBIND_GATEWAY_TRANSPORT|
|19|VERIFY_REBOUND_ROUTE_MAP|
|20|PUT_ROUTE.mcp-ingestion-history|
|21|READ_ROUTE.mcp-ingestion-history|
|22|PUT_ROUTE.mcp-ingestion-status|
|23|READ_ROUTE.mcp-ingestion-status|
|24|VERIFY_FINAL|
|25|ingestion.RESTORE_RESTART|
|26|gateway.RESTORE_RESTART|
|27|VERIFY_RESTORED_FINAL|

Before every step, the controller verifies the import fence, exact first18 effects and cumulative counter floors. Execution then delegates to the unchanged sealed native entrypoint, retaining its current HUMAN/Owner/database admission/runtime generation/Gateway/readiness gates. At most one native effect per stage; at most two route PUTs total. Never recreate the already applied key/image/container stages. Run each command explicitly and inspect its result; do not use a loop or batch past STOP.

8. One further `bash RUNTIME_LAUNCHER step` records the native terminal incident state after all28 stages and reports complete. This final call dispatches no additional effect. Completion still proves functional4/6, not release acceptance or published native client profile.

## Stop and reconciliation

After ANY STOP preserve launcher, cache, logs, every context and claim; do not retry an effect, import, approval, window or budget grant. `bash RUNTIME_LAUNCHER status` reads metadata without opening a HUMAN/bearer or service connection. `bash HUMAN_LAUNCHER status HUMAN_CONTROL_PATH` is read-only session metadata.

An explicit `reconcile` under STILL CURRENT authority observes an existing native claim without apply, or reconciles the operator metadata when the native journal already has no pending claim and is IDLE/RETRY_WAIT. It never resets counters, extends deadlines or creates a new budget. Partial issuance/import is not automatically repaired. Expiry, boot/clock drift, revocation, custody/generation drift or exhausted reads block continuation. Fresh live service gates after authorization may still fail; prior metadata/CI is not production readiness proof.

## Verification and limits

Tests use disposable journals, actual root custody/Ed25519 signatures and competing processes. They check four requests288→292, wrong identity, lost/pending replies, denied/partial windows, unchanged old tokens/history, native contract acceptance of the explicitly granted new limit, copied resource/counter preservation, expiry/revocation, crash points and only ten residual stages applying. Sealed artifact and shell tests verify reproducibility, frozen graph equality, tampering/mode denial, real wrapper execution, safe logs and cache reuse without another GitHub request. Local environments without /proc use an explicitly labelled synthetic boot in tests; CI requires the real boot ID with zero skips on Python3.12 and3.13.5. Existing native composition tests are also run.

No production effect, new login or authority is performed by development/CI. Exact source/run/artifact pins are recorded in `evidence/ingestion-rollout-stage18-delivery-pins-20261021.json`. Target results must be recorded separately; do not promote synthetic ports or CI into database/application/provider/THS acceptance.
