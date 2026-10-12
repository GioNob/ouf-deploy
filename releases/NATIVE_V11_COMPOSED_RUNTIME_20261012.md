# Composed native runtime boundaries — 12 October 2026

The operator policy preflight succeeded; [target observation](../evidence/native-v11-transition-preflight-target-20261012.json) confirms current selected installer/attestor windows and key metadata, without reading keys or granting runtime authority.

## Native pause/release composition

The signed phase intents reference prior phases rather than guessing a future container ID/PID. [NativeEvidenceStore](../tools/semantic_application_cutover/native_evidence_store.py) keeps bounded canonical payloads in private, generation-bound directories and one-use files. The journal's nativeEvidenceHash authenticates each consumed payload. Partial, corrupt, linked, foreign or replaced inputs are denied and retained; no overwrite occurs. The creation adapter optionally publishes its exact stopped native payload. Reconciliation can publish private evidence but never retransmits a Docker mutation; the eventual root entrypoint must account for these protected writes.

[PausedStageAdapter and ReleasePausedAdapter](../tools/semantic_application_cutover/runtime_adapters.py) reuse the bounded Engine checks while Executor owns effect claims. Stage authenticates the exact recorded stopped creation, then starts and pauses once. Release consumes the prior paused payload and preserves container ID, PID, start time and configuration/mount/network hashes. Reconciliation of running-but-unpaused staging does not retry either operation. The sealed checkpoint still owns current DB/producer/lease fences and actual complete OCI, signed transport and attestation; private payloads alone grant none.

[CI38204944770](https://github.com/GioNob/ouf-deploy/actions/runs/38204944770), job114666249533 SUCCESS:3 private-store tests and3 actual native runtime tests. An isolated sleep process survives actual controller deaths after pause and unpause as the same generation; repeats send no mutation. A start/pause interruption remains IN_FLIGHT, and a corrupt creation payload blocks before start. The fixture runs no Semantic JVM. Authority, preceding phases, DB/lease fencing and attestation are synthetic, explicitly not target qualification. [Receipt](../evidence/native-v11-runtime-executor-qualified-20261012.json).

## Fresh backup ownership

The composed backup additionally publishes a one-use backup-phase-binding.json before invoking the qualified primitive. It binds the signed intent to the exact transition context, which includes authority/request/predecessor history. Preexisting backup files prevent apply; foreign/unbound old receipts cannot be adopted during reconciliation. A partial binding remains consumed and fail-closed. Six composition tests cover this ownership boundary, with native PostgreSQL controller-death qualification required for the updated source.

The complete target applicator remains OPEN. Missing pieces include coordinated R12 stop/revoke with cumulative history, inventoried target producers and endpoint release, complete new OCI/peer attestation and authenticated transport/distinct worker, scoped migration admission, current application/CSV acceptance and the sealed root entrypoint. No new root command or runtime approval is requested for an incomplete applicator; existing R12, image-import history, Cinema and Teatri remain retained.
