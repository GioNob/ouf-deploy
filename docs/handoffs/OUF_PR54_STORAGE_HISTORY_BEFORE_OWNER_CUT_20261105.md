# Stato PR prima del common cut dell'owner — 5 novembre 2026

## Deploy PR54, descrizione conservata integralmente

## Checkpoint 2026-11-05: two requested steps completed

1. Implemented the actual Onboarding upload owner: durable intent and fixed key before S3 PUT, short reserve/finish transactions, generation-bound ACK and reconciliation without reupload.
2. Qualified the implementation against PostgreSQL17.11 and the exact previously qualified SeaweedFS OCI33. **15 native scenarios +8 API/store tests PASS**, including abrupt JVM halt before/after PUT, response loss, concurrency, generation changes, finite budgets and V38 receipt upgrade.

Application changes are reviewable in [ouf-source-onboarding PR54](https://github.com/GioNob/ouf-source-onboarding/pull/54), final source `b64e8b5bc514223aa562719d31eb027e7f27b7b9`. All7 source workflows SUCCESS, including the complete module CI, blocking image scan and container boot. The scan initially rejected inherited Ubuntu apt packages; the bounded Dockerfile fix and original failed scan are preserved. General Maven suite executed365 tests successfully; the15 native tests run separately.

[Independent hosted readback41991405508](https://github.com/GioNob/ouf-deploy/actions/runs/41991405508) SUCCESS: original native artifact39members/38checksums,258 source SHA256 bindings and446 Git blobs verified; receipt byte-identical to the local canonical result. Original artifact13397423414,61920bytes SHA256`91b7f31c4e73510a0d58aefd7408ec6a91c988db404db2baa9aac753cacca37a`. Readback artifact13398352499,87905bytes SHA256`8c27623293d65c218b926d990d5608c7b0c837328c99c56a6052c35310939586` contains the unchanged original. First CRLF/LF comparison failure and its diagnostic remain preserved.

Deploy checkpoint: `99594c878a3130a353531841e91c53c38741dbd0` on the requested branch.
- [Dossier](https://github.com/GioNob/ouf-deploy/blob/99594c878a3130a353531841e91c53c38741dbd0/docs/OUF_STORAGE_ONBOARDING_UPLOAD39_20261105.md)
- [Final receipt](https://github.com/GioNob/ouf-deploy/blob/99594c878a3130a353531841e91c53c38741dbd0/evidence/onboarding-upload39-hosted-readback-20261105.json)
- [Previous PR body, preserved verbatim](https://github.com/GioNob/ouf-deploy/blob/99594c878a3130a353531841e91c53c38741dbd0/docs/handoffs/OUF_PR54_STORAGE_HISTORY_BEFORE_UPLOAD39_20261105.md)

Earlier acquired proofs remain intact: compaction/crash189tests/14scenarios, physical common-cut35tests, fresh-runner exported restore44tests, and writer-source map256files. Previous deploy head783f883e completed50/50 workflows successfully. Automatic checks on later documentation checkpoints are separate from that result.

Limits remain explicit: owner ACK fence does not physically revoke in-flight S3 credentials or fence all UDP/Ingestion writers. Direct requests without Idempotency-Key remain distinct. No common-cut/PITR qualification of V39 tables, mixed rollout or wire-level response-loss claim. The Windows workspace became unavailable after local verification; final publication and checks continued through GitHub.

Next pair: integrate this owner's drain/fence/reconciliation with the coordinated PostgreSQL/S3 fixture, then qualify recovery and rejection of stale writers. Persistent preference: **two steps per continuation**, no subagents.

MiniPET18.3/46=39.78%;0/8 gates,0/21 acceptance tests,0/120 real objects. Source lock and MinIO unchanged. No merge, deployment, target operation, admission, replay, reset, grant or real-data reacquisition.


## Onboarding PR54, descrizione conservata integralmente

Managed-file uploads previously wrote S3 before a durable upload intent existed; a crash or lost reply could leave an untracked object and a retry could allocate another key. V39 now reserves owner, request identity, expected bytes, stable object reference and storage epoch before PUT. Both upload routes perform network I/O outside database transactions and acknowledge only under the same ACTIVE generation. Repeats read the receipt or reconcile the same object's exact bytes, with no second PUT and a persistent 128-read/24-hour bound.

Direct upload accepts optional Idempotency-Key; unkeyed requests remain distinct. Existing successful delegated receipts survive V38→V39 unchanged. No deployment or source-lock promotion is included.

Validation completed:
- Final head `b64e8b5bc514223aa562719d31eb027e7f27b7b9`: all seven push/PR workflows SUCCESS.
- [Native actual-owner run41990619971](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41990619971): 15 PostgreSQL17.11/exact OCI33 scenarios plus8 API/store tests PASS. Includes separate JVM halt before/after PUT, ambiguous response, concurrent retry, stale generation, bounded reconciliation and V38 upgrade.
- [Full module PR CI41990627231](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41990627231) and [push CI41990619972](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41990619972) SUCCESS, including blocking image scan and staging-enabled container boot. General Maven suite:365 executed PASS;15 native cases skipped there and all executed in the dedicated job.
- [Independent readback41991405508](https://github.com/GioNob/ouf-deploy/actions/runs/41991405508) SUCCESS for the original qualified source9d8a1ec:39 artifact members,38 checksums,258 SHA256 source bindings and446 Git blobs; canonical receipt byte-identical to the local verification. The only change from9d8a1ec to final head is Dockerfile.
- The full image scan initially found inherited Ubuntu apt/libapt-pkg7.0 HIGH findings. Updated both to3.2.1ubuntu0.1; scan threshold remains unchanged. Original failed scan and the first readback's CRLF/LF formatting failure are preserved.

Scope: application ACK fencing does not revoke in-flight storage credentials, stop other deployed writers or establish a common recovery cut. Wire-level lost-response faults and operational rollout remain open. No target operation, HUMAN authority, merge, admission, reset or grant.

[Deploy coordination PR54](https://github.com/GioNob/ouf-deploy/pull/54), [complete evidence dossier](https://github.com/GioNob/ouf-deploy/blob/99594c878a3130a353531841e91c53c38741dbd0/docs/OUF_STORAGE_ONBOARDING_UPLOAD39_20261105.md), [final evidence receipt](https://github.com/GioNob/ouf-deploy/blob/99594c878a3130a353531841e91c53c38741dbd0/evidence/onboarding-upload39-hosted-readback-20261105.json).


