# Native archive successor — 22 October 2026

## Purpose and target boundary

The retained native input bundle uses configuration image ID sha256:76c38ddfc886b9e004064fd19bcfe561ce5b8459de241c625765afab5a7260bc. Docker29 uses the distinct native manifest ID sha256:d173aa8beeb9a1ac29c35a163e254a902e95fedad2871e328886a41831c10697. The existing audited image_custody adapter links these identities while preserving configuration/layer bytes. The prequalified tagless tar SHA256 is d8acfed23e9388d6ba5434a5731789c8b272395208f07272aeae4c7eb4c6026e.

The new offline preparation reads the completed parent ab6c1953b8eb0bed19fdd1ee82c4b34828642726e4582152852eb5b4711f14ec and the already retained compressed archive SHA2565f6893d1ac63d5c5ee96c961e5c91a3b1c058a6300af169663961f1d5fbf8be6. It performs no image download/import, Engine/API/SQL/provider call, runtime operation, bearer/key-file read or login. It writes a DISTINCT root-private context and one persistent preparation claim. This is a necessary native-format successor, never a rerun or rewrite of the completed parent preparation.

The capsule expands and audits the retained archive, re-envelopes it without tags, verifies the exact derived tar/native ID, re-audits all configuration/layer bytes, seals new files400 and authenticates the immutable parent again. It retains original archive provenance/stage-intent hash and the same logical operation6c7d73cbc2d9c613d5fe0b4fafe5ac20853478a883bf15371dadbb3f201afbc5. It only changes native image/archive bindings and corresponding reviewed intent hashes. Gateway/Owner/Postgres/application snapshots remain historical inputs; no fresh runtime gate is claimed.

After success or STOP preserve every file/claim/log. A second invocation fails before rereading the parent/image. An incomplete context is reconciliation-only; never remove a claim or replay with a new case.

## Qualification

At a1ed61aba1954c3d62ab60b55723357ad6e38573, CI39716681130 passed all jobs:28 tests per Python3.12/3.13.5 and3 full Docker29/APISIX/JVM/Postgres17 tests. Full isolated sequence13stages(two networks),8Engine POSTs,0Gateway writes,0new keys. Lost-create response and expired-bearer boundaries passed. Real native image/config/rootfs custody is recorded in CI39716055766/job119618314393.

The new139-module sealed graph adds only archive_preparation/archive_projection/custody to the previously136-module graph. All114 original frozen source hashes are checked against the immutable qualified production capsule; source paths alone are not treated as byte proof. New tests use actual isolated capsules, actual root-private archives, safe shell download/hash/log execution and corruption/partial-STOP/no-replay cases. Local35 scoped/loader/authority/archive/delivery tests pass across their suites. The new delivery CI is pending until recorded below; no operator command is published before that qualification.

Infrastructure issuance is tested with disposable keys and a synthetic HUMAN journal. A real isolated entry test verifies executable/stdlib custody, creates both role signatures, reloads the issued authority and initializes an empty journal without any runtime effect. The fixture uses /usr/bin/python3, a synthetic boot identity and a Python executable in the non-invoked Docker slot; it does not prove real Docker admission or current target authority. Separate full platform tests cover actual Docker/PG/APISIX/JVM.

## What follows

Once the new delivery CI passes, publish a single pinned offline archive-preparation launcher/capsule and return its exact command. No fresh HUMAN authentication, OAuth budget extension or runtime approval is requested by this preparation. The eventual execution controller/delivery, complete fresh-human governance path and separately explicit finite infrastructure consent still require implementation/qualification before asking for tokens.

Target remains technical8/8,functional4/6,G3OPEN,OAuth292/292; patch not installed and releaseAcceptance:false. Existing source approval and paused activation remain distinct. Consulted original Matrix1.7 §1 for ownership and Ingestion1.3 migration-safety baseline: no migration or owner/HUMAN contract change.

## Exact packaged delivery checkpoint

Capsule commit7a22715eadf10d1b574e6ef4af36f2ae0c0bca48, capsule SHA25613335a0aa4ba672c80cc2f63ca1b3e2e9d97b111f876d61c62dbda514d8d4f31, wrapper SHA256f3bcc189874e2264c8ab4cefca9ddc9cb11a281607e6d13ee9d1d77d063fefd7. The exact public case hash is86a63c83ae644484400e2e3531db57e5aa4869ca8c5f17bcbec908de889bb6c6. Target output will be /etc/ouf/deploy-snapshots/ingestion-readiness-native-archive-86a63c83ae644484400e2e3531db57e5aa4869ca8c5f17bcbec908de889bb6c6. Target execution has NOT occurred.

The release adds two production artifact/launcher reproducibility checks, bringing local focused count to37. Actual root-private archive/capsule/wrapper tests still use isolated synthetic files; no real target was accessed. CI39717720682 Python failures came from an absent historical capsule in a new regression test. The corrected test uses a canonical hash fixture extracted only after verifying original artifact SHA42b2569a0ba1f2234dfbcc011588cdf133d0e5c97a3f3433b903750f010448ea; fixture SHA7771116d297cb5c0aa7037d294fb5b72c8e489bc308075a95edc39149699822a. It compares all114 current frozen source hashes, not just source paths. No policy relaxation or source hash regeneration from the new graph was used.

This version stabilizes only the compressed source-capsule envelope across Python3.12/3.13; image configuration/layer bytes remain unchanged. Before publishing the terminal command, record the final delivery CI outcome and immutable job references. Expected public result is NATIVE_ARCHIVE_INPUTS_PREPARED_NO_AUTHORITY, complete:true,plannedStages:12,imagesImported:0,oauthRequests:0,runtimeEffectsDispatched:0,runtimeAuthorityIssued:false. This input completion is not new runtime health/admission or patch installation.
