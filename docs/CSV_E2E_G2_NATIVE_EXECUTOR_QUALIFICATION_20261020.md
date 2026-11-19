# CSV E2E — G2 native executor qualification

**Decision: PASS**, 2026-10-20T12:51:39.940Z (Europe/Rome14:51:39). Baseline Mini-PET1.1 remains d190193773116c9a59403aa42ccc9f89423eb959. Technical8/8, functional4/6; this does not close F5/F6 or authorize target execution.

Qualified source: [24c2d9b8c7b3f4f8a4a61125b86877ffbd635dba](https://github.com/GioNob/ouf-deploy/tree/24c2d9b8c7b3f4f8a4a61125b86877ffbd635dba). The114 module source hashes and loader were checked against the immutable Git blob identities before the receipt was compiled.92 scratch materialization files had an extra trailing newline; those were corrected locally only when the exact pinned Git blob matched. No remote code was altered by that correction.

| Proof | Provider evidence | Result |
|---|---|---|
| Signed CAS, finite budgets, drift/revocation/restart, custody, issuer, isolated loader | [run39424156253](https://github.com/GioNob/ouf-deploy/actions/runs/39424156253), job118632330532 |162tests PASS, no skips |
| Actual PG17 finite native collector, repeated readonly snapshots, drift and role rejection | [run39424156111](https://github.com/GioNob/ouf-deploy/actions/runs/39424156111), job118632329877 |3tests PASS |
| Actual Docker29, two networks, APISIX/etcd, candidate JVM, full sequence, loss and expiry | same run, job118632330311 |3tests PASS; completed12:49:12Z |

The happy path executes through a verified-memory114module loader under Python-I-B-S, the new issuer using existing disposable Ed25519 fixture keys, exact two-role scope and sealed entry. Every explicit step reopens NativePorts; a separate readonly oracle reopens the issued action and checks persisted results. No reset/reissuance/replay is used. All29stages complete: exactly2GatewayPUTs, all82routes matched,80unrelated routes retained, predecessors stopped/retained, durable new CIDs and first process generations, restart policies restored. Final checkpoint:2966/4096direct EngineGETs,16/32directPOSTs,240/512OwnerGETs,80/128nativeSQLsessions. Lost actual CREATE reply without durable CID remains UNKNOWN and is not rediscovered or replayed; expired bearer dispatches no effects.

Candidate native image ea64511009e8fa29d1df0bab1edf0ab4656dd7336c3fae967728f0d288119a77 is distinct from its configuration-image identity5dfdf2239fa9eb3ae2ff8510521322cf91718bc787eee179db8e65c515a30e8b. Candidate source remains0fe0de60c6d980fe97610acf195d4bfd46d3777f. WP5 images are not substituted into this qualified retained rollout.

## Limits and next gate

The HUMAN bearer/decision, Owner GET service and bootstrap qualification input are explicitly synthetic within disposable CI. This is an executor qualification, not current provider authorization, actual Owner7 readback, target DB admission, deployment, native profile publication, PLAT representative acceptance or F5/F6. The adapter qualified here is Linux/local custodied Unix Engine with namespace FDs; independent multi-host transport acceptance remains a separate final installation-profile obligation. All fixture network addresses/MACs are observed parameters, not installer defaults.

Historical HUMAN278/288 and the closed20October00:57:44Europe/Rome window remain history only. No login/refresh/reset/renewal or target request was made. WP3 requires a current governed HUMAN/THS decision and qualified target executor, exact retained contexts/claims, fresh Owner/DB/generation evidence and effective validate-only startup. Existing completed Owner7/publication/preflight actions must not be replayed.

Normative originals actually consulted for this decision: Matrix1.7§1; Blueprint0.3§§9–10; Ingestion1.3§§146–146.1; Mini-PET1.1WP2/WP3. Their release/representative gates remain distinct.

## Chronology versus baseline

G2 baseline cumulative central14h. Measured cumulative technical effort at decision **3.161h**; conservative bound including all initial/unverified intervals **3.731h**. This includes independent WP5 work interleaved during qualification and cannot be assigned wholly to WP2. Difference from14h lies between **-10.839 and -10.269h**. Baseline remains unchanged; no blanket10x/20x division or passive/HUMAN effort is inferred. WP3+WP4 retain their planned8–12active hours pending actual runtime gates; calendar completion cannot be inferred from that effort.
