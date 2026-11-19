# Registry recovery: native path implemented, target repair still open

The required result is recovery of the exact reviewed Registry followed by HTTP 200 for the original authenticated semantic-reference request. No VPS operation occurred during this source work. The 502 remains OPEN.

## Incident and corrective target

The owner-provided current route receipt binds the semantic GET to the reviewed stopped Registry, with no network endpoint at its configured address and port. The subsequent shutdown receipt corroborates Docker termination, containerd stop and host shutdown in the Registry stop window. Restart policy is `no`; its entrypoint waits for a fresh, admitted SIGUSR1 before starting Java. This explains why an ordinary Docker start is insufficient. The initiating shutdown actor and a reproduced data-plane failure remain unproven. Historical readers must not be replayed.

Correct the exact Registry's availability. Preserve Gateway routes and the other services. Do not retry source activation. A fresh process must receive fresh current admission and its own attestation; old process claims and signatures remain consumed.

## Source and qualification

Qualified source: `f5937486fcfe1e461caed65abf45ca49887ca33f`.

[CI 39871804763](https://github.com/GioNob/ouf-deploy/actions/runs/39871804763) passed 87 tests, with zero skips: 82 component/regression tests, three real Docker generation tests and two real PostgreSQL 17 tests. Every one of the 17 changed implementation/test/workflow files was read back at that exact commit and matched the published content. Evidence: `evidence/semantic-registry-native-path-ci-20261023.json`.

The newly connected path includes:

- `factory.py`: typed read-only construction from a complete current context, actual CutoverAuthority, actual InstalledTokenOwner observer, verifier and signer. It preserves the historical image/frame/rootfs recipe and configtree. The canonical recovery directory must be under the original installation's evidence parent; copying retained inputs elsewhere cannot bypass consumed claims. The factory creates no directories, journals, authority or tokens.
- `native.py`: concrete NativePorts connecting all 12 recovery stages. Actual owners guard start, pause, attestation, current admission, unpause, the same generation's SIGUSR1, readiness and final authenticated GET. No boolean/callback substitutes enter the factory.
- `database.py`: current PostgreSQL generation and executable custody, current reviewed image admission, and a bounded readonly psql session checking database name/OID, connection admission, role and complete ordered Flyway history. No migration or database write is performed. The subprocess uses the exact Engine socket, an empty Docker configuration and a sanitized environment.
- `read_budget.py`: separately durable, signed native-read counters. Slots are consumed before transmission. Existing counters are never reset or recreated by a reader. Proposed limits are not a new granted budget.
- `admission.py`: current database plus actual token-owner admission. Parked, expired or revoked owners stop recovery; there is no token acquisition, automatic renewal or login fallback.
- `process_binding.py` and the versioned observers: the fresh process remains tied to its first durable start generation after unpause. The complete independent rootfs seal is checked again before Java release. Running Java is not reported as a pristine paused rootfs.
- `node_owner.py`: private retained paused observation and authenticated acceptance are tied to the original durable signature attempt. A retained signature is explicitly historical paused evidence, never a claim that the process is still paused.
- `gateway.py`: complete current route equality and exact target occupancy checks using the qualified admin GET primitive with a distinct signed read scope. It does not replay the completed diagnostic or write routes.
- `semantic_request.py`: bounded original semantic GET using the existing Ingestion service token, exact frozen reference versions and the current pinned Gateway. Token bytes travel through private stdin, never argv/environment/logs. TLS requires CA verification and an independent certificate pin; redirects and credential refresh are disabled. Health 200 cannot substitute for this request.

The production caller was checked in `GioNob/ouf-ingestion-runtime` at `4165b9e149be467d5d7c6bed35e4e1af4e249db1`: `PublicationGatewayClient.java`, `FrozenConfigurationProbe.java` and `PublishedActivation.java`. It uses the configured activation service token and query fields semanticId/revisionId/publicationSetId, then checks exact version/reference and ACTIVE state. The recovery verifier follows that contract. It must not use the HUMAN administration token or invoke activation/readiness flows that can dispatch other application operations.

## What the tests establish

HTTP/TLS tests execute real sockets and the sealed private-stdin client with disposable credentials. They reject 502, a different reference/version, non-ACTIVE state, redirects, 401/403, token drift and TLS pin mismatch. NativePorts wiring tests deliberately substitute native owners and are component tests. Docker tests use an Alpine waiting shell, not the Semantic JVM. PostgreSQL tests use a real disposable PG17 container, Engine client and readonly session; image/node/token admission is synthetic in that fixture. Ed25519 tests use disposable authority and synthetic node reports.

These tests do not qualify the whole production recovery against real Semantic JVM, independent OCI/rootfs recipe, live IAM/token owner, Gateway and retained target inputs together. They do not establish target service readiness or resolve the 502. The original shared frame/node/mount observers remain unchanged; completed source caches and historical binding hashes remain valid.

## Remaining operational blockers

1. Complete the sealed source closure/loader, immutable current-context collector, native installer, issuer and delivery/launcher. The installer must initialize the one canonical directory and both finite ledgers only after independently authenticated current scope, preserving all existing claims. There is no executable target recovery command yet.
2. Resolve the exact currently authorized InstalledTokenOwner from reviewed target references and prove its current admission. The factory accepts this actual owner but does not select, revive or recover it. Some owner profiles bind a running Registry generation; the selected target profile must be inspected before declaring that composition feasible. No bootstrap cycle has been established from the available receipts. If its worker is parked/expired or requires governed recovery, that is a distinct real blocker, not permission to renew or reset it silently.
3. Qualify the complete executable path with representative native owners and the actual Semantic JVM, including crash/reconciliation boundaries, partial signatures, rootfs drift, revocation, current route/endpoint and refusal to close on final GET 502.
4. Only then prepare the exact review and fresh native HUMAN/dual-role authority. The user's instruction to fix the incident authorizes development; it does not manufacture the signed target records required by the existing implementation. Do not request premature login/token/window approval.
5. Execute through the operator terminal, the only available VPS channel, then verify every original semantic reference through the same service-authenticated GET. A source commit or green CI is not target recovery.

The current container may retain JVM-created writable-layer files. Full independent rootfs admission remains mandatory for the new paused PID. No historical running-JVM exception, silent cleanup, image replacement or relaxed seal is selected. A successful one-time recovery also does not by itself prove a persistent postboot recovery policy.

## Retained state

Preserve every proposal/history/composition/context/claim/log, including the historical input SHA256 `8facd750a673d25c14bfc1a58c8c0ae28d63d8a5ce487ab956b8f2b23dc902c9` and composition SHA256 `65717005bcbcd03c342832193cabb5f23160583972635337159a0e5334de7e81`. Owner receipts remain owner evidence, not independent VPS readbacks.

Patch 12/12; technical 8/8; functional 4/6; WP3/CSV-H-13; G3 OPEN; nativeProfilePublished false; releaseAcceptance false. OAuth history 304/304 remains exhausted. The source's historical window is not renewed. No runtime authority, target effects, automatic authentication, provider recovery, activation replay or budget reset occurred. Normative originals consulted: Matrix 1.7 §1 and Registry PET 1.3 §§160.6–160.7.
