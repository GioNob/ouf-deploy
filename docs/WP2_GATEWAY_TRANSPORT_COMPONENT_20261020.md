# WP2 — transport and custody component, 2026-10-20

Scope: preparation of CSV-H-08, not closure of G2. The complete NativePorts,
current read-only DB/Owner admission, image import, issuer and entrypoint remain
open. Roadmap: technical8/8, functional4/6. No target operation or authority.

## Installation contract

`gatewayTransportProfile` is part of the complete signed review hash. Its schema
`ouf.ingestion-rollout-gateway-transport.v1` requires an explicit loopback host,
port, root-custodied Python executable path/hash, complete selected config file
binding and optional separately selected admin-key file binding. Each file
includes path, bytes digest, full nine-field metadata and an ordered chain of
directory identities from root. No municipality-specific path, port, trusted
UID/GID or custody exception is embedded in the adapter. Profiles are private;
credential values and hashes are excluded from diagnostic proofs.

This is explicitly a local namespace-FD adapter. Its host placement must be
qualified with the selected Engine and replacement process. Distributed
installations require an independently qualified transport/profile; there is no
fallback to a guessed backend or host loopback namespace.

PET API semantics remain fixed: GET the complete APISIX route inventory, PUT only
the two exact reviewed route resources and values. The private child receives
endpoint/key/body only on stdin, uses the held new-process FD and performs no
redirect, proxy, login, refresh, discovery write or automatic HTTP retry.
Before/after checks bind the actual replacement generation, current HUMAN, role
signatures, journal and selected local files. The parent never calls setns.

## Claimed-once route changes

A full82-route comparison precedes each PUT. The persistent per-stage
`nativeGatewayPutAttempted` marker precedes dispatch; a lost response leaves the
claim and supports GET reconciliation only. The full expected map includes each
previous committed PUT and preserves the other80 routes. Neither a missing
attempt marker nor a changed collateral route authorizes retrying a claimed PUT.

GET429/502/503/504 returns a typed transient with the provider Retry-After floor,
for the finite Runner policy to consume. A PUT error remains ambiguous and cannot
be automatically repeated. No private credential is returned in proofs.

## Qualification and limits

Nine local tests passed on actual private files and rejected child inputs. Five
additional tests require the root signature fixture and an actual Linux
namespace FD; this CLOUD scratch does not expose /proc/self/ns/net. They use
actual Ed25519 signatures and persistent CAS with synthetic process/HTTP
observations: they qualify claim semantics, not Docker/APISIX readiness.
The native CI runs these together with16 finite-core and7 lifecycle regressions.
Completion/results are appended to the chronological evidence after observation.

No complete NativePorts, APISIX/DB end-to-end or deployment acceptance is claimed.
The original Gateway PET1.5 §§12–13 and AGENTS installation/custody/resilience
instructions were consulted. Full native integration is still required by
Mini-PET WP2.6/G2.
