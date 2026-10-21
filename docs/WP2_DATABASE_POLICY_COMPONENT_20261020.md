# WP2 — read-only database snapshot policy component

2026-10-20. Technical8/8, functional4/6. G1 PASS; G2 OPEN.

Reuses the fixed read-only PostgreSQL17 catalog query,18 Flyway migration
resources/checksums and qualified schema digest from
`scripts/read-ingestion-db-postboot-preflight-20261020.py`.
The historical selection/context/owner/projection constants are not imported or
executed. This preparation does not replay the completed target preflight.
The query adds only current serverPort to bind an explicitly selected per-Ente
PostgreSQL port; database name, user and OID are explicit profile inputs.

The new strict boundary rejects incomplete role memberships/flags, duplicate
privilege/history rows, numeric substitutes for booleans, omitted work/headroom
counters and snapshots older than5seconds or from the future. Fresh role/identity,
release schema/history, grants, pressure and drained-work predicates remain
required. A DB snapshot never by itself proves startup policy or grants runtime
authority/admission; current HUMAN, Owner7/payload/projection and actual runtime
generation still have to be composed in NativePorts.

Nine local synthetic-fact tests pass. Their positive catalog branch explicitly
patches the reference only inside the unit fixture. Production keeps the
qualified digest fixed; the empty fixture catalog fails that real release pin.
The native SQL channel, real candidate JVM startup and complete gate composition
still require WP2 qualification. No Docker/SQL/Owner/Gateway target calls,
credential access, migration or privilege modification occurred.

Normative references consulted for this component: original Blueprint0.3 §§9–10
(build/database/integration versus representative-acceptance gates) and AGENTS
current-admission, installation configuration and retained-budget rules.
