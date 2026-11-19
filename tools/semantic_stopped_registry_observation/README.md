# Historical observation after the retained Registry predicate failed

This distinct reader follows the owner-supplied `STOP_RECONCILE / HISTORICAL_REGISTRY_NOT_RUNNING`
receipt from `/home/oufadmin/ouf-semantic-transport.UIPPICGG/operator.log`. It does not rerun,
modify or complete `tools/semantic_transport_correlation`. That reader's live-Registry
precondition remains unchanged. Its combined predicate does not prove the precise stopped,
paused, restarting or identity-failure state. No cause of the HTTP502 was established.

The new question is deliberately independent of a live Registry address: what lifecycle
metadata does the exact historical container expose, and does one retained Gateway error
line contain both `NO_ROUTE_TO_HOST` and the exact GET `/api/semantic/v1/references:resolve`?

## Closed observation

The versioned installation case retains the completed12-stage context, the historical
RegistryID already selected by the prior case, and the same2026-10-22T13:12–13:15Z window.
It never discovers a replacement by name or substitutes a container. The completed patch
review supplies the exact Gateway process generation and Engine Unix-socket identity.

Exactly five possible Docker Engine GETs, in order: Gateway inspect, historical Registry
inspect, historical Gateway logs, Gateway inspect, historical Registry inspect. There is
no list endpoint, Registry log read, API probe, DNS/TCP probe, route-admin read/write,
credential-file read, OAuth/provider call, DB operation, retry or runtime effect. A404,
missing input, changed process/lifecycle/config/network, changed socket or changed retained
review/journal produces STOP without fallback. Maximum35seconds,4seconds/socket timeout,
2MiB/reply, tail4000, followfalse. A stopped/paused historical container can be observed as
data; it is never accepted as a current service binding. The second snapshots must match.

Output contains only closed lifecycle enums/booleans, bounded counters, validated timestamps
and same-line classifications. Neither raw errors/log lines, URLs, IP addresses, environment
values nor container identifiers are returned. An upstream path match is separate from an
address match. Address comparison is always null; current Registry identity, readiness,
route map and root cause remain unproven even when the read completes. Finish-time comparison
is only timestamp ordering, not lifecycle-history reconstruction or proof of causality.
An empty result or tail truncation never proves health.

Launch only once with the published Git commit and both SHA256 pins, using
`sudo python3 -I -B -S reader.py case.json`. Preserve all old contexts/claims/logs and the new
operator log. Do not rerun a STOP, restart a service, change routing, reset a budget or retry
activation from this observation.

## Qualification and normative scope

13 local stdlib tests PASS on Python3.12.14,0skips. They cover the complete five-call fixture
for stopped/running retained metadata, exact same-line/path matching, nanosecond/window
validation, lifecycle/config/network/context drift, closed paths/budget, duplicate JSON,
frame validation, private-file custody/symlinks, socket identity and public error redaction.
The HTTP test uses the actual stdlib HTTP client/parser with a simulated byte-stream socket,
including404 and no fallback. A real AF_UNIX socket cannot be created in this development
sandbox (`PermissionError`); no actual Docker/host/Unix-network qualification is claimed.
The unchanged predecessor's five regression tests also PASS,0skips. Target execution of
this new reader remains pending. These tests do not close G3, F5/F6 or release acceptance.

Consulted: original Matrix1.7 §§1,4,6 (owner truth, actual bindings, no manufactured health),
original Gateway PET1.5 T33.7 and §34 (failure semantics and safe operational projection),
Mini-PET1.1 §§12–14 (scope, evidence and STOP/reconciliation), and resilience policyv3.
This is an installation-specific operator diagnostic, not a product workflow or new MCP
capability. Existing owner APIs, domain authority and HUMAN/THS decisions are unchanged.
