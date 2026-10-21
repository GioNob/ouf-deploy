# WP2 — current Owner/DB read components, 2026-10-20

G1 PASS. G2 OPEN. Technical8/8, functional4/6. No target calls or authority.

Owner control uses an explicit local Onboarding namespace FD and unchanged full
Engine runtime binding, including the reviewed existing restart count. Paths,
endpoint/port, namespace identity, executable, installation, immutable payload,
strong active ETag and selected projection are all private signed profile inputs.
It accepts only GET active and GET the retained immutable revision, sandwiches
the payload/projection check between two active reads, and never exports a
projection or writes to Owner. Backend JWT/capability checks remain authoritative.
The current HUMAN journal/token must match without renewal, login or wait loops.
The Onboarding source at b0f5e3 was checked: IamSecurityConfiguration,
InstallationBootstrapApi and InstallationConfigurationService retain bearer
validation and installation.configuration.read. Native backend/transport
qualification remains open; this source inspection alone is not acceptance.

The DB channel uses explicit database/user/OID/port, PG runtime and restart
binding, Engine socket, Docker executable, empty config directory identity,
container binary paths and Unix socket directory. It inherits no credentials.
The fixed SQL uses a repeatable-read/read-only transaction, bounded queries and
ROLLBACK. Current release policy checks the observed facts; the component cannot
grant standalone runtime admission or prove JVM startup migration policy.

Owner GET and SQL attempts are persisted before dispatch in the same private
CAS journal: maximum512 GETs and128 SQL sessions within the existing finite
review window. Creating another component object does not reset either counter.
Failed dispatches consume attempts. There are no retry, login, refresh or
background loops. Profiles explicitly describe local FD/Docker adapters;
distributed placements require separately qualified adapters, with no fallback.

Local tests:10 Owner and8 DB channel tests PASS under real role signatures/CAS,
with synthetic process/HTTP/SQL observations. Invalid child protocol/namespace
tests execute the sealed child and fail before HTTP. Actual Onboarding/Postgres,
candidate JVM, APISIX and full Ports/issuer/closure integration still require
WP2.6. These component results never close G2 or functional5/6.

Normative original references: Blueprint0.3 §§9–10, GatewayPET1.5 §§12–13 and
AGENTS installation identity, role custody, finite budgets and reconciliation.
