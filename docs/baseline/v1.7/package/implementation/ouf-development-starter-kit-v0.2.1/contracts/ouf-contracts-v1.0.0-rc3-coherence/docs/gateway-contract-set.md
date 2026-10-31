# OUF Urban API Gateway Contracts + Consistency Check — v0.9

## Result

**PASS**

Contracts checked/materialized: **11**  
Cross-contract invariants: **21**

## Contract set

- Common ProblemDetails (controlled reconciliation)
- CapabilityManifest
- SourceRuntimeProfile
- ExtractionRuntimeProfile
- RouteBinding
- SourceSchemaBinding
- ClientCredentialBinding
- HealthState
- GatewayConnectorHandoff
- GatewayAuthorizationContext
- GatewayPublicationManifest

## Boundary

Gateway owns boundary crossing, identity validation, coarse capability authorization, route binding,
rate limiting, payload/stream controls, correlation, protocol governance and controlled configuration publication.

Gateway does not become fine-grained data authorization, Query Complexity Governor, Durable ACK authority,
schema-drift classifier, ETL/semantic processor, object resolver, GIS profiler, lineage store or UDP data layer.

## Controlled common-contract correction

The earlier draft `common/problem-details-v1.json` required `reasonCode`.
Urban API Gateway v1.2 explicitly freezes the OUF HTTP error shape with application field `code`.
The draft common contract is therefore corrected to require `code`; `reasonCode` remains optional for module-local decision semantics.

## Immediate check

The fixture validates exact capability/route/source/extraction/schema/context/publication consistency.
The negative fixture deliberately introduces capability, extraction profile, correlation, schema version,
MCP-security metadata, coarse-scope and ACTIVE-without-verification errors.
