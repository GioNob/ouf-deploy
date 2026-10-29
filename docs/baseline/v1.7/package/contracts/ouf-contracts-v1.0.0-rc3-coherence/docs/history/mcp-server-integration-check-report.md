# OUF MCP Server v1.1 — Integration Check against ouf-contracts v0.9

## Scope

Check only. No MCP Server contract, behavior, architecture, document or implementation has been modified.

## Result

Semantic/cross-module consistency: **PASS**

Repository v1.0 candidate readiness after MCP review: **BLOCKED by 2 contractization gaps**.

## What is aligned

- Gateway-mediated execution and no direct backend URLs.
- Capability identity is owner/canonical; tools/list visibility is not authorization.
- Server-side authorization plus backend fine-grained authorization.
- HUMAN_REQUIRED separation from AI_AGENT / MCP_SERVER / SERVICE_IDENTITY.
- Problem Details / Retry-After / mismatch errors preserved without semantic redirect.
- MCP orchestration budget remains separate from UDP Query Complexity Governor.
- Durable ACK semantics remain owned by Ingestion/downstream.
- SemanticReference / PublicationSet resolution is exact, with no invented latest fallback.
- MCP may create/link ApprovalChallenge and return trustedApprovalRef, but HUMAN confirmation is direct THS -> Gateway -> backend.
- Protected Human Operations remain non-discoverable/non-invocable through MCP.

## Open findings

### MCP-GAP-01 — P0 before ouf-contracts v1.0
The repository does not yet contain a machine-readable schema for the MCP Server v1.1 Canonical Capability Manifest.

The MCP PET itself freezes a richer descriptor with:
`toolName`, `capabilityId`, `capabilityVersion`, `owner`, `operationClass`, `mcpClass`,
`publicationState`, `toolEligible`, `requiredAuthorizationCapability`, `gatewayBindingRef`,
input/output schema refs, `actorTypes`, `baseCostEnvelope` and `conditionalOutcomeCost`.

This is not a contradiction with the Gateway CapabilityManifest. They are different projections.
But the projection must be machine-readable before independent teams implement both sides.

### MCP-GAP-02 — P1 before integrated acceptance
Source-of-truth precedence for MCP-only fields is not yet frozen in ouf-contracts:
`actorTypes`, `mcpClass`, `publicationState`, `baseCostEnvelope`, `conditionalOutcomeCost`.

The closure is a contract/repository task only. It does not require a new service or a change to MCP architecture.

## Scope-creep control

No new Agent Host, analytics engine, graph/vector DB, broker, THS operation, Query Governor or MCP runtime component is proposed.
