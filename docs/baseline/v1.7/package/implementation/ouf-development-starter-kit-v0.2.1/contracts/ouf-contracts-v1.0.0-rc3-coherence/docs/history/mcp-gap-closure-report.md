# OUF MCP contractization gap closure — v0.11

## Result

**PASS**

Both gaps from the v0.10 MCP integration check are closed.

### MCP-GAP-01 — CLOSED
Machine-readable schema added:

`mcp/canonical-capability-manifest-v1.json`

It mirrors the canonical descriptor frozen by MCP Server v1.1:
`toolName`, `capabilityId`, `capabilityVersion`, `owner`, `operationClass`,
`mcpClass`, `publicationState`, `toolEligible`, `requiredAuthorizationCapability`,
`gatewayBindingRef`, input/output schema refs, `actorTypes`,
`baseCostEnvelope` and `conditionalOutcomeCost`.

### MCP-GAP-02 — CLOSED
Projection precedence added:

`consistency/mcp-capability-projection-rules-v1.yaml`

The repository now freezes which bounded context is authoritative for each field:

- module owner: canonical capability identity/version/owner/operation and typed I/O;
- Authorization: required authorization capability, actor eligibility, HUMAN_REQUIRED semantics;
- Gateway: governed binding and exposure gating;
- MCP: toolName, mcpClass, publicationState and orchestration-budget metadata.

No new runtime registry or service is introduced.

## Validation

Two positive fixtures pass:
- ordinary MCP tool;
- TRUSTED_HUMAN_ONLY capability with `toolEligible=false`.

The negative fixture detects divergent capability identity, authorization binding,
operation class, physical Gateway URL, schema drift and conflicting tool eligibility.

## Scope control

MCP Server v1.1 is not modified.
The THS direct-human path, Protected Human Operations exclusion, Gateway mediation,
Authorization ownership and MCP orchestration-budget model remain unchanged.
