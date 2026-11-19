# OUF Common Technical Contracts — v1.0.0-rc3-coherence

This repository materializes the cross-module contracts defined by the OUF System Integration & Development Blueprint.

## Status

**DRAFT / PRE-DEVELOPMENT HARDENING**

The repository is intentionally versioned `0.1`. It is sufficient to establish ownership, naming, versioning and CI targets, but it is **not yet the final v1.0 contract freeze**.

The schemas currently contain the core fields supported by the aligned PETs. Before promotion to `v1.0`, each owner must validate the field-level schema against its Development Ready PET and existing machine-readable artifacts, especially:

- `HandoffPayload` against Ingestion Runtime v1.2;
- `PublishedConfigurationBundle`, `SourceRuntimeProfile`, `ExtractionProfile` against Onboarding/THS v1.5;
- `SemanticReference` and `SemanticPublicationSet` against Semantic Registry v1.3;
- Authorization schemas against Authorization v1.4;
- Gateway publication artifacts against Urban API Gateway v1.3.

## Normative rules

1. A contract has one semantic owner and one canonical machine-readable definition.
2. Consumer modules must not create divergent local copies.
3. Breaking semantic changes require a new major.
4. Historical references required for lineage/replay remain resolvable for the supported retention window.
5. Authorization, identity and capability semantics fail closed when an unknown/incompatible mandatory contract is encountered.
6. OpenAPI/JSON Schema/examples are validated together in CI.
7. MCP Server is not modified by this repository; it consumes capability metadata and governed backend contracts only.

## Promotion path to v1.0

See `docs/v1.0-promotion-checklist.md`.

## v0.2 scope
Only `HandoffPayload v1` has been reconciled field-by-field. Other schemas remain draft skeletons.

## v0.3 scope
`LineageRecord v1` has been reconciled field-by-field. No other shared contract has been promoted in this revision.

## v0.4 scope
`CanonicalDataEnvelope v1` is now reconciled field-by-field. The Ingestion core trio — CanonicalDataEnvelope, HandoffPayload, LineageRecord — is materialized, while all other common contracts remain outside this revision.

## v0.5 scope
No new contract was added. The release only adds cross-contract invariants, fixtures and an automated consistency check for CanonicalDataEnvelope v1, HandoffPayload v1 and LineageRecord v1.

## v0.6 scope
All currently source-supported cross-module runtime contracts from Onboarding toward Ingestion/Gateway have been materialized and cross-checked. Approval/THS/Authz/Semantic API and supplier contracts remain out of scope.

## v0.7 scope
Authorization common/runtime contracts have been reconciled and immediately cross-checked. External IAM/M2M bindings remain explicit platform gates.

## v0.8 scope
Semantic Registry cross-module contracts have been reconciled and immediately consistency-checked against exact publication pinning and historical-resolution rules.

## v0.9 scope
Urban API Gateway boundary/runtime contracts have been reconciled and immediately cross-checked. One controlled correction aligns the draft common ProblemDetails profile with the Gateway v1.2 required `code` field.

## v0.10 scope
Check-only review of MCP Server v1.1 against the repository. Semantic integration passes, but two machine-readable contractization/projection gaps are intentionally left OPEN before a v1.0 candidate. No MCP Server artifact or behavior was modified.

## v0.11 scope
MCP-GAP-01 and MCP-GAP-02 are closed by adding the machine-readable MCP Canonical Capability Manifest and deterministic projection/source-of-truth rules. MCP Server v1.1 itself is unchanged.

## v1.0.0-rc1 promotion status
Final promotion/freeze check: PASS. Internal logical contracts are freeze-eligible with 0 internal blockers. Production/integrated release remains conditional on external platform integration gates.

## v1.0.0-rc2 identity integration
Added one scenario-neutral M2M Identity Integration Profile. Scenario A/B/C remains an unresolved external platform gate. Application modules depend only on normalized PrincipalContext semantics and environment bindings.

## Current status authority
See `docs/CURRENT_STATUS.md`. Files under `docs/history/` are superseded evidence, not current blockers.
