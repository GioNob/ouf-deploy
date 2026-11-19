# OUF Onboarding → Ingestion / Gateway Contract Set — v0.6

## Scope

This revision materializes all currently source-supported runtime contracts that cross the boundary from
Source Onboarding / Configuration toward Ingestion and Urban API Gateway.

It does not expand into workflow/approval, THS, AuthorizationPolicyBundle, Semantic Registry APIs,
managed-file intake, schema-surveillance DTOs, supplier vertical APIs or MCP Server.

## Result

**PASS**

Contracts materialized: **14**

- PublishedConfigurationBundle
- ExtractionProfile
- SyncProfile
- SourceObjectIdentityPolicy
- TemporalMapping
- ChangeRepresentationProfile
- DeltaPatchContract
- SemanticMapping
- RelationshipMapping
- AuthorityPolicyDescriptor
- DataAccessPolicy
- SourceRuntimeProfile
- SourceSchemaBinding
- RouteBinding

## Boundary principles

- Onboarding owns full approved source configuration.
- Gateway receives/materializes only the technical runtime projection required for routing and egress.
- Ingestion consumes the pinned immutable bundle and does not reconstruct configuration from Onboarding tables.
- Gateway does not interpret semantic mapping, field classification or ontology/vocabulary decisions.
- Source-object identity is provenance identity, not UrbanObjectId.
- Authority and access labels are propagated, while final conflict resolution/access enforcement remain downstream.
- DELTA_PATCH requires a precompiled logical DeltaPatchContract; physical UDP indexing remains out of scope.
