# OUF Semantic Registry Cross-Module Contracts + Consistency Check — v0.8

## Result

**PASS**

Contracts materialized: **12**  
Cross-module invariants: **18**

## Contracts

- SemanticReference
- ArtifactDetail
- ArtifactRevision
- SemanticPublicationMember
- SemanticPublicationSet
- SearchResult
- DiscoveryRequest
- DiscoveryCandidate
- ExternalOrigin
- SemanticChangeNotice
- ImpactReport
- SemanticMigrationProposal

## Core boundary

The Registry is authoritative for semantic identity, TBox/vocabulary/relation semantics and immutable publication snapshots.
Source Onboarding owns source-specific mappings and resolution strategy; Ingestion consumes exact published references read-only;
UDP preserves semantic provenance and materializes ABox objects/edges.

The immediate consistency check validates exact PublicationSet pinning, member/revision/content-hash consistency,
consumer id/version/manifestHash alignment, historical no-latest fallback, candidate-vs-official identity separation,
and coherent change-notice/impact/migration references.

## Deliberately excluded

Approval/THS contracts, Authorization policy contracts, source-specific mapping authoring, UDP ABox DTOs,
Query Governor/budget, MCP implementation, mandatory SHACL, and new semantic infrastructure.
