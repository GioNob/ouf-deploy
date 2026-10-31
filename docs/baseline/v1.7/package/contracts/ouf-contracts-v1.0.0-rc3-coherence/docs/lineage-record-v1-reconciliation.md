# LineageRecord v1 reconciliation note

## Scope

This revision reconciles **only `LineageRecord v1`**.

It intentionally does not define or modify:

- HandoffPayload v1;
- CanonicalDataEnvelope v1;
- replay request/response DTOs;
- quarantine/runtime issue schemas;
- UDP physical lineage indexes;
- relationship-resolution evidence schemas;
- source-provider contracts.

## Source-derived contract

The Ingestion Runtime v1.2 defines LineageRecord as the minimum evidence linking source, acquisition, contracts,
processing and output.

The field groups materialized here are:

- Identity: `lineageId`, `ingestionRunId`, `ingestionId`, `handoffId`;
- Source: `sourceId`, `typeCode`, `sourceObjectId`, optional `sourceRevision`, `sourceObservedAt`;
- Contracts: `sourceSchemaRef`, `bundleRef`, `mappingRefs`, `semanticPublicationSetRef`, `adapterProfileRef`;
- Processing: `pipelineVersion`, `transformationIds`, `validationResultRef`;
- Data: `rawObjectRef`, `rawHash`, `normalizedHash`, `outputHash`;
- Times: `acquiredAt`, `processedAt`, `handedOffAt`;
- Trace: `correlationId`, optional `traceId`;
- Outcome: `SUCCESS | QUARANTINED | TOMBSTONE | FAILED` plus `issueRefs`.

`processingAttemptId` is included as an optional processing field because the v1.2 identity/correlation section
explicitly states that the attempt/replay identifier is persisted in lineage/quarantine.

## Propagation and retention

- `lineageId` is propagated in HandoffPayload and preserved by UDP as a provenance reference.
- One canonical Urban Object may have multiple revisions with different lineage evidence.
- Relationships materialized downstream must be able to reference the evidence contributing to resolution.
- Reprocessing with different contracts creates new lineage/revision and does not rewrite historical evidence.
- LineageRecord retention is at least aligned with the associated canonical/audit output and it is not deleted independently.

No new lineage product or dedicated infrastructure is introduced.
