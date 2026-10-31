# HandoffPayload v1 reconciliation note

## Scope
Only `HandoffPayload v1` is reconciled in this revision.

Out of scope:
- CanonicalDataEnvelope v1
- LineageRecord v1
- DurableHandoffReceipt / ACK payload shape
- CandidateCanonicalObject as a separate shared schema
- UDP materialization DTOs
- supplier/source API contracts

## Normative points reflected
- `handoffId`, `ingestionRunId`, `ingestionId`, `sourceIdentity`, `operation`, `contractRefs`, `lineageId`, `contentHash` and acquisition time are part of v1.
- `canonicalPayload` is required for UPSERT.
- `operation` is UPSERT | DELETE | TOMBSTONE.
- `rawObjectRef` and `qualitySummary` are optional/recommended.
- Schema, bundle, semantic set and adapter profile are pinned; mapping refs are preserved.
- `changeRepresentation` is FULL_SNAPSHOT, DELTA_PATCH or PROPERTY_EVENTS.
- Delta/event modes carry base revision/hash or event sequence as needed.
- observation/validity times and access labels are preserved when declared.
- UDP remains authoritative for UrbanObjectId, merge/split, authority competition and final materialization.

## Durable ACK
ACK semantics remain contractual but are not encoded in this payload:
- ACK means durable acceptance, not HTTP receipt/enqueue/schema validation;
- committed watermark does not advance before required ACK;
- retry reuses the same handoffId;
- duplicate handoff/ACK is logically idempotent;
- object resolution/materialization may complete after ACK.
