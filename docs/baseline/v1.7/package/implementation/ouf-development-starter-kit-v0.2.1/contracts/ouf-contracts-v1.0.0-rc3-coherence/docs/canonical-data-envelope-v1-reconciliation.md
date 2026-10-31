# Canonical Data Envelope v1 reconciliation note

## Scope

This revision reconciles **only the OUF Canonical Data Envelope v1**.

Out of scope:

- HandoffPayload v1;
- LineageRecord v1;
- Candidate Canonical Object / semantic processing output;
- TransformationRule / Mapping schemas;
- source-provider API contracts;
- UDP materialization and serving DTOs;
- replay/quarantine/runtime issue DTOs.

## Boundary

The envelope is the stable internal boundary between Connector/Adapter and the Ingestion processing pipeline.
The source-specific payload remains under `data` (or a durable source-data reference) and does **not** become the
OUF canonical Urban Object model.

## Source-derived minimum contract

The Ingestion Runtime v1.2 freezes:

- `envelopeVersion` — baseline `1.0`;
- `ingestionId`;
- `runId`;
- `sourceId`;
- `typeCode` when applicable;
- `sourceObjectId` for record envelopes, explicitly not an `urbanObjectId`;
- source schema identifier + version;
- PublishedConfigurationBundle identifier + version;
- `operation = UPSERT | DELETE | TOMBSTONE | SNAPSHOT_RECORD`;
- `observedAt` and `acquiredAt` as UTC timestamps;
- `contentType`;
- conditional source-native/adapted `data`;
- required non-secret `provenance`;
- optional additive `extensions`.

## Compatibility

The PET requires consumers to ignore unknown optional v1 fields and reject an unsupported major before processing.
Therefore the schema keeps `additionalProperties: true` at the envelope root.

The concrete schema artifact represents baseline `envelopeVersion = 1.0`.
A later compatible 1.x artifact may add optional fields without changing the semantics of required fields.

## Deliberate non-inference

The PET says `typeCode` is required "when applicable", `sourceObjectId` is required "for records", and `data` is conditional.
It does not freeze a machine-readable discriminator that allows those conditions to be encoded without guessing.
This schema therefore documents those rules but does not invent conditional logic that could reject valid future envelope classes.

The PET mentions provenance for correlation, route and page/change-token references, but does not freeze a complete provenance DTO.
Only those source-supported concepts are represented; additional non-secret provenance remains extensible.
