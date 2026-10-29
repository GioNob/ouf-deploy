# CSV Cinema: documented file-to-UDP chain and current authorized search

11 October 2026. This reuses the component evidence of 1 October, as requested by the owner; it does not replay the succeeded run or its consumed schedule. [Current safe serving evidence](../evidence/cinema-current-authorized-serving-20261011.json).

| Link | Evidence | Result and scope |
|---|---|---|
| Managed CSV/profile | Asset8ec8ae90-808a-4d9e-907c-d56de119e376, profile4462692b-9c85-446b-b6fd-779f01eab64d; September27 handoff | Existing governed file/profile; no new upload/profile |
| Published semantics | Current exact get: Cinema revision51706bed-81e4-4306-aca1-70119821727d, publicationf92a2e17-30c9-456f-bb12-63afa84f41e6 | ACTIVE;17 asserted statements, complete projection; Cinema subclass of schema:MovieTheater |
| Source/bundle and ingestion | October1 owner readback: managed-cinema-8ec8ae90/version68394f42-5c82-4127-a1f3-126516665749; run86809c17-3354-45ca-a7e6-57e903944b24 | Documented ACTIVE/SUCCEEDED; trigger_once consumed/DISABLED; historical evidence retained |
| Durable ACK and materialization | October1 owner readback |8 ACKED handoffs/lineages;8 PROCESSED intakes/SUCCEEDED jobs/NEW_OBJECT decisions/observations/revisions/bindings/active objects; resolved quarantine/retry audit retained |
| Actual authorized serving | Current MCP urban.object.search, ouf-admin, exact canonical Cinema IRI, pageSize20 |8 ACTIVE objects/revision1, nome/indirizzo visible; nextCursor=null, partial=false |

The current search establishes a previously missing serving result. It does not by itself join the returned UrbanObjectIds to the historical ingestionRunId. Both current source status/history MCP reads were denied with authorization denied, retryable=false. No retry, alternative account, direct database workaround, route/grant expansion or source replay was used. Their published descriptors require ingestion.operations.read; the precise denying runtime layer and complete readiness must be inspected before any governed release proposal. Historical documentation warns that OA dispatch/producer bindings may be incomplete; a broader grant alone is not a remedy.

**Full exact-lineage acceptance remains open.** Obtain an authorized bounded owner lineage/status read connecting this run and its handoffs/bindings to the eight returned IDs, preserve historical retry/audit, and qualify search-specific negative authorization. Independent RAW/NORMALIZED/CURATED byte/hash verification and clean-host installer acceptance remain separate. Current source-history denial is an access/readiness boundary, not a transient dependency incident.

The Teatri fixture remains separate:13rows/20columns, no new source/run/objects yet. The new signed SemanticV11 package was qualified and staged on the VPS but not imported/applied. Cinema serving succeeded on the existing runtime; it does not prove new-image readiness, internal term-search completeness or Teatro semantic equivalence.

Historical sources: [September27 handoff](https://github.com/GioNob/ouf-semantic-registry/blob/3ec99277b8383e496913b9fd3bb05c877825abf5/docs/handoffs/OUF_HANDOFF_2026-09-27_R4A.md), [October1 next-sprint handoff](https://github.com/GioNob/ouf-semantic-registry/blob/3ec99277b8383e496913b9fd3bb05c877825abf5/docs/handoffs/OUF_HANDOFF_2026-10-01_FILE_TO_UDP_NEXT_SPRINT.md), [roadmap October1 19:28 checkpoint](https://github.com/GioNob/ouf-semantic-registry/blob/3ec99277b8383e496913b9fd3bb05c877825abf5/docs/OUF_ROADMAP_PET_1_7.md). Current read/serving results are recorded separately above; no property values/raw CSV samples are republished.
