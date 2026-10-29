# CSV Teatri: source-scoped operational read correction — 12 October 2026

[PR63](https://github.com/GioNob/ouf-mcp-server/pull/63) is merged at `619d3b525ef5f904b327e6e3c5f6a6dad984df99`. Qualified source `4ab69097ecc6061ec0237211d4b3df7c859d6a22` has exactly the same Git tree as the merge. [Focused race qualification38304002148](https://github.com/GioNob/ouf-mcp-server/actions/runs/38304002148) and [full MCP CI38304002151](https://github.com/GioNob/ouf-mcp-server/actions/runs/38304002151) passed. All12 push qualification workflows passed for that source. [Exact subjects and limits](../evidence/csv-ingestion-source-read-qualified-20261012.json).

## Concrete correction

MCP status/history declared the owner permission `ingestion.operations.read` but evaluated their tool IDs and lacked source resource context. These two reads now bind that declared permission and the ingestion owner's existing operational resource type, trusted tenant, INGESTION module and TENANT_OPERATIONAL detail. The validated optional source filter contributes exact sourceRef. Source-only grants cannot authorize another source or an unfiltered collection.

Original tool IDs, Gateway bindings, request arguments, fingerprints, budgets and independent owner row/job authorization stay in place. No grant is added. The real SDK/cache/admission/HTTPS path exercises12 cases across both reads, client permission override rejection, owner refusal, fresh revocation and manifest drift. Gateway responses and authorization inputs are synthetic; this does not explain the old deployed denial or prove deployed Gateway/owner acceptance. Job-only grants may still deny collection preflight because the job identity is not established there.

The existing full verification passes pairwise gates, formatting, vet, PostgreSQL ordinary/race suites, build, migration/maintenance, staticcheck and vulnerability checks. There is no new transient retry, budget reset, owner incident/session or automatic replay.

## Actual CSV state

Current governed ONTOLOGY search for teatro through giovanni-chatgpt returned0 artifacts. This metadata search cannot establish absence of contained RDF terms. No incompatible Cinema domain is substituted and no semantic adoption/publication is performed.

The retained authorized Teatri profile remains13 rows/20 columns, asset6609b245-86ed-4315-8ce0-73f2a8555bf3, profile7984c39c-7396-4248-ab0a-f2efc390b49c version1. That is historical profile evidence, not a fresh raw-file read or active ingestion configuration.

No new ingestion status/history request repeats the previously permanent denial; no alternate account or permission proposal bypasses it. No target deploy, new run, ACK, object lineage join or search acceptance has occurred. MCP read correction is development progress toward owner-observable CSV execution, not CSV acceptance.

## Remaining executable gates

The existing private005f6a7a… intake and37b517ed… creation request still require the real installed token DomainOwner, credential re-establishment, full protected runtime installation, governed finite sessions and independently authenticated target six-mount policy/HUMAN/attestor scope. Root runner access was not established by the historical read; development GitHub authority is not runtime HUMAN authority (AGENTS.md and resilience policy v3§14).

After governed target application verification, Teatri needs exact published compatible class/property revisions, reviewed mapping and HUMAN-approved source bundle. The same source/configuration/run must join13 durable record outcomes to owner ACKs, canonical object IDs/revisions and complete authorized search. Existing MCP status/history is operational projection only; bounded owner lineage access remains a separate missing contract/grant. Do not infer completeness from totals or repeat consumed activation/ingestion claims.
