# OUF Reality Baseline Package v1.7

Status: **CURRENT NORMATIVE BASELINE**

This package is a consolidated, self-contained successor to Reality Baseline Package v1.6. It incorporates the Operational Awareness and channel-neutral capability alignment into the normative baseline rather than requiring a separate delta package.

## Normative authority

The Cross-Module Alignment Matrix **v1.7** is the L0 cross-module alignment authority for this baseline. It is intentionally included as a first-class normative artifact and must be consulted together with the applicable L1 PET before implementation or acceptance decisions.

The current changed PET revisions are MCP Server v1.4, Urban API Gateway v1.5, Ingestion Runtime v1.3, Source Onboarding v1.6, and Authorization/Access Control v1.5. UDP Urban Object Registry v1.3 and Semantic Model Registry v1.3 remain unchanged from v1.6.

## Channel-neutral Operational Awareness

Human-facing OUF capabilities are channel-independent. MCP is a governed conversational interface, not an exclusive application API or alternate service bus. A capability such as `ouf.system.status` remains Gateway-mediated and can be exposed through separately governed MCP/M2M and API/OIDC bindings that converge on the same owner backend. Persistent operational catch-up is normative; live push is optional.

## Supersession

The superseded v1.6 L0/L1 files are not retained in the active normative directories. Their replacement mapping is recorded in `MANIFEST.json`. The original v1.6 package remains the historical source if a superseded document must be inspected.

## Integrity

`SHA256SUMS.txt` contains hashes for every file in this package except itself. `MANIFEST.json` provides package metadata, normative versions, supersession mapping, and per-file checksums.
