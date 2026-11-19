# Installation-specific retained endpoint inventory

Read docs/handoffs/OUF_SEMANTIC_RETAINED_ENDPOINT_INVENTORY_20261022.md for evidence, exact scope and limitations.

Execute reader.py with the separately SHA256-checked case.json using sudo python3 -I -B -S. This is a new reader, not a rerun or substitution of either historical Registry reader. Four EngineGET maximum,35seconds; no target writes, logs, probes, DNS, credentials, DB or OAuth. Success status RETAINED_ENDPOINT_INVENTORY_ONLY. Copy its public JSON and operator.log path. Preserve everything after STOP; no retry or activation.

Inventory candidates are exact address observations against retained inline semantic nodes. They do not establish service ownership/current routing/port readiness. Names and addresses are never printed. Missing/indirect/ambiguous route definitions STOP without fallback.

8local fixture tests pass;18unchanged predecessor regressions pass. No native Docker/VPS/CI execution of this reader is claimed.
