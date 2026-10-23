# Retained semantic endpoint inventory v2

Corrects the v1 list/map contract defect. BeforeRoutes is an ID-keyed dictionary produced by tools/chatbot_file_cohort/gateway.py:route_map. No list/envelope fallback; each key must equal row.id.

See docs/handoffs/OUF_SEMANTIC_ENDPOINT_MAP_SCHEMA_STOP_20261022.md for exact evidence and limitations. Four DockerGET maximum,35seconds;inventory candidates only,no current route/service/readiness/rootcause assertion. No logs/probes/DNS/admin/credentials/DB/OAuth/writes/activation or retry.

New SHA256-checked reader and case only,sudo python3 -I -B -S,one execution in a new private directory. Preserve old v1 and every stopped diagnostic. Success result schema v2,status RETAINED_ENDPOINT_INVENTORY_ONLY. Preserve and report any STOP.

11v2 fixture tests PASS including actual producer function contract and82synthetic routes;26unchanged predecessor regressions PASS. No native Docker/VPS/CI qualification claimed.
