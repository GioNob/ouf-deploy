-- For each identity issue of a run (any state), the properties whose incoming value differs from
-- the latest payload the best candidate received from a reference source.
-- This is how the 2026-11-10 spreadsheet corruption was found.
-- vars: run_id, reference_source
\pset format aligned
BEGIN READ ONLY;
SET LOCAL statement_timeout = '10s';

WITH best AS (
  SELECT DISTINCT ON (i.issue_id) i.issue_id, h.payload_json->'canonicalPayload' AS incoming,
         (x->>'objectId')::uuid AS candidate
  FROM ouf_udp.handoff_intake h
  JOIN ouf_udp.resolution_issue i ON i.handoff_id = h.handoff_id,
       jsonb_array_elements(COALESCE(i.evidence_refs->0->'assessments', '[]'::jsonb)) x
  WHERE h.ingestion_run_id = :'run_id'
  ORDER BY i.issue_id, jsonb_array_length(jsonb_path_query_array(x, '$.evidence[*] ? (@.kind == "AGREE")')) DESC
), reference AS (
  SELECT DISTINCT ON (b.urban_object_id) b.urban_object_id, h.payload_json->'canonicalPayload' AS stored
  FROM ouf_udp.source_binding b
  JOIN ouf_udp.handoff_intake h ON h.source_id = b.source_id AND h.source_object_id = b.source_object_id
  WHERE b.source_id = :'reference_source'
  ORDER BY b.urban_object_id, h.received_at DESC
)
SELECT best.issue_id, best.incoming->>'https://schema.org/name' AS name,
       regexp_replace(e.key, '^.*[#/]', '') AS property,
       reference.stored->>e.key AS reference_value, e.value #>> '{}' AS incoming_value
FROM best
JOIN reference ON reference.urban_object_id = best.candidate,
     jsonb_each(best.incoming) e
WHERE reference.stored->e.key IS DISTINCT FROM e.value
ORDER BY name, property;
ROLLBACK;
