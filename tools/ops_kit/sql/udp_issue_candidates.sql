-- Open identity issues of a run: best candidate (most AGREE signals), how many
-- candidates agree on every signal, which signals disagree, satisfied rules.
-- Use it to prepare the issueId -> objectId list for the THS resolution page.
-- vars: run_id
\pset format aligned
BEGIN READ ONLY;
SET LOCAL statement_timeout = '10s';

WITH a AS (
  SELECT i.issue_id, h.source_object_id,
         h.payload_json #>> '{canonicalPayload,https://schema.org/name}' AS name,
         x->>'objectId' AS candidate,
         (x->>'excluded')::boolean AS excluded,
         x->'satisfiedRules' AS satisfied_rules,
         jsonb_path_query_array(x, '$.evidence[*] ? (@.kind == "AGREE").signalId') AS agree,
         jsonb_path_query_array(x, '$.evidence[*] ? (@.kind == "DISAGREE").signalId') AS disagree,
         jsonb_array_length(jsonb_path_query_array(x, '$.evidence[*]')) AS signals
  FROM ouf_udp.handoff_intake h
  JOIN ouf_udp.resolution_issue i ON i.handoff_id = h.handoff_id,
       jsonb_array_elements(COALESCE(i.evidence_refs->0->'assessments', '[]'::jsonb)) x
  WHERE h.ingestion_run_id = :'run_id' AND i.state = 'OPEN'
), ranked AS (
  SELECT *, row_number() OVER (PARTITION BY issue_id ORDER BY jsonb_array_length(agree) DESC) AS rk,
         count(*) FILTER (WHERE jsonb_array_length(agree) = signals) OVER (PARTITION BY issue_id) AS full_matches,
         count(*) OVER (PARTITION BY issue_id) AS candidates
  FROM a
), best AS (
  SELECT * FROM ranked WHERE rk = 1
)
SELECT issue_id, name, candidate AS best_candidate,
       jsonb_array_length(agree) AS agree, jsonb_array_length(disagree) AS disagree,
       full_matches, candidates, excluded, satisfied_rules, disagree AS disagreeing_signals,
       (SELECT count(DISTINCT candidate) FROM best) AS distinct_best_candidates
FROM best ORDER BY name;
ROLLBACK;
