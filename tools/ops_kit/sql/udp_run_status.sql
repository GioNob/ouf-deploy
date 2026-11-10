-- Runs of a source seen by UDP, then per-record state of one run.
-- vars: source_id, run_id
\pset format aligned
BEGIN READ ONLY;
SET LOCAL statement_timeout = '10s';

SELECT ingestion_run_id, state, count(*) AS handoffs, min(received_at), max(received_at),
       max(payload_json #>> '{contractRefs,bundleRef}') AS bundle_ref
FROM ouf_udp.handoff_intake
WHERE source_id = :'source_id'
GROUP BY 1, 2 ORDER BY 4;

SELECT h.source_object_id, h.handoff_id, h.state AS intake_state,
       j.state AS job_state, j.safe_failure_code,
       i.issue_id, i.state AS issue_state, i.reason_code,
       m.urban_object_id, m.revision_id, m.material_change
FROM ouf_udp.handoff_intake h
JOIN ouf_udp.materialization_job j USING (handoff_id)
LEFT JOIN ouf_udp.resolution_issue i USING (handoff_id)
LEFT JOIN ouf_udp.materialization_observation m USING (handoff_id)
WHERE h.source_id = :'source_id' AND h.ingestion_run_id = :'run_id'
ORDER BY h.source_object_id;
ROLLBACK;
