-- Canonical payloads of one run as a JSON array, input for rebuild_csv_from_udp.py.
-- vars: source_id, run_id
\pset format unaligned
\pset tuples_only on
BEGIN READ ONLY;
SET LOCAL statement_timeout = '10s';
SELECT jsonb_agg(payload_json->'canonicalPayload' ORDER BY received_at)
FROM ouf_udp.handoff_intake
WHERE source_id = :'source_id' AND ingestion_run_id = :'run_id';
ROLLBACK;
