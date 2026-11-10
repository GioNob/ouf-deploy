-- After THS confirmation: per object of a run, revision, material change,
-- canonical/authority change versus the previous revision, labels and how many
-- properties retain contributions from more than one source.
-- vars: source_id, run_id
\pset format aligned
BEGIN READ ONLY;
SET LOCAL statement_timeout = '10s';

WITH run AS (
  SELECT m.urban_object_id, m.revision_id, m.material_change
  FROM ouf_udp.materialization_observation m
  JOIN ouf_udp.handoff_intake h USING (handoff_id)
  WHERE h.ingestion_run_id = :'run_id' AND h.source_id = :'source_id'
), by_property AS (
  SELECT r.urban_object_id, p.property_iri, p.access_label,
         count(DISTINCT c.source_id) AS retained_sources
  FROM run r
  JOIN ouf_udp.property_value p USING (revision_id)
  LEFT JOIN ouf_udp.property_contribution c
    ON c.urban_object_id = r.urban_object_id AND c.property_iri = p.property_iri
  GROUP BY r.urban_object_id, p.property_iri, p.access_label
)
SELECT run.urban_object_id, o.status, rev.revision_no, run.material_change,
       rev.canonical_hash = prev.canonical_hash AS canonical_unchanged,
       rev.authority_hash <> prev.authority_hash AS authority_changed,
       (SELECT string_agg(b.source_id || ':' || b.state, ',' ORDER BY b.source_id)
          FROM ouf_udp.source_binding b WHERE b.urban_object_id = run.urban_object_id) AS bindings,
       count(p.property_iri) AS properties,
       count(*) FILTER (WHERE p.retained_sources > 1) AS multi_source_properties,
       string_agg(DISTINCT p.access_label, ',') AS labels
FROM run
JOIN ouf_udp.urban_object o ON o.urban_object_id = run.urban_object_id
JOIN ouf_udp.object_revision rev ON rev.revision_id = run.revision_id
LEFT JOIN ouf_udp.object_revision prev
  ON prev.urban_object_id = run.urban_object_id AND prev.revision_no = rev.revision_no - 1
LEFT JOIN by_property p ON p.urban_object_id = run.urban_object_id
GROUP BY run.urban_object_id, o.status, rev.revision_no, run.material_change,
         rev.canonical_hash, prev.canonical_hash, rev.authority_hash, prev.authority_hash
ORDER BY run.urban_object_id;
ROLLBACK;
