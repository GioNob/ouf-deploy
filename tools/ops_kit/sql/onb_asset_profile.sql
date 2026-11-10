-- Managed file asset and its profile, as JSON: ownership, hash, size, staging
-- reference and inferred schema. Inputs for onboarding_swap_asset.py.
-- vars: asset_id, owner_subject
\pset format unaligned
\pset tuples_only on
BEGIN READ ONLY;
SET LOCAL statement_timeout = '10s';
SELECT jsonb_pretty(to_jsonb(x)) FROM (
  SELECT a.asset_id, a.source_id, a.status, a.tenant_id,
         a.uploaded_by = :'owner_subject' AS owned_by_expected_subject,
         a.content_hash, a.size_bytes, a.staging_ref, a.media_type,
         p.profile_id, p.version AS profile_version, p.metadata, p.candidate_keys, p.inferred_schema
  FROM ouf_onboarding.managed_file_asset a
  LEFT JOIN ouf_onboarding.file_profile p USING (asset_id)
  WHERE a.asset_id = :'asset_id'
) x;
ROLLBACK;
