-- Onboarding versions, managed files and active publication of a source.
-- vars: source_id
\pset format aligned
BEGIN READ ONLY;
SET LOCAL statement_timeout = '10s';

SELECT version, onboarding_version_id, state, lock_version, parent_version_id, configuration_hash
FROM ouf_onboarding.onboarding_version WHERE source_id = :'source_id' ORDER BY version DESC;

SELECT publication_id, onboarding_version_id, active, checksum, effective_from
FROM ouf_onboarding.published_configuration WHERE source_id = :'source_id' ORDER BY created_at DESC;

SELECT status, metadata FROM ouf_onboarding.source WHERE source_id = :'source_id';
ROLLBACK;
