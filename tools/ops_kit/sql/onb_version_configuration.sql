-- Full configuration of one onboarding version as JSON, input for
-- onboarding_swap_asset.py and rebuild_csv_from_udp.py.
-- vars: version_id
\pset format unaligned
\pset tuples_only on
BEGIN READ ONLY;
SET LOCAL statement_timeout = '10s';
SELECT configuration FROM ouf_onboarding.onboarding_version WHERE onboarding_version_id = :'version_id';
ROLLBACK;
