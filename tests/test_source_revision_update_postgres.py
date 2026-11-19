"""Actual additive V34 under an application role and native metadata readback."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.source_revision_update.database import sql
from tools.source_revision_update.owner import MIGRATION


@unittest.skipUnless(os.environ.get('OUF_NATIVE_REVISION_PG') == '1','disposable PostgreSQL qualification only')
class NativeMetadata(unittest.TestCase):
    def query(self, statement):
        result = subprocess.run(['/usr/bin/psql','-h','127.0.0.1','-U','postgres','-d','postgres',
            '-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-c',statement],stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        return result.stdout

    def test_exact_candidate_migration_readback_owner_and_append_only_trigger(self):
        source = Path(os.environ['OUF_REVISION_OWNER_ROOT'])/'src/main/resources/db/migration'/MIGRATION['script']
        raw = source.read_bytes(); self.assertEqual(hashlib.sha256(raw).hexdigest(),MIGRATION['sha256'])
        self.query('CREATE ROLE ouf_onboarding; CREATE SCHEMA ouf_onboarding AUTHORIZATION ouf_onboarding; '
            'SET ROLE ouf_onboarding; '
            'CREATE TABLE ouf_onboarding.source(source_id varchar(160) PRIMARY KEY); '
            'CREATE TABLE ouf_onboarding.onboarding_version(onboarding_version_id uuid PRIMARY KEY,source_id varchar(160) '
            'REFERENCES ouf_onboarding.source(source_id),UNIQUE(onboarding_version_id,source_id)); '
            'CREATE TABLE ouf_onboarding.managed_onboarding_review(onboarding_version_id uuid PRIMARY KEY '
            'REFERENCES ouf_onboarding.onboarding_version(onboarding_version_id)); '
            'CREATE TABLE ouf_onboarding.flyway_schema_history(installed_rank integer,version text,script text,checksum integer,success boolean); '
            'CREATE FUNCTION ouf_onboarding.reject_audit_change() RETURNS trigger LANGUAGE plpgsql AS '
            "$$BEGIN RAISE EXCEPTION 'append only'; END$$; RESET ROLE;")
        before = json.loads(self.query(sql('onboarding','ouf_onboarding')))
        self.assertTrue(before['transactionReadOnly']); self.assertFalse(before['revisionTablePresent'])
        self.query('SET ROLE ouf_onboarding; '+raw.decode()+' RESET ROLE;')
        after = json.loads(self.query(sql('onboarding','ouf_onboarding')))
        self.assertTrue(after['transactionReadOnly']); self.assertTrue(after['revisionTablePresent'])
        self.assertTrue(after['revisionTableOwned']); self.assertTrue(after['revisionAppendOnly'])
        self.query('ALTER TABLE ouf_onboarding.source_property_revision DISABLE TRIGGER source_property_revision_append_only;')
        changed = json.loads(self.query(sql('onboarding','ouf_onboarding')))
        self.assertFalse(changed['revisionAppendOnly'])


if __name__ == '__main__': unittest.main()
