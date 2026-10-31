import copy,importlib.util,json,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=module('ownership_reader','scripts/read-managed-file-ownership-20261028.py')
builder=module('ownership_builder','tools/build_managed_file_ownership_reader.py')

class Contract(unittest.TestCase):
    def test_sealed_reader_is_reproducible_from_persistent_modules(self):
        self.assertEqual(builder.build(),(ROOT/'scripts/read-managed-file-ownership-20261028.py').read_text())
    def test_closed_query_is_read_only_and_cannot_select_arbitrary_identifiers(self):
        q=m.query(m.CASE)
        self.assertTrue(q.startswith('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;'))
        self.assertTrue(q.endswith('ROLLBACK;'))
        self.assertEqual(q.count(m.CASE['teatriAssetId']),1)
        self.assertNotIn('staging_ref',q);self.assertNotIn('file_id',q);self.assertNotIn('last_error',q)
        for value in ["ouf-lab';DELETE FROM x;--",' OUFlab','x'*65]:
            with self.subTest(value=value),self.assertRaises(ValueError):m.query({**m.CASE,'tenantId':value})
        with self.assertRaises(ValueError):m.query({**m.CASE,'assetId':"';drop table x"})
    def facts(self):
        rows=[]
        for kind,asset in [('FARMACIE',m.CASE['assetId']),('TEATRI',m.CASE['teatriAssetId'])]:
            reviewed=kind=='TEATRI'
            rows.append(dict(kind=kind,assetId=asset,present=True,uploadedByMatchesExpectedSubject=True,uploadReceiptCount=0,
                exactUploadTenantSubjectProof=False,exactReviewTenantSubjectProof=reviewed,otherUploadIdentityObserved=False,
                otherReviewIdentityObserved=False,expectedPrincipalOwnerPredicate=reviewed,contentHash=m.CASE['contentHash'],sizeBytes=13903))
        return dict(schema='ouf.managed-file-ownership-sql-observation.v1',readOnly='on',standby=False,database='ouf_onboarding',databaseOid=17,
            user='owner',serverVersionNum=170009,installedSchemaVersion=36,assets=rows,
            job=dict(jobId=m.CASE['jobId'],assetId=m.CASE['assetId'],status='FAILED',cumulativeAttempts=5,generation=0,expectedVersion=0,hasRecoverySession=False),
            sameAssetJobCount=1,recoverySessionCount=0,recoveryEventCount=0)
    def validate(self,v):return m.validate(v,{'database':'ouf_onboarding','databaseOid':17,'adminRole':'owner'},m.CASE,m.require)
    def test_legacy_uploader_match_without_tenant_is_not_authority(self):
        out=self.validate(self.facts());self.assertEqual(out['classification'],'RETAINED_UPLOADER_MATCHES_TENANT_PROOF_MISSING')
        self.assertFalse(out['browserSubjectOrTenantObserved']);self.assertEqual(out['job']['cumulativeAttempts'],5)
    def test_subject_mismatch_is_distinct_from_missing_tenant(self):
        f=self.facts();f['assets'][0]['uploadedByMatchesExpectedSubject']=False
        self.assertEqual(self.validate(f)['classification'],'EXPECTED_SUBJECT_DIFFERS_FROM_RETAINED_UPLOADER')
    def test_durable_receipt_does_not_prove_the_browser_identity(self):
        f=self.facts();f['assets'][0].update(exactUploadTenantSubjectProof=True,uploadReceiptCount=1,expectedPrincipalOwnerPredicate=True)
        out=self.validate(f);self.assertIn('BROWSER_IDENTITY_STILL_UNOBSERVED',out['classification']);self.assertFalse(out['browserSubjectOrTenantObserved'])
    def test_contradictory_or_unbounded_facts_fail_closed(self):
        for mutation in [lambda f:f.update(installedSchemaVersion=37),lambda f:f.update(readOnly='off'),
            lambda f:f['assets'][0].update(expectedPrincipalOwnerPredicate=True),lambda f:f['assets'][0].update(staging_ref='private'),
            lambda f:f['job'].update(cumulativeAttempts=True),lambda f:f['assets'].append(f['assets'][0])]:
            f=self.facts();mutation(f)
            with self.assertRaises(m.Stop):self.validate(f)
    def test_no_tty_stops_before_scope_sql_or_auth(self):
        account=type('User',(),{'pw_uid':1001})();flags=type('Flags',(),{'isolated':1,'no_site':1})()
        with patch.object(m.sys,'argv',['read.py']),patch.object(m.os,'geteuid',return_value=0),patch.object(m.os,'getegid',return_value=0),patch.object(m.sys,'flags',flags),patch.object(m.sys,'dont_write_bytecode',True),patch.object(m.pwd,'getpwnam',return_value=account),patch.dict(m.os.environ,{'SUDO_UID':'1001'}),patch.object(m.sys.stdin,'isatty',return_value=False),patch.object(m,'Capture')as cap,patch.object(m,'inspect_ownership')as sql,patch('builtins.print'):
            self.assertEqual(m.main(),2)
        cap.assert_not_called();sql.assert_not_called()

if __name__=='__main__':unittest.main()
