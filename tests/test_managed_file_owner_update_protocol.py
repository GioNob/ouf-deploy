"""CI/local fixture signatures only; never a target HUMAN approval."""
import copy,importlib.util,json,os,unittest
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
def module(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
retained=module('owner_v38_retained_crypto',BASE/'tests/test_managed_csv_control_update_protocol.py')
bundle=module('owner_v38_bundle',BASE/'tools/managed_file_owner_update/bundle.py');retained.bundle=bundle
class Protocol(retained.Protocol):
    def setUp(self):
        super().setUp();proposal=self.review['nativePlan']['proposal'];facts=json.loads((BASE/'releases/managed-file-owner-v38-image-custody-20261028.json').read_text())['application']['migrations']
        proposal.update(readReplacements={'onboarding':{'oldBinding':{'imageId':'sha256:'+'a'*64},'request':{'Image':'sha256:'+'b'*64}}},candidateApplicationFacts={'migrations':facts},databaseMigration={'from':36,'to':38,'newMigrations':2,'newMigrationFacts':facts[36:]})
        self.review.update(schema='ouf.managed-file-owner-v38-update-review.v1',targetRoles=['onboarding'],sameNativeImageRequired=False,imageImportAuthorized=True,iamMutationAuthorized=False,humanOwnershipAuthorized=False,databaseMigrationAuthorized=True,databaseMigration=copy.deepcopy(proposal['databaseMigration']))
        self.review['negativeCleanup']['maximumStops']=1;self.review['nativePlanHash']=self.core.digest(self.review['nativePlan'])
    def test_migration_backup_scope_cannot_be_widened_or_silently_removed(self):
        for field,value in [('databaseMigrationAuthorized',False),('maximumBackupBytes',536870912),('maximumBackupSeconds',91),('databaseMigration',{'from':36,'to':39,'newMigrations':3}),('humanOwnershipAuthorized',True),('imageImportAuthorized',False),('iamMutationAuthorized',True),('targetRoles',['onboarding','mcp'])]:
            v=copy.deepcopy(self.review);v[field]=value
            with self.subTest(field=field),self.assertRaises(self.core.Stop):self.core.validate_review(v)
        self.assertEqual(self.core.ROLES,('onboarding',));self.assertEqual(self.core.LIMITS['sqlSessions'],7);self.assertEqual(self.core.LIMITS['imageLoadAttempts'],1);self.assertEqual(self.core.LIMITS['engineWrites'],10);self.assertEqual(self.core.LIMITS['quarantineStops'],1)
    def test_second_owner_or_same_image_is_not_this_review(self):
        for kind in('second','same'):
            v=copy.deepcopy(self.review);rows=v['nativePlan']['proposal']['readReplacements']
            if kind=='second':rows['mcp']=copy.deepcopy(rows['onboarding'])
            else:rows['onboarding']['request']['Image']=rows['onboarding']['oldBinding']['imageId']
            v['nativePlanHash']=self.core.digest(v['nativePlan'])
            with self.subTest(kind=kind),self.assertRaises(self.core.Stop):self.core.validate_review(v)
    def test_old_review_or_mandate_cannot_be_relabelled_as_v38(self):
        self.assertNotEqual(self.core.AUTHORITY_SCHEMA,'ouf.ths-owner-request-update-authority.v1')
        self.assertEqual(len(self.core.STAGES),16);self.assertIn('IMPORT_ONBOARDING_OWNER',self.core.STAGES);self.assertNotIn('VERIFY_BEFORE_MCP',self.core.STAGES)
        v=copy.deepcopy(self.review);v['schema']='ouf.ths-owner-request-update-review.v1'
        with self.assertRaises(self.core.Stop):self.core.validate_review(v)
    def test_no_tty_stops_before_preflight_or_signing(self):
        from unittest.mock import patch
        account=type('User',(),{'pw_uid':1001})();flags=type('Flags',(),{'isolated':1,'no_site':1})()
        with patch.object(self.entry.sys,'argv',['entry']),patch.object(self.entry.sys,'flags',flags),patch.object(self.entry.sys,'dont_write_bytecode',True),patch.object(self.entry.pwd,'getpwnam',return_value=account),patch.dict(self.entry.os.environ,{'SUDO_UID':'1001'}),patch.object(self.entry.os,'isatty',return_value=False),patch.object(self.entry,'components')as c,patch('builtins.print'):
            self.assertEqual(self.entry.main(),2)
        c.assert_not_called()
if __name__=='__main__':unittest.main()
