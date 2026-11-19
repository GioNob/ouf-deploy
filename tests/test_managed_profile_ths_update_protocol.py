"""CI-only real signatures and exact new review, never target authority."""
import copy,hashlib,importlib.util,json,os,sys,time,unittest
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
retained=module('retained_ths_crypto_fixture',BASE/'tests/test_managed_csv_control_update_protocol.py')
bundle=module('ths_update_bundle',BASE/'tools/managed_profile_ths_update/bundle.py')
retained.bundle=bundle

class Protocol(retained.Protocol):
    def setUp(self):
        super().setUp()
        proposal=self.review['nativePlan']['proposal']
        proposal['readReplacements']={'onboarding':{'oldBinding':{'imageId':'sha256:'+'a'*64},'request':{'Image':'sha256:'+'a'*64}}}
        self.review.update(schema='ouf.ths-owner-request-update-review.v1',targetRoles=['onboarding'],
            sameNativeImageRequired=True,imageImportAuthorized=False,iamMutationAuthorized=False)
        self.review['negativeCleanup']['maximumStops']=1
        self.review['nativePlanHash']=self.core.digest(self.review['nativePlan'])
    def test_migration_backup_scope_cannot_be_widened_or_silently_removed(self):
        for field,value in [('databaseMigrationAuthorized',True),('maximumBackupBytes',536870912),('maximumBackupSeconds',91),
            ('databaseMigration',{'from':35,'to':36,'newMigrations':1}),('imageImportAuthorized',True),('iamMutationAuthorized',True),
            ('targetRoles',['onboarding','mcp']),('sameNativeImageRequired',False)]:
            with self.subTest(field=field):
                review=copy.deepcopy(self.review);review[field]=value
                with self.assertRaises(self.core.Stop):self.core.validate_review(review)
        self.assertEqual(self.core.ROLES,('onboarding',));self.assertEqual(self.core.LIMITS['sqlSessions'],7)
        self.assertEqual(self.core.LIMITS['imageLoadAttempts'],0);self.assertEqual(self.core.LIMITS['engineWrites'],9)
        self.assertEqual(self.core.LIMITS['quarantineStops'],1);self.assertEqual(self.core.LIMITS['backupProcesses'],2)
    def test_injected_second_owner_or_image_change_in_signed_plan_is_denied(self):
        for kind in ('second-owner','image-change'):
            review=copy.deepcopy(self.review);rows=review['nativePlan']['proposal']['readReplacements']
            if kind=='second-owner':rows['mcp']=copy.deepcopy(rows['onboarding'])
            else:rows['onboarding']['request']['Image']='sha256:'+'b'*64
            review['nativePlanHash']=self.core.digest(review['nativePlan'])
            with self.subTest(kind=kind),self.assertRaises(self.core.Stop):self.core.validate_review(review)
    def test_old_two_owner_mandate_cannot_be_relabelled_as_this_operation(self):
        self.assertNotEqual(self.core.AUTHORITY_SCHEMA,'ouf.managed-csv-control-update-authority.v1')
        self.assertNotIn('IMPORT_ONBOARDING_OWNER',self.core.STAGES)
        self.assertNotIn('VERIFY_BEFORE_MCP',self.core.STAGES)
        self.assertEqual(len(self.core.STAGES),15)
    def test_no_tty_stops_before_preflight_or_signing(self):
        from unittest.mock import patch
        account=type('User',(),{'pw_uid':1001})()
        flags=type('Flags',(),{'isolated':1,'no_site':1})()
        with patch.object(self.entry.sys,'argv',['entry']),patch.object(self.entry.sys,'flags',flags),patch.object(self.entry.sys,'dont_write_bytecode',True),patch.object(self.entry.pwd,'getpwnam',return_value=account),patch.dict(self.entry.os.environ,{'SUDO_UID':'1001'}),patch.object(self.entry.os,'isatty',return_value=False),patch.object(self.entry,'components')as components,patch('builtins.print')as output:
            self.assertEqual(self.entry.main(),2)
        components.assert_not_called();self.assertIn('DIRECT_INTERACTIVE_SUDO_NO_PIPE_REQUIRED',str(output.call_args))
if __name__=='__main__':unittest.main()
