"""Native custody/signatures/ledger; issuer calls are simulated here."""
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tests')]
import test_policy_token_legacy_retirement as fixtures
import credential_transaction as transaction
import legacy_retirement as legacy
binding=transaction.binding

class CredentialTransactionTest(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.RetirementTest();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.root=self.f.f.root;self.destination=self.root/'new-owner';self.destination.mkdir(mode=0o700)
        self.f.host['proposedRootsMetadata']={'ownerCredential':{'path':str(self.destination)}}
        self.f.host['executables']['docker']=self.f.host['executables']['systemctl']
        self.f.raw=binding.encoded(self.f.host);digest=binding.sha(self.f.raw)
        p=patch.object(legacy,'HOST_HASH',digest);p.start();self.addCleanup(p.stop)
        self.f.f.write(self.root/('policy-token-migration-host-inputs-'+digest+'.private.json'),self.f.raw)
        self.gate=self.f.f.gate();self.retirement=legacy.LegacyRetirement(self.gate,self.f.f.authority,self.f.raw)
        self.registration={'id':'11111111-1111-1111-1111-111111111111','clientId':'fixture-client',
            'enabled':True,'serviceAccountsEnabled':True,'publicClient':False,'protocol':'openid-connect',
            'clientAuthenticatorType':'client-secret','protocolMappers':[],'defaultClientScopes':['fixture-read']}
        info=self.destination.stat();self.identity={'device':info.st_dev,'inode':info.st_ino}
        initial=self.make();scope=initial.scope
        a=json.loads(self.f.f.authority);a['policyTokenLegacyRetirement']=self.retirement.scope;a['policyTokenCredentialReestablishment']=scope
        self.f.f.authority=binding.encoded(a);self.f.f.approval['executionAuthorityHash']=binding.sha(self.f.f.authority)
        self.f.f.write(self.f.f.mandate,binding.encoded(self.f.f.approval));self.f.f.approved=binding.sha(self.f.f.mandate.read_bytes())
        for role in self.f.f.grant['roles']:self.f.f.sign(role)
        self.gate=self.f.f.gate();self.retirement=legacy.LegacyRetirement(self.gate,self.f.f.authority,self.f.raw)
        self.f.f.write(self.root/self.retirement.name,binding.encoded({'operation':self.retirement.operation,
            'scope':self.retirement.scope,'state':'QUIESCENCE_OBSERVED','commandAttemptConsumed':True}))
        p=patch.object(legacy,'read_units',return_value=self.f.after);p.start();self.addCleanup(p.stop)
        self.calls=[];self.new='N'*48;self.old='O'*48
    def make(self):return transaction.CredentialTransaction(self.retirement,self.gate,self.f.f.authority,
        self.registration,str(self.destination),self.identity)
    def admin(self,method,suffix=''):
        self.calls.append((method,suffix))
        if method=='create':
            row=json.loads((self.root/self.make().name).read_bytes());self.assertTrue(row['iamMutationAttemptConsumed'])
            return {'type':'secret','value':self.new}
        if suffix=='/client-secret':return {'type':'secret','value':self.new if ('create','/client-secret')in self.calls else self.old}
        return self.registration
    def test_success_creates_root_readonly_secret_with_unknown_grant_and_no_replay(self):
        with patch.object(transaction.SecretAdmin,'call',side_effect=self.admin):
            report=self.make().run()
        self.assertTrue(report['credentialPublished']);self.assertEqual(report['tokenGrantRequests'],0)
        path=self.destination/'client-secret';self.assertEqual(path.read_text(),self.new);self.assertEqual(path.stat().st_mode&0o777,0o400)
        self.assertEqual(self.calls.count(('create','/client-secret')),1)
        with patch.object(transaction.SecretAdmin,'call')as call:
            with self.assertRaisesRegex(binding.CandidateDenied,'NO_AUTOMATIC_REPLAY'):self.make().run()
            call.assert_not_called()
    def test_ambiguous_rotation_does_not_adopt_later_secret_or_repeat_mutation(self):
        def ambiguous(method,suffix=''):
            if method=='create':raise TimeoutError('synthetic')
            return self.admin(method,suffix)
        with patch.object(transaction.SecretAdmin,'call',side_effect=ambiguous):
            with self.assertRaises(TimeoutError):self.make().run()
        self.assertFalse((self.destination/'client-secret').exists())
        with patch.object(transaction.SecretAdmin,'call')as call:
            with self.assertRaisesRegex(binding.CandidateDenied,'NO_AUTOMATIC_REPLAY'):self.make().run()
            call.assert_not_called()
    def test_changed_readback_and_changed_registration_leave_reserved_without_secret(self):
        def mismatch(method,suffix=''):
            value=self.admin(method,suffix)
            if method=='get' and suffix and ('create','/client-secret')in self.calls:return {'type':'secret','value':'Z'*48}
            return value
        with patch.object(transaction.SecretAdmin,'call',side_effect=mismatch):
            with self.assertRaisesRegex(binding.CandidateDenied,'READBACK_NOT_PROVEN'):self.make().run()
        self.assertFalse((self.destination/'client-secret').exists())
        row=json.loads((self.root/self.make().name).read_bytes());self.assertEqual(row['state'],'ROTATION_RESERVED_OUTCOME_UNPROVEN')
    def test_existing_secret_and_unquiesced_writer_deny_before_iam(self):
        (self.destination/'client-secret').write_text('untouched')
        with patch.object(transaction.SecretAdmin,'call')as call:
            with self.assertRaisesRegex(binding.CandidateDenied,'MUST_BE_EMPTY'):self.make().run()
            call.assert_not_called()
        with patch.object(legacy,'read_units',return_value=self.f.before),patch.object(transaction.SecretAdmin,'call')as call:
            with self.assertRaisesRegex(binding.CandidateDenied,'QUIESCENCE'):self.make().run()
            call.assert_not_called()
    def test_process_crash_after_effect_reservation_is_not_a_new_attempt(self):
        child=os.fork()
        if child==0:
            def crash(method,suffix=''):
                if method=='create':os._exit(0)
                return self.admin(method,suffix)
            with patch.object(transaction.SecretAdmin,'call',side_effect=crash):
                try:self.make().run()
                except Exception:os._exit(91)
            os._exit(92)
        _,status=os.waitpid(child,0);self.assertEqual(os.waitstatus_to_exitcode(status),0)
        with patch.object(transaction.SecretAdmin,'call')as call:
            with self.assertRaisesRegex(binding.CandidateDenied,'NO_AUTOMATIC_REPLAY'):self.make().run()
            call.assert_not_called()

if __name__=='__main__':unittest.main()
