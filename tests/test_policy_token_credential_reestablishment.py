import copy
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools/semantic_policy_token_owner'))
import credential_reestablishment as checks

class CredentialGuardsTest(unittest.TestCase):
    def setUp(self):
        self.before={'id':'11111111-1111-1111-1111-111111111111','clientId':'fixture-client',
            'enabled':True,'serviceAccountsEnabled':True,'publicClient':False,'protocol':'openid-connect',
            'clientAuthenticatorType':'client-secret','defaultClientScopes':['fixture-scope'],
            'protocolMappers':[{'name':'fixture-claim'}],'attributes':{'client.secret.creation.time':'123'}}
        self.after=copy.deepcopy(self.before);self.after['attributes']['client.secret.creation.time']='456'
        self.secret={'type':'secret','value':'X'*48};self.old='O'*48
    def test_only_secret_and_valid_creation_time_may_change(self):
        self.assertEqual(checks.verify_reestablishment(self.before,self.after,self.secret,self.secret,self.old),'X'*48)
        self.assertEqual(self.before['attributes']['client.secret.creation.time'],'123')
        for key,value in [('clientId','different'),('defaultClientScopes',[]),('protocolMappers',[]),('authorizationServicesEnabled',True)]:
            changed=copy.deepcopy(self.after);changed[key]=value
            with self.assertRaises(checks.binding.CandidateDenied):checks.verify_reestablishment(self.before,changed,self.secret,self.secret,self.old)
    def test_overlap_and_unrecognized_attribute_changes_deny(self):
        for key in checks.ROTATION_ATTRIBUTES|{'unreviewed.attribute'}:
            changed=copy.deepcopy(self.after);changed['attributes'][key]='true'
            with self.assertRaises(checks.binding.CandidateDenied):checks.verify_reestablishment(self.before,changed,self.secret,self.secret,self.old)
    def test_old_secret_mismatched_readback_and_vault_placeholder_deny(self):
        with self.assertRaises(checks.binding.CandidateDenied):checks.verify_reestablishment(self.before,self.after,self.secret,self.secret,'X'*48)
        changed={**self.secret,'value':'Z'*48}
        with self.assertRaises(checks.binding.CandidateDenied):checks.verify_reestablishment(self.before,self.after,self.secret,changed,self.old)
        for value in ('${vault.'+'x'*40+'}', 'x'*31,'x'*4097,'x'*40+'\n'):
            with self.assertRaises(checks.binding.CandidateDenied):checks.secret_value({'type':'secret','value':value})
    def test_unknown_schema_or_inactive_registration_deny(self):
        for value in ({'type':'secret','value':'x'*48,'extra':True},{'type':'password','value':'x'*48}):
            with self.assertRaises(checks.binding.CandidateDenied):checks.secret_value(value)
        changed=copy.deepcopy(self.before);changed['enabled']=False
        with self.assertRaises(checks.binding.CandidateDenied):checks.stable_registration(changed)

if __name__=='__main__':unittest.main()
