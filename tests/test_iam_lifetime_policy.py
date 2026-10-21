"""Finite policy update, ledger chain, drift and actual Keycloak round trip."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_iam_explicit_api as fixture
from tools.ingestion_rollout_preparation import iam_lifetime_policy as m,iam_lifetime_delivery as delivery
from tools.ingestion_rollout_preparation import iam_explicit_api as auth,iam_policy_read as p,human_timing as files
from tools.ingestion_rollout_preparation import iam_session_context_reconcile as process
from tools.semantic_lease_recovery.recovery_journal import Journal


class LifetimePolicy(unittest.TestCase):
    def setUp(self):
        self.a=fixture.ExplicitApi();self.a.setUp();self.addCleanup(self.a.doCleanups)
        self.f=self.a.f
        self.receipt=self.a.invoke()
        self.select_case(self.receipt)
        self.client=copy.deepcopy(self.f.client)
        self.realm=copy.deepcopy(self.f.realm)
        self.operations=[]

    def select_case(self,receipt):
        profile={'schema':'ouf.iam-client-lifetime-installation-profile.v1',
            **{k:receipt[k]for k in ('realm','clientId','clientUuid')},'proposedAccessTokenSeconds':1200,
            'acceptedNormalTokenFreshnessBoundSeconds':1200,'runtimeMaximumSeconds':900,
            'clockSafetyMarginSeconds':30,'reviewAndApprovalAllowanceSeconds':120,
            'administrativeWriterIsolation':'EXCLUSIVE_OPERATOR_MAINTENANCE_WINDOW'}
        self.case={'schema':'ouf.iam-client-lifetime-case.v1','originalApiCase':copy.deepcopy(self.a.case),
            'originalApiSourceHash':hashlib.sha256((ROOT/'tools/ingestion_rollout_preparation/iam_explicit_api.py').read_bytes()).hexdigest(),
            'retainedApiResultHash':p.digest(receipt),'installationDurationProfile':profile,'expectedAttempts':283,
            'maximumCumulativeOAuthAttempts':288,'maximumNewOAuthRequests':1,'maximumNewEngineGets':2,
            'maximumNewAdminGets':5,'maximumClientPuts':1}
        self.destination=Path(receipt['contextPath'])/'lifetime-policy-successor'

    def get(self,api,program,ns,payload):
        op=payload['operation'];self.operations.append(op)
        self.assertEqual(Journal(self.destination).read()['attempts'],284)
        if op=='PASSWORD_GRANT':return self.a.token()
        if op=='IDENTITY':return {'id':'fixture-admin-subject','username':'fixture-admin','enabled':True}
        if op=='REALM':return copy.deepcopy(self.realm)
        if op=='CLIENT':return copy.deepcopy(self.client)
        raise AssertionError(op)

    def put(self,api,program,ns,payload):
        self.operations.append('PUT')
        self.assertEqual(Journal(self.destination).read()['clientPutsReserved'],1)
        self.assertEqual(payload['lifespan'],1200)
        self.client['attributes']=copy.deepcopy(payload['attributes'])

    def invoke(self,put=None,get=None):
        with self.a.c.process_fixture(),self.f.synthetic_namespace(),patch.object(p,'EngineRead',self.f.fake_engine()), \
            patch.object(auth,'terminal',side_effect=[True,'PRIVATE-ADMIN-PASSWORD']), \
            patch.object(auth,'dispatch',side_effect=get or self.get),patch.object(m,'put',side_effect=put or self.put):
            return m.run(self.case,p,auth,files,process,Journal)

    def test_one_field_update_retains_both_ledgers_and_no_secret_persistence(self):
        parent=Path(self.receipt['contextPath'])/'recovery.json';old=parent.read_bytes()
        human=(self.a.session/'recovery.json').read_bytes()
        before=copy.deepcopy(self.client)
        result=self.invoke()
        self.assertEqual(self.operations,['PASSWORD_GRANT','IDENTITY','REALM','CLIENT','PUT','CLIENT','REALM'])
        expected=copy.deepcopy(before);expected['attributes']['access.token.lifespan']='1200'
        self.assertEqual(self.client,expected)
        self.assertEqual(parent.read_bytes(),old)
        self.assertEqual((self.a.session/'recovery.json').read_bytes(),human)
        self.assertEqual(result['attempts'],284);self.assertEqual(result['remainingAttempts'],4)
        self.assertTrue(result['authenticationFlowFlagsUnchanged'])
        self.assertFalse(result['runtimeAuthorityIssued'])
        self.assertFalse(result['effectiveFutureHumanIssuedLifetimeProven'])
        self.assertNotIn('PRIVATE-',json.dumps(result))
        self.assertNotIn('PRIVATE-',(self.destination/'recovery.json').read_text())

    def test_pre_put_policy_drift_reserves_auth_but_never_writes(self):
        self.realm['accessTokenLifespan']=301
        with self.assertRaisesRegex(ValueError,'POLICY_DRIFT_NO_PUT'):
            self.invoke()
        row=Journal(self.destination).read()
        self.assertEqual(row['attempts'],284);self.assertEqual(row['clientPutsReserved'],0)

    def test_put_unknown_outcome_and_consumed_claim_block_replay(self):
        def ambiguous(*args):raise ValueError('CLIENT_PUT_OUTCOME_UNPROVEN_RECONCILE_NO_REPLAY')
        with self.assertRaisesRegex(ValueError,'OUTCOME_UNPROVEN'):
            self.invoke(put=ambiguous)
        self.assertEqual(Journal(self.destination).read()['clientPutsReserved'],1)
        with patch.object(auth,'terminal')as tty,patch.object(m,'put')as put:
            with self.assertRaisesRegex(ValueError,'SUCCESSOR_CONSUMED'):
                m.run(self.case,p,auth,files,process,Journal)
            status=m.status(self.case,p,files,Journal)
        tty.assert_not_called();put.assert_not_called()
        self.assertEqual(status['requestsThisInvocation'],0)
        self.assertEqual(status['attempts'],284)

    def test_unrelated_readback_change_stops_without_compensating_put(self):
        def changed(*args):
            self.put(*args)
            self.client['directAccessGrantsEnabled']=True
        with self.assertRaisesRegex(ValueError,'READBACK_CHANGED_UNRELATED'):
            self.invoke(put=changed)
        self.assertEqual(self.operations.count('PUT'),1)
        self.assertEqual(Journal(self.destination).read()['state'],'STOP_RECONCILE')

    def test_unrelated_new_attribute_before_update_is_preserved(self):
        self.client['attributes']['another-owner-setting']='retained'
        self.invoke()
        self.assertEqual(self.client['attributes']['another-owner-setting'],'retained')

    def test_invalid_duration_and_unapproved_freshness_have_no_terminal_effect(self):
        bad=copy.deepcopy(self.case);bad['installationDurationProfile']['proposedAccessTokenSeconds']=300
        with patch.object(auth,'terminal')as tty:
            with self.assertRaises(ValueError):m.run(bad,p,auth,files,process,Journal)
            tty.assert_not_called()
        bad=copy.deepcopy(self.case);bad['installationDurationProfile']['acceptedNormalTokenFreshnessBoundSeconds']=300
        with self.assertRaises(ValueError):m.profile(bad,self.receipt,p)

    def test_declined_consent_preserves_unconsumed_next_budget(self):
        with patch.object(auth,'terminal',side_effect=ValueError('EXACT_ADMIN_API_TERMINAL_CONSENT_REQUIRED')):
            with self.assertRaises(ValueError):m.run(self.case,p,auth,files,process,Journal)
        self.assertFalse((self.destination.parent/'provider-budget-successor.claim.json').exists())
        self.assertFalse(self.destination.exists())

    def test_delivery_and_launcher_are_reproducible(self):
        case=json.loads((ROOT/'releases/iam-client-lifetime-case-20261021.json').read_text())
        raw,_=delivery.generate(ROOT,case)
        self.assertEqual((ROOT/'scripts/iam-client-lifetime-20261021.py').read_bytes(),raw)
        script=ROOT/'scripts/launch-iam-client-lifetime-20261021.sh';shell=script.read_text()
        self.assertIn(hashlib.sha256(raw).hexdigest(),shell)
        self.assertIn(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),shell)
        self.assertEqual(subprocess.run(['/bin/bash','-n',str(script)]).returncode,0)

    def physical(self,real):
        # Actual prior operation remains immutable; only disposable test
        # installation preparation is repeated here, never a target action.
        other=fixture.ExplicitApi();other.setUp();self.addCleanup(other.doCleanups)
        if real:
            other.test_real_keycloak_26_admin_password_grant_and_identity_policy_api()
        else:
            source=fixture.PHYSICAL_SERVER
            client={'id':'fixture-client-uuid','clientId':'fixture-human-admin','enabled':True,
                'protocol':'openid-connect','attributes':{'access.token.lifespan':'300'},'secret':'PRIVATE-CLIENT-SECRET'}
            source=source.replace('issued=None','issued=None\nclient_state='+repr(client))
            source=re.sub(r'(?m)^  client=.*$','  client=client_state',source)
            method=''' def do_PUT(self):
  if issued is None or self.headers.get('Authorization')!='Bearer '+issued or self.path!='/admin/realms/fixture/clients/fixture-client-uuid':self.reply(403,{});return
  n=int(self.headers.get('Content-Length','0'))
  if not 0<n<=65536:self.reply(400,{});return
  v=json.loads(self.rfile.read(n))
  if set(v)!={'attributes'}:self.reply(400,{});return
  client_state['attributes']=v['attributes'];self.send_response(204);self.end_headers()
'''
            source=source.replace(' def do_GET(self):',method+' def do_GET(self):')
            with patch.object(fixture,'PHYSICAL_SERVER',source):other.test_actual_docker_namespace_and_terminal_sealed_authentication()
        self.a=other;self.f=other.f
        result=Journal(other.destination).read()['result']
        self.select_case(result)
        raw,_=delivery.generate(ROOT,self.case)
        script=self.f.root/'sealed-lifetime.py';script.write_bytes(raw)
        old=(Path(result['contextPath'])/'recovery.json').read_bytes()
        output=fixture.run_terminal(script,[b'APPROVO TOKEN ',b'Password IAM per '],[None,b'PRIVATE-ADMIN-PASSWORD\n'])
        self.assertEqual(output['returncode'],0,output['text'])
        receipt=json.loads(output['text'].splitlines()[-1])
        self.assertEqual(receipt['publishedClientLifetimeSeconds'],1200)
        self.assertEqual(receipt['attempts'],284)
        self.assertTrue(receipt['unrelatedClientFieldsUnchanged'])
        self.assertEqual((Path(result['contextPath'])/'recovery.json').read_bytes(),old)
        self.assertNotIn('PRIVATE-',output['text'])
        status=subprocess.run(['/usr/bin/python3','-I','-B','-S',str(script),'status'],capture_output=True,text=True,timeout=15)
        self.assertEqual(status.returncode,0,status.stdout+status.stderr)
        self.assertEqual(json.loads(status.stdout)['requestsThisInvocation'],0)
        replay=subprocess.run(['/usr/bin/python3','-I','-B','-S',str(script),'execute'],capture_output=True,text=True,timeout=15)
        self.assertEqual(replay.returncode,2)
        if real:
            # Independent, disposable-fixture provider probe, not a request
            # issued by the target policy module. Prove actual new-token1200.
            cid=self.f.selection['keycloakContainer']
            row=json.loads(subprocess.run(['docker','inspect',cid],capture_output=True,text=True,check=True).stdout)[0]
            ns=os.open('/proc/'+str(row['State']['Pid'])+'/ns/net',os.O_RDONLY)
            try:
                binding=json.loads((self.f.production/'preparation.json').read_text())['sourceClosure']['executables']['python']
                response=auth.dispatch(p,binding,ns,{'host':'127.0.0.1','port':8080,'adminRealm':'master','clientId':'admin-cli',
                    'expectedUser':'fixture-admin','targetRealm':'master','targetClient':'admin-cli','operation':'PASSWORD_GRANT',
                    'credential':'PRIVATE-ADMIN-PASSWORD','subject':'','clientUuid':''})
                self.assertEqual(response['expires_in'],1200)
            finally:os.close(ns)

    def test_actual_docker_tty_one_field_put_and_status(self):
        if os.environ.get('GITHUB_ACTIONS')!='true':self.skipTest('Physical namespace/tty is mandatory in CI')
        self.physical(False)

    def test_real_keycloak_partial_client_put_preserves_fields_and_issues_1200(self):
        if os.environ.get('GITHUB_ACTIONS')!='true':self.skipTest('Actual disposable Keycloak is mandatory in CI')
        self.physical(True)


if __name__=='__main__':unittest.main()
