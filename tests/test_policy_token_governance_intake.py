"""Real root-private custody/public policy; no key contents or IAM writes."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tests')]
import iam_governance_intake as intake
import iam_binding_candidate as binding
from test_policy_token_introspection_audience_plan import inputs,planner,fixture

class GovernanceIntakeTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(self.tmp.cleanup)
        self.parent=Path(self.tmp.name);self.parent.chmod(0o700)
        self.snapshot,_,proposal,ph=inputs()
        for index,scope in enumerate(self.snapshot['defaultScopes']+self.snapshot['optionalScopes']):
            scope['id']='11111111-1111-1111-1111-'+str(index+1).zfill(12)
        digest=binding.sha(binding.encoded(self.snapshot))
        candidate,_=planner.semantics.review(self.snapshot,digest,fixture.REF)
        proposal.update(bindingCandidate=candidate,bindingCandidateHash=binding.sha(binding.encoded(candidate)))
        self.plan,_=planner.compile_plan(self.snapshot,digest,proposal,binding.sha(binding.encoded(proposal)))
        self.context={'installationRef':'synthetic-test','entityRef':'synthetic-test','intentIssuerRef':'synthetic-installer',
            'approvalIssuerRef':'synthetic-installer','attestorRef':'synthetic-attestor'}
        self.now=int(time.time())
        keys=[{'keyRef':role,'issuerRef':issuer,'roles':roles,'publicKey':'a'*64,'state':'ACTIVE',
               'notBefore':self.now-10,'expiresAt':self.now+600}
              for role,issuer,roles in [('installer','synthetic-installer',['DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL']),
                                       ('attestor','synthetic-attestor',['CREATION_ATTESTATION'])]]
        self.policy={'schema':'ouf.semantic-deployment-trust-policy.v1','installationRef':'synthetic-test','entityRef':'synthetic-test','keys':keys}
        self.pb=self.write('policy.json',self.policy)
        # These key references deliberately do not exist. A successful intake
        # proves the preparation never attempts to open/probe a private key.
        self.profile={'schema':'ouf.semantic-existing-installation-authority-bindings.v1','authorities':self.context,
            'policyBinding':self.pb,'keyRefs':{'installer':'installer','attestor':'attestor'},
            'keyBindings':{r:{'path':str(self.parent/(r+'-PRIVATE-NONEXISTENT.pem')),'sha256':'b'*64} for r in ('installer','attestor')}}
        self.ab=self.write('profile.json',self.profile)
        self.write('plan.json',self.plan);self.write('snapshot.json',self.snapshot)
        self.closure={'sourceCommit':'a'*40,'sourceHashes':{n:binding.sha((ROOT/'tools/semantic_policy_token_owner'/(n+'.py')).read_bytes()) for n in intake.SOURCE_NAMES}}
        self.patches=[patch.object(binding,'PARENT',self.parent),patch.object(intake,'PROFILE',self.ab),patch.object(intake,'POLICY',self.pb),
            patch.object(intake,'CONTEXT',self.context),patch.object(intake,'PLAN','plan.json'),patch.object(intake,'SNAPSHOT','snapshot.json'),
            patch.object(intake,'PLAN_HASH',binding.sha(binding.encoded(self.plan))),patch.object(intake,'SNAPSHOT_HASH',binding.sha(binding.encoded(self.snapshot))),
            patch.object(intake.metadata,'Reader',return_value=object()),patch.object(intake.metadata,'core',return_value=intake.metadata.anchor(self.snapshot)),
            patch.object(intake.metadata,'complete_mappers',return_value={}),patch.object(intake.metadata,'enriched',return_value=self.snapshot),
            patch.object(intake,'executable',side_effect=lambda p:{'path':str(Path(p).resolve()),'sha256':'c'*64}),
            patch.object(intake.subprocess,'run',return_value=type('Result',(),{'returncode':0,'stdout':b'OpenSSL 3.0.0 fixture\n'})())]
        for p in self.patches:p.start();self.addCleanup(p.stop)
    def write(self,name,value):
        raw=binding.encoded(value);path=self.parent/name;path.write_bytes(raw);path.chmod(0o600)
        return {'path':str(path),'sha256':binding.sha(raw)}
    def test_native_custody_intake_preserves_inputs_no_key_reads_and_idempotent_publication(self):
        before={n:(self.parent/n).read_bytes() for n in ('profile.json','policy.json','plan.json','snapshot.json')}
        report={'privateEvidenceWrites':0};first=intake.prepare(self.closure,report)
        again={'privateEvidenceWrites':0};second=intake.prepare(self.closure,again)
        self.assertEqual(first,second);self.assertEqual(report['privateEvidenceWrites'],1);self.assertEqual(again['privateEvidenceWrites'],0)
        self.assertFalse(first['applySourceClosurePrepared']);self.assertFalse(first['productionApplyReady'])
        self.assertFalse(first['runtimeAuthorityIssued']);self.assertTrue(first['freshAuthorityAndReconciliationRequiredBeforePost'])
        self.assertNotIn('PRIVATE-NONEXISTENT',json.dumps(report))
        self.assertEqual(before,{n:(self.parent/n).read_bytes() for n in before})
        self.assertEqual(Path(report['privateEvidencePath']).stat().st_mode&0o777,0o600)
    def test_changed_public_policy_hash_denies_before_iam_or_publication(self):
        self.write('policy.json',{**self.policy,'entityRef':'OTHER'})
        with patch.object(intake.metadata,'core')as read:
            with self.assertRaisesRegex(binding.CandidateDenied,'HASH_DRIFT'):intake.prepare(self.closure,{'privateEvidenceWrites':0})
            self.assertFalse(read.called)
    def test_expired_revoked_or_missing_role_policy_denies_without_key_probe(self):
        for case in ('expiry','revoke','roles'):
            policy=copy.deepcopy(self.policy)
            if case=='expiry':policy['keys'][0]['expiresAt']=self.now-1
            if case=='revoke':policy['keys'][0]['state']='REVOKED'
            if case=='roles':policy['keys'][0]['roles']=['DEPLOYMENT_INTENT']
            with self.assertRaisesRegex(binding.CandidateDenied,'CURRENT_EXISTING_ROLE'):intake.authority_metadata(self.profile,policy,self.now)
    def test_current_iam_baseline_drift_blocks_before_publication(self):
        changed=copy.deepcopy(self.snapshot);changed['client']['clientId']='OTHER'
        with patch.object(intake.metadata,'enriched',return_value=changed):
            report={'privateEvidenceWrites':0}
            with self.assertRaisesRegex(binding.CandidateDenied,'MAPPER_BASELINE_DRIFT'):intake.prepare(self.closure,report)
            self.assertEqual(report['privateEvidenceWrites'],0)
    def test_unsafe_profile_symlink_and_wrong_preparation_source_set_deny(self):
        profile=self.parent/'profile.json';profile.rename(self.parent/'original-profile.json');profile.symlink_to(self.parent/'original-profile.json')
        with self.assertRaises(binding.CandidateDenied):intake.prepare(self.closure,{'privateEvidenceWrites':0})
        with self.assertRaisesRegex(binding.CandidateDenied,'SOURCE_CLOSURE'):intake.prepare({'sourceCommit':'a'*40,'sourceHashes':{}},{'privateEvidenceWrites':0})

if __name__=='__main__':unittest.main()
