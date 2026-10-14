"""Retained-only conditional IAM review never infers role audiences or applies."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
import subprocess
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tests')]
import iam_binding_candidate as binding
import iam_mapper_semantics_review as semantics
import iam_introspection_audience_plan as planner
from test_policy_token_mapper_semantics_review import standard,fixture

def inputs(explicit=False):
    snapshot=standard();snapshot['client']['id']='11111111-1111-1111-1111-111111111111'
    if explicit:snapshot['client']['protocolMappers'].append({'protocol':'openid-connect','protocolMapper':'oidc-audience-mapper',
        'config':{'included.client.audience':snapshot['client']['clientId'],'access.token.claim':'true','introspection.token.claim':'true'}})
    snapshot_hash=binding.sha(binding.encoded(snapshot));candidate,_=semantics.review(snapshot,snapshot_hash,fixture.REF)
    proposal={'schema':'ouf.policy-token-install-input-proposal.v1','bindingCandidate':candidate,
        'bindingCandidateHash':binding.sha(binding.encoded(candidate)),
        'issuerArtifact':{'declaredVersion':planner.VERSION,'imageId':planner.IMAGE,'codeMountObserved':False},
        'runtimeAuthorityIssued':False,'productionApplyReady':False,'budgetReset':False}
    return snapshot,snapshot_hash,proposal,binding.sha(binding.encoded(proposal))

class CallerAudiencePlanTest(unittest.TestCase):
    def test_missing_explicit_caller_has_conditional_exact_one_mapper_no_grant_or_bypass(self):
        data=inputs();plan,public=planner.compile_plan(*data)
        self.assertEqual(public['plannedIamMutations'],1)
        change=plan['changeProposal'];self.assertEqual(change['operation'],'ADD_EXACT_CALLER_AUDIENCE_MAPPER')
        self.assertEqual(change['proposedMapper']['config']['included.client.audience'],data[0]['client']['clientId'])
        self.assertTrue(change['conditionalProposalNotProofThatCurrentTokenFails'])
        self.assertTrue(change['requiresCurrentApprovedCallerAudienceReconciliation'])
        self.assertFalse(change['applyAuthorized']);self.assertFalse(public['introspectionCheckDisableRequested'])
        self.assertNotIn('PRIVATE_FIXTURE_CLIENT',json.dumps(public))
    def test_existing_explicit_caller_audience_does_not_get_duplicate_change(self):
        plan,public=planner.compile_plan(*inputs(True))
        self.assertTrue(public['explicitCallerAudienceMapperObserved'])
        self.assertIsNone(plan['changeProposal']);self.assertEqual(public['plannedIamMutations'],0)
        self.assertFalse(plan['runtimeAuthorityIssued'])
    def test_role_resolution_and_unrequested_optional_do_not_prove_caller_audience(self):
        data=list(inputs());s=data[0]
        s['client']['protocolMappers'].append({'protocol':'openid-connect','protocolMapper':'oidc-audience-resolve-mapper','config':{}})
        s['optionalScopes'][1]['protocolMappers']=[{'protocol':'openid-connect','protocolMapper':'oidc-audience-mapper',
            'config':{'included.client.audience':s['client']['clientId'],'access.token.claim':'true','introspection.token.claim':'true'}}]
        data[1]=binding.sha(binding.encoded(s));candidate,_=semantics.review(s,data[1],fixture.REF)
        data[2]['bindingCandidate']=candidate;data[2]['bindingCandidateHash']=binding.sha(binding.encoded(candidate))
        data[3]=binding.sha(binding.encoded(data[2]));_,public=planner.compile_plan(*data)
        self.assertTrue(public['audienceResolveMapperObserved']);self.assertFalse(public['roleResolvedCallerAudienceProven'])
        self.assertFalse(public['explicitCallerAudienceMapperObserved'])
    def test_target_version_image_acceptance_drift_and_managed_name_collision_block(self):
        for case in ('version','image','authority','collision'):
            data=list(inputs())
            if case=='version':data[2]['issuerArtifact']['declaredVersion']='26.0.8'
            if case=='image':data[2]['issuerArtifact']['imageId']='sha256:'+'f'*64
            if case=='authority':data[2]['runtimeAuthorityIssued']=True
            if case=='collision':
                data[0]['client']['protocolMappers'][0]['name']=planner.NAME
                data[1]=binding.sha(binding.encoded(data[0]));candidate,_=semantics.review(data[0],data[1],fixture.REF)
                data[2]['bindingCandidate']=candidate;data[2]['bindingCandidateHash']=binding.sha(binding.encoded(candidate))
            with self.assertRaises(binding.CandidateDenied):planner.compile_plan(*data)
    def test_private_plan_reconciles_and_preserves_both_inputs(self):
        s,h,p,ph=inputs()
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            parent=Path(temporary);parent.chmod(0o700)
            metadata=parent/('policy-token-iam-metadata-'+'a'*32+'.private.json')
            proposal=parent/('policy-token-install-inputs-'+ph+'.private.json')
            mr,pr=binding.encoded(s),binding.encoded(p)
            for path,raw in ((metadata,mr),(proposal,pr)):path.write_bytes(raw);path.chmod(0o600)
            with patch.object(binding,'PARENT',parent),patch.object(planner,'image_bindings',return_value=({},{})):
                first={'privateEvidenceWrites':0};planner.prepare(str(metadata),h,str(proposal),ph,first)
                second={'privateEvidenceWrites':0};planner.prepare(str(metadata),h,str(proposal),ph,second)
                self.assertEqual(first['privateEvidenceWrites'],1);self.assertEqual(second['privateEvidenceWrites'],0)
                self.assertEqual(Path(first['privateEvidencePath']).stat().st_mode&0o777,0o600)
            self.assertEqual(metadata.read_bytes(),mr);self.assertEqual(proposal.read_bytes(),pr)

    def test_selected_image_distribution_drift_and_private_repository_names_are_not_exposed(self):
        official='quay.io/keycloak/keycloak@sha256:'+'a'*64
        replies=[{'image':planner.IMAGE,'running':True}, {'id':planner.IMAGE,'architecture':'amd64','os':'linux',
            'digests':[official,'PRIVATE_REGISTRY/PRIVATE_IMAGE@sha256:'+'b'*64]}]
        def run(argv,**kwargs):return subprocess.CompletedProcess(argv,0,binding.encoded(replies.pop(0)))
        report={}
        with patch.object(planner.subprocess,'run',side_effect=run): image,public=planner.image_bindings(report)
        self.assertEqual(report['dockerMetadataReads'],2);self.assertEqual(public['recognizedOfficialImageReferences'],[official])
        self.assertNotIn('PRIVATE_',json.dumps(public));self.assertFalse(public['targetProviderImplementationProven'])
        with patch.object(planner.subprocess,'run',return_value=subprocess.CompletedProcess([],0,binding.encoded({'image':'sha256:'+'c'*64,'running':True}))):
            with self.assertRaises(binding.CandidateDenied):planner.image_bindings({})

if __name__=='__main__':unittest.main()
