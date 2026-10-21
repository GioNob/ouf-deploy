"""Actual root custody and existing Ed25519 signer; simulated IAM effects."""
import copy
from pathlib import Path
import sys
import time
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tests')]
import test_cutover_authority_native as signed_fixture
import iam_binding_candidate as binding
import iam_governance_intake as governance
import iam_owner_action as owner
import iam_action_runtime as runtime
from test_policy_token_introspection_audience_plan import inputs,planner,fixture

def sources():
    paths={p.stem:p for p in (ROOT/'tools/semantic_policy_token_owner').glob('*.py')}
    paths.update({p.stem:p for p in (ROOT/'tools/semantic_application_cutover').glob('*.py')})
    paths.update({'tools.'+p.stem:p for p in (ROOT/'tools/semantic_cohort_admission/cohort-draft/tools').glob('*.py')})
    return {n:paths[n].read_bytes() for n in runtime.MODULES}

class OwnerActionTest(unittest.TestCase):
    def setUp(self):
        signed=signed_fixture.SignedCutover();signed.setUp();self.addCleanup(signed.doCleanups);self.signed=signed
        self.snapshot,_,proposal,_=inputs()
        for i,s in enumerate(self.snapshot['defaultScopes']+self.snapshot['optionalScopes']):s['id']='11111111-1111-1111-1111-'+str(i+1).zfill(12)
        sh=binding.sha(binding.encoded(self.snapshot));candidate,_=planner.semantics.review(self.snapshot,sh,fixture.REF)
        proposal.update(bindingCandidate=candidate,bindingCandidateHash=binding.sha(binding.encoded(candidate)))
        self.plan,_=planner.compile_plan(self.snapshot,sh,proposal,binding.sha(binding.encoded(proposal)))
        self.plan_hash=binding.sha(binding.encoded(self.plan))
        profile={'schema':'ouf.semantic-existing-installation-authority-bindings.v1','authorities':signed.context,
            'policyBinding':signed.binding(signed.policy),'keyRefs':{'installer':signed.grant['keyRef'],'attestor':'synthetic-fixture-attestor-key'},
            'keyBindings':{'installer':signed.binding(signed.key),'attestor':{'path':str(signed.root/'UNREAD-ATTESTOR.pem'),'sha256':'a'*64}}}
        self.profile=signed.root/'profile.json';signed.write(self.profile,binding.encoded(profile))
        self.programs={'python':{'path':str(Path(sys.executable).resolve()),'sha256':'b'*64},
            'docker':{'path':str(Path('/usr/bin/docker').resolve()),'sha256':'c'*64},
            'openssl':{**signed.binding(signed.openssl),'version':signed.native('version').decode().split()[1]}}
        change=self.plan['changeProposal'];scope={'reviewPlanHash':self.plan_hash,'resource':change['resource'],
            'mapperHash':binding.sha(binding.encoded(change['proposedMapper'])),'operation':'ADD_EXACT_CALLER_AUDIENCE_MAPPER',
            'maximumIamMutations':1,'introspectionCheckMustRemainEnabled':True,'runtimeAuthorityIssued':False}
        intake={'schema':'ouf.policy-token-governed-iam-preparation-intake.v1','authorityProfile':signed.binding(self.profile),
            'trustPolicy':signed.binding(signed.policy),'context':signed.context,'runtimeAuthorityIssued':False,'productionApplyReady':False,
            'reviewPlanHash':self.plan_hash,'snapshotHash':sh,'executablesProposedNotAccepted':self.programs,'policyTokenIamPreparation':scope}
        self.intake=signed.root/'intake.json';signed.write(self.intake,binding.encoded(intake))
        signed.write(signed.root/'plan.json',binding.encoded(self.plan));signed.write(signed.root/'snapshot.json',binding.encoded(self.snapshot))
        self.library={'root':'SYNTHETIC-UNIT-FIXTURE','fileHashes':{'stdlib.py':{'sha256':'d'*64}},'noSiteRequired':True}
        self.manifest=runtime.declaration('a'*40,sources(),(ROOT/'tools/semantic_policy_token_owner/iam_action_runtime.py').read_bytes())
        self.patches=[patch.object(binding,'PARENT',signed.root),patch.object(owner,'INTAKE',self.intake.name),
            patch.object(owner,'INTAKE_HASH',binding.sha(self.intake.read_bytes())),patch.object(governance,'PROFILE',signed.binding(self.profile)),
            patch.object(governance,'POLICY',signed.binding(signed.policy)),patch.object(governance,'CONTEXT',signed.context),
            patch.object(governance,'PLAN','plan.json'),patch.object(governance,'PLAN_HASH',self.plan_hash),
            patch.object(governance,'SNAPSHOT','snapshot.json'),patch.object(governance,'SNAPSHOT_HASH',sh),
            patch.object(governance,'executable',side_effect=lambda p:next({k:v for k,v in item.items() if k in {'path','sha256'}} for item in self.programs.values() if item['path']==p)),
            patch.object(owner,'stdlib_binding',return_value=self.library)]
        for p in self.patches:p.start();self.addCleanup(p.stop)
    def review(self):
        report={};review=owner.prepare(self.manifest,report);digest=report['privateEvidenceHash']
        now=int(time.time());decision={'approvalRef':'SYNTHETIC_IAM_ONLY_APPROVAL','approvedReviewHash':digest,
            'approvedSourceClosureHash':review['sourceClosureHash'],'approvedAt':now,'firstInvocationBefore':now+120,
            'decision':'APPROVE_ONE_EXACT_IAM_CALLER_AUDIENCE_MAPPER','state':'ACTIVE'}
        return review,digest,decision
    def report(self):return {'signaturesIssued':0,'installationKeyAccessAttempted':False,'humanIssuanceClaimConsumed':False}
    def test_prepare_closes_all_sources_without_signing_or_iam_reads(self):
        with patch.object(owner.ExistingEd25519Signer,'sign')as sign,patch.object(owner.MapperAdmin,'models')as read:
            review,h,decision=self.review()
        self.assertFalse(sign.called);self.assertFalse(read.called);self.assertEqual(review['sourceClosure']['declaration']['moduleCount'],22)
        self.assertTrue(review['freshHumanApprovalRequired']);self.assertFalse(review['productionApplyReady'])
    def test_actual_two_role_signatures_current_human_one_effect_and_consumed_issuance(self):
        _,h,decision=self.review();models=copy.deepcopy(self.snapshot['client']['protocolMappers']);calls=[]
        def baseline(s):
            value=copy.deepcopy(s);value['client']['protocolMappers']=copy.deepcopy(models);return value
        def create(m):calls.append(m);models.append(copy.deepcopy(m))
        report=self.report()
        with patch.object(owner.MapperAdmin,'models',side_effect=lambda:copy.deepcopy(models)),patch.object(owner.MapperAdmin,'baseline',side_effect=baseline), \
            patch.object(owner.MapperAdmin,'create',side_effect=create):
            owner.apply(self.manifest,h,decision,report)
            with self.assertRaisesRegex(binding.CandidateDenied,'ISSUANCE_ALREADY_CONSUMED'):owner.apply(self.manifest,h,decision,self.report())
        self.assertEqual(len(calls),1);self.assertEqual(report['signaturesIssued'],2)
        self.assertTrue(report['installationKeyAccessAttempted']);self.assertTrue(report['iamPreparationAuthorityVerified'])
        self.assertFalse(report['runtimeAuthorityIssued']);self.assertEqual(report['iamMutations'],1)
    def test_missing_expired_or_wrong_hash_approval_and_host_drift_deny_before_key_access(self):
        _,h,decision=self.review()
        for case in ('absent','expired','hash','stdlib'):
            d=copy.deepcopy(decision)
            if case=='absent':d=None
            if case=='expired':d['firstInvocationBefore']=d['approvedAt']
            if case=='hash':d['approvedReviewHash']='f'*64
            with patch.object(owner.ExistingEd25519Signer,'sign')as sign:
                if case=='stdlib':
                    with patch.object(owner,'stdlib_binding',return_value={}):
                        with self.assertRaises(binding.CandidateDenied):owner.apply(self.manifest,h,d,self.report())
                else:
                    with self.assertRaises(binding.CandidateDenied):owner.apply(self.manifest,h,d,self.report())
                self.assertFalse(sign.called)
    def failed_post(self,scenario):
            _,h,decision=self.review();decision['approvalRef']+='_'+scenario
            models=copy.deepcopy(self.snapshot['client']['protocolMappers']);calls=[]
            def create(m):
                calls.append(m);models.append(copy.deepcopy(m))
                if scenario=='ambiguous':raise TimeoutError('SYNTHETIC_AMBIGUOUS_POST')
                context=next(self.signed.root.glob('policy-token-iam-signed-context-*'))
                path=context/'human.json';value=binding.decode(path.read_bytes());value['state']='REVOKED';self.signed.write(path,binding.encoded(value))
            with patch.object(owner.MapperAdmin,'models',side_effect=lambda:copy.deepcopy(models)), \
                patch.object(owner.MapperAdmin,'baseline',side_effect=lambda s:copy.deepcopy(s)),patch.object(owner.MapperAdmin,'create',side_effect=create):
                with self.assertRaises(Exception):owner.apply(self.manifest,h,decision,self.report())
            self.assertEqual(len(calls),1)
            with self.assertRaisesRegex(binding.CandidateDenied,'ISSUANCE_ALREADY_CONSUMED'):owner.apply(self.manifest,h,decision,self.report())
    def test_late_human_revocation_preserves_consumption(self):self.failed_post('revocation')
    def test_ambiguous_post_preserves_consumption(self):self.failed_post('ambiguous')
    def test_only_exact_public_python_shared_library_link_is_bound(self):
        self.patches[-1].stop()
        real=owner.stdlib_binding
        with tempfile.TemporaryDirectory(dir=ROOT)as temporary:
            prefix=Path(temporary);prefix.chmod(0o700);root=prefix/'stdlib';root.mkdir(mode=0o700)
            version=str(sys.version_info.major)+'.'+str(sys.version_info.minor);arch='synthetic-test-arch'
            config=root/('config-'+version+'-'+arch);config.mkdir(mode=0o700)
            public=prefix/'lib';public.mkdir(mode=0o700);target=public/('libpython'+version+'.so.1.0')
            target.write_bytes(b'SYNTHETIC_SHARED_CODE');target.chmod(0o600)
            link=config/('libpython'+version+'.so');link.symlink_to(target)
            with patch.object(owner.sysconfig,'get_path',return_value=str(root)),patch.object(owner.sysconfig,'get_config_var',return_value=arch), \
                patch.object(owner.sys,'base_prefix',str(prefix)):
                value=real();self.assertEqual(len(value['fileHashes']),1)
                link.unlink();unknown=prefix/'PRIVATE-UNRELATED';unknown.write_bytes(b'UNRELATED');unknown.chmod(0o600);link.symlink_to(unknown)
                with self.assertRaisesRegex(binding.CandidateDenied,'LINK_DESTINATION_UNPROVEN'):real()

if __name__=='__main__':unittest.main()
