"""Production bridge state/custody and frozen loader; synthetic HUMAN/issuer.

No target calls or authority. Existing native signatures/platform qualification
are separate. This fixture exercises real private journals and HUMAN reader.
"""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),
    str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_ingestion_rollout_native_review as native_fixture
import test_governed_human_operator as human_fixture
from tools.governed_human_successor import operator as hop
from tools.governed_human_successor.session import ExplicitFreshSession
from tools.ingestion_rollout_execution import contract as c,authority as a
from tools.ingestion_rollout_preparation import production_control as p,production_delivery
from tools.semantic_lease_recovery.recovery_journal import Journal
import test_ingestion_rollout_authority as issuer_fixture

class ProductionControl(unittest.TestCase):
    def setUp(self):
        self.native=native_fixture.NativeReview();self.native.setUp();self.addCleanup(self.native.doCleanups)
        self.human_fixture=human_fixture.OperatorControl();self.human_fixture.setUp();self.addCleanup(self.human_fixture.doCleanups)
        hf=self.human_fixture;hf.open()
        replies=[hf.discovery(),hf.device(),(200,{'access_token':hf.token(),'refresh_token':'private-fixture-refresh','token_type':'Bearer'},0),
            (200,{'sub':hf.selection['subject']},0)]
        with patch.object(hop,'terminal_confirm',return_value=True),patch.object(ExplicitFreshSession,'_http',side_effect=replies):
            hop.execute('step',hf.control,hf.case,hf.confirmed,hf.closure)
            hop.execute('step',hf.control,hf.case,hf.confirmed,hf.closure);hf.now+=6
            hop.execute('step',hf.control,hf.case,hf.confirmed,hf.closure)
            ready=hop.execute('step',hf.control,hf.case,hf.confirmed,hf.closure)
        self.human_path=ready['privateHumanReadProfilePath']
        f=self.native;profiles=f.profiles;self.root=Path(profiles['ownerControlProfile']['projection']['path']).parent
        owner=self.root/'retained-owner';owner.mkdir(mode=0o700)
        f.owner_plan.update(authorityDirectory=str(owner),humanBinding={'selectionHash':c.digest(hf.selection)})
        f.packet['ownerPlanSha256']=c.digest(f.owner_plan);f.completed['planHash']=c.digest(f.owner_plan)
        self.case={'retainedHumanAttempts':278,'maximumCumulativeOAuthAttempts':288,
            'expiredHumanWindowExpiresAt':hf.row['binding']['expiresAt']}
        for key,value in zip(('packetBinding','verifiedInputsBinding','ownerPlanBinding','ownerResultBinding'),
            (f.packet,f.inputs,f.owner_plan,f.completed)):
            file=self.write(owner/(key+'.json'),value);self.case[key]={'path':str(file),'sha256':c.digest(value)}
        root=self.root/'ingestion-native-profiles-ABCDEFGH';root.mkdir(mode=0o700)
        self.case['nativeProfiles']={'contextPath':str(root),'captureContext':str(self.root/'retained-capture'),
            'sourceClosureHash':'a'*64,'selectedEndpoints':{n:profiles[k]['endpoint']for n,k in
                (('owner','ownerControlProfile'),('ingestion','ingestionReadinessProfile'),('gateway','gatewayTransportProfile'))}}
        logical=c.digest({'profile':'ouf.ingestion-native-profile-preparation.v1',
            'captureContext':self.case['nativeProfiles']['captureContext'],'packetBinding':self.case['packetBinding']})
        Journal(root).initialize({'schema':'ouf.ingestion-native-profile-preparation.v1','complete':True,'phase':'COMPLETE',
            'sourceClosureHash':'a'*64,'logicalRef':logical,'budgetReset':False,'runtimeAuthorityIssued':False})
        self.write(self.root/('ingestion-native-profiles-'+logical+'.claim.json'),{'logicalRef':logical,'contextPath':str(root),'sourceClosureHash':'a'*64})
        self.write(root/'profiles.json',profiles)
        installed=self.write(owner/'issuer.json',{'synthetic':'public-issuer-only-no-key-read'})
        policy=self.write(owner/'policy.json',{'synthetic':'public-policy-only-no-key-read'})
        self.case['existingIssuer']={'installationAuthority':{'path':str(installed),'sha256':hashlib.sha256(installed.read_bytes()).hexdigest()},
            'policy':{'path':str(policy),'sha256':hashlib.sha256(policy.read_bytes()).hexdigest()},'authorityContext':{'installationRef':'fixture-installation','entityRef':'fixture-entity','intentIssuerRef':'fixture-intent','approvalIssuerRef':'fixture-approval','attestorRef':'fixture-attestor'},'opensslExecutablePath':'/fixture/openssl'}
        self.manifest={'sourceCommit':'1'*40,'sourceHashes':{'fixture.source':'a'*64},'entryModule':'tools.ingestion_rollout_execution.entry',
            'requiredPythonFlags':['-I','-B','-S'],'runtimeAuthorityIssued':False,'moduleCount':114}
        self.case['qualification']={'schema':'ouf.ingestion-rollout-native-qualification.v1',
            'sourceCommit':'1'*40,'sourceHashes':self.manifest['sourceHashes'],
            'candidateNativeImageId':f.packet['candidate']['nativeImageId'],'candidateSourceCommit':f.packet['candidate']['sourceCommit'],
            'results':dict.fromkeys(a.QUALIFICATION,'PASS'),'runtimeAuthorityIssued':False,'notReleaseAcceptance':True,
            'evidenceRefs':{k:{'repository':'GioNob/ouf-deploy','runId':1,'jobId':1,'sourceCommit':'1'*40}for k in a.QUALIFICATION}}
        self.entry=SimpleNamespace(c=c,authority=a,Journal=Journal,load_action=Mock(return_value=object()),execute=Mock())
        self.control_hash='b'*64
        python=copy.deepcopy(profiles['ownerControlProfile']['pythonExecutable']);docker=copy.deepcopy(profiles['databaseControlProfile']['dockerExecutable'])
        programs={python['path']:python,docker['path']:docker,sys.executable:python,'/fixture/openssl':{'path':'/fixture/openssl','sha256':'e'*64}}
        self.patches=[]
        for patched in[patch.object(a,'current_issuer',return_value=({},b'public-fixture')),
            patch.object(a,'verify_closure'),patch.object(a,'stdlib_binding',return_value={'fileHashes':{'fixture.py':'d'*64}}),
            patch.object(a.governance,'executable',side_effect=lambda path:copy.deepcopy(programs[path])),
            patch.object(p.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=b'OpenSSL 3.0.1 fixture'))]:
            patched.start();self.addCleanup(patched.stop);self.patches.append(patched)
    def write(self,path,value):path.write_bytes(c.encoded(value));path.chmod(0o600);return path
    def invoke(self,*args):return p.execute(self.entry,self.manifest,self.case,self.control_hash,list(args))
    def prepare(self):
        result=self.invoke('prepare');self.context=result['contextPath'];return result
    def reviewed(self):self.prepare();return self.invoke('review',self.context,self.human_path)
    def decision(self,review,summary):
        now=int(time.time());return {'schema':'ouf.semantic-scoped-terminal-decision.v1','reviewHash':c.digest(review),
            'approvalRef':'mcp-scoped-'+c.digest(review)[:24]+'-'+str(now),'sourceClosureHash':review['sourceClosureHash'],
            'humanSessionHash':c.digest(review['authenticatedHuman']),'approvedAt':now,'expiresAt':now+900,
            'decision':'APPROVE_EXACT_FINITE_SCOPED_ACTION','state':'ACTIVE'}
    def issued(self):
        self.reviewed()
        def issue(review,decision,human,approved_hash):
            self.assertEqual(approved_hash,c.digest(decision))
            self.write(Path(self.context)/'decision.json',decision);self.write(Path(self.context)/'human.json',{'synthetic':'mandate'})
        with patch.object(a,'terminal_consent',side_effect=self.decision),patch.object(a,'issue_action',side_effect=issue):
            return self.invoke('approve',self.context)
    def test_prepare_is_one_private_context_no_human_or_runtime_dispatch(self):
        before={file:file.read_bytes()for file in(self.root/'retained-owner').iterdir()}
        with patch.object(a.human_reader,'open_existing')as human:
            result=self.prepare();human.assert_not_called()
        self.assertTrue(result['complete']);self.assertFalse(result['runtimeAuthorityIssued']);self.assertEqual(result['privateKeysRead'],0)
        self.entry.execute.assert_not_called();self.entry.load_action.assert_not_called()
        self.assertEqual({file:file.read_bytes()for file in(self.root/'retained-owner').iterdir()},before)
        self.assertFalse((Path(self.context)/'recovery.json').exists())
        with self.assertRaisesRegex(c.Denied,'ALREADY_CLAIMED'):self.invoke('prepare')
    def test_failed_public_policy_keeps_preparation_claim_no_reinitialization(self):
        with patch.object(a,'current_issuer',side_effect=c.Denied('CURRENT_EXISTING_ROLE_WINDOW_REQUIRED')):
            with self.assertRaises(c.Denied):self.invoke('prepare')
        context=p.CHECKPOINT['contextPath'];self.assertEqual(self.invoke('status',context)['state'],'PREPARING')
        with self.assertRaisesRegex(c.Denied,'ALREADY_CLAIMED'):self.invoke('prepare')
    def test_changed_profile_endpoint_or_missing_qualification_stops_before_new_claim(self):
        original=copy.deepcopy(self.case)
        self.case['nativeProfiles']['selectedEndpoints']['owner']={'host':'::1','port':8080}
        with self.assertRaisesRegex(c.Denied,'ENDPOINT_RECEIPT_CHANGED'):self.invoke('prepare')
        self.case=original;self.case['qualification']['results']['apisix']='BLOCKED'
        with self.assertRaises(c.Denied):self.invoke('prepare')
        self.assertFalse(list(self.root.glob('ingestion-rollout-control-*.claim.json')))
    def test_status_after_human_expiration_never_opens_human_credentials(self):
        self.prepare();self.human_fixture.now+=10000
        with patch.object(a.human_reader,'open_existing')as human:
            result=self.invoke('status',self.context);human.assert_not_called()
        self.assertTrue(result['readOnly']);self.assertEqual(result['engineRequests'],0)
    def test_wrong_case_source_or_control_claim_has_no_runtime_dispatch(self):
        self.prepare()
        with self.assertRaisesRegex(c.Denied,'SAME_RETAINED_PRODUCTION_CONTROL'):
            p.execute(self.entry,self.manifest,self.case,'c'*64,['status',self.context])
        claim=next(self.root.glob('ingestion-rollout-control-*.claim.json'));value=json.loads(claim.read_text());value['contextPath']='/foreign'
        self.write(claim,value)
        with self.assertRaises(c.Denied):self.invoke('status',self.context)
        self.entry.execute.assert_not_called()
    def test_review_uses_concrete_read_only_human_no_new_provider_request(self):
        with patch.object(ExplicitFreshSession,'_http')as http:result=self.reviewed();http.assert_not_called()
        self.assertEqual(result['status'],'EXACT_RUNTIME_REVIEW_PREPARED_APPROVAL_REQUIRED')
        review=json.loads((Path(self.context)/'review.json').read_text())
        self.assertEqual(review['operatorBinding']['controlSourceHash'],self.control_hash)
        self.assertEqual(review['authenticatedHuman']['selectionHash'],c.digest(self.human_fixture.selection))
        self.assertEqual(review['executionReview']['humanReadProfile']['minimumCumulativeAttempts'],282)
        self.entry.execute.assert_not_called()
        with self.assertRaisesRegex(c.Denied,'REVIEW_NOT_REPLAYABLE'):self.invoke('review',self.context,self.human_path)
    def test_expired_human_fails_before_review_claim_or_runtime(self):
        self.prepare();self.human_fixture.now+=10000
        with self.assertRaisesRegex(c.Denied,'EXPIRED_NO_LOGIN_OR_RENEWAL'):self.invoke('review',self.context,self.human_path)
        self.assertFalse((Path(self.context)/'review.json').exists());self.entry.execute.assert_not_called()
    def test_approval_requires_terminal_decision_and_never_dispatches_rollout(self):
        self.reviewed()
        with patch.object(a,'terminal_consent',side_effect=c.Denied('EXACT_CURRENT_TERMINAL_CONSENT_NOT_GIVEN')),patch.object(a,'issue_action')as issue:
            with self.assertRaises(c.Denied):self.invoke('approve',self.context)
            issue.assert_not_called()
        self.entry.execute.assert_not_called()
    def test_partial_issuance_is_retained_and_cannot_be_approved_again(self):
        self.reviewed()
        def interrupted(*args):self.write(Path(self.context)/'ingestion-rollout-issuance.claim.json',{'fixture':'claimed'});raise RuntimeError('synthetic signature interruption')
        with patch.object(a,'terminal_consent',side_effect=self.decision),patch.object(a,'issue_action',side_effect=interrupted):
            with self.assertRaises(RuntimeError):self.invoke('approve',self.context)
        self.assertEqual(self.invoke('status',self.context)['state'],'ISSUING')
        with patch.object(a,'issue_action')as issue:
            with self.assertRaisesRegex(c.Denied,'ISSUANCE_NOT_REPLAYABLE'):self.invoke('approve',self.context)
            issue.assert_not_called()
    def test_one_runtime_call_per_explicit_mode_and_stop_requires_reconciliation(self):
        self.issued();self.entry.execute.return_value={'initialized':True,'complete':False}
        result=self.invoke('initialize',self.context);self.assertEqual(result['controlState'],'INITIALIZED');self.assertEqual(self.entry.execute.call_count,1)
        with self.assertRaises(c.Denied):self.invoke('initialize',self.context)
        self.entry.execute.side_effect=RuntimeError('synthetic ambiguous effect')
        with self.assertRaises(RuntimeError):self.invoke('step',self.context)
        self.assertEqual(self.invoke('status',self.context)['state'],'RECONCILE_REQUIRED')
        before=self.entry.execute.call_count
        with self.assertRaises(c.Denied):self.invoke('step',self.context)
        self.assertEqual(self.entry.execute.call_count,before)
        self.entry.execute.side_effect=None;self.entry.execute.return_value={'complete':True,'runtimeAuthorityIssued':False}
        self.assertTrue(self.invoke('reconcile',self.context)['complete']);self.assertEqual(self.entry.execute.call_count,before+1)
    def test_operator_binding_cannot_be_changed_after_review(self):
        self.reviewed();review=json.loads((Path(self.context)/'review.json').read_text());review['operatorBinding']['controlSourceHash']='f'*64
        self.write(Path(self.context)/'review.json',review)
        with patch.object(a,'terminal_consent')as consent:
            with self.assertRaises(c.Denied):self.invoke('approve',self.context)
            consent.assert_not_called()

class SealedProductionDelivery(unittest.TestCase):
    def test_complete_private_preparation_through_frozen_entry_actual_public_policy_and_stdlib(self):
        # The actual root-custodied distro interpreter is used for this complete
        # host-custody path; matrix interpreters additionally qualify delivery
        # reproducibility, control states and isolated114-module loading.
        if not Path('/usr/bin/python3').exists():self.skipTest('Root distro interpreter mandatory in Linux CI')
        fixture=ProductionControl();fixture.setUp();self.addCleanup(fixture.doCleanups)
        for patched in reversed(fixture.patches):patched.stop()
        def binding(path):
            path=Path(path).resolve();return {'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
        root=fixture.root;case=copy.deepcopy(fixture.case);profiles_path=Path(case['nativeProfiles']['contextPath'])/'profiles.json'
        profiles=json.loads(profiles_path.read_text());program=binding('/usr/bin/python3');docker=binding('/usr/bin/true')
        for key in('ownerControlProfile','retainedGatewayTransportProfile','gatewayTransportProfile','ingestionReadinessProfile'):profiles[key]['pythonExecutable']=program
        for key in('databaseControlProfile','imageImportProfile'):profiles[key]['dockerExecutable']=docker
        fixture.write(profiles_path,profiles)
        context=case['existingIssuer']['authorityContext'];context['approvalIssuerRef']=context['intentIssuerRef'];now=int(time.time())
        # No private keys exist at these references. Successful preparation
        # therefore proves it does not open/probe them while inspecting policy.
        policy={'schema':'ouf.semantic-deployment-trust-policy.v1','installationRef':context['installationRef'],
            'entityRef':context['entityRef'],'keys':[
                {'keyRef':'fixture-installer','issuerRef':context['intentIssuerRef'],'roles':['DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL'],
                 'publicKey':'a'*64,'state':'ACTIVE','notBefore':now-30,'expiresAt':now+3600},
                {'keyRef':'fixture-attestor','issuerRef':context['attestorRef'],'roles':['CREATION_ATTESTATION'],
                 'publicKey':'b'*64,'state':'ACTIVE','notBefore':now-30,'expiresAt':now+3600}]}
        policy_path=Path(case['existingIssuer']['policy']['path']);fixture.write(policy_path,policy);case['existingIssuer']['policy']=binding(policy_path)
        installed={'schema':'ouf.semantic-existing-installation-authority-bindings.v1','authorities':context,
            'policyBinding':case['existingIssuer']['policy'],'keyRefs':{'installer':'fixture-installer','attestor':'fixture-attestor'},
            'keyBindings':{'installer':{'path':str(root/'private-installer-does-not-exist'),'sha256':'a'*64},
                'attestor':{'path':str(root/'private-attestor-does-not-exist'),'sha256':'b'*64}}}
        installed_path=Path(case['existingIssuer']['installationAuthority']['path']);fixture.write(installed_path,installed)
        case['existingIssuer'].update(installationAuthority=binding(installed_path),opensslExecutablePath='/usr/bin/openssl')
        actual=json.loads((ROOT/'releases/ingestion-rollout-production-case-20261020.json').read_text())
        case['qualifiedNativeSource']=actual['qualifiedNativeSource'];case['qualification']['sourceCommit']=actual['qualification']['sourceCommit']
        case['qualification']['sourceHashes']=actual['qualification']['sourceHashes']
        case['qualification']['evidenceRefs']=actual['qualification']['evidenceRefs']
        case['fixtureOnlyNeverTargetAuthority']=True
        raw,_=production_delivery.generate(ROOT,case);script=root/'actual-sealed-production-prepare.py';script.write_bytes(raw)
        run=subprocess.run(['/usr/bin/python3','-I','-B','-S',str(script),'prepare'],capture_output=True,text=True,timeout=90)
        self.assertEqual(run.returncode,0,run.stdout+run.stderr);value=json.loads(run.stdout)
        self.assertTrue(value['complete']);self.assertEqual(value['sourceModuleCount'],114)
        self.assertEqual(value['privateKeysRead'],0);self.assertEqual(value['humanCredentialJournalsRead'],0);self.assertFalse(value['runtimeAuthorityIssued'])
        self.assertFalse((root/'private-installer-does-not-exist').exists())
        status=subprocess.run(['/usr/bin/python3','-I','-B','-S',str(script),'status',value['contextPath']],capture_output=True,text=True,timeout=30)
        self.assertEqual(status.returncode,0,status.stdout+status.stderr);self.assertEqual(json.loads(status.stdout)['state'],'PRIVATE_READY')
    def test_reproducible_exact_115_git_blobs_and_actual_native_memory_loader(self):
        case=json.loads((ROOT/'releases/ingestion-rollout-production-case-20261020.json').read_text())
        raw,declaration=production_delivery.generate(ROOT,case)
        self.assertEqual((ROOT/'scripts/ingestion-rollout-production-control-20261020.py').read_bytes(),raw)
        self.assertEqual(declaration['nativeDeclaration']['moduleCount'],114)
        # Before any retained target lookup, use a deliberately wrong status
        # context; the actual frozen loader/entry and bridge run in isolation.
        result=subprocess.run([sys.executable,'-I','-B','-S',str(ROOT/'scripts/ingestion-rollout-production-control-20261020.py'),
            'status','/unqualified-context'],capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,2,result.stdout+result.stderr)
        value=json.loads(result.stdout);self.assertEqual(value['reasonCode'],'EXACT_PRIVATE_PRODUCTION_CONTEXT_REQUIRED')
        self.assertNotIn('PRIVATE_FIXTURE',result.stdout)
    def test_changed_native_source_pin_rejected_without_delivery(self):
        case=json.loads((ROOT/'releases/ingestion-rollout-production-case-20261020.json').read_text())
        name=next(iter(case['qualifiedNativeSource']['gitBlobPins']));case['qualifiedNativeSource']['gitBlobPins'][name]='f'*40
        with self.assertRaisesRegex(ValueError,'QUALIFIED_NATIVE_GIT_BYTES_CHANGED'):production_delivery.generate(ROOT,case)

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','actual disposable Ed25519 fixture required')
class NativeOperatorBinding(unittest.TestCase):
    setUp=issuer_fixture.NativeIssuer.setUp
    compile=issuer_fixture.NativeIssuer.compile
    issue=issuer_fixture.NativeIssuer.issue
    def test_operator_binding_is_in_actual_dual_signature_mandate_intake(self):
        self.review['operatorBinding']={'controlSourceHash':'b'*64,'caseHash':'c'*64,'preparationHash':'d'*64,
            'modeContract':'EXPLICIT_ONE_STAGE_NO_AUTOMATIC_REPLAY_V1'}
        digest=c.digest(self.review);self.decision.update(reviewHash=digest,
            approvalRef='mcp-scoped-'+digest[:24]+'-'+str(self.decision['approvedAt']))
        self.crypto.write(self.context/'review.json',c.encoded(self.review))
        action=self.issue();self.assertEqual(action.authority.expected['intakeHash'],digest)
        self.assertTrue(action.guard(c.AUTHORITY_KEY,c.scope(self.native_review)))
        changed=copy.deepcopy(self.review);changed['operatorBinding']['controlSourceHash']='f'*64
        action.authority.expected['intakeHash']=c.digest(changed)
        with self.assertRaises(Exception):action.guard(c.AUTHORITY_KEY,c.scope(self.native_review))

if __name__=='__main__':unittest.main()
