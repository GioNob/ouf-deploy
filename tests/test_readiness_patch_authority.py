"""New exact scope and real two-role issuance with disposable fixture keys.

Qualification receipts and HUMAN sessions here are synthetic unit inputs, never
target authority or a claim that representative qualification has completed.
"""
import copy
import base64
import hashlib
import tempfile
import subprocess
import json
import os
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),
             str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_cutover_authority_native as crypto
import test_readiness_patch_execution as patch_fixture
from test_ingestion_rollout_gateway_transport import binding
from tools.ingestion_readiness_patch_execution import authority as a,contract as c,native_review as nr,human_reader as hr,entry as e
from tools.chatbot_file_cohort.human_session import HumanSession
from tools.chatbot_file_cohort import human_session as hm


def fixture_human(root):
    folder=root/'human';folder.mkdir(mode=0o700);now=int(time.time())
    selection={'issuer':'https://fixture.invalid','tenant':'fixture','subject':'fixture-human'}
    retry={**hm.PROFILE,'id':'synthetic-fixture-292-to-296','maximumAttempts':296}
    b={'sessionId':'synthetic-fixture','selectionHash':c.digest(selection),**selection,
        'clientId':hm.CLIENT,'scopes':hm.SCOPES,'tokenPath':str(folder/'human-access.jwt'),
        'sessionDirectory':str(folder),'createdAt':now,'expiresAt':now+7200,'retryProfile':retry}
    review={'maximumCumulativeOAuthAttempts':296,'priorOAuthAttempts':292,'requestedScopes':hm.SCOPES,
        'budgetReset':False,'automaticRenewalAllowed':False,'oldCredentialsReusable':False,'freshIssuerAuthenticationRequired':True}
    receipt={'review':review,'decision':{'reviewHash':c.digest(review),'approvedAt':now,'expiresAt':now+7200}}
    claims={'iss':selection['issuer'],'sub':selection['subject'],'tenant_id':selection['tenant'],
        'ouf_actor_type':'HUMAN','azp':hm.CLIENT,'acr':'fixture-only','aud':'ouf-api-gateway',
        'scope':' '.join(hm.SCOPES),'exp':now+1800}
    token='fixture.'+base64.urlsafe_b64encode(c.encoded(claims)).decode().rstrip('=')+'.fixture'
    bootstrap=HumanSession(selection,folder,folder/'human-access.jwt',b['expiresAt']);deadline=time.monotonic()+7200
    row={'schema':'ouf.chatbot-human-session.private.v1','binding':b,'bootId':bootstrap._boot(),
        'monotonicDeadline':deadline,'lastObservedAt':time.time(),'attempts':296,'state':'READY','budgetReset':False,
        'accessExpiresAt':now+1800,'publishedAccessToken':token,'governedWindowRenewal':receipt,'version':0}
    bootstrap.journal.initialize(row)
    p={'schema':hr.SCHEMA,'selection':selection,'expectedBinding':b,'journal':binding(bootstrap.journal.record),
        'minimumCumulativeAttempts':296,'maximumCumulativeAttempts':296,'expectedBootId':row['bootId'],
        'expectedMonotonicDeadline':deadline,'governedWindowReceiptHash':c.digest(receipt),'readOnly':True,
        'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False}
    return hr.open_existing(p),p

@unittest.skipUnless(os.environ.get('OUF_NATIVE_UIDS')=='1','actual root fixture keys and role signatures required')
class NativeIssuer(unittest.TestCase):
    def setUp(self):
        boot=patch.object(hm.HumanSession,'_boot',return_value='synthetic-fixture-boot');boot.start();self.addCleanup(boot.stop)
        self.temp=tempfile.TemporaryDirectory(dir=os.environ['OUF_TEST_ROOT']);self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name);root.chmod(0o700);self.crypto=crypto.SignedCutover()
        with patch.object(crypto,'ROOT',root):self.crypto.setUp()
        self.addCleanup(self.crypto.doCleanups);q=self.crypto
        self.context=q.root/'patch-execution';self.context.mkdir(mode=0o700)
        self.fixture,native,self.packet=patch_fixture.fixture(self.context);self.addCleanup(self.fixture.doCleanups)
        self.human,self.profile=fixture_human(self.context)
        self.native_review,self.packet=nr.compile_review(native['preparedInputs'],native['preparedInputsBinding'],
            self.profile['expectedBinding'],str(self.context),human_read_profile=self.profile)
        self.closure={'declaration':{'entryModule':'tools.ingestion_readiness_patch_execution.entry',
            'sourceCommit':'1'*40,'sourceHashes':{'fixture.only':'a'*64},'requiredPythonFlags':['-I','-B','-S'],
            'runtimeAuthorityIssued':False},'executables':{
                'python':copy.deepcopy(native['ownerControlProfile']['pythonExecutable']),
                'docker':copy.deepcopy(native['databaseControlProfile']['dockerExecutable']),
                'openssl':copy.deepcopy(q.verifier.openssl_binding)},'stdlibHash':'b'*64,'stdlibFileCount':1}
        installed={'schema':'ouf.semantic-existing-installation-authority-bindings.v1',
            'authorities':q.context,'policyBinding':q.binding(q.policy),
            'keyRefs':{'installer':q.grant['keyRef'],'attestor':'synthetic-fixture-attestor-key'},
            'keyBindings':{'installer':q.binding(q.key),'attestor':q.binding(q.key)}}
        path=q.root/'existing-installation-profile.json';q.write(path,c.encoded(installed))
        self.issuer={'schema':'ouf.ingestion-rollout-existing-issuer-profile.v1',
            'installationAuthority':binding(path),'policy':binding(q.policy),'authorityContext':q.context}
        self.qualification={'schema':'ouf.ingestion-readiness-patch-native-qualification.v1',
            'sourceCommit':'1'*40,'sourceHashes':self.closure['declaration']['sourceHashes'],
            'candidateNativeImageId':self.packet['candidate']['nativeImageId'],'candidateSourceCommit':'2'*40,
            'results':dict.fromkeys(a.QUALIFICATION,'PASS'),'runtimeAuthorityIssued':False,'notReleaseAcceptance':True,
            'evidenceRefs':{k:{'repository':'synthetic/fixture-only','runId':1,'jobId':1,'sourceCommit':'1'*40}for k in a.QUALIFICATION}}
        self.review=self.compile()
        now=int(time.time());self.decision={'schema':'ouf.semantic-scoped-terminal-decision.v1',
            'reviewHash':c.digest(self.review),'approvalRef':'mcp-scoped-'+c.digest(self.review)[:24]+'-'+str(now),
            'sourceClosureHash':self.review['sourceClosureHash'],'humanSessionHash':c.digest(self.review['authenticatedHuman']),
            'approvedAt':now,'expiresAt':now+210,'decision':'APPROVE_EXACT_FINITE_SCOPED_ACTION','state':'ACTIVE'}
        q.write(self.context/'review.json',c.encoded(self.review))
    def compile(self):
        return a.compile_action_review(self.native_review,self.packet,self.closure,self.issuer,self.qualification,210)
    def issue(self):
        # Only executable/stdlib materialization is outside this test. Role
        # verification, existing key custody/signing and the claims are real.
        with patch.object(a,'verify_closure'):
            return a.issue_action(self.review,self.decision,self.human,c.digest(self.decision))
    def test_actual_existing_key_two_roles_exact_scope_and_consumed_issuance(self):
        action=self.issue();scope=c.scope(self.native_review);self.assertTrue(action.guard(c.AUTHORITY_KEY,scope))
        raw=json.loads(action.raw)
        self.assertNotIn('chatbotFileAuthorization',raw);self.assertFalse(raw['databaseRestoreAuthorized'])
        signatures=list(self.context.glob(action.authority_hash+'.*.json'));self.assertEqual(len(signatures),2)
        with self.assertRaises(c.Denied):self.issue()
        self.assertEqual(len(list(self.context.glob(action.authority_hash+'.*.json'))),2)
    def test_missing_platform_result_foreign_source_or_mutable_reference_blocks(self):
        original=copy.deepcopy(self.qualification)
        for mutate in(lambda q:q['results'].update(apisix='BLOCKED'),
                       lambda q:q.update(sourceCommit='f'*40),lambda q:q['evidenceRefs']['postgres17'].update(runId=True)):
            self.qualification=copy.deepcopy(original);mutate(self.qualification)
            with self.assertRaises(c.Denied):self.compile()
        self.assertFalse((self.context/'ingestion-readiness-patch-issuance.claim.json').exists())
    def test_development_permission_or_wrong_explicit_decision_hash_never_issues(self):
        with self.assertRaises(c.Denied):a.issue_action(self.review,self.decision,self.human,'0'*64)
        self.assertFalse((self.context/'ingestion-readiness-patch-issuance.claim.json').exists())
        changed=copy.deepcopy(self.review);changed['scopes']['foreignGrant']={'allowed':True}
        with self.assertRaises(c.Denied):a.validate_action_review(changed)
    def test_current_human_and_existing_policy_context_are_required_before_key_read(self):
        self.human.current=lambda:{**self.review['authenticatedHuman'],'sessionId':'foreign'}
        with self.assertRaises(Exception):self.issue()
        self.human.current=lambda:self.review['authenticatedHuman']
        changed=copy.deepcopy(self.issuer);changed['authorityContext']={**changed['authorityContext'],'entityRef':'another-ente'}
        with self.assertRaises(Exception):a.current_issuer(changed,self.decision['expiresAt'])
        self.assertFalse((self.context/'ingestion-readiness-patch-issuance.claim.json').exists())
    def test_partial_signature_failure_retains_claim_and_never_reissues(self):
        original=a.ExistingEd25519Signer.sign;calls=[]
        def sign(signer,raw):
            calls.append(signer.scope['role'])
            if len(calls)==2:raise RuntimeError('synthetic second-signature interruption')
            return original(signer,raw)
        with patch.object(a.ExistingEd25519Signer,'sign',sign):
            with self.assertRaises(RuntimeError):self.issue()
        self.assertTrue((self.context/'ingestion-readiness-patch-issuance.claim.json').exists())
        before=list(self.context.glob('*.FINAL_DEPLOYMENT_APPROVAL.json'));self.assertEqual(before,[])
        with patch.object(a.ExistingEd25519Signer,'sign')as signer:
            with self.assertRaises(c.Denied):self.issue()
            signer.assert_not_called()
    def test_qualification_receipt_cannot_be_removed_after_compilation(self):
        changed=copy.deepcopy(self.review);changed['qualification']['results']['adversarial']='BLOCKED'
        changed['qualificationHash']=c.digest(changed['qualification'])
        with self.assertRaises(c.Denied):a.validate_action_review(changed)

    def test_required_human_adapter_cannot_be_omitted_before_issuance(self):
        changed=copy.deepcopy(self.native_review);changed.pop('humanReadProfile')
        with self.assertRaises(c.Denied):
            a.compile_action_review(changed,self.packet,self.closure,self.issuer,self.qualification,210)
        self.assertFalse((self.context/'ingestion-readiness-patch-issuance.claim.json').exists())
    def test_existing_issued_artifacts_are_read_without_resigning(self):
        action=self.issue();decision_hash=c.digest(self.decision)
        mandate_hash=hashlib.sha256((self.context/'human.json').read_bytes()).hexdigest()
        before={p.name:p.read_bytes() for p in self.context.iterdir() if p.is_file()}
        with patch.object(a,'verify_closure'),patch.object(a,'issue_action') as issue:
            loaded=e.load_action(self.review,self.decision,self.human,decision_hash,mandate_hash)
            issue.assert_not_called()
        self.assertEqual(loaded.authority_hash,action.authority_hash)
        self.assertEqual(before,{p.name:p.read_bytes() for p in self.context.iterdir() if p.is_file()})
        with patch.object(a,'verify_closure'),self.assertRaises(c.Denied):
            e.load_action(self.review,self.decision,self.human,decision_hash,'0'*64)
    def test_disk_import_cannot_dispatch_and_foreign_scope_cannot_load(self):
        action=self.issue();raw=json.loads(action.raw);raw['ingestionGatewayRollout']={}
        with self.assertRaises(c.Denied):e.validate_raw(self.review,c.encoded(raw))
        for mode in ('initialize','step','reconcile','auto'):
            with patch.object(e,'NativePorts') as ports,self.assertRaises(c.Denied):
                e.execute(mode,self.review,self.packet,self.human,action,self.review['sourceClosure']['declaration'])
            ports.assert_not_called()


    def test_sealed_entry_actual_issuance_load_and_initialize_dispatches_no_runtime_effect(self):
        # Only boot identity and the unavailable Docker peer are fixture inputs.
        # No closure/role verification or entry dispatch is mocked in the child.
        script="""import importlib.util,json,sys,time
from pathlib import Path
root=Path(sys.argv[1]);path=root/'tools/ingestion_readiness_patch_execution/runtime.py'
spec=importlib.util.spec_from_file_location('verified_patch_loader',path)
loader=importlib.util.module_from_spec(spec);spec.loader.exec_module(loader)
sources={n:(root/loader.SOURCE_PATHS[n]).read_bytes()for n in loader.MODULES}
pins={n:'1'*40 for n in ('ouf-deploy','ouf-onboarding','ouf-ingestion-runtime','ouf-api-gateway')}
manifest=loader.declaration('1'*40,sources,path.read_bytes(),pins)
entry,actual=loader.load_entry('1'*40,sources,path.read_bytes(),loader.digest(manifest),pins)
a,c=entry.authority,entry.c;p=json.loads(sys.stdin.read())
entry.human_reader.existing.HumanSession._boot=lambda self:'synthetic-fixture-boot'
entry.NativePorts.boot=lambda self:'synthetic-fixture-boot'
human=entry.human_reader.open_existing(p['humanProfile'])
python=a.governance.executable(str(Path(sys.executable).resolve()))
openssl={**a.governance.executable(p['opensslPath']),'version':p['opensslVersion']}
b=p['bundle']
for k in ('ownerControlProfile','unchangedGatewayTransportProfile','ingestionReadinessProfile'):
 b[k]['pythonExecutable']=python
for k in ('databaseControlProfile','imageImportProfile'):
 b[k]['dockerExecutable']=python
native,packet=a.native_review.compile_review(b,{'path':str(Path(p['context'])/'inputs.json'),'sha256':c.digest(b)},
 p['humanProfile']['expectedBinding'],p['context'],human_read_profile=p['humanProfile'])
library=a.stdlib_binding()
closure={'declaration':actual,'executables':{'python':python,'docker':python,'openssl':openssl},
 'stdlibHash':c.digest(library),'stdlibFileCount':len(library['fileHashes'])}
q=p['qualification'];q['sourceHashes']=actual['sourceHashes']
review=a.compile_action_review(native,packet,closure,p['issuer'],q,210)
now=int(time.time())
decision={'schema':'ouf.semantic-scoped-terminal-decision.v1','reviewHash':c.digest(review),
 'approvalRef':'mcp-scoped-'+c.digest(review)[:24]+'-'+str(now),'sourceClosureHash':review['sourceClosureHash'],
 'humanSessionHash':c.digest(review['authenticatedHuman']),'approvedAt':now,'expiresAt':now+210,
 'decision':'APPROVE_EXACT_FINITE_SCOPED_ACTION','state':'ACTIVE'}
selected=Path(p['context'])/'review.json';selected.write_bytes(c.encoded(review));selected.chmod(0o600)
action=a.issue_action(review,decision,human,c.digest(decision))
mandate_hash=entry.hashlib.sha256((Path(p['context'])/'human.json').read_bytes()).hexdigest()
loaded=entry.load_action(review,decision,human,c.digest(decision),mandate_hash)
assert loaded.authority_hash==action.authority_hash
result=entry.execute('initialize',review,packet,human,loaded,actual)
row=entry.Journal(Path(p['context'])).read()
assert row['nextStage']==0 and row['effects']==[]
assert result['initialized']is True and result['effectsDispatched']==0
assert not result['releaseAcceptance']
print(json.dumps({'initialized':True,'effectsDispatched':0,'moduleCount':actual['moduleCount']}))
"""
        payload={'bundle':self.native_review['preparedInputs'],'context':str(self.context),
            'humanProfile':self.profile,'qualification':self.qualification,'issuer':self.issuer,
            'opensslPath':str(self.crypto.openssl),'opensslVersion':self.crypto.verifier.openssl_binding['version']}
        result=subprocess.run(['/usr/bin/python3','-I','-B','-S','-c',script,str(ROOT)],
            input=c.encoded(payload),capture_output=True,timeout=90)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(json.loads(result.stdout),{'initialized':True,'effectsDispatched':0,'moduleCount':136})

if __name__=='__main__':unittest.main()

