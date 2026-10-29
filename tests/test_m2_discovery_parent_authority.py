"""Actual Ed25519/HUMAN custody; no native component effects or admission."""
import copy,hashlib,json,os,shutil,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_application_cutover'),
    str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.m2_discovery_installation_profile import parent_authority as m
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator,signing_bytes
from tools.semantic_provider_preexec import PreexecDenied
from cutover_authority import CutoverAuthority
from transition_journal import PHASES


class Parent(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(),0)
        tmp=tempfile.TemporaryDirectory(dir=ROOT,prefix='discovery-parent-authority-');self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name);self.root.chmod(0o700)
        env=mock.patch.dict(os.environ,{'TMPDIR':str(self.root)});env.start();self.addCleanup(env.stop)
        cached=mock.patch.object(tempfile,'tempdir',str(self.root));cached.start();self.addCleanup(cached.stop)
        self.now=int(time.time());self.openssl=Path(shutil.which('openssl')).resolve()
        self.key=self.root/'disposable-key.pem';self.native('genpkey','-algorithm','ED25519','-out',str(self.key));self.key.chmod(0o600)
        self.context={'installationRef':'synthetic-parent-installation','entityRef':'synthetic-parent-entity',
            'intentIssuerRef':'synthetic-parent-installer','approvalIssuerRef':'synthetic-parent-installer',
            'attestorRef':'synthetic-parent-attestor'}
        public=self.native('pkey','-in',str(self.key),'-pubout','-outform','DER')[12:].hex()
        self.policy=self.root/'public-policy.json'
        keys=[{'keyRef':ref,'issuerRef':issuer,'roles':roles,'publicKey':public,'notBefore':self.now-10,
            'expiresAt':self.now+600,'state':'ACTIVE'} for ref,issuer,roles in
            [('synthetic-installer-key',self.context['intentIssuerRef'],['DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL']),
             ('synthetic-attestor-key',self.context['attestorRef'],['CREATION_ATTESTATION'])]]
        self.write(self.policy,m.encoded({'schema':'ouf.semantic-deployment-trust-policy.v1',
            'installationRef':self.context['installationRef'],'entityRef':self.context['entityRef'],'keys':keys}))
        self.signatures=self.root/'signatures';self.signatures.mkdir(mode=0o700)
        self.verifier=DetachedAuthenticator(self.binding(self.policy),str(self.signatures),
            {**self.binding(self.openssl),'version':self.native('version').decode().split()[1]},clock=lambda:self.now)
        self.review={'schema':'ouf.discovery-parent-installation-review.v1','sourceClosureHash':'a'*64,
            'installationInputsHash':'b'*64,'desiredProfileHash':'c'*64,'predecessorHistoryHash':'d'*64,
            'components':{k:{'schema':'synthetic.component.v1','approvedPlanHash':'e'*64} for k in m.COMPONENTS},
            'operationalSemantics':copy.deepcopy(m.SEMANTICS),'runtimeAuthorityIssued':False,
            'targetApplyAuthorized':False,'releaseAcceptance':False}

    def native(self,*args):
        return subprocess.check_output([str(self.openssl),*args],stderr=subprocess.DEVNULL,timeout=5)
    def write(self,p,raw):p.write_bytes(raw);p.chmod(0o600)
    def binding(self,p):return {'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
    def sign(self,raw,role):
        header={'schema':'ouf.semantic-deployment-detached-signature.v1','algorithm':'Ed25519',
            'keyRef':'synthetic-installer-key','role':role,'issuerRef':self.context['intentIssuerRef'],
            'installationRef':self.context['installationRef'],'entityRef':self.context['entityRef'],
            'payloadHash':hashlib.sha256(raw).hexdigest()}
        frame=self.root/'frame';self.write(frame,signing_bytes(raw,header))
        signature=self.native('pkeyutl','-sign','-rawin','-inkey',str(self.key),'-in',str(frame))
        self.write(self.signatures/(header['payloadHash']+'.'+role+'.json'),m.encoded({**header,'signature':signature.hex()}))

    def fixture(self,decision=m.DECISION):
        scope=m.review_scope(self.review)
        raw=m.encoded({'schema':'ouf.discovery-parent-execution-authority.v1','scope':scope,
            'issuedAt':self.now,'expiresAt':self.now+120,'installationRef':self.context['installationRef'],
            'entityRef':self.context['entityRef'],'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False})
        human={'schema':'ouf.discovery-parent-human-decision.v1','decision':decision,'state':'ACTIVE',
            'approvalRef':'SYNTHETIC_PARENT_NOT_TARGET_APPROVAL','scope':scope,'authorityHash':hashlib.sha256(raw).hexdigest(),
            'issuedAt':self.now,'expiresAt':self.now+120}
        path=self.root/'parent-human.json';self.write(path,m.encoded(human))
        for role in ('DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL'):self.sign(raw,role)
        return m.DiscoveryParentAuthority(self.verifier,self.binding(path),self.binding(path)['sha256'],
            self.context,self.review,raw,lambda:self.now)

    def test_exact_components_require_current_explicit_normal_use_decision_and_both_signatures(self):
        actor=self.fixture()
        for component in m.COMPONENTS:self.assertTrue(actor.guard(component,self.review['components'][component]))

    def test_old_finite_only_human_decision_cannot_authorize_normal_operation(self):
        actor=self.fixture('APPROVE_FINITE_INFRASTRUCTURE_CUTOVER_ONLY')
        with self.assertRaisesRegex(ValueError,'CURRENT_EXPLICIT_DISCOVERY'):
            actor.guard('operationalLeaseInstallation',self.review['components']['operationalLeaseInstallation'])

    def test_one_missing_role_is_not_replaced_by_a_provenance_hash(self):
        actor=self.fixture();(self.signatures/(actor.sha+'.FINAL_DEPLOYMENT_APPROVAL.json')).unlink()
        with self.assertRaises(FileNotFoundError):actor.guard('providerInstallation',self.review['components']['providerInstallation'])

    def test_scope_and_human_decision_drift_are_denied(self):
        actor=self.fixture();wrong={**self.review['components']['registryGatePeerWindow'],'approvedPlanHash':'f'*64}
        with self.assertRaisesRegex(ValueError,'EXACT_SEPARATE_DISCOVERY'):actor.guard('registryGatePeerWindow',wrong)
        self.write(Path(actor.binding['path']),b'CHANGED_HUMAN_DECISION')
        with self.assertRaisesRegex(ValueError,'HUMAN_DECISION_CHANGED'):
            actor.guard('providerInstallation',self.review['components']['providerInstallation'])

    def test_expired_window_is_not_reused(self):
        actor=self.fixture();self.now+=121
        with self.assertRaisesRegex(ValueError,'CURRENT_EXPLICIT_DISCOVERY'):
            actor.guard('providerInstallation',self.review['components']['providerInstallation'])

    def test_budget_reset_runtime_signing_and_unadmitted_generation_are_not_review_defaults(self):
        for name,value in (('automaticBudgetResetAllowed',True),('runtimeSigningKeyAccessAllowed',True),
                           ('currentNativeAdmissionRequiredForEveryGeneration',False)):
            review=copy.deepcopy(self.review);review['operationalSemantics'][name]=value
            with self.assertRaisesRegex(ValueError,'EXACT_DISCOVERY_PARENT_INSTALLATION_REVIEW'):m.review_scope(review)

    def child(self,expires=90,replay=False,creation_request_hash='2'*64):
        expected={'intakeHash':'1'*64,'sourceClosureHash':self.review['sourceClosureHash'],'creationRequestHash':creation_request_hash,
            'predecessorHistoryHash':self.review['predecessorHistoryHash'],'predecessorIncidentRef':'3'*64}
        child_raw=m.encoded({'schema':'ouf.semantic-cutover-execution-authority.v1',**{k:v for k,v in expected.items() if k!='intakeHash'},
            'issuedAt':self.now,'expiresAt':self.now+expires,'phaseIntentHashes':{
                p:creation_request_hash if p=='CREATE_REPLACEMENT' else '4'*64 for p in PHASES},
            'newDistinctLeaseWorkerRequired':True,'automaticReplayAllowed':False,'databaseRestoreAuthorized':False,'r12ReplayAuthorized':replay})
        human={'schema':'ouf.semantic-cutover-human-mandate.v1','approvalRef':'SYNTHETIC_CHILD_NOT_TARGET_APPROVAL',
            'decision':'APPROVE_FINITE_INFRASTRUCTURE_CUTOVER_ONLY','state':'ACTIVE','issuedAt':self.now,'expiresAt':self.now+expires+10,
            'executionAuthorityHash':hashlib.sha256(child_raw).hexdigest(),**expected}
        path=self.root/'child-human.json';self.write(path,m.encoded(human));binding=self.binding(path)
        child=CutoverAuthority(self.verifier,binding,binding['sha256'],self.context,expected,lambda:self.now)
        self.review['components']['registryCutover']={'schema':'ouf.discovery-registry-child-scope.v1',
            'authorityHash':hashlib.sha256(child_raw).hexdigest(),'humanManifestHash':binding['sha256'],**expected}
        for role in ('DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL'):self.sign(child_raw,role)
        return child,child_raw

    def test_separate_generic_thirteen_phase_child_is_bound_inside_parent_window(self):
        child,raw=self.child();actor=self.fixture();self.assertTrue(actor.registry_child(child,raw))

    def test_child_cannot_extend_parent_window_or_replay_consumed_r12(self):
        for options in ({'expires':121},{'replay':True}):
            child,raw=self.child(**options);actor=self.fixture()
            with self.assertRaisesRegex(ValueError,'FULL_DISCOVERY_CHILD_WITHIN_PARENT_WINDOW'):
                actor.registry_child(child,raw)

if __name__=='__main__':unittest.main()
