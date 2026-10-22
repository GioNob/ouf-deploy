"""Real Ed25519 and private issuance journal; synthetic native/token fixtures.

No target credentials or mandates are used. Full native observation is replaced
only in these tests; the production owner retains the complete native observer.
"""
import copy,json,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'tests'),str(ROOT)]
import test_file_only_preparation as frame_fixture
import test_cutover_authority_native as signed
from file_only_profile import FileOnlyProfile,PROFILE,PHASES
from cutover_authority import CutoverAuthority
from engine_creation import Engine
from paused_node_acceptance import PausedNodeAcceptance
from tools.semantic_policy_token_owner.installed_owner import InstalledTokenOwner
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
from tools.semantic_registry_recovery_execution import core as c,authorization as a,lifecycle as l,node_owner as n
from tools.semantic_registry_recovery_composition.compose import candidate_contract,GATES

class NodeOwner(unittest.TestCase):
    native=signed.SignedCutover.native
    write=signed.SignedCutover.write
    binding=signed.SignedCutover.binding
    sign=signed.SignedCutover.sign

    def setUp(self):
        signed.SignedCutover.setUp(self)
        self.temp_root=self.root
        template,launch,context,args,request=frame_fixture.Preparation().gated_frame()
        self.profile=FileOnlyProfile(request,args['execution_profile'].configtree)
        token=copy.deepcopy(args['renewable_token']);token.pop('directoryCustodyScopeHash')
        token.update(directoryDevice=1,directoryInode=2)
        recipe={'schema':'ouf.semantic-file-only-node-recipe.v1','sourceClosureHash':self.expected['sourceClosureHash'],
            'qualifiedPackageHash':'3'*64,'imageConfigurationHash':'4'*64,
            'expectedRootfsSeal':{'schema':'ouf.semantic-rootfs-seal.v1','sha256':'5'*64,'entries':3,'bytes':64},
            'template':template,'launch':launch,'dockerContext':context,'runtimeRoot':'/fixture/runtime',
            'observationConfiguration':{},'frameSourceBinding':{},'renewableToken':token,
            'delegationKeyMetadataHash':'6'*64,'proposalReceiptKey':args['proposal_receipt_key'],
            'transactionId':'7'*64,'observationSeconds':10}
        baseline={'Id':'8'*64,'Image':request['Image'],'Config':{},'HostConfig':{},'Mounts':[],
            'State':{'Status':'exited','Pid':0}}
        proposal={'registry':{'containerId':baseline['Id'],'imageId':request['Image'],'configHash':c.digest({}),
            'hostConfigHash':c.digest({}),'mountsHash':c.digest([])},'requiredGates':list(GATES),'unresolvedGateCount':8}
        plan=candidate_contract(proposal,'9'*64,self.expected['predecessorIncidentRef']);self.plan=plan
        self.expected['creationRequestHash']=c.digest(request)
        policy=json.loads(self.policy.read_bytes());policy['keys'][1]['publicKey']=self.grant['publicKey']
        self.write(self.policy,signed.encoded(policy));self.verifier.policy_binding=self.binding(self.policy)
        raw={'schema':'ouf.semantic-cutover-execution-authority.v2',**{k:v for k,v in self.expected.items() if k!='intakeHash'},
            'issuedAt':self.now,'expiresAt':self.now+120,'deploymentProfile':PROFILE,
            'executionProfileHash':self.profile.sha256,'newDistinctLeaseWorkerRequired':False,
            'phaseIntentHashes':{phase:'a'*64 for phase in PHASES},
            'semanticRegistryRecovery':a.scope(plan),'semanticRegistryRecoveryNode':n.node_scope(plan,recipe,self.profile)}
        self.authority=c.encoded(raw)
        self.approval.update(schema='ouf.semantic-cutover-human-mandate.v2',**self.expected,
            executionAuthorityHash=signed.sha(self.authority),deploymentProfile=PROFILE,executionProfileHash=self.profile.sha256)
        self.write(self.mandate,c.encoded(self.approval));self.approved=signed.sha(self.mandate.read_bytes())
        for role in self.grant['roles']:self.sign(role)
        authority=CutoverAuthority(self.verifier,self.binding(self.mandate),self.approved,self.context,self.expected,
            self.clock,execution_profile=self.profile)
        scope=a.AuthorityScope(authority,self.authority,plan,request)
        root=self.temp_root/('semantic-registry-recovery-'+plan['logicalOperationRef']);root.mkdir(mode=0o700)
        (root/'node').mkdir(mode=0o700)
        store=c.Store(root,plan['logicalOperationRef']);self.store=store
        fresh={'containerId':baseline['Id'],'bootId':'11111111-2222-3333-4444-555555555555',
            'pid':4242,'startTicks':1234,'namespaceDevice':4,'namespaceInode':12}
        initial=c.initial(plan,authority_hash=scope.hash,expires_unix=self.now+110,expires_monotonic=110,
            boot_id=fresh['bootId'],predecessor_history_hash=self.expected['predecessorHistoryHash'],
            created_unix=self.now,created_monotonic=10)
        effects=[]
        for stage in plan['stages'][:6]:
            evidence={'newGeneration':fresh,'durableNativeStartEvidence':True}
            effects.append({'stage':stage['name'],'state':'APPLIED','intentHash':stage['intentHash'],
                'authorityHash':scope.hash,'nativeEvidence':evidence,'nativeEvidenceHash':c.digest(evidence)})
        effects[-1].update(state='CLAIMED',nativeEvidence=None);effects[-1].pop('nativeEvidenceHash')
        initial.update(nextStage=5,effects=effects,state='IN_FLIGHT',newGeneration=fresh)
        store.initialize(initial)
        engine=Engine.__new__(Engine)
        with patch.object(l,'process_type',return_value=lambda req:None):
            lifecycle=l.Lifecycle(engine,scope,store,plan,request,baseline,proposal)
        owner=InstalledTokenOwner.__new__(InstalledTokenOwner)
        owner.observer=True;owner.authority=authority;owner.raw=self.authority
        class FixtureBinding:
            def digest(self):return 'b'*64
        owner.binding=FixtureBinding();owner.guard=lambda value:None
        attestor=policy['keys'][1]
        signer=ExistingEd25519Signer(self.binding(self.key),attestor['keyRef'],self.verifier,
            {'role':'CREATION_ATTESTATION','issuerRef':self.context['attestorRef'],
             'installationRef':self.context['installationRef'],'entityRef':self.context['entityRef']})
        self.owner=n.RecoveryNodeOwner(lifecycle,self.profile,owner,self.verifier,signer,recipe)
        self.signer=signer
        expected={k:recipe[k] for k in ('sourceClosureHash','qualifiedPackageHash','imageConfigurationHash')}
        expected.update(applicationHash='c'*64,artifactHash='d'*64,transportHash='e'*64,
            transitionContextHash=plan['logicalOperationRef'],creationRequestHash=c.digest(request),
            phaseIntentHash=plan['stages'][5]['intentHash'])
        ctx={k:self.context[k] for k in ('installationRef','entityRef','attestorRef')}
        self.payload=c.encoded({'schema':'ouf.semantic-paused-node-acceptance-authorization.v1',
            'issuerRef':ctx['attestorRef'],'installationRef':ctx['installationRef'],'entityRef':ctx['entityRef'],**expected,
            'containerId':baseline['Id'],'generationBinding':'OBSERVED_PAUSED_GATED','rootfsSeal':recipe['expectedRootfsSeal'],
            'issuedAt':self.now,'expiresAt':self.now+120,'state':'ACTIVE','attestationAuthorized':True,'completeCreationAccepted':True})
        self.report={'schema':'ouf.semantic-paused-node-observation.v1','applicationHash':expected['applicationHash'],
            'rootfsSeal':recipe['expectedRootfsSeal'],'creationFrameHash':'f'*64,
            'state':{'id':baseline['Id'],'status':'paused','pid':fresh['pid']},
            'generation':{k:fresh[k] for k in ('pid','startTicks','namespaceInode')},
            'nativeStateContract':{'stateContract':'RUNC_PAUSED_ENGINE_PAUSED','containerId':baseline['Id'],'pid':fresh['pid']}}
        self.acceptance=PausedNodeAcceptance(self.verifier,ctx,expected,self.clock)
        self.observation=patch.object(self.owner,'native_observation',
            side_effect=lambda:(copy.deepcopy(self.report),self.acceptance,self.payload))
        self.observation.start();self.addCleanup(self.observation.stop)

    def test_actual_scoped_signature_is_issued_once_and_verified_again(self):
        with patch.object(self.signer,'sign',wraps=self.signer.sign) as sign:
            self.owner.apply();state,proof=self.owner.observe()
            self.assertEqual(state,'APPLIED');self.assertTrue(proof['currentScopedAcceptanceSignatureVerified'])
            with self.assertRaisesRegex(c.RecoveryDenied,'ALREADY_ATTEMPTED'):self.owner.apply()
            self.owner.verify_retained();self.assertEqual(sign.call_count,1)
        self.assertFalse(proof['runtimeAuthorityIssued']);self.assertFalse(proof['releaseAcceptance'])

    def test_crash_after_durable_claim_never_signs_again(self):
        with patch.object(self.signer,'sign',side_effect=OSError('fixture crash')) as sign:
            with self.assertRaises(OSError):self.owner.apply()
            self.assertEqual(self.owner.observe(),('UNKNOWN',{}))
            with self.assertRaisesRegex(c.RecoveryDenied,'ALREADY_ATTEMPTED'):self.owner.apply()
            self.assertEqual(sign.call_count,1)

    def test_partial_signature_publication_is_observation_only(self):
        with patch.object(n,'publish_once',side_effect=OSError('fixture publication crash')):
            with self.assertRaises(OSError):self.owner.apply()
        self.assertEqual(self.owner.observe(),('UNKNOWN',{}))
        with self.assertRaisesRegex(c.RecoveryDenied,'ALREADY_ATTEMPTED'):self.owner.apply()

    def test_current_signed_recipe_cannot_be_replaced(self):
        self.owner.recipe['expectedRootfsSeal']['sha256']='0'*64
        with self.assertRaisesRegex(c.RecoveryDenied,'RECIPE_OR_PLAN_CHANGED'):self.owner.apply()

    def test_tampered_signature_or_paused_report_does_not_verify(self):
        self.owner.apply();self.report['state']['status']='running'
        with self.assertRaises(ValueError):self.owner.observe()
        self.report['state']['status']='paused'
        path=self.signatures/(signed.sha(self.payload)+'.CREATION_ATTESTATION.json')
        envelope=json.loads(path.read_bytes());envelope['signature']='0'*128;self.write(path,c.encoded(envelope))
        from tools.semantic_provider_preexec import PreexecDenied
        with self.assertRaises(PreexecDenied):self.owner.observe()

    def test_current_human_revocation_prevents_node_issuance(self):
        self.approval['state']='REVOKED';self.write(self.mandate,c.encoded(self.approval))
        from cutover_authority import AuthorityDenied
        with self.assertRaises(AuthorityDenied):self.owner.apply()
        self.assertNotIn('nativeAttestationAttempted',self.store.read()['effects'][5])

if __name__=='__main__':unittest.main()
