"""Actual Ed25519/custody/evidence; Docker, process, mount, HTTP and DB fixtures.

These tests do not establish target admission, native mounts or Registry E2E.
"""
import copy,hashlib,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]+[str(ROOT/'tools'/p) for p in
    ('semantic_application_cutover','semantic_frame_compiler','semantic_database_cutover',
     'semantic_cohort_admission/cohort-draft')]
import test_m2_discovery_parent_authority as crypto
import test_m2_discovery_frame_observation as frame_fixture
from test_m2_discovery_native_profile import fixture
from tools.m2_discovery_installation_profile import running_admission as m
from tools.m2_discovery_installation_profile.node_owner import DiscoveryNodeOwner
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
from cutover_authority import CutoverAuthority,AuthorityDenied
from transition_journal import Transition,PHASES
from engine_creation import Engine
from native_evidence_store import NativeEvidenceStore

class RunningAdmission(unittest.TestCase):
    setUp=crypto.Parent.setUp
    native=crypto.Parent.native
    write=crypto.Parent.write
    binding=crypto.Parent.binding
    sign=crypto.Parent.sign

    def prepared(self):
        source,policy,_,_,_,wrapper=frame_fixture.Observation.prepared(self)
        profile=source.profile;r=copy.deepcopy(profile.request);_,_,t,l,_=fixture()
        fs=profile.selection['files']
        for i,f in enumerate(fs.values()):
            l['sources'][i]={k:v for k,v in f.items() if k!='metadataHash'}
            l['manifest']['mounts'][i]['source']=f['source'];t['expectedOci']['mounts'][i]['source']=f['source']
        root=self.root/'node';root.mkdir(mode=0o700)
        tasks=self.root/'tasks';tasks.mkdir(mode=0o700);bundle=tasks/('c'*64);bundle.mkdir(mode=0o700)
        context={'schema':'ouf.semantic-docker-frame-context.v1','bundleParent':str(tasks),
            'metadataParent':'/var/lib/fixture/containers','networkNamespaceParent':'/run/fixture/netns',
            'cgroupDriver':'systemd','storageParent':'/var/lib/fixture'}
        candidate={'networkBindings':[],'transport':{},'tableName':'fixture_only'}
        recipe={'schema':'ouf.semantic-discovery-node-recipe.v1','executionProfileHash':profile.sha256,
            'sourceClosureHash':'a'*64,'qualifiedPackageHash':'3'*64,'imageConfigurationHash':'4'*64,
            'expectedRootfsSeal':{'schema':'ouf.semantic-rootfs-seal.v1','sha256':'5'*64,'entries':3,'bytes':64},
            'template':t,'launch':l,'dockerContext':context,'runtimeRoot':'/fixture/runtime',
            'observationConfiguration':{'bundleParents':[str(tasks)],'candidate':candidate},
            'frameSourceBinding':self.binding(wrapper),'transactionId':'7'*64,'observationSeconds':10}
        intent={'creationRequestHash':m.digest(r),'sourceClosureHash':recipe['sourceClosureHash'],
            'qualifiedPackageHash':recipe['qualifiedPackageHash'],'imageConfigurationHash':recipe['imageConfigurationHash'],
            'nodeRecipeHash':m.digest(recipe)}
        scope={'databaseContainerId':'d'*64,'databaseUser':'fixture_semantic','database':'fixture_registry',
            'databaseOid':1,'flywaySchema':'ouf_sem','flywayHistoryHash':'6'*64,
            'health':{'address':'172.20.0.10','port':8080,'path':'/actuator/health','timeoutSeconds':1}}
        ready=m.ApplicationReadinessChannel(scope)
        verify={'creationRequestHash':m.digest(r),'readinessScopeHash':ready.scope_hash,
            'priorReleaseEvidencePhase':'START_REPLACEMENT'}
        expected={'intakeHash':'9'*64,'sourceClosureHash':'a'*64,'creationRequestHash':m.digest(r),
            'predecessorHistoryHash':'d'*64,'predecessorIncidentRef':'e'*64}
        raw=m.encoded({'schema':'ouf.semantic-cutover-execution-authority.v1',
            **{k:v for k,v in expected.items() if k!='intakeHash'},'issuedAt':self.now,'expiresAt':self.now+120,
            'phaseIntentHashes':{p:m.digest(intent if p=='ATTEST_NEW_OCI_PEER' else verify if p=='VERIFY_APPLICATION' else {}) for p in PHASES},
            'automaticReplayAllowed':False,'databaseRestoreAuthorized':False,'r12ReplayAuthorized':False,
            'newDistinctLeaseWorkerRequired':True})
        human=self.root/'child-human.json';self.write(human,m.encoded({
            'schema':'ouf.semantic-cutover-human-mandate.v1','approvalRef':'SYNTHETIC_NOT_TARGET_AUTHORITY',
            'decision':'APPROVE_FINITE_INFRASTRUCTURE_CUTOVER_ONLY','state':'ACTIVE',
            'issuedAt':self.now,'expiresAt':self.now+120,'executionAuthorityHash':hashlib.sha256(raw).hexdigest(),**expected}))
        for role in ('DEPLOYMENT_INTENT','FINAL_DEPLOYMENT_APPROVAL'):self.sign(raw,role)
        authority=CutoverAuthority(self.verifier,self.binding(human),self.binding(human)['sha256'],self.context,expected,lambda:self.now)
        signer=ExistingEd25519Signer(self.binding(self.key),'synthetic-attestor-key',self.verifier,
            {'role':'CREATION_ATTESTATION','issuerRef':self.context['attestorRef'],
             'installationRef':self.context['installationRef'],'entityRef':self.context['entityRef']})
        directory=self.root/'evidence';directory.mkdir(mode=0o700);store=NativeEvidenceStore(directory)
        transition=object.__new__(Transition);transition.execution_profile=None;transition.profile_hash=None;transition.context='8'*64
        row={'state':'READY','nextPhase':12,'creationRequestHash':m.digest(r),'effects':[]}
        transition.read=lambda:copy.deepcopy(row) # explicit modeled journal boundary
        engine=object.__new__(Engine)
        actual={'Id':'c'*64,'Image':r['Image'],'Config':{},'HostConfig':r['HostConfig'],'Mounts':[],
            'NetworkSettings':{'Networks':{'fixture':{'IPAddress':'172.20.0.10'}}},'RestartCount':0,
            'GraphDriver':{'Data':{'MergedDir':'/var/lib/fixture/overlay/merged'}},
            'State':{'Running':True,'Paused':False,'Status':'running','Pid':123,'StartedAt':'fixture-only'}}
        engine.inspect=lambda _:copy.deepcopy(actual)
        engine.matching_configuration=lambda *args:copy.deepcopy(actual) # modeled Engine config leaf
        node=DiscoveryNodeOwner(engine,transition,r,intent,store,profile,source.token_owner,
            authority,raw,self.verifier,signer,recipe,root)
        reader=m.RunningDiscoveryFrame(node,m.ObservationBudget(30));policy=reader.policy(actual)
        self.write(root/'frame-policy.json',m.encoded(policy));self.write(bundle/'config.json',m.encoded(policy['expectedOci']))
        child=m.decode(raw,131072)
        accepted={'schema':'ouf.semantic-paused-node-acceptance-authorization.v1',
            'issuerRef':self.context['attestorRef'],'installationRef':self.context['installationRef'],'entityRef':self.context['entityRef'],
            **{k:recipe[k] for k in ('sourceClosureHash','qualifiedPackageHash','imageConfigurationHash')},
            'applicationHash':m.digest(policy['expectedOci']),'artifactHash':hashlib.sha256(m.encoded(policy)).hexdigest(),
            'transportHash':m.transport_hash(candidate),'transitionContextHash':transition.context,
            'creationRequestHash':m.digest(r),'phaseIntentHash':node.intent_hash,'containerId':actual['Id'],
            'generationBinding':'OBSERVED_PAUSED_GATED','rootfsSeal':recipe['expectedRootfsSeal'],
            'issuedAt':child['issuedAt'],'expiresAt':child['expiresAt'],'state':'ACTIVE',
            'attestationAuthorized':True,'completeCreationAccepted':True}
        accepted_raw=m.encoded(accepted);self.write(root/'paused-acceptance.json',accepted_raw)
        self.write(self.signatures/(hashlib.sha256(accepted_raw).hexdigest()+'.CREATION_ATTESTATION.json'),signer.sign(accepted_raw))
        generation={'pid':123,'startTicks':456,'namespaceInode':789}
        receipt={'schema':'ouf.semantic-owner-signed-paused-node-phase.v1','transitionContextHash':transition.context,
            'intentHash':node.intent_hash,'creationRequestHash':m.digest(r),'containerId':actual['Id'],
            'generation':generation,'rootfsSeal':accepted['rootfsSeal'],'completeNativeObservationPerformed':True,
            'currentScopedAcceptanceSignatureVerified':True}
        evidence={'ATTEST_NEW_OCI_PEER':receipt,'START_REPLACEMENT':{'runtimeBinding':engine.runtime_binding(actual),'generation':generation},
            'VERIFY_APPLICATION':{'runtimeBinding':engine.runtime_binding(actual)}}
        for phase,proof in evidence.items():
            store.publish(phase,proof);row['effects'].append({'phase':phase,'state':'APPLIED',
                'intentHash':node.intent_hash if phase=='ATTEST_NEW_OCI_PEER' else m.digest({}), 'nativeEvidenceHash':m.digest(proof)})
        reader.running.process.observe=lambda _:{'generation':generation,'processKind':'APPLICATION_RUNNING'}
        return reader,actual,row,accepted,ready

    def call(self,reader,*,mutate=None,token_error=None):
        n=reader.node;policy=reader.policy(n.engine.inspect(n.transition));mounted={'pid':123,'startTicks':456,'networkNamespaceInode':789}
        frame=m.ProjectedFrameObservation({'source':n.recipe['frameSourceBinding'],
            'configuration':self.binding(n.root/'frame-policy.json'),'bundleParents':n.recipe['observationConfiguration']['bundleParents']},reader.budget)
        modules,schema=frame.owner(frame.pinned()['source']) # real embedded loader
        modules['review_semantic_oci_policy'].configured_profile=lambda *a:{'fixture':True}
        modules['observe_semantic_mount_view'].generation=lambda *a:dict(mounted)
        def files(*args):
            self.assertEqual(len(args[3]),5)
            if mutate:mutate()
            return {'fixture':True}
        modules['observe_semantic_creation_frame'].source_mount_frame=files
        with patch.object(m.ProjectedFrameObservation,'owner',return_value=(modules,schema)), \
             patch.object(m.NativeBackend,'generation',return_value={'pid':123,'startTicks':456,'namespaceInode':789}), \
             patch.object(m,'ConfigtreeMountObservation') as tree,patch.object(m,'RenewableTokenMountObservation') as token, \
             patch.object(m,'generation',return_value={'pid':123}):
            tree.return_value.observe.return_value={'fixture':True}
            token.return_value.observe.side_effect=token_error
            token.return_value.observe.return_value={'fixture':True}
            return reader.observe()

    def test_signed_current_running_frame_retains_false_release_and_authority(self):
        reader,*_=self.prepared();before={p:p.read_bytes() for p in reader.node.root.iterdir()}
        signatures={p:p.read_bytes() for p in self.signatures.iterdir()}
        proof=self.call(reader)
        self.assertTrue(proof['sameAttestedGenerationNowRunningJava']);self.assertTrue(proof['sevenCurrentMountsObserved'])
        for field in ('rootfsResealedWhileRunning','fullCohortProven','runtimeAuthorityIssued','targetApplyAuthorized','releaseAcceptance'):
            self.assertIs(proof[field],False)
        self.assertEqual(before,{p:p.read_bytes() for p in reader.node.root.iterdir()})
        self.assertEqual(signatures,{p:p.read_bytes() for p in self.signatures.iterdir()})

    def test_actual_token_observer_accepts_the_canonical_running_binding_type(self):
        reader,actual,*_=self.prepared();policy=reader.policy(actual)
        observer=m.RenewableTokenMountObservation(policy['renewableToken'],reader.node.token_owner,
            m.time.monotonic()+reader.budget.remaining(30),running_binding=reader.running)
        self.assertIs(observer.running_binding,reader.running)
        self.assertIsNone(observer.pause_binding)

    def test_completed_attestation_generation_is_not_replaced_by_running_health(self):
        reader,_,row,*_=self.prepared();node=reader.node;phase='ATTEST_NEW_OCI_PEER'
        effect=next(e for e in row['effects'] if e['phase']==phase)
        receipt=node.store.read(phase,effect['nativeEvidenceHash']);receipt['generation']['startTicks']+=1
        self.write(node.store.path(phase),m.encoded(receipt));effect['nativeEvidenceHash']=m.digest(receipt)
        with self.assertRaisesRegex(ValueError,'SAME_ATTESTED_GENERATION'):self.call(reader)

    def test_no_shared_observation_budget_is_rearmed(self):
        reader,*_=self.prepared();reader.budget.until=m.time.monotonic()-1
        with self.assertRaisesRegex(ValueError,'OBSERVATION_DEADLINE'):self.call(reader)

    def test_acceptance_requires_every_exact_scope_time_and_transport_field(self):
        reader,actual,_,accepted,_=self.prepared();policy=reader.policy(actual)
        for field,value in {'transportHash':'f'*64,'generationBinding':'RUNNING','creationRequestHash':'e'*64,
                            'phaseIntentHash':'f'*64,'issuedAt':self.now-1,'expiresAt':self.now+119,'extra':True}.items():
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'INDEPENDENT_RUNNING_NODE_ACCEPTANCE'):
                reader.acceptance(m.encoded({**accepted,field:value}),policy,actual['Id'])

    def test_signature_revocation_and_expiry_are_current_not_historical(self):
        reader,*_=self.prepared();path=reader.node.root/'paused-acceptance.json';raw=path.read_bytes()
        signature=self.signatures/(hashlib.sha256(raw).hexdigest()+'.CREATION_ATTESTATION.json');signature.unlink()
        with self.assertRaises((OSError,ValueError)):self.call(reader)
        self.now+=121
        with self.assertRaises(AuthorityDenied):self.call(reader)

    def test_gate_paused_restarted_or_replaced_process_cannot_pass(self):
        reader,actual,*_=self.prepared()
        for field,value in [('Paused',True),('Status','paused'),('Pid',124),('StartedAt','other')]:
            saved=actual['State'][field];actual['State'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.call(reader)
            actual['State'][field]=saved
        actual['RestartCount']=1
        with self.assertRaises(ValueError):self.call(reader)
        actual['RestartCount']=0;reader.running.process.observe=lambda _:{'generation':{'pid':123,'startTicks':456,'namespaceInode':789},'processKind':'GATE_WAITING'}
        with self.assertRaises(ValueError):self.call(reader)

    def test_token_denial_propagates_without_repair_or_new_admission(self):
        reader,*_=self.prepared()
        with self.assertRaisesRegex(ValueError,'CURRENT_TOKEN_REVOKED_FIXTURE'):
            self.call(reader,token_error=ValueError('CURRENT_TOKEN_REVOKED_FIXTURE'))

    def test_file_or_oci_or_policy_drift_during_observation_is_rejected(self):
        for case in ('file','bundle','policy','signature'):
            reader,actual,*_=self.prepared()
            def mutate():
                if case=='file':Path(next(iter(reader.node.profile.selection['files'].values()))['source']).chmod(0o600)
                if case=='bundle':self.write(Path(reader.node.recipe['dockerContext']['bundleParent'])/actual['Id']/'config.json',b'{}')
                if case=='policy':self.write(reader.node.root/'frame-policy.json',b'{}')
                if case=='signature':(self.signatures/(hashlib.sha256((reader.node.root/'paused-acceptance.json').read_bytes()).hexdigest()+'.CREATION_ATTESTATION.json')).unlink()
            with self.subTest(case=case),self.assertRaises((ValueError,OSError)):self.call(reader,mutate=mutate)
            # Each subcase uses its own protected source/key/evidence fixture.
            self.doCleanups();self.setUp()

    def test_current_readiness_is_signed_and_addresses_exact_registry(self):
        reader,actual,_,_,ready=self.prepared();admission=m.RunningRegistryAdmission(reader.node,ready)
        self.assertEqual(admission.current(),reader.node.engine.runtime_binding(actual))
        actual['NetworkSettings']['Networks']['fixture']['IPAddress']='172.20.0.11'
        with self.assertRaises(ValueError):admission.current()
        changed=copy.deepcopy(ready.scope);changed['databaseOid']+=1
        with self.assertRaisesRegex(ValueError,'SIGNED_CURRENT_REGISTRY_READINESS'):
            m.RunningRegistryAdmission(reader.node,m.ApplicationReadinessChannel(changed)).current()

    def test_readiness_reports_are_rechecked_and_share_one_budget(self):
        reader,actual,_,_,ready=self.prepared();admission=m.RunningRegistryAdmission(reader.node,ready)
        binding=reader.node.engine.runtime_binding(actual)
        with patch.object(m,'RunningDiscoveryFrame') as frame,patch.object(ready,'health',return_value={'status':'UP'}), \
             patch.object(ready,'database',side_effect=[{'migrationCount':3},{'migrationCount':4}]):
            frame.return_value.observe.return_value={'runtimeBinding':binding}
            with self.assertRaisesRegex(ValueError,'ADMISSION_CHANGED'):admission.observe()
            self.assertIs(type(frame.call_args.args[1]),m.ObservationBudget)

    def test_readiness_absence_cannot_be_replaced_by_frame_success(self):
        reader,_,_,_,ready=self.prepared();admission=m.RunningRegistryAdmission(reader.node,ready)
        with patch.object(m,'RunningDiscoveryFrame') as frame,patch.object(ready,'health',return_value=None), \
             patch.object(ready,'database') as database:
            frame.return_value.observe.return_value={}
            with self.assertRaisesRegex(ValueError,'CURRENT_RUNNING_REGISTRY_HEALTH'):admission.observe()
            database.assert_not_called()

if __name__=='__main__':unittest.main()
