"""Actual Ed25519 and existing profile compilers; native/application facts modeled."""
import copy,hashlib,json,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),
    str(ROOT/'tools/semantic_frame_compiler'),str(ROOT/'tools/semantic_lease_recovery'),
    str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_m2_provider_creation as creates
from test_m2_discovery_native_profile import fixture as registry_fixture
from tools.m2_discovery_installation_profile import provider_profiles as m
from tools.semantic_transaction_profiles.repair_broker_sources import repair
from tools.semantic_registry_operational_owner.core import Denied as InputDenied

class Profiles(unittest.TestCase):
    def fixture(self):
        case=creates.Creation();old,w,auth,state,calls,*_=case.fixture();self.addCleanup(case.doCleanups)
        r,selection,t,l,c=registry_fixture();self.assertEqual(r,w.request)
        context={k:v for k,v in c.items() if k not in {'containerId','networkNamespaceName','rootfsPath'}}
        context['rootfsLayout']='docker-containerd-overlayfs-v1'
        recipe={'schema':'ouf.semantic-discovery-node-recipe.v1','sourceClosureHash':w.scope['sourceClosureHash'],
            'qualifiedPackageHash':'1'*64,'imageConfigurationHash':'2'*64,
            'expectedRootfsSeal':{'schema':'ouf.semantic-rootfs-seal.v1','sha256':'3'*64,'entries':3,'bytes':64},
            'template':t,'launch':l,'dockerContext':context,'runtimeRoot':'/fixture/runc/runtime',
            'observationConfiguration':{},'frameSourceBinding':{},'executionProfileHash':w.profile.sha256,
            'transactionId':'4'*64,'observationSeconds':10}
        node_intent={'creationRequestHash':w.request_hash,'sourceClosureHash':recipe['sourceClosureHash'],
            'qualifiedPackageHash':recipe['qualifiedPackageHash'],'imageConfigurationHash':recipe['imageConfigurationHash'],
            'nodeRecipeHash':m.digest(recipe)}
        phases={p:w.request_hash if p=='CREATE_REPLACEMENT' else m.digest(node_intent)
            if p=='ATTEST_NEW_OCI_PEER' else '4'*64 for p in creates.gate.m.PHASES}
        child,raw=auth.child(creation_request_hash=w.request_hash,phase_intent_hashes=phases)
        w.child,w.raw,w.child_hash=child,raw,hashlib.sha256(raw).hexdigest()
        boundary=w.transition.read()
        # Replace only the isolated fixture's transition callback with the same
        # predecessor assertions under the newly signed exact node intent.
        boundary['transitionAuthorityEvidenceHash']=w.child_hash
        for effect in boundary['effects']:
            effect.update(authorityEvidenceHash=w.child_hash,intentHash=phases[effect['phase']])
        w.transition.read=lambda:copy.deepcopy(boundary)
        source=auth.root/'provider-source';source.mkdir(mode=0o700)
        source_base=ROOT/'tools/semantic_cohort_admission/cohort-draft'
        sources=repair({str(p.relative_to(source_base)):p.read_bytes() for p in source_base.rglob('*.py')})
        for name,content in sources.items():
            p=source/name;p.parent.mkdir(mode=0o700,parents=True,exist_ok=True);auth.write(p,content)
        registry=auth.root/'provider-registry';registry.mkdir(mode=0o700)
        issuance=auth.root/'provider-profiles';issuance.mkdir(mode=0o700)
        python=Path('/usr/bin/python3').resolve();py={'path':str(python),'sha256':hashlib.sha256(python.read_bytes()).hexdigest()}
        prior={'schema':'ouf.semantic-docker-runtime-adapter.v4','sourceHash':m.RUNTIME_SHA,
            'runtimePath':old.template['runtimeBinding']['path'],'runtimeSha256':old.template['runtimeBinding']['sha256'],
            'pythonPath':py['path'],'pythonSha256':py['sha256'],
            'driverPath':str(source/'scripts/semantic_provider_preexec_hook.py'),
            'driverSha256':hashlib.sha256(sources['scripts/semantic_provider_preexec_hook.py']).hexdigest(),
            'admissionPath':str(source/m.BROKER),'admissionSha256':m.BROKER_SHA,'registryRoot':str(registry),
            'runtimeStateRoot':str(auth.root/'native-runc-state'),'candidates':{'e'*64:{'intentRef':'1'*64,
                'bundleParents':['/fixture/bundles'],'admissionConfiguration':str(registry/('e'*64)/'broker.json'),
                'admissionConfigurationHash':'2'*64}}}
        cfg=auth.root/'prior-runtime.json';auth.write(cfg,m.encoded(prior))
        frame=auth.root/'frame-observer.py';auth.write(frame,(ROOT/'tools/semantic_frame_compiler/frame-observer.py').read_bytes())
        kernel={'tableName':'fixture_lease','guardedInterfaces':['brfixture'],'existingInterfaces':[],
            'staticFlows':[{'purpose':'DNS','source':'10.77.0.2','destination':'192.0.2.53','protocol':p,'port':53} for p in ('tcp','udp')],
            'providerFlows':[{'endpointRef':'fixture','endpoint':'https://provider.fixture.invalid/sparql',
                'source':'10.77.0.2','addresses':[],'leaseSeconds':30,'resolutionEvidenceRef':'fresh-fixture','allowedPrivateAddresses':[]}]}
        true=Path('/usr/bin/true').resolve();command_hash=hashlib.sha256(true.read_bytes()).hexdigest()
        prep={'schema':'ouf.semantic-admission-preparer-template.v1','pythonPath':py['path'],'pythonHash':py['sha256'],
            'commands':{k:str(true) for k in ('nft','ip','nsenter','unshare','mount','umount')},
            'commandHashes':{k:command_hash for k in ('nft','ip','nsenter','unshare','mount','umount')},
            'candidate':{'containerId':None,'transactionId':'f'*64,'networkBindings':old.template['networkBindings'],
                'transport':old.template['transportTemplate'],'tableName':old.template['tableName'],
                'runtimeBinding':old.template['runtimeBinding']},'kernel':kernel,
            'dns':{'resolvers':['192.0.2.53'],'resolverPort':53,'timeoutSeconds':1,'maxLeaseSeconds':30,'applyBudgetSeconds':1},
            'coordinationBinding':{'transactionId':'5'*64,'configurationHash':'6'*64,'leaseStructureHash':'7'*64},
            'coordinationJournal':str(auth.root/'existing-coordination.json'),'lockFile':str(auth.root/'existing-common.lock'),
            'budgetSeconds':5,'hostNetworkNamespace':123}
        opts=dict(registry_recipe=recipe,source_root=str(source),source_hashes={k:hashlib.sha256(v).hexdigest() for k,v in sources.items()},
            runtime_configuration_binding=auth.binding(cfg),runtime_configuration=prior,journal_directory=str(issuance),
            python_binding=py,crypto={'policyBinding':auth.verifier.policy_binding,'signatureDirectory':str(auth.signatures),
                'opensslBinding':auth.verifier.openssl_binding},frame_source_binding=auth.binding(frame),
            keys={'installer':auth.binding(auth.key),'attestor':auth.binding(auth.key)},
            key_refs={'installer':'synthetic-installer-key','attestor':'synthetic-attestor-key'},
            runtime_root_parents=['/fixture/runc'],rootfs_limits={'maxEntries':10000,'maxBytes':1048576,'maxDepth':32},
            transaction_id='f'*64,approval_ref='SYNTHETIC_PROVIDER_INITIAL_ONLY',preparer_template=prep)
        scope=m.profile_scope(old.template,old.scope,**opts)
        component={'schema':'ouf.discovery-composed-provider-installation-scope.v1','creation':old.scope,'installation':scope,
            'admission':{'schema':'ouf.discovery-materialized-provider-admission-scope.v1','providerTemplateHash':m.digest(old.template)}}
        auth.review['components']['providerInstallation']=component
        parent=auth.fixture();w.parent=parent;w.parent_hash=parent.sha
        creation=m.ProviderCreation(parent=parent,window=w,template=old.template,journal_directory=old.root,installation_component=component)
        signers={}
        for name,(role,issuer,key) in m.ROLES.items():
            signers[name]=m.ExistingEd25519Signer(scope['keys'][key],scope['keyRefs'][key],auth.verifier,
                {'role':role,'issuerRef':auth.context[issuer],**{k:auth.context[k] for k in ('installationRef','entityRef')}})
        issuer=m.ProviderInitialIssuer(creation=creation,scope=scope,signers=signers)
        return issuer,w,auth,state,calls,opts,sources
    def test_real_three_mandates_and_existing_v4_profiles_preserve_all_old_candidates(self):
        issuer,w,auth,state,calls,opts,sources=self.fixture()
        with w.peer_window():
            issuer.creation.create_once();issuer.issue_once();self.assertEqual(issuer.observe()[0],'APPLIED')
            material=issuer.material(m.private_json(issuer.root/'issuance-claim.json'))
            self.assertEqual(material['profiles']['attestation-producer.json']['schema'],'ouf.semantic-node-attestor.v4')
            self.assertEqual(material['profiles']['broker.json']['schema'],'ouf.semantic-deployment-broker.v1')
            self.assertEqual(material['profiles']['deployment.json']['state'],'STAGED')
            self.assertEqual(material['runtimeConfiguration']['candidates']['e'*64],opts['runtime_configuration']['candidates']['e'*64])
            self.assertEqual(len(material['runtimeConfiguration']['candidates']),2)
            self.assertEqual(material['materialized']['independentNodeProfile'],m.templates.expected_node_profile(issuer.template))
            self.assertFalse(material['runtimeSwitchOrStartAuthorized']);self.assertFalse(material['profilesPublished'])
            self.assertFalse(any(p.exists() for p in map(Path,material['directories'])))
        self.assertEqual(issuer.observe()[0],'APPLIED')
        with self.assertRaises(ValueError):issuer.issue_once()
        self.assertEqual(sum(method=='POST' for method,_,_ in calls),1)
    def test_partial_signing_is_preserved_and_never_reissued(self):
        issuer,w,auth,*_=self.fixture()
        with w.peer_window():
            issuer.creation.create_once()
            with patch.object(issuer.signers['live'],'sign',side_effect=TimeoutError('CI_UNKNOWN_SIGNING')):
                with self.assertRaises(TimeoutError):issuer.issue_once()
            self.assertEqual(issuer.observe()[0],'UNKNOWN')
            with self.assertRaises(FileExistsError):issuer.issue_once()
    def test_source_or_runtime_configuration_drift_precedes_key_access(self):
        issuer,w,auth,*_=self.fixture()
        with w.peer_window():
            issuer.creation.create_once();path=Path(issuer.scope['sourceRoot'])/m.BROKER;auth.write(path,b'DRIFT')
            with patch.object(issuer.signers['intent'],'sign',side_effect=AssertionError('KEY_MUST_NOT_BE_READ')):
                with self.assertRaisesRegex(InputDenied,'OPERATIONAL_INPUT_HASH_CHANGED'):issuer.issue_once()
        self.assertFalse((issuer.root/'issuance-claim.json').exists())
    def test_live_mandate_binds_full_expected_frame_not_observed_oci(self):
        issuer,w,auth,*_=self.fixture()
        with w.peer_window():
            issuer.creation.create_once();cid,registry,sources=issuer.current()
            material=m.compile_material(issuer.template,issuer.scope,sources,cid,registry,auth.context,auth.now,auth.now+80)
            live=material['payloads']['live'];self.assertEqual(live['generationBinding'],'OBSERVED_CREATED')
            self.assertEqual(live['applicationHash'],m.digest(material['materialized']['framePolicy']['expectedOci']))
            self.assertEqual(live['rootfsSeal'],issuer.template['expectedRootfsSeal'])
            self.assertNotIn('generation',live)
    def test_old_candidate_collision_or_incomplete_preparer_is_denied(self):
        issuer,w,auth,state,calls,opts,sources=self.fixture()
        incomplete=copy.deepcopy(opts);incomplete['preparer_template'].pop('coordinationBinding')
        with self.assertRaisesRegex(ValueError,'COMPLETE_STATIC_PROVIDER_PREPARER'):
            m.profile_scope(issuer.template,issuer.creation.scope,**incomplete)
        with self.assertRaisesRegex(ValueError,'CANNOT_REUSE_OLD_RUNTIME_CANDIDATE'):
            m.compile_material(issuer.template,issuer.scope,sources,'e'*64,{'containerId':'a'*64,'applicationHash':'b'*64},auth.context,auth.now,auth.now+80)
    def test_unqualified_runtime_or_foreign_key_scope_cannot_sign(self):
        issuer,w,auth,*_=self.fixture();issuer.signers['intent'].scope['role']='CREATION_ATTESTATION'
        with self.assertRaisesRegex(ValueError,'EXACT_PROVIDER_EXISTING_KEY'):issuer.check_scope()
        self.assertFalse((issuer.root/'issuance-claim.json').exists())
    def test_same_signature_bytes_in_replaced_inode_are_not_adopted(self):
        issuer,w,auth,*_=self.fixture()
        with w.peer_window():
            issuer.creation.create_once();issuer.issue_once();path=issuer.root/'live.json'
            raw=path.read_bytes();replacement=path.with_name('replacement');auth.write(replacement,raw);replacement.replace(path)
            with self.assertRaisesRegex(ValueError,'OWNED_INODE_DRIFT'):issuer.observe()
    def test_signed_other_registry_recipe_is_not_accepted(self):
        issuer,w,auth,*_=self.fixture();recipe=copy.deepcopy(issuer.scope['registryRecipe']);recipe['qualifiedPackageHash']='e'*64
        with self.assertRaisesRegex(ValueError,'REGISTRY_SIGNED_NODE_INTENT'):m.validate_registry_recipe(recipe,w)

if __name__=='__main__':unittest.main()
