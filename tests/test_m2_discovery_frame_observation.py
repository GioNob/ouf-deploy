"""Real protected files and embedded owner loader; Engine/mount/token leaves are fixtures.

These tests do not establish native Docker or current owner admission.
"""
import copy, hashlib, json, os, sys, tempfile, types, unittest
from pathlib import Path
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'tests'), str(ROOT/'tools/semantic_application_cutover'),
               str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from test_m2_discovery_native_profile import fixture
from tools.m2_discovery_installation_profile.native_profile import DiscoveryProfile
from tools.m2_discovery_installation_profile.frame import compile_policy, validate_observation_policy
from tools.m2_discovery_installation_profile import observation as m


class DenyOwnerFixture(m.DomainOwner):
    """Every real admission call fails; token mount leaf is explicitly mocked."""
    def prepare(self,*a,**k):raise AssertionError('No real owner operation allowed')
    def admit(self,*a,**k):raise AssertionError('No real owner admission allowed')
    def guard(self,*a,**k):raise AssertionError('No real owner guard allowed')
    def pause(self,*a,**k):raise AssertionError('No real owner mutation allowed')


class Observation(unittest.TestCase):
    def prepared(self):
        self.assertEqual(os.geteuid(), 0, 'qualification must use the isolated root fixture')
        tmp = tempfile.TemporaryDirectory(dir=ROOT); self.addCleanup(tmp.cleanup); root = Path(tmp.name); root.chmod(0o700)
        r,s,t,l,c = fixture()
        for role,f in s['files'].items():
            p=root/role; p.write_bytes(role.encode()); os.chown(p,f['uid'],f['gid']); p.chmod(f['mode'])
            f['source']=str(p); f['sha256']=hashlib.sha256(p.read_bytes()).hexdigest()
            f['metadataHash']=m.digest(m.attributes(p.lstat()))
        for i,role in enumerate(s['files']):
            f=s['files'][role]
            r['HostConfig']['Mounts'][i]['Source']=f['source']
            l['sources'][i]={k:v for k,v in f.items() if k!='metadataHash'}
            l['manifest']['mounts'][i]['source']=f['source']; t['expectedOci']['mounts'][i]['source']=f['source']
        profile=DiscoveryProfile(r,**s); policy=compile_policy(t,l,c,execution_profile=profile)
        task=root/'tasks'; task.mkdir(mode=0o700); bundle=task/('c'*64); bundle.mkdir(mode=0o700)
        oci=bundle/'config.json'; oci.write_bytes(json.dumps(policy['expectedOci']).encode()); oci.chmod(0o644)
        owner=root/'owner.py'; owner.write_bytes((ROOT/'tools/semantic_frame_compiler/frame-observer.py').read_bytes()); owner.chmod(0o600)
        pol=root/'policy.json'; pol.write_bytes(json.dumps(policy).encode()); pol.chmod(0o600)
        cfg={name:{'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for name,p in [('source',owner),('configuration',pol)]}
        cfg['bundleParents']=[str(task)]
        generation={'pid':123,'startTicks':456,'namespaceInode':789}
        transition=types.SimpleNamespace(execution_profile=None, phases=m.PHASES,
            read=lambda:{'creationRequestHash':profile.compiled['creationRequestHash']})
        paused=object.__new__(m.PausedWorkloadBinding); paused.transition=transition; paused.request_hash=profile.compiled['creationRequestHash']
        paused.observe=lambda:{'creationRequestHash':paused.request_hash,'runtimeBinding':{'pid':123}}
        budget=types.SimpleNamespace(check=lambda:None, remaining=lambda n:n)
        observer=m.DiscoveryFrameObservation(cfg,budget,DenyOwnerFixture(),paused,profile)
        return observer,policy,oci,generation,pol,owner

    def call(self,o,p,oci,g,*,mutate=None):
        current={'pid':123,'startTicks':456,'networkNamespaceInode':789}
        modules,schema=o.owner(o.pinned()['source']) # actual protected embedded source pinning
        modules['review_semantic_oci_policy'].configured_profile=lambda *a:{'fixture':True}
        modules['observe_semantic_mount_view'].generation=lambda *a:dict(current)
        def files(*args):
            self.assertEqual(len(args[3]),5)
            if mutate:mutate()
            return {'fixture':True}
        modules['observe_semantic_creation_frame'].source_mount_frame=files
        with patch.object(o,'owner',return_value=(modules,schema)), \
             patch.object(m,'ConfigtreeMountObservation') as tree, \
             patch.object(m,'RenewableTokenMountObservation') as token, \
             patch.object(m,'token_generation',return_value={'pid':123}):
            tree.return_value.observe.return_value={'fixture':True}
            token.return_value.observe.return_value={'fixture':True}
            return o.observe(g,oci,m.digest(p['expectedOci']),o.configured['configuration']['sha256'])

    def test_protected_observation_keeps_acceptance_and_signing_external(self):
        o,p,oci,g,_,_=self.prepared(); result,inputs=self.call(o,p,oci,g)
        self.assertRegex(result,'^[a-f0-9]{64}$'); self.assertEqual(len(inputs),2)
        self.assertEqual(validate_observation_policy(p,o.profile),o.profile_hash)

    def test_all_file_role_metadata_is_reobserved_after_leaf_observations(self):
        for role in ('providerCredential','discoveryReceiptKey','tlsTrustStore'):
            o,p,oci,g,_,_=self.prepared()
            def drift():Path(p['fileBindings'][role]['source']).chmod(0o400)
            with self.subTest(role=role),self.assertRaisesRegex(ValueError,'METADATA_IDENTITY_DRIFT'):
                self.call(o,p,oci,g,mutate=drift)

    def test_wrong_policy_purpose_or_extra_authority_is_denied(self):
        o,p,*_=self.prepared()
        for change in ({'schema':'ouf.semantic-configured-proposal-seven-mount-frame-policy.v1'}, {'startAuthorized':True}):
            bad=copy.deepcopy(p);bad.update(change)
            with self.assertRaises(ValueError):validate_observation_policy(bad,o.profile)

    def test_policy_cannot_swap_key_roles_directory_or_profile(self):
        o,p,*_=self.prepared()
        for case in ('files','token','profile','args'):
            bad=copy.deepcopy(p)
            if case=='files':bad['fileBindings']['discoveryReceiptKey']=bad['fileBindings']['proposalReceiptKey']
            if case=='token':bad['renewableToken']['directoryInode']+=1
            if case=='profile':bad['executionProfileHash']='f'*64
            if case=='args':bad['startup']['args']=['java','unreviewed']
            with self.subTest(case=case),self.assertRaises(ValueError):validate_observation_policy(bad,o.profile)

    def test_policy_and_oci_file_changes_are_detected(self):
        for case in ('policy','oci','generation','paused'):
            o,p,oci,g,pol,_=self.prepared()
            if case=='policy':pol.write_bytes(b'{}')
            if case=='oci':oci.write_bytes(b'{}')
            if case=='generation':g['startTicks']+=1
            if case=='paused':o.pause_binding.observe=lambda:{'creationRequestHash':'f'*64,'runtimeBinding':{'pid':123}}
            with self.subTest(case=case),self.assertRaises(ValueError):self.call(o,p,oci,g)

    def test_file_only_transition_and_wrong_creation_are_rejected_before_observation(self):
        o,*_=self.prepared()
        for case in ('file-only','request'):
            transition=o.pause_binding.transition
            if case=='file-only':transition.execution_profile=object()
            else:transition.execution_profile=None;o.pause_binding.request_hash='f'*64
            with self.assertRaisesRegex(ValueError,'FULL_CURRENT_TRANSITION'):
                m.DiscoveryFrameObservation(o.configured,o.budget,o.token_owner,o.pause_binding,o.profile)

    def checkpoint(self, position):
        o,*_=self.prepared(); t=o.pause_binding.transition; t.context='c'*64
        effects=[{'phase':p,'state':'APPLIED','intentHash':'a'*64,'nativeEvidenceHash':'b'*64,
                  'authorityEvidenceHash':'d'*64} for p in m.PHASES[:position+1]]
        effects[-1]['state']='IN_FLIGHT'
        row={'creationRequestHash':o.pause_binding.request_hash,'state':'IN_FLIGHT','nextPhase':position,'effects':effects}
        t.read=lambda:copy.deepcopy(row)
        store=types.SimpleNamespace(read=lambda phase,h:{'schema':'ouf.semantic-owner-signed-paused-node-phase.v1',
            'transitionContextHash':t.context,'creationRequestHash':row['creationRequestHash'],'intentHash':'a'*64,
            'completeNativeObservationPerformed':True,'currentScopedAcceptanceSignatureVerified':True})
        from engine_creation import Engine
        return o,t,row,store,object.__new__(Engine)

    def test_full_reentry_requires_both_transport_and_worker_before_migration_or_release(self):
        for pos in (9,10):
            o,t,row,store,engine=self.checkpoint(pos)
            value=m.PausedWorkloadBinding.retained_discovery_at_checkpoint(engine,t,o.profile.request,store,
                attestation_intent_hash='a'*64,checkpoint_row=row,execution_profile=o.profile)
            self.assertEqual(value.current_row(),row)
            for phase in ('INSTALL_AUTHENTICATED_TRANSPORT','START_DISTINCT_LEASE_WORKER'):
                for effect in row['effects']:
                    if effect['phase']==phase:effect['state']='IN_FLIGHT'
                with self.assertRaises(ValueError):value.current_row()
                for effect in row['effects'][:-1]:effect['state']='APPLIED'

    def test_full_reentry_rejects_legacy_positions_and_old_contract_stays_closed(self):
        for pos in (7,8):
            o,t,row,store,engine=self.checkpoint(pos)
            with self.assertRaises(ValueError):
                m.PausedWorkloadBinding.retained_discovery_at_checkpoint(engine,t,o.profile.request,store,
                    attestation_intent_hash='a'*64,checkpoint_row=row,execution_profile=o.profile)
        o,t,row,store,engine=self.checkpoint(9)
        with self.assertRaises(ValueError):
            m.PausedWorkloadBinding.retained_at_checkpoint(engine,t,o.profile.request,store,
                attestation_intent_hash='a'*64,checkpoint_row=row)


if __name__=='__main__':unittest.main()
