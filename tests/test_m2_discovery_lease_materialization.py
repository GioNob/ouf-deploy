"""Actual signed scopes/files/claims; native generation and admissions modeled.

No provider, manager or target operation is dispatched by these fixtures.
"""
import copy,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),
    str(ROOT/'tools/semantic_frame_compiler'),str(ROOT/'tools/semantic_lease_recovery'),
    str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_m2_discovery_lease_attestation as attest
from tools.m2_discovery_installation_profile import lease_materialization as m


class Materialization(unittest.TestCase):
    def fixture(self):
        f=attest.Attest();issuer,intent,auth,_,_=f.fixture(registration=True,sequence=True)
        self.addCleanup(f.doCleanups);material=issuer.installation.material
        template=material['template'];snapshot=copy.deepcopy(material['proposal']['nativeObservation'])
        # Remove only the disposable fixture's preseeded worker fence/snapshot.
        # Production materialization never deletes/adopts an existing fence.
        Path(template['configurationTemplate']['commonInvocationLock']).unlink()
        (issuer.installation.probe.root/(m.digest(snapshot)+'.json')).unlink()
        capsule=material['files'][template['installationRoot']+'/capsule.py'][1]
        owner=m.WorkerMaterialization(node_owner=issuer.start.node_owner,provider=issuer.provider,
            signer=issuer.signer,capsule=capsule,installation_sources=material['installationSources'])
        for selected in (patch.object(owner,'capture_native',return_value=snapshot),
                patch.object(m,'boot_id',return_value=snapshot['bootId'])):
            selected.start();self.addCleanup(selected.stop)
        return owner,intent,auth,snapshot

    def test_prepares_current_peers_once_without_signing_and_retains_original_clocks(self):
        owner,intent,auth,snapshot=self.fixture()
        with patch.object(owner.signer,'sign',side_effect=AssertionError('NO_KEY_ACCESS')):
            phase=owner.prepare_once(intent);again=owner.prepared(intent)
        self.assertIs(type(phase),m.WorkerInstallationPhase)
        self.assertEqual(phase.files.material,again.files.material)
        self.assertEqual(phase.files.material['proposal']['nativeObservation'],snapshot)
        self.assertEqual(phase.files.material['initialTime'],m.private_json(owner.root/'materialization-claim.json')['initialTime'])
        self.assertFalse((owner.root/'claim.json').exists())
        with self.assertRaises(FileExistsError):owner.prepare_once(intent)

    def test_lost_owned_commit_reply_reconciles_without_any_write_or_resigning(self):
        owner,intent,auth,_=self.fixture();original=m.new_file
        def lost(fd,name,raw,mode=0o600):
            result=original(fd,name,raw,mode)
            if name=='materialization-owned.json':raise TimeoutError('SYNTHETIC_LOST_OWNED_REPLY')
            return result
        with patch.object(m,'new_file',side_effect=lost),self.assertRaises(TimeoutError):owner.prepare_once(intent)
        with (patch.object(m,'new_file',side_effect=AssertionError('NO_RECONCILIATION_WRITES')),
                patch.object(owner.signer,'sign',side_effect=AssertionError('NO_KEY_ACCESS'))):
            self.assertIsNotNone(owner.prepared(intent))

    def test_partial_materialization_preserves_claim_and_fence_without_recreation(self):
        owner,intent,auth,_=self.fixture()
        with (patch.object(owner,'capture_native',side_effect=TimeoutError('SYNTHETIC_LOST_CAPTURE')),
                self.assertRaises(TimeoutError)):owner.prepare_once(intent)
        lock=Path(owner.template['configurationTemplate']['commonInvocationLock']);identity=m.inode(lock)
        self.assertIsNone(owner.prepared(intent));self.assertEqual(owner.observe(intent)[0],'UNKNOWN')
        with self.assertRaises(FileExistsError):owner.prepare_once(intent)
        self.assertEqual(m.inode(lock),identity)
        with self.assertRaisesRegex(ValueError,'NO_REPREPARATION'):owner.continue_installation(intent)

    def test_native_generation_mismatch_cannot_commit_owned_material(self):
        owner,intent,auth,_=self.fixture()
        with patch.object(m.NativeLeaseGenerationProbe,'__call__',return_value={}),self.assertRaisesRegex(ValueError,'EXACT_CURRENT'):
            owner.prepare_once(intent)
        self.assertFalse((owner.root/'materialization-owned.json').exists())

    def test_new_boot_cannot_reconstruct_or_rearm_the_retained_material(self):
        owner,intent,auth,_=self.fixture();owner.prepare_once(intent)
        with patch.object(m,'boot_id',return_value='new-boot'),self.assertRaisesRegex(ValueError,'NO_REARM'):
            owner.prepared(intent)

    def test_provider_and_worker_must_share_independent_recipe_and_actual_kernel_contract(self):
        owner,_,_,_=self.fixture();t=owner.template;r=t['recipeTemplate'];recipe=copy.deepcopy(owner.node.recipe)
        # Pure cross-input checks only. This partial profile is never an issuer
        # input, native admission or substitute for recompile_scope/check_scope.
        profile={'schema':'ouf.discovery-provider-profile-installation-scope.v1','registryRecipe':{
            **recipe,'sourceClosureHash':t['sourceClosureHash']},'preparerTemplate':{
            'kernel':r['kernel'],'dns':r['dns'],'coordinationBinding':r['binding'],
            'coordinationJournal':r['coordinationJournal'],'lockFile':r['leaseCommonLock'],
            'commands':{'nft':r['nft']['path']},'commandHashes':{'nft':r['nft']['sha256']}}}
        # The Registry recipe must be the exact independent one fixed in t.
        profile['registryRecipe']=recipe
        recipe['sourceClosureHash']=t['sourceClosureHash']
        from tools.m2_discovery_installation_profile import lease_installation_template as templates
        options={k:t[k] for k in ('sourceClosureHash','expectedImages','expectedNodeProfiles','installationRoot','signingKeyPaths','engineUnit','sandboxRoot')}
        options['expectedNodeProfiles']=copy.deepcopy(options['expectedNodeProfiles'])
        options['expectedNodeProfiles']['registry']['nodeRecipeHash']=m.digest(recipe)
        t=templates.template(t['configurationTemplate'],r,t['python'],**{
            'source_closure_hash':options['sourceClosureHash'],'expected_images':options['expectedImages'],
            'expected_node_profiles':options['expectedNodeProfiles'],'installation_root':options['installationRoot'],
            'signing_key_paths':options['signingKeyPaths'],'engine_unit':options['engineUnit'],'sandbox_root':options['sandboxRoot']})
        lock=[*r['leaseCommonLockIdentity'],0,1,1];request={'Image':t['expectedImages']['registry']}
        m.paired_native_inputs(t,profile,request,lock)
        for field in ('kernel','dns','coordinationBinding','coordinationJournal','lockFile','commands','commandHashes'):
            wrong=copy.deepcopy(profile);wrong['preparerTemplate'][field]={} if type(wrong['preparerTemplate'][field]) is dict else '/other'
            with self.assertRaises((ValueError,KeyError)):m.paired_native_inputs(t,wrong,request,lock)
        with self.assertRaises(ValueError):m.paired_native_inputs(t,profile,request,[*lock[:1],lock[1]+1,*lock[2:]])
        with self.assertRaises(ValueError):m.paired_native_inputs(t,profile,{'Image':'sha256:'+'f'*64},lock)

    def test_replaced_snapshot_and_invalid_reference_are_not_adopted(self):
        for change in ('inode','path'):
            owner,intent,auth,_=self.fixture();owner.prepare_once(intent)
            record=owner.root/'materialization-owned.json';owned=m.private_json(record)
            if change=='inode':
                selected=owner.probe.root/(owned['snapshotHash']+'.json');replacement=owner.probe.root/'replacement.json'
                auth.write(replacement,selected.read_bytes());replacement.replace(selected)
            else:
                owned['snapshotHash']='../other';auth.write(record,m.encoded(owned))
            with (patch.object(owner.signer,'sign',side_effect=AssertionError('NO_KEY_ACCESS')),
                    self.assertRaises(ValueError)):owner.prepared(intent)

    def test_original_clock_tamper_or_revoked_admission_blocks_reconstruction(self):
        for change in ('clock','admission'):
            owner,intent,auth,_=self.fixture();owner.prepare_once(intent)
            if change=='clock':
                path=owner.root/'materialization-claim.json';claim=m.private_json(path)
                claim['initialTime'][0]+=1;auth.write(path,m.encoded(claim))
                selected=patch.object(owner.signer,'sign',side_effect=AssertionError('NO_KEY_ACCESS'))
            else:selected=patch.object(owner.provider,'current',side_effect=ValueError('SYNTHETIC_ADMISSION_REVOKED'))
            with selected,self.assertRaises(ValueError):owner.prepared(intent)

    def test_late_material_drives_real_signatures_and_files_before_modeled_manager_boundary(self):
        owner,intent,auth,_=self.fixture()
        with (patch.object(m.LeaseRegistration,'apply',side_effect=TimeoutError('MODELED_MANAGER_UNAVAILABLE')),
                self.assertRaises(TimeoutError)):owner.apply(intent)
        phase=owner.prepared(intent)
        from tools.m2_discovery_installation_profile.lease_installation_phase import checked_row
        self.assertEqual(checked_row(phase.start)['stageIndex'],2)
        self.assertEqual(phase.issuer.observe(intent)[0],'APPLIED')
        self.assertEqual(phase.files.observe(intent)[0],'APPLIED')
        with (patch.object(owner.signer,'sign',side_effect=AssertionError('NO_RESIGNING')),
                patch.object(m.LeaseRegistration,'apply',side_effect=AssertionError('NO_MANAGER_REPLAY'))):
            self.assertEqual(owner.observe(intent)[0],'UNKNOWN')

if __name__=='__main__':unittest.main()
