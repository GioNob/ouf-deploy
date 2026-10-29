"""Real files/Ed25519/fsync/flock; application admissions/native probe synthetic.

No host service or application is installed. Fixtures use a private disposable
repository subtree and the actual qualified capsule, not a replacement payload.
"""
import copy,hashlib,os,sys,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),
    str(ROOT/'tools/semantic_frame_compiler'),str(ROOT/'tools/semantic_lease_recovery'),
    str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_m2_discovery_lease_start_owner as starts
from tools.m2_discovery_installation_profile import lease_file_installation as m,lease_capsule
from tools.m2_discovery_installation_profile import lease_installation_template as templates
from tools.semantic_provider_deployment_authentication import signing_bytes


class Files(unittest.TestCase):
    def fixture(self):
        parent_case=starts.Start();base,auth,intent,row,calls,reads,obs=parent_case.fixture()
        self.addCleanup(parent_case.doCleanups)
        c=copy.deepcopy(base.template['configurationTemplate']);r=copy.deepcopy(base.template['recipeTemplate'])
        snapshot=copy.deepcopy(base.proposal['nativeObservation']);old=base.template['installationRoot']
        install=str(auth.root/'installation');ledger=str(auth.root/'ledger')
        for name in ('fences','kernel','public','file-transaction','probe-staging'):(auth.root/name).mkdir(mode=0o700)
        lock=auth.root/'fences/owner.lock';auth.write(lock,b'')
        kernel=auth.root/'kernel/kernel.lock';auth.write(kernel,b'')
        c.update(ledgerRoot=ledger,serviceUnitPath=install+'/owner.service',generationReceiptPath=install+'/current-generation.json',
            hostBootIdPath=install+'/host-boot-id',commonInvocationLock=str(lock))
        r.update(coordinationJournal=ledger+'/coordination.json',leaseCommonLock=str(kernel),leaseCommonLockIdentity=m.inode(kernel))
        python=Path('/usr/bin/python3').resolve();nft=Path('/usr/bin/true').resolve()
        def program(p):return {'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'maximumBytes':67108864}
        py=program(python);r['nft']=program(nft)
        policy=auth.root/'public/policy.json';auth.write(policy,auth.policy.read_bytes())
        c['verification']={'trustPolicy':auth.binding(policy),'openssl':{
            **auth.binding(auth.openssl),'version':auth.native('version').decode().split()[1]},
            'context':{k:auth.context[k] for k in ('installationRef','entityRef','attestorRef')}}
        c['sources']=[py,program(nft),program(auth.openssl),
            {'path':install+'/capsule.py','sha256':templates.CAPSULE_SHA,'maximumBytes':templates.CAPSULE_BYTES},
            {'path':install+'/worker-recipe.json','sha256':templates.ZERO,'maximumBytes':1048576}]
        # This workspace does not expose host boot metadata. Native generation
        # and boot facts are deliberately synthetic in these protocol tests.
        boot=patch.object(m,'boot_id',return_value=snapshot['bootId']);boot.start();self.addCleanup(boot.stop)
        snapshot['generationRef']=templates.generation_reference(snapshot)
        t=templates.template(c,r,py,source_closure_hash=base.template['sourceClosureHash'],
            expected_images=base.template['expectedImages'],expected_node_profiles=base.template['expectedNodeProfiles'],
            installation_root=install,signing_key_paths=[str(auth.key)])
        proposal=templates.materialize(t,snapshot,m.inode(lock))
        scope=starts.m.start_scope(t,unit_name=base.scope['unitName'],manager=base.scope['manager'],directory=str(base.root))
        publication=str(auth.root/'file-transaction');component=m.publication_scope(t,scope,publication)
        intent={**intent,'leaseInstallationScopeHash':m.digest(scope)}
        hashes={phase:m.digest(base.node_owner.request) if phase=='CREATE_REPLACEMENT' else m.digest(intent) if phase==starts.m.PHASE
            else '4'*64 for phase in starts.m.PHASES}
        child,raw=auth.child(creation_request_hash=m.digest(base.node_owner.request),phase_intent_hashes=hashes)
        auth.review['components']['operationalLeaseInstallation']=component;parent=auth.fixture()
        ah=hashlib.sha256(raw).hexdigest();row['transitionAuthorityEvidenceHash']=ah
        for effect in row['effects']:
            effect['authorityEvidenceHash']=ah;effect['intentHash']=hashes[effect['phase']]
        node=base.node_owner;node.authority=child;node.raw=raw
        start=starts.m.LeaseStartAdapter(parent=parent,authority=child,authority_raw=raw,transition=base.transition,
            store=base.store,node_owner=node,template=t,proposal=proposal,scope=scope,intent=intent,publication_directory=publication)
        capsule,_=lease_capsule.build(ROOT)
        material=m.compile_material(t,proposal,capsule,initial_time=(time.time(),time.monotonic()),installation_sources={})
        self.signatures=auth.signatures
        def sign(value):
            raw=m.encoded(value);header={'schema':'ouf.semantic-deployment-detached-signature.v1','algorithm':'Ed25519',
                'keyRef':'synthetic-attestor-key','role':m.ROLE,'issuerRef':auth.context['attestorRef'],
                'installationRef':auth.context['installationRef'],'entityRef':auth.context['entityRef'],
                'payloadHash':hashlib.sha256(raw).hexdigest()}
            frame=auth.root/'receipt-frame';auth.write(frame,signing_bytes(raw,header))
            sig=auth.native('pkeyutl','-sign','-rawin','-inkey',str(auth.key),'-in',str(frame))
            auth.write(auth.signatures/(header['payloadHash']+'.'+m.ROLE+'.json'),m.encoded({**header,'signature':sig.hex()}))
        for payload in (material['seal'],material['receipt'],material['generation']):sign(payload)
        verifier=m.DetachedAuthenticator(c['verification']['trustPolicy'],str(auth.signatures),c['verification']['openssl'],clock=lambda:auth.now)
        staging=auth.root/'probe-staging';auth.write(staging/(m.digest(snapshot)+'.json'),m.encoded(snapshot))
        probe=m.NativeLeaseGenerationProbe(staging)
        def native(instance,value):
            return {k:value[k] for k in ('nativeObservationHash','nativeProfileHash','generationRef','bootId')}
        mocked=patch.object(m.NativeLeaseGenerationProbe,'__call__',native);mocked.start();self.addCleanup(mocked.stop)
        installer=m.LeaseFileInstallation(start,material,verifier=verifier,probe=probe)
        return installer,intent,auth,material,calls

    def test_exact_files_signed_receipts_and_initial_ledger_no_start_or_sign(self):
        owner,intent,auth,material,calls=self.fixture();owner.apply(intent)
        outcome,evidence=owner.observe(intent)
        self.assertEqual(outcome,'APPLIED');self.assertEqual(evidence['signaturesIssued'],0)
        self.assertFalse(evidence['managerStartPerformed']);self.assertEqual(calls,[])
        row=m.private_json(Path(material['proposal']['configuration']['ledgerRoot'])/'recovery.json')
        self.assertEqual(row['attempts'],0);self.assertEqual(row['publicationCount'],0)
        self.assertEqual(row['startedWall'],material['initialTime'][0])
        self.assertEqual(row['timeAccountingProfile'],m.DiscoveryRecovery.PROFILE)
        with self.assertRaises(FileExistsError):owner.apply(intent)

    def test_lost_completion_reply_reconciles_without_writes_or_signing(self):
        owner,intent,auth,material,_=self.fixture();original=m.new_file
        def lost(fd,name,raw,mode=0o600):
            if name=='complete.json':raise TimeoutError('SYNTHETIC_LOST_REPLY_AFTER_FILE_COMMIT')
            return original(fd,name,raw,mode)
        with patch.object(m,'new_file',side_effect=lost),self.assertRaises(TimeoutError):owner.apply(intent)
        with patch.object(m,'new_file',side_effect=AssertionError('READ_ONLY_RECONCILIATION')):
            self.assertEqual(owner.observe(intent)[0],'APPLIED')

    def test_published_material_is_accepted_by_existing_installed_runtime_guard(self):
        owner,intent,auth,material,calls=self.fixture();owner.apply(intent)
        with patch.object(starts.m,'boot_id',return_value=material['generation']['bootId']):
            guard=owner.start.installed(before_start=True)
        self.assertEqual(guard.configuration,material['proposal']['configuration'])
        self.assertEqual(calls,[])

    def test_partial_file_write_is_preserved_and_cannot_be_replayed(self):
        owner,intent,auth,material,_=self.fixture();original=owner.put
        def partial(name,raw,mode=0o600):
            if name.endswith('/configuration.json'):
                original(name,raw[:12],mode);raise OSError('SYNTHETIC_DISK_FAILURE')
            return original(name,raw,mode)
        with patch.object(owner,'put',side_effect=partial),self.assertRaises(OSError):owner.apply(intent)
        self.assertEqual(owner.observe(intent)[0],'UNKNOWN')
        with self.assertRaises(FileExistsError):owner.apply(intent)
        self.assertEqual((Path(owner.start.template['installationRoot'])/'configuration.json').stat().st_size,12)

    def test_crash_after_claim_before_destinations_is_consumed(self):
        owner,intent,auth,material,_=self.fixture()
        with m.directory(owner.root) as fd:m.new_file(fd,'claim.json',m.encoded(owner.claim()))
        self.assertEqual(owner.observe(intent)[0],'UNKNOWN')
        with self.assertRaises(FileExistsError):owner.apply(intent)
        self.assertFalse(Path(owner.start.template['installationRoot']).exists())

    def test_foreign_existing_ledger_and_counters_are_never_adopted(self):
        owner,intent,auth,material,_=self.fixture();ledger=Path(owner.start.proposal['configuration']['ledgerRoot'])
        ledger.mkdir(mode=0o700);auth.write(ledger/'recovery.json',b'PRESERVE_EXHAUSTED_HISTORY_128')
        with self.assertRaisesRegex(ValueError,'EXISTING_DISCOVERY'):owner.apply(intent)
        self.assertEqual((ledger/'recovery.json').read_bytes(),b'PRESERVE_EXHAUSTED_HISTORY_128')
        self.assertTrue((owner.root/'claim.json').exists())

    def test_generation_signature_revocation_or_parent_revocation_prevents_claim(self):
        for which in ('generation','seal','parent'):
            owner,intent,auth,material,_=self.fixture()
            sha=owner.start.parent.sha if which=='parent' else m.digest(material[which])
            role='FINAL_DEPLOYMENT_APPROVAL' if which=='parent' else m.ROLE
            (auth.signatures/(sha+'.'+role+'.json')).unlink()
            with self.assertRaises((ValueError,FileNotFoundError,RuntimeError)):owner.apply(intent)
            self.assertFalse((owner.root/'claim.json').exists())

    def test_native_drift_blocks_before_any_destination_write(self):
        owner,intent,auth,material,_=self.fixture()
        with patch.object(m.NativeLeaseGenerationProbe,'__call__',side_effect=ValueError('NATIVE_GENERATION_CHANGED')):
            with self.assertRaisesRegex(ValueError,'NATIVE_GENERATION'):owner.apply(intent)
        self.assertFalse((owner.root/'claim.json').exists())

    def test_concurrent_publications_use_same_existing_logical_inode(self):
        owner,intent,auth,material,_=self.fixture();c=owner.start.proposal['configuration']
        with m.existing_kernel_lock(c['commonInvocationLock'],c['commonLockIdentity']):
            with self.assertRaises(BlockingIOError):owner.apply(intent)
        self.assertFalse((owner.root/'claim.json').exists())

    def test_replaced_inode_equal_bytes_or_changed_permissions_are_not_adopted(self):
        for which in ('inode','mode','bytes'):
            owner,intent,auth,material,_=self.fixture();owner.apply(intent)
            file=Path(owner.start.template['installationRoot'])/'configuration.json'
            if which=='inode':
                other=file.with_name('replacement');auth.write(other,file.read_bytes());other.replace(file)
            elif which=='mode':file.chmod(0o644)
            else:auth.write(file,b'CORRUPT')
            with self.assertRaises((ValueError,RuntimeError)):owner.observe(intent)

    def test_noop_native_callback_or_material_drift_is_denied(self):
        owner,intent,auth,material,_=self.fixture();owner.probe=lambda value:value
        with self.assertRaisesRegex(ValueError,'TYPED_DISCOVERY'):owner.apply(intent)
        owner,intent,auth,material,_=self.fixture();owner.material['seal']['budgetReset']=True
        with self.assertRaisesRegex(ValueError,'MATERIAL_DRIFT'):owner.apply(intent)

    def test_mid_publication_revocation_prevents_commit_marker(self):
        owner,intent,auth,material,_=self.fixture();original=owner.put
        def revoke(name,raw,mode=0o600):
            original(name,raw,mode)
            if name.endswith('/publication-seal.json'):
                (auth.signatures/(owner.start.parent.sha+'.FINAL_DEPLOYMENT_APPROVAL.json')).unlink()
        with patch.object(owner,'put',side_effect=revoke),self.assertRaises(FileNotFoundError):owner.apply(intent)
        self.assertTrue((owner.root/'claim.json').exists())
        self.assertFalse((Path(owner.start.template['installationRoot'])/'installed.json').exists())

    def test_capsule_or_added_unreviewed_source_is_denied_by_pure_compiler(self):
        owner,intent,auth,material,_=self.fixture();t,p=material['template'],material['proposal']
        capsule=material['files'][t['installationRoot']+'/capsule.py'][1]
        for raw,extras in ((capsule+b'X',{}),(capsule,{t['installationRoot']+'/unreviewed':b'X'})):
            with self.assertRaises(ValueError):m.compile_material(t,p,raw,initial_time=material['initialTime'],installation_sources=extras)


if __name__=='__main__':unittest.main()
