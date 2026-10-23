"""Real rmdir/FD/flock/full sealed filesystem; explicit Engine/kernel fixtures."""
import copy,hashlib,importlib.util,json,os,stat,types
from pathlib import Path
import unittest
from unittest.mock import patch
import test_postboot_root_binding_metadata as f
import test_postboot_paused_rootfs_diagnostic as native

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('jvm_directory_cleanup',ROOT/'scripts/apply-registry-jvm-directory-cleanup-20261023.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class Cleanup(unittest.TestCase):
    write=f.RootBinding.write
    refresh=f.RootBinding.refresh
    def setUp(self):
        f.RootBinding.setUp(self);self.readonly=False;self.ns=native.primitives()
        self.merged=self.root/'engine/rootfs/overlayfs'/self.journal['newGeneration']['containerId']
        tmp=self.merged/'tmp';tmp.mkdir(mode=0o1777);tmp.chmod(0o1777)
        limits={'maxEntries':100,'maxBytes':1024,'maxDepth':8}
        after,_=m.sealed_rows(dict(self.ns),self.b,self.merged,limits,m.Budget(5))
        hs=tmp/'hsperfdata_ouf';hs.mkdir()
        tc=tmp/'tomcat.9555.12345';(tc/'work/Tomcat/localhost/ROOT').mkdir(parents=True)
        self.paths=[p for p in tmp.rglob('*') if p.is_dir()]
        for p in self.paths:
            try:os.chown(p,10001,10001)
            except OSError:
                if os.environ.get('OUF_NATIVE_UIDS')=='1':raise
                # Managed local sandbox cannot map UID10001; CI requires real ownership.
            p.chmod(0o700 if p==tc else 0o755)
        before,rows=m.sealed_rows(dict(self.ns),self.b,self.merged,limits,m.Budget(5))
        ordered=sorted([row for row in rows if row['path'] not in ('','app.jar','tmp')],key=lambda r:(-r['path'].count('/'),r['path']))
        prepared=json.loads((self.prep/'prepared.json').read_bytes());ctx=prepared['nativeContext']
        ctx['nodeRecipe']['expectedRootfsSeal']=after
        prepared['registryInputs']['creationRequest']['HostConfig']['ReadonlyRootfs']=False
        prepared['registryInputs']['creationRequest']['User']='10001:10001'
        self.write(self.prep/'prepared.json',prepared)
        review=json.loads((self.prep/'review.json').read_bytes());review['currentContext']=ctx;self.write(self.prep/'review.json',review)
        receipt=json.loads((self.prep/'authority/receipt.json').read_bytes());receipt['reviewHash']=self.b.digest(review);self.write(self.prep/'authority/receipt.json',receipt)
        oci=json.loads(self.bundle.read_bytes());oci['root'].pop('readonly');self.write(self.bundle,oci)
        self.write(self.execution/'node/frame-policy.json',{'expectedOci':oci})
        for p in (self.execution/'invocation.lock',self.ownerroot/'invocation.lock'):p.write_bytes(b'');p.chmod(0o600)
        self.planroot=self.root/'cleanup-plan';self.planroot.mkdir()
        proof={'directories':ordered,'expectedSealRestoredByRemovingOnlySixDirectories':True,'observedRootfsSeal':before,'expectedRootfsSeal':after}
        self.write(self.planroot/'proof.json',proof)
        self.plan={'schema':'ouf.semantic-jvm-empty-directory-cleanup-plan.v1','proofHash':self.b.digest(proof),
            'preparationHash':self.b.digest(prepared),'reviewHash':self.b.digest(review),'retainedGeneration':self.journal['newGeneration'],
            'orderedDirectories':ordered,'expectedBeforeSeal':before,'expectedAfterSeal':after,'operation':'RMDIR_EMPTY_DIRECTORIES_ONLY',
            'maximumDirectoryRemovals':6,'grantAttemptAllowance':0,'fileUnlinkAllowed':False,'recursiveRemovalAllowed':False,
            'unpauseAllowed':False,'javaReleaseAllowed':False,'expectedSealMayBeReplaced':False}
        self.write(self.planroot/'cleanup-plan.json',self.plan)
        for name,value in {'PREPARATION_HASH':self.b.digest(prepared),'REVIEW_HASH':self.b.digest(review)}.items():
            p=patch.object(self.b,name,value);p.start();self.addCleanup(p.stop)
        real=Path
        for name,value in {'base_module':lambda:self.b,'PLAN_ROOT':'cleanup-plan','PLAN_HASH':self.b.digest(self.plan),'PROOF_HASH':self.b.digest(proof),
            'primitives':f.fixture.m.primitives,'frozen_generation':lambda pin:[123,10,4,5,'frozen'],
            'mount_guard':lambda root:[], 'Path':lambda v:self.bootfile if v=='/proc/sys/kernel/random/boot_id' else real(v)}.items():
            p=patch.object(m,name,value);p.start();self.addCleanup(p.stop)
        self.immutable=[self.prep/'prepared.json',self.prep/'review.json',self.execution/'recovery.json',self.execution/'native-reads.json',self.ownerroot/'recovery.json']

    def test_real_six_empty_rmdirs_restore_full_independent_seal_without_other_effect_or_replay(self):
        before={p:p.read_bytes() for p in self.immutable};payload=(self.merged/'app.jar').read_bytes()
        v=m.run();self.assertEqual(v['status'],'JVM_RESIDUE_REMOVED_ORIGINAL_SEAL_RESTORED')
        self.assertEqual(v['directoryRemovalsConfirmed'],6);self.assertEqual(v['runtimeEffectsDispatched'],6)
        self.assertEqual(v['engineGets'],2);self.assertEqual(v['combinedEngineGets'],6)
        self.assertEqual(v['retainedControlledGrantAttempts'],320);self.assertEqual(v['oauthRequests'],0)
        self.assertFalse(v['javaReleased']);self.assertFalse(v['serviceReadinessEstablished'])
        self.assertEqual(before,{p:p.read_bytes() for p in self.immutable});self.assertEqual(payload,(self.merged/'app.jar').read_bytes())
        self.assertEqual(list((self.merged/'tmp').iterdir()),[])
        stop=m.run();self.assertEqual(stop['reasonCode'],'MAINTENANCE_ALREADY_CLAIMED_RECONCILE_OUTCOME_ONLY');self.assertEqual(len(self.calls),2)

    def test_changed_before_seal_prevents_all_removals(self):
        (self.merged/'app.jar').write_bytes(b'changed')
        v=m.run();self.assertEqual(v['reasonCode'],'FULL_LIVE_BEFORE_SEAL_MUST_MATCH_REVIEWED_PLAN');self.assertEqual(v['directoryRemovalAttempts'],0)
        self.assertTrue(all(p.exists() for p in self.paths))

    def test_other_native_or_token_invocation_lock_blocks_maintenance(self):
        fd=m.lock_existing(self.ownerroot/'invocation.lock')
        try:v=m.run()
        finally:os.close(fd)
        self.assertEqual(v['reasonCode'],'OTHER_RECOVERY_OR_TOKEN_OWNER_IS_ACTIVE');self.assertEqual(v['directoryRemovalAttempts'],0);self.assertEqual(self.calls,[])

    def test_kernel_unfreeze_prevents_even_preflight_removal(self):
        def unfrozen(pin):raise ValueError('REVIEWED_CONTAINER_MUST_REMAIN_KERNEL_FROZEN')
        with patch.object(m,'frozen_generation',unfrozen):v=m.run()
        self.assertEqual(v['reasonCode'],'REVIEWED_CONTAINER_MUST_REMAIN_KERNEL_FROZEN');self.assertEqual(v['directoryRemovalAttempts'],0)

    def test_partial_failure_retains_claim_and_applied_receipt_without_automatic_retry(self):
        real=m.remove_directories
        def partial(root,ordered,guard,claim,applied):
            def stopped(n,row,pin):applied(n,row,pin);raise ValueError('SIMULATED_FAILURE_AFTER_ONE_CONFIRMED_RMDIR')
            return real(root,ordered,guard,claim,stopped)
        with patch.object(m,'remove_directories',partial):v=m.run()
        self.assertEqual(v['directoryRemovalAttempts'],1);self.assertEqual(v['directoryRemovalsConfirmed'],1);self.assertTrue(v['runtimeEffectsMayBePartial'])
        roots=list(self.root.glob('semantic-registry-jvm-cleanup-*'));self.assertEqual(len(roots),1)
        self.assertTrue((roots[0]/'rmdir-0-claimed.json').is_file());self.assertTrue((roots[0]/'rmdir-0-applied.json').is_file())
        again=m.run();self.assertEqual(again['reasonCode'],'MAINTENANCE_ALREADY_CLAIMED_RECONCILE_OUTCOME_ONLY')
        self.assertEqual(sum(p.exists() for p in self.paths),5)

    def test_child_created_after_preflight_is_not_unlinked_or_recursively_removed(self):
        child=self.merged/self.plan['orderedDirectories'][0]['path']/'keep'
        def guard():child.write_bytes(b'must survive')
        with self.assertRaisesRegex(ValueError,'EXACT_EMPTY_REVIEWED_DIRECTORY_INODE_REQUIRED'):
            m.remove_directories(self.merged,self.plan['orderedDirectories'],guard,lambda *a:self.fail('must not dispatch'),lambda *a:None)
        self.assertEqual(child.read_bytes(),b'must survive')

    def test_symlink_inode_replacement_cannot_remove_other_directory(self):
        first=self.merged/self.plan['orderedDirectories'][0]['path'];outside=self.root/'outside';outside.mkdir();changed=False
        def guard():
            nonlocal changed
            if not changed:first.rmdir();first.symlink_to(outside);changed=True
        with self.assertRaisesRegex(ValueError,'EXACT_EMPTY_REVIEWED_DIRECTORY_INODE_REQUIRED'):
            m.remove_directories(self.merged,self.plan['orderedDirectories'],guard,lambda *a:self.fail('must not dispatch'),lambda *a:None)
        self.assertTrue(outside.is_dir());self.assertTrue(first.is_symlink())

    def test_current_container_changed_after_removals_never_reports_success(self):
        self.mode='changed';v=m.run()
        self.assertEqual(v['directoryRemovalsConfirmed'],6);self.assertEqual(v['reasonCode'],'CONTAINER_CHANGED_AFTER_MAINTENANCE')
        self.assertTrue(v['runtimeEffectsMayBePartial']);self.assertFalse(v['serviceReadinessEstablished'])


class Freeze(unittest.TestCase):
    def test_cgroup_v2_freeze_pid_namespace_and_container_scope_are_required(self):
        pin={'pid':123,'containerId':'a'*64}
        fake=types.SimpleNamespace(O_RDONLY=os.O_RDONLY,O_NOFOLLOW=os.O_NOFOLLOW,O_NONBLOCK=os.O_NONBLOCK,open=lambda *a:1,close=lambda *a:None,fstat=lambda *a:types.SimpleNamespace(st_dev=2,st_ino=3),read=lambda *a:b'populated 1\nfrozen 1\n')
        with patch.object(m,'generation',lambda p:[123,10,4,5]),patch.object(m,'kernel_file',lambda *a:('0::/system.slice/docker-'+pin['containerId']+'.scope\n').encode()),patch.object(m,'os',fake):
            self.assertEqual(m.frozen_generation(pin)[:4],[123,10,4,5])
            fake.read=lambda *a:b'populated 1\nfrozen 0\n'
            with self.assertRaisesRegex(ValueError,'REVIEWED_CONTAINER_MUST_REMAIN_KERNEL_FROZEN'):m.frozen_generation(pin)


if __name__=='__main__':unittest.main()
