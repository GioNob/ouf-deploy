"""Real protected metadata, protocol flocks and prior six-rmdir receipts; no runtime adapter."""
import hashlib,importlib.util,json,os
from pathlib import Path
import unittest
from unittest.mock import patch
import test_postboot_jvm_directory_cleanup as cleanup

spec=importlib.util.spec_from_file_location('resumption_capture',cleanup.ROOT/'scripts/capture-registry-resumption-inputs-20261023.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Capture(unittest.TestCase):
    write=cleanup.Cleanup.write
    refresh=cleanup.Cleanup.refresh
    def setUp(self):
        cleanup.Cleanup.setUp(self)
        review=json.loads((self.prep/'review.json').read_bytes())
        fence={'path':str(self.root/'current.fence.json'),'value':{'fixture':True}}
        review['scopes']['semanticRegistryPostbootOwner']['fenceBinding']=fence
        self.write(Path(fence['path']),fence['value'])
        self.write(self.prep/'review.json',review)
        receipt=json.loads((self.prep/'authority/receipt.json').read_bytes());receipt['reviewHash']=self.b.digest(review);self.write(self.prep/'authority/receipt.json',receipt)
        self.plan['reviewHash']=self.b.digest(review);self.write(self.planroot/'cleanup-plan.json',self.plan)
        for target,key,value in ((self.b,'REVIEW_HASH',self.b.digest(review)),(cleanup.m,'PLAN_HASH',self.b.digest(self.plan))):
            p=patch.object(target,key,value);p.start();self.addCleanup(p.stop)
        scope=review['scopes']['semanticRegistryPostbootOwner']
        self.write(self.ownerroot/'owner-session.json',scope)
        self.write(self.ownerroot/'owner-admission.json',{'state':'BLOCKED','contextRef':scope['contextRef'],'generationRef':scope['generationRef']})
        self.write(self.ownerroot/'owner-first-grant.json',{'fixture':True,'historical':True})
        result=cleanup.m.run();self.assertEqual(result['status'],'JVM_RESIDUE_REMOVED_ORIGINAL_SEAL_RESTORED')
        self.maintenance=Path(result['privateMaintenancePath'])
        real=Path
        for key,value in {'PLAN_HASH':self.b.digest(self.plan),'PLAN_ROOT':'cleanup-plan',
            'Path':lambda p:self.bootfile if p=='/proc/sys/kernel/random/boot_id' else real(p)}.items():
            p=patch.object(m,key,value);p.start();self.addCleanup(p.stop)

    def test_completed_cleanup_current_cancelled_metadata_pinned_with_no_runtime_or_old_writes(self):
        before={p:p.read_bytes() for p in self.root.rglob('*.json')}
        calls=len(self.calls);value=m.capture(self.b)
        self.assertEqual(value['status'],'CHECKPOINT_FOUR_SUCCESSOR_INPUTS_RETAINED')
        self.assertEqual(value['engineGets'],0);self.assertEqual(len(self.calls),calls)
        self.assertEqual(value['retainedControlledGrantAttempts'],320);self.assertFalse(value['runtimeAuthorityIssued'])
        self.assertEqual(before,{p:p.read_bytes() for p in before})
        artifact=Path(value['privateInputsPath']);self.assertEqual(artifact.stat().st_mode&0o777,0o400)
        self.assertEqual(hashlib.sha256(artifact.read_bytes()).hexdigest(),value['privateInputsHash'])
        retained=json.loads(artifact.read_bytes());self.assertEqual(retained['newGrantAllowance'],0)
        self.assertEqual(retained['retainedNativeJournal'],self.journal)
        self.assertFalse(value['currentContainerStateObserved']);self.assertFalse(value['serviceReadinessEstablished'])
        with self.assertRaisesRegex(ValueError,'EXISTING_RESUMPTION_INPUTS_RETAINED_NO_REPLAY'):m.capture(self.b)

    def test_missing_applied_receipt_cannot_be_promoted_to_completed_inputs(self):
        (self.maintenance/'rmdir-5-applied.json').unlink()
        with self.assertRaises(FileNotFoundError):m.capture(self.b)
        self.assertEqual(list(self.root.glob('semantic-registry-resumption-inputs-*')),[])

    def test_different_cancelled_global_fence_refused(self):
        self.write(self.root/'current.fence.json',{'changed':True})
        with self.assertRaisesRegex(ValueError,'EXACT_RETAINED_POSTBOOT_GLOBAL_FENCE_REQUIRED'):m.capture(self.b)

    def test_active_native_invocation_refused_without_runtime_requests(self):
        fd=m.lock_existing(self.execution/'invocation.lock');calls=len(self.calls)
        try:
            with self.assertRaisesRegex(ValueError,'OTHER_RECOVERY_OR_TOKEN_OWNER_IS_ACTIVE'):m.capture(self.b)
        finally:os.close(fd)
        self.assertEqual(len(self.calls),calls)

    def test_metadata_changed_between_initial_and_final_read_refused(self):
        original=m.Snapshot.recheck
        def move(r):
            self.write(self.ownerroot/'recovery.json',dict(self.owner,controlledCumulativeGrantAttempts=321))
            original(r)
        with patch.object(m.Snapshot,'recheck',move):
            with self.assertRaisesRegex(ValueError,'METADATA_HASH_OR_BYTE_BOUND'):m.capture(self.b)
        self.assertEqual(list(self.root.glob('semantic-registry-resumption-inputs-*')),[])

if __name__=='__main__':unittest.main()
