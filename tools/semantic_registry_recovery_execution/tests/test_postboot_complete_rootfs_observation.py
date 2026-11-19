"""Actual sealed full-rootfs IO; explicit Engine/kernel cohort substitutes."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import test_postboot_root_binding_metadata as f

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('complete_rootfs_observation',ROOT/'scripts/observe-registry-complete-rootfs-20261023.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class Observation(unittest.TestCase):
    write=f.RootBinding.write
    refresh=f.RootBinding.refresh

    def setUp(self):
        f.RootBinding.setUp(self)
        self.readonly=False
        prepared=json.loads((self.prep/'prepared.json').read_bytes())
        prepared['registryInputs']['creationRequest']['HostConfig']['ReadonlyRootfs']=False
        self.write(self.prep/'prepared.json',prepared)
        p=patch.object(self.b,'PREPARATION_HASH',self.b.digest(prepared));p.start();self.addCleanup(p.stop)
        pred=json.loads((self.successor/'resource-predicates.json').read_bytes())
        pred.update(reviewedRootfsReadOnly=False,currentRootfsReadOnly=False);self.write(self.successor/'resource-predicates.json',pred)
        oci=json.loads(self.bundle.read_bytes());oci['root'].pop('readonly');self.write(self.bundle,oci)
        self.write(self.execution/'node/frame-policy.json',{'expectedOci':oci})
        real=Path
        values={'base_module':lambda:self.b,'primitives':f.fixture.m.primitives,'generation':lambda pin:[123,10,4,5],
            'mount_guard':lambda root:[],'Path':lambda v:self.bootfile if v=='/proc/sys/kernel/random/boot_id' else real(v)}
        for name,value in values.items():
            p=patch.object(m,name,value);p.start();self.addCleanup(p.stop)

    def test_complete_native_seal_omitted_false_and_two_prior_gets_preserved_no_replay(self):
        files=[p for directory in (self.predecessor,self.successor,self.execution,self.ownerroot) for p in directory.rglob('*.json')]
        before={p:p.read_bytes() for p in files}
        v=m.observe()
        self.assertTrue(v['rootfsSealMatchesExpected']);self.assertEqual(v['engineGets'],2)
        self.assertEqual(v['combinedDiagnosticEngineGets'],4);self.assertEqual(v['priorDiagnosticEngineGets'],2)
        self.assertEqual(v['additionalDiagnosticEngineGetAllowance'],1);self.assertEqual(v['previousCombinedDiagnosticEngineGetCeiling'],3)
        self.assertFalse(v['budgetReset']);self.assertEqual(v['retainedControlledGrantAttempts'],320)
        self.assertFalse(v['currentImageLayerMetadataRead']);self.assertFalse(v['serviceReadinessEstablished'])
        self.assertLessEqual(v['metadataReads'],20);self.assertLessEqual(v['predecessorMetadataReads'],14)
        path=Path(v['privateManifestPath']);self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),v['privateManifestHash'])
        self.assertEqual(before,{p:p.read_bytes() for p in files})
        with self.assertRaisesRegex(ValueError,'ROOTFS_DIAGNOSTIC_ALREADY_CONSUMED'):m.observe()
        self.assertEqual(len(self.calls),2)

    def test_explicit_false_equals_reviewed_false(self):
        oci=json.loads(self.bundle.read_bytes());oci['root']['readonly']=False;self.write(self.bundle,oci)
        self.write(self.execution/'node/frame-policy.json',{'expectedOci':oci})
        self.assertTrue(m.observe()['rootfsSealMatchesExpected'])

    def test_changed_pause_reports_before_rootfs_read(self):
        self.mode='unpaused';v=m.observe()
        self.assertEqual(v['status'],'PAUSED_GENERATION_PREDICATES_REJECTED');self.assertEqual(v['fullRootfsPasses'],0)
        self.assertEqual(len(self.calls),1)

    def test_second_predecessor_extra_attempt_refused_without_get(self):
        self.write(self.successor/'engine-get-2.json',{'attempt':2})
        with self.assertRaisesRegex(ValueError,'PREDECESSOR_DIAGNOSTIC_HAS_OTHER_ATTEMPTS'):m.observe()
        self.assertEqual(self.calls,[])

    def test_after_scan_generation_drift_cannot_publish_success(self):
        self.mode='changed'
        with self.assertRaisesRegex(ValueError,'PAUSED_CONTAINER_CHANGED_DURING_ROOTFS_READ'):m.observe()
        self.assertEqual(len(self.calls),2)
        self.assertFalse(list(self.root.glob('semantic-registry-rootfs-complete-*/rootfs-manifest.json')))

    def test_changed_image_content_is_fully_retained_but_never_substituted_for_expected(self):
        oci=json.loads(self.bundle.read_bytes());(Path(oci['root']['path'])/'app.jar').write_bytes(b'changed image payload')
        v=m.observe();self.assertFalse(v['rootfsSealMatchesExpected']);self.assertFalse(v['releaseAcceptance'])
        manifest=json.loads(Path(v['privateManifestPath']).read_bytes())
        self.assertNotEqual(manifest['observedRootfsSeal'],manifest['expectedRootfsSeal'])
        self.assertTrue(manifest['diagnosticOnly'])

    def test_oci_change_during_full_scan_rejected_even_after_container_matches(self):
        real=m.sealed_rows
        def changing(*args):
            result=real(*args);oci=json.loads(self.bundle.read_bytes());oci['annotations']={'changed':'yes'}
            self.write(self.bundle,oci);return result
        with patch.object(m,'sealed_rows',changing),self.assertRaisesRegex(ValueError,'FULL_OCI_CHANGED_DURING_ROOTFS_READ'):m.observe()
        self.assertEqual(len(self.calls),2)

    def test_metadata_phase_deadline_does_not_count_rootfs_scan_time_or_reset_aggregate(self):
        readers=[];real_reader=m.KeepingReader;real_scan=m.sealed_rows
        def keeping(b):
            r=real_reader(b);readers.append(r);return r
        def scan(*args):
            v=real_scan(*args);readers[0].until=-1;return v
        with patch.object(m,'KeepingReader',keeping),patch.object(m,'sealed_rows',scan):v=m.observe()
        self.assertEqual(len(readers),2)
        self.assertEqual(v['metadataReads'],sum(r.reads for r in readers))
        self.assertEqual(v['metadataBytesRead'],sum(r.bytes for r in readers))
        self.assertEqual(v['combinedDiagnosticEngineGets'],4)


if __name__=='__main__':unittest.main()
