"""Real retained-file IO; no Engine or image-rootfs-content operation."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import test_postboot_paused_rootfs_reconciliation as fixture

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('root_binding_metadata',ROOT/'scripts/inspect-registry-root-binding-20261023.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class RootBinding(unittest.TestCase):
    write=fixture.Cohort.write
    refresh=fixture.Cohort.refresh

    def setUp(self):
        fixture.Cohort.setUp(self)
        self.b=fixture.fixture.m
        p=patch.object(m,'base_module',lambda:self.b);p.start();self.addCleanup(p.stop)
        real=Path
        p=patch.object(m,'Path',side_effect=lambda v:self.bootfile if v=='/proc/sys/kernel/random/boot_id' else real(v));p.start();self.addCleanup(p.stop)
        identity=dict(self.predecessor_identity,purpose='PAUSED_ROOTFS_DIAGNOSTIC_RECONCILIATION_V1')
        path='/v1.44/containers/'+self.journal['newGeneration']['containerId']+'/json'
        predecessor,_=fixture.m.reconcile_predecessor(self.b,identity,path)
        self.successor=self.root/('semantic-registry-rootfs-reconciliation-'+self.b.digest(identity))
        self.successor.mkdir(mode=0o700)
        self.write(self.successor/'claim.json',{**identity,'predecessor':predecessor,'maximumEngineGets':2,
            'maximumCombinedDiagnosticEngineGets':3,'maximumFullRootfsPasses':1,'maximumSeconds':180,
            'retainedControlledGrantAttempts':320,'automaticReplayAllowed':False,'budgetReset':False})
        self.write(self.successor/'engine-get-1.json',{'attempt':1,'requestPathHash':self.b.digest(path)})
        self.write(self.successor/'stop.json',{'reasonCode':'SAME_HOST_IMAGE_AND_OCI_ROOT_REQUIRED','engineGets':1,'automaticReplayAllowed':False})
        self.write(self.successor/'resource-predicates.json',{'predicates':{k:True for k in ('containerIdentityMatches','imageIdentityMatches',
            'pidMatches','running','paused','notRestarting','notDead','reviewedRootfsFlagIsBoolean','currentRootfsFlagIsBoolean','rootfsFlagMatchesReviewed')},
            'reviewedRootfsReadOnly':True,'currentRootfsReadOnly':True})
        self.bundle=self.root/'bundles'/self.journal['newGeneration']['containerId']/'config.json'

    def test_exact_retained_shapes_classified_without_engine_or_any_old_write(self):
        selected=[p for p in self.root.rglob('*.json')]
        before={p:p.read_bytes() for p in selected}
        result=m.inspect()
        self.assertEqual(result['engineGets'],0);self.assertEqual(result['priorDiagnosticEngineGets'],2)
        self.assertEqual(result['remainingDiagnosticEngineGets'],1);self.assertEqual(result['metadataReads'],27)
        self.assertTrue(result['rootBinding']['rootPathLexicallyMatchesStorage'])
        self.assertTrue(result['rootBinding']['oldExplicitReadonlyPredicatePasses'])
        self.assertFalse(result['currentContainerStateObserved']);self.assertFalse(result['rootfsContentsRead'])
        self.assertEqual(self.calls,[]);self.assertEqual(before,{p:p.read_bytes() for p in selected})
        self.assertNotIn(str(self.root),json.dumps(result))

    def test_omitted_oci_false_classified_using_existing_frame_compiler_default(self):
        prepared=json.loads((self.prep/'prepared.json').read_bytes())
        prepared['registryInputs']['creationRequest']['HostConfig']['ReadonlyRootfs']=False
        self.write(self.prep/'prepared.json',prepared)
        p=patch.object(self.b,'PREPARATION_HASH',self.b.digest(prepared));p.start();self.addCleanup(p.stop)
        pred=json.loads((self.successor/'resource-predicates.json').read_bytes())
        pred.update(reviewedRootfsReadOnly=False,currentRootfsReadOnly=False);self.write(self.successor/'resource-predicates.json',pred)
        oci=json.loads(self.bundle.read_bytes());oci['root'].pop('readonly');self.write(self.bundle,oci)
        self.write(self.execution/'node/frame-policy.json',{'expectedOci':oci})
        result=m.inspect()['rootBinding']
        self.assertFalse(result['ociReadonlyKeyPresent']);self.assertFalse(result['oldExplicitReadonlyPredicatePasses'])
        self.assertTrue(result['ociReadonlyEffectiveMatchesReviewed']);self.assertFalse(result['ociReadonlyEffectiveValue'])
        self.assertEqual(self.calls,[])

    def test_full_oci_drift_refused_without_requests(self):
        oci=json.loads(self.bundle.read_bytes());oci['root']['readonly']=False;self.write(self.bundle,oci)
        with self.assertRaisesRegex(ValueError,'CURRENT_FULL_OCI_DIFFERS_FROM_RETAINED_FRAME'):m.inspect()
        self.assertEqual(self.calls,[])

    def test_extra_successor_attempt_refused_without_requests(self):
        self.write(self.successor/'engine-get-2.json',{'attempt':2})
        with self.assertRaisesRegex(ValueError,'DIAGNOSTIC_ATTEMPT_SET_CHANGED'):m.inspect()
        self.assertEqual(self.calls,[])

    def test_wrong_successor_stop_not_adopted(self):
        self.write(self.successor/'stop.json',{'reasonCode':'different','engineGets':1,'automaticReplayAllowed':False})
        with self.assertRaisesRegex(ValueError,'EXACT_SECOND_DIAGNOSTIC_STOP_REQUIRED'):m.inspect()
        self.assertEqual(self.calls,[])

    def test_paths_report_only_comparisons_and_optional_flag_types_are_distinguished(self):
        v=m.classify({'path':'rootfs/../rootfs'},'/reviewed/bundle/rootfs',Path('/reviewed/bundle'),False)
        self.assertFalse(v['rootPathLexicallyMatchesStorage']);self.assertTrue(v['rootPathNormalizedMatchesStorage'])
        self.assertTrue(v['ociReadonlyEffectiveMatchesReviewed'])
        v=m.classify({'path':'/different','readonly':0},'/reviewed/bundle/rootfs',Path('/reviewed/bundle'),False)
        self.assertFalse(v['rootPathNormalizedMatchesStorage']);self.assertFalse(v['ociReadonlyEffectiveBoolean'])
        self.assertIsNone(v['ociReadonlyEffectiveValue'])

    def test_symlinked_oci_metadata_refused(self):
        moved=self.bundle.with_name('saved');self.bundle.rename(moved);self.bundle.symlink_to(moved)
        with self.assertRaises(OSError):m.inspect()
        self.assertEqual(self.calls,[])


if __name__=='__main__':unittest.main()
