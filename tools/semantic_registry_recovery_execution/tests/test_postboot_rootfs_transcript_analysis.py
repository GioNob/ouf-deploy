"""Pinned transcript-only IO; synthetic expected/image manifests, no live rootfs."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import test_postboot_root_binding_metadata as f

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('rootfs_transcript_analysis',ROOT/'scripts/analyze-registry-rootfs-transcript-20261023.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def sample():
    def directory(p,links=2):return {'path':p,'kind':'directory','mode':493,'uid':0,'gid':0,'links':links,'xattrs':{}}
    def file(p,data):return {'path':p,'kind':'file','mode':420,'uid':0,'gid':0,'links':1,'xattrs':{},'size':len(data),'sha256':hashlib.sha256(data).hexdigest()}
    baseline=[directory('',3),file('app',b'payload'),directory('run')]
    actual=[directory('',3),file('.dockerenv',b''),file('app',b'payload'),directory('run',3),directory('run/ouf',4),
        file('run/ouf/delegation',b''),directory('run/ouf/password'),file('run/ouf/proposal',b''),directory('run/ouf/token')]
    mounts=['/run/ouf/delegation','/run/ouf/proposal','/run/ouf/password','/run/ouf/token']
    return baseline,actual,mounts


def independent(rows):
    h=hashlib.sha256(b'OUF-ROOTFS-SEAL\x00V1\x00')
    for item in rows:
        raw=json.dumps(item,sort_keys=True,separators=(',',':'),allow_nan=False).encode();h.update(len(raw).to_bytes(4,'big'));h.update(raw)
    return {'schema':'ouf.semantic-rootfs-seal.v1','sha256':h.hexdigest(),'entries':len(rows),'bytes':sum(r.get('size',0) for r in rows)}


class Algorithm(unittest.TestCase):
    def setUp(self):self.b=m.base_module();self.baseline,self.actual,self.mounts=sample()

    def test_six_zero_byte_scaffold_entries_and_parent_links_exactly_explain_independent_seal(self):
        v=m.analyze(self.b,self.actual,independent(self.baseline),independent(self.actual),self.mounts,m.Work())
        self.assertTrue(v['searchComplete']);self.assertEqual(len(v['matchingVariants']),1)
        self.assertEqual(v['matchingVariants'][0]['directoryLinkRule'],'subtract-removed-directories')
        self.assertEqual(len(v['matchingVariants'][0]['removedPaths']),6)
        self.assertTrue(v['variantDoesNotGrantAcceptance']);self.assertTrue(v['hypothesisIsNotRuntimeProvenance'])

    def test_equal_byte_count_does_not_hide_changed_existing_file_content(self):
        actual=copy.deepcopy(self.actual);actual[2]['sha256']=hashlib.sha256(b'changed').hexdigest()
        v=m.analyze(self.b,actual,independent(self.baseline),independent(actual),self.mounts,m.Work())
        self.assertEqual(v['matchingVariants'],[])

    def test_nonempty_file_or_unrelated_path_cannot_be_excluded(self):
        rows={x['path']:x for x in self.actual};rows['run/ouf/token/secret']={**rows['app'],'path':'run/ouf/token/secret'}
        options=m.candidates(rows,self.mounts)
        self.assertNotIn('run/ouf/token',options);self.assertNotIn('run/ouf',options)
        self.assertNotIn('app',options)

    def test_corrupted_transcript_refused(self):
        observed=independent(self.actual);self.actual[2]['mode']=0
        with self.assertRaisesRegex(ValueError,'COMPLETE_NATIVE_TRANSCRIPT_SEAL_MISMATCH'):
            m.analyze(self.b,self.actual,independent(self.baseline),observed,self.mounts,m.Work())

    def test_hash_and_variant_limits_produce_explicit_partial_search(self):
        with patch.object(m,'MAX_VARIANTS',0):
            v=m.analyze(self.b,self.actual,independent(self.baseline),independent(self.actual),self.mounts,m.Work())
        self.assertFalse(v['searchComplete']);self.assertEqual(v['matchingVariants'],[])
        work=m.Work();work.until=-1
        with self.assertRaisesRegex(ValueError,'TRANSCRIPT_ANALYSIS_WORK_BOUND'):
            m.analyze(self.b,self.actual,independent(self.baseline),independent(self.actual),self.mounts,work)


class Metadata(unittest.TestCase):
    write=f.RootBinding.write
    refresh=f.RootBinding.refresh
    def setUp(self):
        f.RootBinding.setUp(self);self.baseline,self.actual,self.mounts=sample()
        prepared=json.loads((self.prep/'prepared.json').read_bytes())
        prepared['nativeContext']['nodeRecipe']['expectedRootfsSeal']=independent(self.baseline)
        prepared['registryInputs']['creationRequest']['HostConfig']['Binds']=['/reviewed/source'+str(n)+':'+p+':ro' for n,p in enumerate(self.mounts)]
        review=json.loads((self.prep/'review.json').read_bytes());review['currentContext']=prepared['nativeContext']
        self.write(self.prep/'prepared.json',prepared);self.write(self.prep/'review.json',review)
        receipt=json.loads((self.prep/'authority/receipt.json').read_bytes());receipt['reviewHash']=self.b.digest(review)
        self.write(self.prep/'authority/receipt.json',receipt)
        for name,value in {'PREPARATION_HASH':self.b.digest(prepared),'REVIEW_HASH':self.b.digest(review)}.items():
            p=patch.object(self.b,name,value);p.start();self.addCleanup(p.stop)
        identity={'authorityHash':self.b.AUTHORITY_HASH,'operation':self.journal['logicalOperationRef'],'boot':self.boot,'purpose':'PAUSED_ROOTFS_COMPLETE_OBSERVATION_V1'}
        name='semantic-registry-rootfs-complete-'+self.b.digest(identity);self.completed=self.root/name;self.completed.mkdir(mode=0o700)
        manifest={'schema':'ouf.rootfs-diagnostic-manifest.v1','authorityHash':self.b.AUTHORITY_HASH,'expectedRootfsSeal':independent(self.baseline),
            'observedRootfsSeal':independent(self.actual),'entries':self.actual,'diagnosticOnly':True}
        self.write(self.completed/'rootfs-manifest.json',manifest)
        sha=self.b.digest(manifest)
        self.write(self.completed/'observation.json',{'schema':'ouf.semantic-registry-paused-rootfs-complete-observation.v1','status':'PAUSED_ROOTFS_OBSERVED',
            'privateManifestHash':sha,'combinedDiagnosticEngineGets':4,'fullRootfsPasses':1,'samePausedGenerationBeforeAndAfter':True,
            'fullPausedOciMatchesRetainedFrame':True,'rootfsSealMatchesExpected':False})
        real=Path
        for name,value in {'base_module':lambda:self.b,'MANIFEST_HASH':sha,'MANIFEST_ROOT':name,
            'Path':lambda v:self.bootfile if v=='/proc/sys/kernel/random/boot_id' else real(v)}.items():
            p=patch.object(m,name,value);p.start();self.addCleanup(p.stop)

    def test_pinned_private_manifest_analyzed_without_engine_or_old_writes_and_no_replay(self):
        paths=list(self.completed.iterdir())+[self.prep/'prepared.json',self.prep/'review.json',self.execution/'recovery.json',self.ownerroot/'recovery.json']
        before={p:p.read_bytes() for p in paths}
        v=m.inspect();self.assertTrue(v['sixEntryScaffoldVariantMatchesExpected']);self.assertEqual(v['distinctMatchingEntrySets'],1)
        self.assertEqual(v['engineGets'],0);self.assertEqual(v['priorDiagnosticEngineGets'],4)
        self.assertFalse(v['liveRootfsContentsRead']);self.assertEqual(self.calls,[])
        self.assertEqual(before,{p:p.read_bytes() for p in paths})
        self.assertNotIn('/run/ouf',json.dumps(v));self.assertNotIn('/reviewed/source',json.dumps(v))
        analysis=Path(v['privateAnalysisPath']);self.assertEqual(hashlib.sha256(analysis.read_bytes()).hexdigest(),v['privateAnalysisHash'])
        with self.assertRaisesRegex(ValueError,'TRANSCRIPT_ANALYSIS_ALREADY_CONSUMED'):m.inspect()

    def test_tampered_manifest_not_adopted(self):
        manifest=json.loads((self.completed/'rootfs-manifest.json').read_bytes());manifest['entries'][0]['uid']=123
        self.write(self.completed/'rootfs-manifest.json',manifest)
        with self.assertRaisesRegex(ValueError,'METADATA_HASH_OR_BYTE_BOUND'):m.inspect()
        self.assertEqual(self.calls,[])


if __name__=='__main__':unittest.main()
