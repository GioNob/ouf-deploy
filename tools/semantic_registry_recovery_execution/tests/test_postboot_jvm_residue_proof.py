"""Exact transcript proof and plan-only retained-file IO; never live cleanup."""
import copy,hashlib,importlib.util,json
from pathlib import Path
import unittest
from unittest.mock import patch
import test_postboot_root_binding_metadata as f

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('jvm_residue_proof',ROOT/'scripts/prove-registry-jvm-residue-20261023.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def digest_rows(rows):
    h=hashlib.sha256(b'OUF-ROOTFS-SEAL\x00V1\x00')
    for row in rows:
        raw=json.dumps(row,sort_keys=True,separators=(',',':'),allow_nan=False).encode();h.update(len(raw).to_bytes(4,'big'));h.update(raw)
    return {'schema':'ouf.semantic-rootfs-seal.v1','sha256':h.hexdigest(),'entries':len(rows),'bytes':sum(row.get('size',0) for row in rows)}


def sample():
    def directory(p,links=2,mode=0o755,uid=0,gid=0):return {'path':p,'kind':'directory','links':links,'mode':mode,'uid':uid,'gid':gid,'xattrs':{}}
    app={'path':'app.jar','kind':'file','links':1,'mode':0o444,'uid':0,'gid':0,'size':7,'sha256':hashlib.sha256(b'payload').hexdigest(),'xattrs':{}}
    baseline=[directory('',3),app,directory('tmp',2,0o1777)]
    root='tmp/tomcat.9555.123456'
    observed=[directory('',3),app,directory('tmp',4,0o1777),directory('tmp/hsperfdata_ouf',uid=10001,gid=10001),
        directory(root,3,0o700,10001,10001),directory(root+'/work',3,0o755,10001,10001),
        directory(root+'/work/Tomcat',3,0o755,10001,10001),directory(root+'/work/Tomcat/localhost',3,0o755,10001,10001),
        directory(root+'/work/Tomcat/localhost/ROOT',2,0o755,10001,10001)]
    manifest={'schema':'ouf.rootfs-diagnostic-manifest.v1','authorityHash':m.base_module().AUTHORITY_HASH,'diagnosticOnly':True,
        'entries':observed,'expectedRootfsSeal':digest_rows(baseline),'observedRootfsSeal':digest_rows(observed)}
    return manifest,{'User':'10001:10001'},{'health':{'port':9555}}


class Proof(unittest.TestCase):
    def setUp(self):self.manifest,self.request,self.readiness=sample();self.b=m.base_module()

    def test_exact_six_jvm_directories_and_tmp_link_delta_restore_independent_tuple(self):
        before=copy.deepcopy(self.manifest);v=m.prove(self.b,self.manifest,self.request,self.readiness)
        self.assertEqual(v['matchingRules'],['subtract-removed-directories']);self.assertEqual(len(v['paths']),6)
        self.assertIn('tmp/tomcat.9555.123456',v['paths']);self.assertEqual(v['paths'][0],'tmp/tomcat.9555.123456/work/Tomcat/localhost/ROOT')
        self.assertEqual(before,self.manifest)

    def test_changed_existing_file_cannot_be_hidden_by_cleanup_variant(self):
        self.manifest['entries'][1]['sha256']='b'*64;self.manifest['observedRootfsSeal']=digest_rows(self.manifest['entries'])
        self.assertEqual(m.prove(self.b,self.manifest,self.request,self.readiness)['matchingRules'],[])

    def test_file_in_residue_subtree_is_refused_even_when_empty(self):
        row=copy.deepcopy(self.manifest['entries'][1]);row.update(path=self.manifest['entries'][-1]['path']+'/data',size=0)
        self.manifest['entries'].append(row)
        with self.assertRaisesRegex(ValueError,'JVM_RESIDUE_SUBTREE_CONTAINS_OTHER_ENTRIES'):m.prove(self.b,self.manifest,self.request,self.readiness)

    def test_wrong_port_owner_xattrs_and_second_tomcat_tree_cannot_be_adopted(self):
        with self.assertRaisesRegex(ValueError,'EXACT_SINGLE_HISTORICAL_JVM_RESIDUE_REQUIRED'):
            m.prove(self.b,self.manifest,self.request,{'health':{'port':9556}})
        for field,value in [('uid',0),('xattrs',{'user.unknown':'00'}),('mode',0o777)]:
            changed=copy.deepcopy(self.manifest);changed['entries'][3][field]=value
            with self.assertRaisesRegex(ValueError,'EXACT_NONSECRET_JVM_DIRECTORY_METADATA_REQUIRED'):m.prove(self.b,changed,self.request,self.readiness)
        extra=copy.deepcopy(self.manifest['entries'][4]);extra['path']='tmp/tomcat.9555.789';self.manifest['entries'].append(extra)
        with self.assertRaisesRegex(ValueError,'EXACT_SINGLE_HISTORICAL_JVM_RESIDUE_REQUIRED'):m.prove(self.b,self.manifest,self.request,self.readiness)

    def test_original_manifest_hash_mismatch_is_refused(self):
        self.manifest['entries'][1]['mode']=0
        with self.assertRaisesRegex(ValueError,'COMPLETE_RETAINED_NATIVE_SEAL_REQUIRED'):m.prove(self.b,self.manifest,self.request,self.readiness)


class Metadata(unittest.TestCase):
    write=f.RootBinding.write
    refresh=f.RootBinding.refresh
    def setUp(self):
        f.RootBinding.setUp(self);self.manifest,request,readiness=sample()
        prepared=json.loads((self.prep/'prepared.json').read_bytes())
        prepared['nativeContext']['nodeRecipe']['expectedRootfsSeal']=self.manifest['expectedRootfsSeal']
        prepared['registryInputs']['creationRequest'].update(request);prepared['registryInputs']['readinessScope']=readiness
        self.write(self.prep/'prepared.json',prepared)
        review=json.loads((self.prep/'review.json').read_bytes());review['currentContext']=prepared['nativeContext'];self.write(self.prep/'review.json',review)
        receipt=json.loads((self.prep/'authority/receipt.json').read_bytes());receipt['reviewHash']=self.b.digest(review);self.write(self.prep/'authority/receipt.json',receipt)
        root=self.root/'complete';root.mkdir();self.write(root/'rootfs-manifest.json',self.manifest)
        comparison={'manifestHash':self.b.digest(self.manifest),'differences':[{'path':p,'observed':{'kind':'file','size':0,'uid':0,'gid':0}}
            for p in ('etc/hostname','etc/hosts','etc/resolv.conf')]}
        archive=self.root/'comparison';archive.mkdir();self.write(archive/'comparison.json',comparison)
        for name,value in {'PREPARATION_HASH':self.b.digest(prepared),'REVIEW_HASH':self.b.digest(review)}.items():
            p=patch.object(self.b,name,value);p.start();self.addCleanup(p.stop)
        real=Path
        for name,value in {'base_module':lambda:self.b,'MANIFEST_HASH':self.b.digest(self.manifest),'MANIFEST_ROOT':'complete',
            'COMPARISON_ROOT':'comparison','COMPARISON_HASH':self.b.digest(comparison),
            'Path':lambda v:self.bootfile if v=='/proc/sys/kernel/random/boot_id' else real(v)}.items():
            p=patch.object(m,name,value);p.start();self.addCleanup(p.stop)

    def test_complete_private_cleanup_plan_is_not_runtime_authority_or_cleanup(self):
        files=list(self.root.rglob('*.json'));before={p:p.read_bytes() for p in files}
        v=m.inspect();self.assertTrue(v['expectedSealRestoredByRemovingOnlySixDirectories']);self.assertTrue(v['cleanupPlanPrepared'])
        self.assertFalse(v['targetApplyAuthorized']);self.assertFalse(v['runtimeAuthorityIssued']);self.assertEqual(v['runtimeEffectsDispatched'],0)
        plan=Path(v['privateCleanupPlanPath']);self.assertEqual(hashlib.sha256(plan.read_bytes()).hexdigest(),v['privateCleanupPlanHash'])
        p=json.loads(plan.read_bytes());self.assertEqual(p['grantAttemptAllowance'],0);self.assertFalse(p['recursiveRemovalAllowed'])
        self.assertFalse(p['expectedSealMayBeReplaced']);self.assertTrue(p['requiresFreshPausedGenerationAndFullSealBeforeApply'])
        self.assertEqual(before,{p:p.read_bytes() for p in files});self.assertEqual(self.calls,[])
        with self.assertRaisesRegex(ValueError,'JVM_RESIDUE_PROOF_ALREADY_RETAINED'):m.inspect()

    def test_counterfactual_mismatch_does_not_prepare_cleanup_plan(self):
        self.manifest['entries'][1]['sha256']='b'*64;self.manifest['observedRootfsSeal']=digest_rows(self.manifest['entries'])
        path=self.root/'complete/rootfs-manifest.json';self.write(path,self.manifest)
        comparison=json.loads((self.root/'comparison/comparison.json').read_bytes());comparison['manifestHash']=self.b.digest(self.manifest)
        self.write(self.root/'comparison/comparison.json',comparison)
        with patch.object(m,'MANIFEST_HASH',self.b.digest(self.manifest)),patch.object(m,'COMPARISON_HASH',self.b.digest(comparison)):
            v=m.inspect()
        self.assertFalse(v['cleanupPlanPrepared']);self.assertIsNone(v['privateCleanupPlanPath'])
        self.assertFalse(list(self.root.glob('semantic-registry-jvm-residue-*/cleanup-plan.json')))


if __name__=='__main__':unittest.main()
