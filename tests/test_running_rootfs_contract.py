"""Frozen-image PerfData bytes and adversarial rootfs projections; no target IO."""
import base64,copy,hashlib,json,os,sys,tempfile,unittest,zlib
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.chatbot_file_cohort import running_rootfs as r
from tools.chatbot_file_cohort.plan import PlanDenied
F=json.loads((ROOT/'tests/fixtures/running-rootfs-ci-20261016.json').read_text())
RAW=zlib.decompress(base64.b64decode(F['perfDataZlibBase64']))

class RunningRootfs(unittest.TestCase):
    def setUp(self):
        self.baseline={'':{'path':'','kind':'directory','mode':0o755,'uid':0,'gid':0,'links':2,'xattrs':{}},
            'app/application.jar':{'path':'app/application.jar','kind':'file','mode':0o444,'uid':0,'gid':0,'links':1,'size':123,'sha256':'a'*64,'xattrs':{}}}
        self.expected=r.replay(self.baseline);self.records={**copy.deepcopy(self.baseline),**copy.deepcopy(F['additions'])}
    def test_original_ci_bytes_and_qualified_schema(self):
        self.assertEqual(hashlib.sha256(RAW).hexdigest(),F['perfDataSha256'])
        schema,values=r.perfdata(RAW);self.assertEqual(len(schema),193);r.verify_perf_schema(schema,values)
    def test_exact_eight_entries_retain_original_seal(self):
        shape=r.immutable_projection(self.records,self.expected);self.assertEqual(len(shape),8)
        self.assertNotIn('sha256',shape[r.PERF_PATH])
    def test_unknown_file_anywhere_is_not_excluded(self):
        for path in ['tmp/unexpected','tmp/hsperfdata_ouf/2','app/unexpected']:
            bad=copy.deepcopy(self.records);bad[path]={**self.baseline['app/application.jar'],'path':path}
            with self.subTest(path=path),self.assertRaisesRegex(PlanDenied,'ORIGINAL_IMAGE_SEAL_DRIFT'):r.immutable_projection(bad,self.expected)
    def test_extra_tomcat_tree_denied(self):
        bad=copy.deepcopy(self.records);key=next(k for k in bad if k.startswith('tmp/tomcat.'))
        bad['tmp/tomcat.8080.1']={**bad[key],'path':'tmp/tomcat.8080.1'}
        with self.assertRaisesRegex(PlanDenied,'EXACT_TOMCAT_ROOTS'):r.immutable_projection(bad,self.expected)
    def test_original_content_metadata_link_or_absence_denied(self):
        for field,value in [('sha256','b'*64),('mode',0o777),('uid',10001),('links',2),('xattrs',{'user.x':'00'})]:
            bad=copy.deepcopy(self.records);bad['app/application.jar'][field]=value
            with self.subTest(field=field),self.assertRaisesRegex(PlanDenied,'ORIGINAL_IMAGE_SEAL_DRIFT'):r.immutable_projection(bad,self.expected)
        del bad['app/application.jar']
        with self.assertRaises(PlanDenied):r.immutable_projection(bad,self.expected)
    def test_runtime_metadata_type_size_and_links_denied(self):
        for field,value in [('kind','symlink'),('mode',0o644),('uid',0),('gid',0),('links',2),('size',32769),('xattrs',{'user.x':'00'})]:
            bad=copy.deepcopy(self.records);bad[r.PERF_PATH][field]=value
            with self.subTest(field=field),self.assertRaisesRegex(PlanDenied,'PERFDATA_SHAPE'):r.immutable_projection(bad,self.expected)
    def test_runtime_directory_change_or_absence_denied(self):
        for path,item in F['additions'].items():
            if item['kind']!='directory':continue
            bad=copy.deepcopy(self.records);bad[path]['mode']=0o777
            with self.subTest(path=path),self.assertRaises(PlanDenied):r.immutable_projection(bad,self.expected)
            del bad[path]
            with self.assertRaises(PlanDenied):r.immutable_projection(bad,self.expected)
    def test_perf_header_size_counts_and_trailing_data_denied(self):
        for start,data in [(0,b'NOPE'),(4,b'\0'),(7,b'\0'),(8,(32769).to_bytes(4,'little')),
                           (12,b'\1'),(24,b'\0'),(28,(513).to_bytes(4,'little')),(32767,b'\1')]:
            bad=bytearray(RAW);bad[start:start+len(data)]=data
            with self.subTest(start=start),self.assertRaises(PlanDenied):r.perfdata(bytes(bad))
        with self.assertRaises(PlanDenied):r.perfdata(RAW[:-1])
    def test_perf_entry_invalid_offsets_type_and_padding_denied(self):
        for offset,value in [(32,0),(36,19),(40,2049),(48,20)]:
            bad=bytearray(RAW);bad[offset:offset+4]=value.to_bytes(4,'little')
            with self.subTest(offset=offset),self.assertRaises(PlanDenied):r.perfdata(bytes(bad))
        for offset,value in [(44,ord('X')),(45,3),(46,0),(47,0)]:
            bad=bytearray(RAW);bad[offset]=value
            with self.assertRaises(PlanDenied):r.perfdata(bytes(bad))
    def test_counter_change_is_allowed_and_does_not_change_schema(self):
        bad=bytearray(RAW);data=32+int.from_bytes(RAW[48:52],'little');bad[data:data+8]=(1234567).to_bytes(8,'little')
        schema,values=r.perfdata(bytes(bad));r.verify_perf_schema(schema,values)
    def test_new_counter_name_and_changed_constant_denied(self):
        bad=RAW.replace(b'sun.rt._sync_Inflations',b'sun.rt._sync_Xnflations')
        schema,values=r.perfdata(bad)
        with self.assertRaisesRegex(PlanDenied,'QUALIFIED_SCHEMA'):r.verify_perf_schema(schema,values)
        schema,values=r.perfdata(RAW);values['java.rt.vmArgs']=b'-javaagent:unexpected'
        with self.assertRaisesRegex(PlanDenied,'QUALIFIED_CONSTANTS'):r.verify_perf_schema(schema,values)
    def test_wrong_java_command_denied(self):
        bad=RAW.replace(b'/app/application.jar',b'/app/unqualified.jar')
        with self.assertRaisesRegex(PlanDenied,'APPLICATION_DRIFT'):r.perfdata(bad)
    def test_complete_double_scan_requires_same_runtime_inode(self):
        schema,values=r.perfdata(RAW)
        with patch.object(r,'capture',return_value=(r.replay(self.records),self.records))as scan,patch.object(r,'mapped_file',side_effect=[(schema,values,(1,2)),(schema,values,(1,3))]):
            with self.assertRaisesRegex(PlanDenied,'RUNTIME_IDENTITY_CHANGED'):r.observe(Path('/fixture'),{},object(),self.expected,42)
            self.assertEqual(scan.call_count,2)
    def test_complete_double_scan_returns_no_contents_or_paths(self):
        schema,values=r.perfdata(RAW)
        with patch.object(r,'capture',return_value=(r.replay(self.records),self.records)),patch.object(r,'mapped_file',return_value=(schema,values,(1,2))):
            proof=r.observe(Path('/fixture'),{},object(),self.expected,42)
        self.assertTrue(proof['originalSealUnchanged']);self.assertNotIn('hsperfdata',json.dumps(proof));self.assertFalse(proof['runtimeAuthorityIssued'])
    def test_capture_uses_original_sealer_without_global_modification(self):
        from tools.semantic_provider_node_observation import rootfs_seal
        original=rootfs_seal.__globals__['encoded']
        with tempfile.TemporaryDirectory(dir=ROOT)as directory:
            path=Path(directory);path.chmod(0o700);(path/'sample').write_bytes(b'public test')
            class Budget:
                def check(self):pass
            seal,records=r.capture(path,{'maxEntries':100,'maxBytes':1000,'maxDepth':8},Budget())
            self.assertEqual(seal,r.replay(records));self.assertIn('sample',records)
            self.assertIs(rootfs_seal.__globals__['encoded'],original)

if __name__=='__main__':unittest.main()
