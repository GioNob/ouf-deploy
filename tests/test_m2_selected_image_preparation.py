"""Real archive/files/custody; only native Engine profile reads are modeled."""
import copy,hashlib,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),
    str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_lease_recovery'),
    str(ROOT/'tools/semantic_frame_compiler'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from test_chatbot_cohort_image_identity import tiny_archive
from tools.m2_discovery_installation_profile import selected_image_preparation as m


class Preparation(unittest.TestCase):
    def fixture(self,wrong_user=False):
        temporary=tempfile.TemporaryDirectory(dir=ROOT,prefix='selected-image-preparation-test-');self.addCleanup(temporary.cleanup)
        root=Path(temporary.name);root.chmod(0o700);output=root/'output';output.mkdir(mode=0o700)
        inputs={}
        for module,user,marker in (('semantic','10001:10001','a'),('mcp','10005:10005','b')):
            source=root/(module+'.source.tar')
            audit=tiny_archive(source,source=marker*40,user='65534:65534' if wrong_user and module=='mcp' else user)
            inputs[module]={'archivePath':str(source),'archiveSha256':audit['archiveSha256'],
                'imageId':audit['imageId'],'sourceCommit':audit['sourceCommit'],'modulePackageHash':marker*64}
        info={'ServerVersion':'29.8.1','Driver':'overlayfs','DriverStatus':[['driver-type','io.containerd.snapshotter.v1']],
            'CgroupDriver':'systemd'};calls=[];engine=object.__new__(m.Engine)
        def request(method,path,body=None):
            self.assertEqual((method,path,body),('GET','/v1.44/info',None));calls.append((method,path))
            return 200,copy.deepcopy(info)
        engine.request=request
        return {'inputs':inputs,'output_directory':output,'engine':engine},info,calls

    def test_prepare_two_archives_read_reconcile_and_never_load_or_overwrite(self):
        args,_,calls=self.fixture();receipt=m.prepare_archives(**args)
        original={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in args['output_directory'].iterdir()}
        self.assertEqual(m.read_prepared_archives(**args),receipt)
        self.assertEqual([r['module'] for r in receipt['images']],['semantic','mcp'])
        self.assertTrue(all(r['audit']['repositoryTags']==[] and 'nativeIdentity' in r['audit'] for r in receipt['images']))
        self.assertEqual(receipt['imageLoads'],0);self.assertFalse(receipt['publisherTrustAccepted'])
        with self.assertRaises(FileExistsError):m.prepare_archives(**args)
        self.assertEqual({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in args['output_directory'].iterdir()},original)
        self.assertTrue(calls and all(method=='GET' for method,_ in calls))

    def test_partial_second_write_cannot_be_finished_or_restarted_automatically(self):
        args,_,_=self.fixture();real=m.tagless_archive;count=0
        def fail_second(*a,**kw):
            nonlocal count
            count+=1
            if count==2:raise OSError('SYNTHETIC_PARTIAL_SECOND_ARCHIVE')
            return real(*a,**kw)
        with patch.object(m,'tagless_archive',side_effect=fail_second):
            with self.assertRaises(OSError):m.prepare_archives(**args)
        root=args['output_directory'];first=(root/'semantic.tagless.tar').read_bytes()
        self.assertTrue(first);self.assertEqual((root/'mcp.tagless.tar').stat().st_size,0)
        with self.assertRaises(FileNotFoundError):m.read_prepared_archives(**args)
        with self.assertRaises(FileExistsError):m.prepare_archives(**args)
        self.assertEqual((root/'semantic.tagless.tar').read_bytes(),first)
        self.assertFalse((root/'prepared-images.json').exists())

    def test_changed_original_or_prepared_bytes_each_deny_read_reconciliation(self):
        for kind in ('original','prepared'):
            args,_,_=self.fixture();m.prepare_archives(**args)
            path=Path(args['inputs']['mcp']['archivePath']) if kind=='original' else args['output_directory']/'mcp.tagless.tar'
            path.write_bytes(b'CHANGED_ARCHIVE')
            with self.assertRaisesRegex(ValueError,'AUTHENTICATED_ARCHIVE_BYTES_CHANGED'):m.read_prepared_archives(**args)

    def test_native_store_or_selected_package_hash_drift_does_not_adopt_completed_output(self):
        for kind in ('engine','package'):
            args,info,_=self.fixture();m.prepare_archives(**args)
            if kind=='engine':info.update(Driver='overlay2',DriverStatus=[])
            else:args['inputs']['mcp']['modulePackageHash']='f'*64
            with self.assertRaisesRegex(ValueError,'EXACT_COMPLETED_SELECTED_IMAGE_PREPARATION_REQUIRED'):
                m.read_prepared_archives(**args)

    def test_wrong_module_user_is_not_accepted_as_a_native_archive(self):
        args,_,_=self.fixture(wrong_user=True)
        with self.assertRaisesRegex(ValueError,'EXACT_SELECTED_IMAGE_RUNTIME_USER_REQUIRED'):m.prepare_archives(**args)
        self.assertFalse((args['output_directory']/'prepared-images.json').exists())


if __name__=='__main__':unittest.main()
