"""Actual six-stage producer lineage and thirteen distinct Docker29 image GETs."""
import json,os,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import qualify_m2_retained_views_native as fixture
from tools.m2_discovery_installation_profile import retained_image_capture as m


class NativePrivateImages(unittest.TestCase):
    fixture_per_role_images=True
    @classmethod
    def setUpClass(cls):
        fixture.NativeViews.setUpClass.__func__(cls)
        views=cls.views
        selected={**views.view_case,'viewCandidatePath':str(views.view_path),
            'viewCandidateHash':views.view_bindings['candidateHash'],'viewResultHash':views.view_bindings['resultHash']}
        for name,value in {'CASE':selected,'ROSTER':cls.args['roster']}.items():
            context=patch.object(m,name,value);context.start();cls.addClassCleanup(context.stop)

    def test_a_actual_full_lineage_and_thirteen_image_archives_without_mounted_content_or_lifecycle(self):
        c=m.ImageCapture(self.root/'actual-private-images');opened=[];original=os.open
        allowed={str(Path(m.CASE[k])) for k in ('candidatePath','resultPath','seedPath','viewCandidatePath')}
        allowed.add(str(Path(m.CASE['viewCandidatePath']).parent/'result.json'))
        def closed(path,flags,*args,**kwargs):
            if not flags&(os.O_DIRECTORY|os.O_PATH|os.O_WRONLY|os.O_RDWR):
                self.assertIn(str(path),allowed);opened.append(str(path))
            return original(path,flags,*args,**kwargs)
        with patch.object(os,'open',side_effect=closed):result=m.collect(c)
        c.put('result.json',result)
        self.assertEqual(result['counts']['engineGets'],13);self.assertEqual(result['counts']['imageArchivesCaptured'],13)
        self.assertEqual(result['cumulativeDirectEngineGets'],35);self.assertEqual(result['cumulativeControlAttempts'],7)
        self.assertTrue(result['allSixPriorScopesPreserved']);self.assertEqual(len(opened),5)
        self.assertEqual(result['counts']['credentialFileReads'],0);self.assertEqual(result['counts']['mountFileContentBytesRead'],0)
        self.assertFalse(result['nativeIdentityAndSourceAdmissionEstablished']);self.assertFalse(result['targetApplyAuthorized'])
        record=json.loads((c.scope/'native-image-archives.private.json').read_bytes());self.assertEqual(len(record['archives']),13)
        import hashlib,tarfile
        for row in record['archives'].values():
            path=c.scope/row['filename'];self.assertEqual(path.stat().st_mode&0o777,0o400)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),row['sha256'])
            with tarfile.open(path) as archive:self.assertIn('manifest.json',archive.getnames())
        public=json.dumps(result)
        for value in ('SYNTHETIC_STATIC_PRIVATE_VALUE','SYNTHETIC_LIVE_TOKEN','NEVER_EMIT_CONFIG_ENV',str(self.root)):
            self.assertNotIn(value,public)
        with self.assertRaisesRegex(ValueError,'CONSUMED_NO_REPLAY'):m.ImageCapture(c.scope)
        self.assertEqual(json.loads((c.scope/'result.json').read_bytes()),result)

    def test_b_changed_view_receipt_denies_before_any_image_get_and_preserves_partial_scope(self):
        path=self.views.view_path.parent/'result.json';raw=path.read_bytes()
        try:
            path.write_bytes(b'{}');c=m.ImageCapture(self.root/'changed-private-view')
            with self.assertRaises((ValueError,KeyError)):m.collect(c)
            self.assertEqual(c.counts['engineGets'],0);self.assertFalse((c.scope/'native-image-archives.private.json').exists())
        finally:path.write_bytes(raw)

    def test_c_changed_engine_root_generation_denies_without_image_get(self):
        c=m.ImageCapture(self.root/'changed-engine')
        with patch.object(m,'process_pin',return_value={}),self.assertRaisesRegex(ValueError,'ROOT_PROCESS'):m.collect(c)
        self.assertEqual(c.counts['engineGets'],0)


if __name__=='__main__':unittest.main()
