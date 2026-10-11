import copy,gzip,hashlib,importlib.util,io,json,tarfile,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('custody',Path(__file__).resolve().parents[1]/'tools/semantic_application_cutover/image_custody.py')
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
SOURCE='a'*40

def fixture(change=None,compressed=False,extra=None):
    layer=b'durable layer bytes';blob=gzip.compress(layer,mtime=0) if compressed else layer
    layer_name='blobs/sha256/'+hashlib.sha256(blob).hexdigest()
    config={'os':'linux','architecture':'amd64','config':{'User':'10001:10001','Env':['JAVA_HOME=/opt/java/openjdk'],'Labels':{'org.opencontainers.image.revision':SOURCE}},'rootfs':{'type':'layers','diff_ids':['sha256:'+hashlib.sha256(layer).hexdigest()]}}
    manifest={'Config':'config.json','RepoTags':None,'Layers':[layer_name]}
    if change:change(config,manifest)
    raw=json.dumps(config).encode();image='sha256:'+hashlib.sha256(raw).hexdigest();stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w') as tar:
        for name,data in [('config.json',raw),('manifest.json',json.dumps([manifest]).encode()),(layer_name,blob)]:
            row=tarfile.TarInfo(name);row.size=len(data);tar.addfile(row,io.BytesIO(data))
        if extra:extra(tar)
    archive=stream.getvalue()
    return archive,hashlib.sha256(archive).hexdigest(),image,config

def audit(data):return c.archive(io.BytesIO(data[0]),data[1],data[2],SOURCE)
def native(a):return {'Id':a['imageId'],'Os':'linux','Architecture':'amd64','Config':copy.deepcopy(a['imageConfig']),'RootFS':{'Type':'layers','Layers':[x['diffId'] for x in a['layers']]}}
class Custody(unittest.TestCase):
    def test_tagless_reenvelope_keeps_exact_config_and_layer_bytes(self):
        d=fixture(lambda conf,manifest:manifest.__setitem__('RepoTags',['unrelated:latest']))
        original=audit(d);output=io.BytesIO()
        result=c.tagless_archive(io.BytesIO(d[0]),output,original)
        derived=c.archive(output,result['derivedArchiveSha256'],d[2],SOURCE)
        self.assertEqual(derived['repositoryTags'],[])
        self.assertEqual(derived['imageConfig'],original['imageConfig']);self.assertEqual(derived['layers'],original['layers'])
        self.assertEqual(result['originalArchiveSha256'],d[1]);self.assertFalse(result['imageRebuilt']);self.assertFalse(result['newSignatureIssued'])
    def test_actual_layer_bytes_and_loaded_projection_for_raw_and_compressed_layers(self):
        for compressed in (False,True):
            with self.subTest(compressed=compressed):
                a=audit(fixture(compressed=compressed));result=c.loaded(a,native(a))
                self.assertTrue(result['imageByteCustodyProven']);self.assertFalse(result['targetApplyAuthorized'])
                self.assertNotIn('imageConfig',result);self.assertNotIn('Env',result)
    def test_archive_digest_and_config_identity_must_both_match(self):
        d=fixture()
        for tar_hash,image in [('0'*64,d[2]),(d[1],'sha256:'+'0'*64)]:
            with self.subTest(tar_hash=tar_hash,image=image),self.assertRaises(ValueError):c.archive(io.BytesIO(d[0]),tar_hash,image,SOURCE)
    def test_declared_diff_id_is_not_proof_of_layer_bytes(self):
        with self.assertRaisesRegex(ValueError,'ROOTFS_LAYER_BYTES_DRIFT'):audit(fixture(lambda conf,m:conf['rootfs']['diff_ids'].__setitem__(0,'sha256:'+'0'*64)))
    def test_source_platform_and_layer_cardinality_drifts_denied(self):
        for change in (lambda x,m:x.__setitem__('os','windows'),lambda x,m:x.__setitem__('architecture','arm64'),lambda x,m:x['config']['Labels'].__setitem__('org.opencontainers.image.revision','b'*40),lambda x,m:m['Layers'].append(m['Layers'][0]),lambda x,m:x['rootfs']['diff_ids'].clear()):
            with self.assertRaises(ValueError):audit(fixture(change))
    def test_duplicate_escaping_link_and_special_outer_entries_denied(self):
        for name,kind in [('config.json',tarfile.REGTYPE),('../escape',tarfile.REGTYPE),('/escape',tarfile.REGTYPE),('link',tarfile.SYMTYPE),('device',tarfile.CHRTYPE)]:
            def extra(tar):
                row=tarfile.TarInfo(name);row.type=kind;row.linkname='config.json';tar.addfile(row)
            with self.subTest(name=name),self.assertRaises(ValueError):audit(fixture(extra=extra))
    def test_metadata_duplicate_keys_denied(self):
        with self.assertRaisesRegex(ValueError,'DUPLICATE_IMAGE_METADATA_KEY'):c.parsed(b'{"os":"linux","os":"windows"}')
    def test_wrong_native_identity_layer_or_execution_config_denied(self):
        a=audit(fixture())
        for field in ('id','platform','layers','env','uid','labels'):
            n=native(a)
            if field=='id':n['Id']='sha256:'+'0'*64
            elif field=='platform':n['Os']='windows'
            elif field=='layers':n['RootFS']['Layers'][0]='sha256:'+'0'*64
            elif field=='env':n['Config']['Env']=['OTHER=value']
            elif field=='uid':n['Config']['User']='0:0'
            else:n['Config']['Labels']['org.opencontainers.image.revision']='b'*40
            with self.subTest(field=field),self.assertRaises(ValueError):c.loaded(a,n)
    def test_finite_archive_limit_applies_before_metadata(self):
        d=fixture();old=c.LIMIT
        try:
            c.LIMIT=32
            with self.assertRaisesRegex(ValueError,'BOUNDED_IMAGE_BYTES_REQUIRED'):audit(d)
        finally:c.LIMIT=old
if __name__=='__main__':unittest.main()
