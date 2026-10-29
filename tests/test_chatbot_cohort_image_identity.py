"""Config bytes and manifest identity remain distinct and strictly bound."""
import copy,hashlib,io,json,os,tarfile,tempfile,unittest
from pathlib import Path
import test_chatbot_cohort_containers
from image_custody import archive,tagless_archive,native_identity,runtime_image_id,loaded,ImageCustodyDenied
from image_import import Import
from tools.chatbot_file_cohort.plan import compile_replacement
from test_chatbot_cohort_plan import fixture
from tools.semantic_lease_recovery.recovery_journal import Journal

def tiny_archive(path,source='e'*40,user='10003:10003'):
    layer=b'exact disposable filesystem bytes'
    config={'os':'linux','architecture':'amd64','config':{'User':user,'Entrypoint':['java','-jar','/app/new.jar'],
        'Cmd':None,'WorkingDir':'/app','Volumes':{},'Labels':{'org.opencontainers.image.revision':source}},
        'rootfs':{'type':'layers','diff_ids':['sha256:'+hashlib.sha256(layer).hexdigest()]}}
    raw=json.dumps(config).encode();identity='sha256:'+hashlib.sha256(raw).hexdigest()
    with tarfile.open(path,'w') as tar:
        data={'manifest.json':json.dumps([{'Config':'config.json','RepoTags':None,'Layers':['layer.tar']}]).encode(),
            'config.json':raw,'layer.tar':layer}
        for name,body in data.items():
            info=tarfile.TarInfo(name);info.size=len(body);tar.addfile(info,io.BytesIO(body))
    path.chmod(0o600)
    with path.open('rb') as stream:audit=archive(stream,hashlib.sha256(path.read_bytes()).hexdigest(),identity,source)
    return audit

class Identity(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1]);self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.path=self.root/'source.tar';self.audit=tiny_archive(self.path)
    def native(self,audit):
        return {'Id':runtime_image_id(audit),'Os':'linux','Architecture':'amd64','Config':copy.deepcopy(audit['imageConfig']),
            'RootFS':{'Type':'layers','Layers':[r['diffId'] for r in audit['layers']]}}
    def bound(self):
        result=copy.deepcopy(self.audit);result['nativeIdentity']=native_identity(result);return result
    def test_configuration_hash_is_not_silently_replaced_by_manifest(self):
        audit=self.bound();self.assertNotEqual(runtime_image_id(audit),audit['imageId'])
        self.assertEqual(audit['imageId'],'sha256:'+audit['configSha256'])
        self.assertEqual(loaded(audit,self.native(audit))['imageId'],runtime_image_id(audit))
        with self.assertRaisesRegex(ImageCustodyDenied,'NATIVE_IMAGE_IDENTITY_DRIFT'):loaded(audit,self.native(self.audit))
    def test_identity_or_layer_descriptor_tampering_is_denied(self):
        for change in ('identity','config-size','blob'):
            audit=self.bound()
            if change=='identity':audit['nativeIdentity']['nativeImageId']='sha256:'+'0'*64
            elif change=='config-size':audit['configBytes']+=1
            else:audit['layers'][0]['blobSha256']='0'*64
            with self.subTest(change=change),self.assertRaisesRegex(ImageCustodyDenied,'NATIVE_MANIFEST_IDENTITY'):runtime_image_id(audit)
    def test_native_identity_never_bypasses_execution_or_rootfs_checks(self):
        audit=self.bound();native=self.native(audit);native['Config']['Env']=['INJECTED=1']
        with self.assertRaisesRegex(ImageCustodyDenied,'EXECUTION_CONFIG_DRIFT'):loaded(audit,native)
        native=self.native(audit);native['RootFS']['Layers']=[]
        with self.assertRaisesRegex(ImageCustodyDenied,'ROOTFS_CUSTODY_DRIFT'):loaded(audit,native)
    def test_explicit_oci_envelope_preserves_every_config_and_layer_byte(self):
        derived=self.root/'derived.tar'
        with self.path.open('rb') as source,derived.open('w+b') as target:
            result=tagless_archive(source,target,self.audit,containerd=True)
            audited=archive(target,result['derivedArchiveSha256'],self.audit['imageId'],self.audit['sourceCommit'])
        self.assertEqual(audited['imageConfig'],self.audit['imageConfig']);self.assertEqual(audited['layers'],self.audit['layers'])
        with tarfile.open(derived) as tar:
            index=json.load(tar.extractfile('index.json'));identity=native_identity(audited)
            self.assertEqual(index['manifests'][0]['digest'],identity['nativeImageId'])
            raw=tar.extractfile('blobs/sha256/'+identity['nativeImageId'][7:]).read()
            self.assertEqual('sha256:'+hashlib.sha256(raw).hexdigest(),identity['nativeImageId'])
            manifest=json.loads(raw)
            for descriptor in [manifest['config'],*manifest['layers']]:
                content=tar.extractfile('blobs/sha256/'+descriptor['digest'][7:]).read()
                self.assertEqual(hashlib.sha256(content).hexdigest(),descriptor['digest'][7:])
                self.assertEqual(len(content),descriptor['size'])
    def test_existing_native_image_is_verified_without_an_import_attempt(self):
        audit=self.bound();directory=self.root/'journal';directory.mkdir(mode=0o700)
        journal=Journal(directory);initial=Import.initial(audit,'f'*64);journal.initialize(initial)
        owner=Import(journal,initial['contextHash']);calls=[]
        with owner.invocation():owner.import_once(audit,lambda:calls.append('FORBIDDEN'),lambda _:self.native(audit),lambda _:'f'*64)
        self.assertFalse(calls);self.assertEqual(journal.read()['effectAttemptCount'],0)
        self.assertEqual(journal.read()['state'],'VERIFIED')
    def test_creation_request_binds_native_id_and_preserves_original_package_pin(self):
        old,image,package=fixture();audit=self.bound()
        package['imageId']=audit['imageId'];image={'Id':runtime_image_id(audit),'Config':audit['imageConfig'],'archiveAudit':audit}
        result=compile_replacement('onboarding',old,image,package,'fixture',{})
        self.assertEqual(result['creationRequest']['Image'],runtime_image_id(audit))
        self.assertEqual(package['imageId'],self.audit['imageId'])
        image['Id']='sha256:'+'0'*64
        with self.assertRaisesRegex(ValueError,'NATIVE_IMAGE_BINDING'):compile_replacement('onboarding',old,image,package,'fixture',{})

if __name__=='__main__':unittest.main()
