import copy,hashlib,importlib.util,io,json,os,shutil,stat,tarfile,tempfile,unittest,zipfile
from pathlib import Path
SOURCE=Path(__file__).resolve().parents[1]/'scripts/stage-acquisition-read-packages-20261025.py'
spec=importlib.util.spec_from_file_location('staging',SOURCE);stage=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage)

def tar_bytes(files):
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w:gz')as archive:
        for name,data in files.items():
            entry=tarfile.TarInfo(name);entry.size=len(data);archive.addfile(entry,io.BytesIO(data))
    return output.getvalue()

def image(config):
    raw=stage.encode({'config':config});digest=stage.sha(raw);path='blobs/sha256/'+digest
    return 'sha256:'+digest,tar_bytes({path:raw,'manifest.json':stage.encode([{'Config':path,'Layers':[]}])})

@unittest.skipUnless(os.geteuid()==os.getegid()==0,'mandatory root custody qualification')
class PackageStagingTest(unittest.TestCase):
    def setUp(self):
        self.base=Path(tempfile.mkdtemp(prefix='acquisition-package-test-',dir=os.environ.get('OUF_CAPTURE_TEST_PARENT',str(SOURCE.parents[1]))));os.chmod(self.base,0o700)
        self.downloads=self.base/'downloads';self.downloads.mkdir(mode=0o700);self.root=self.base/'scope';self.inputs=self.base/'inputs.json'
        self.inputs.write_bytes(stage.encode({'schema':'ouf.acquisition-read-current-private-inputs.v1','authenticationDeclarations':{'mcp':{'clientCredentialsDeclared':True}}}));os.chmod(self.inputs,0o400)
        self.case={'inputsPath':str(self.inputs),'inputsHash':stage.sha(self.inputs.read_bytes()),'artifacts':{}}
        for role in('ingestion','udp','mcp','gateway'):
            commit='a'*40
            descriptor={'commit':commit,'artifactId':17,'zipBytes':1000}
            if role=='gateway':
                files={'source.tar.gz':tar_bytes({name:b'fixture'for name in('tools/materialize_acquisition_read.py','tools/lua/execute_acquisition_read.lua','tools/delegation_functions.py','ouf-config/routes/northbound/acquisition-ingestion-read.yaml','ouf-config/routes/northbound/acquisition-udp-read.yaml','ouf-config/source-runtime/acquisition-ingestion-read.yaml','ouf-config/source-runtime/acquisition-udp-read.yaml')}),'source-commit.txt':(commit+'\n').encode()}
            else:
                config={'User':'10005:10005','Entrypoint':['/usr/local/bin/ouf-mcp'],'Cmd':['server'],'Env':['PRIVATE_FIXTURE=credential-must-not-be-public']}
                ident,archive=image(config);descriptor.update(imageId=ident,user=config['User'],entrypoint=config['Entrypoint'],cmd=config['Cmd'],imageConfigFile='image-config.json')
                inspected=dict(config,Hostname='',AttachStdin=False,Labels=None)
                files={'image.tar.gz':archive,'image-id.txt':(ident+'\n').encode(),'image-config.json':stage.encode([{'Id':ident,'Config':inspected}]),'source-commit.txt':(commit+'\n').encode()}
            files['SHA256SUMS']=''.join(stage.sha(data)+'  '+name+'\n'for name,data in files.items()).encode();descriptor['members']=list(files)
            self.case['artifacts'][role]=descriptor;self.write_zip(role,files)
    def tearDown(self):shutil.rmtree(self.base)
    def write_zip(self,role,files):
        path=self.downloads/(role+'.zip')
        with zipfile.ZipFile(path,'w',compression=zipfile.ZIP_DEFLATED)as archive:
            for name,data in files.items():archive.writestr(name,data)
        self.case['artifacts'][role].update(zipSha256=stage.sha(path.read_bytes()),zipBytes=path.stat().st_size)
    def read_zip(self,role):
        with zipfile.ZipFile(self.downloads/(role+'.zip'))as archive:return{name:archive.read(name)for name in archive.namelist()}
    def run_stage(self):return stage.stage(self.downloads,self.case,self.root)
    def test_complete_private_stage_checks_four_artifacts_and_never_exposes_private_values(self):
        result=self.run_stage();self.assertTrue(result['complete']);self.assertFalse(result['targetApplyAuthorized']);self.assertFalse(result['currentRuntimeRevalidated'])
        self.assertEqual(result['imageImports'],0);self.assertEqual(result['oauthRequests'],0);self.assertEqual(result['engineGetAttempts'],0)
        self.assertNotIn('credential-must-not-be-public',json.dumps(result));self.assertEqual(set(result['artifacts']),{'ingestion','udp','mcp','gateway'})
        for file in self.root.rglob('*'):
            if file.is_file():self.assertEqual(stat.S_IMODE(file.stat().st_mode),0o400)
    def test_scope_cannot_be_replayed_or_overwritten(self):
        self.run_stage();before=(self.root/'complete.json').read_bytes()
        with self.assertRaisesRegex(stage.Stop,'PACKAGE_SCOPE_CONSUMED_NO_REPLAY'):self.run_stage()
        self.assertEqual(before,(self.root/'complete.json').read_bytes())
    def test_wrong_zip_bytes_fail_before_parsing_or_claiming_complete(self):
        self.case['artifacts']['ingestion']['zipSha256']='0'*64
        with self.assertRaisesRegex(stage.Stop,'EXACT_CI_ZIP_HASH_REQUIRED'):self.run_stage()
        self.assertFalse((self.root/'complete.json').exists())
    def test_input_hash_drift_preserves_partial_claim_without_runtime_effect(self):
        self.case['inputsHash']='0'*64
        with self.assertRaisesRegex(stage.Stop,'EXACT_CAPTURED_INPUTS_REQUIRED'):self.run_stage()
        self.assertTrue((self.root/'claim.json').exists());self.assertFalse((self.root/'complete.json').exists())
    def test_unexpected_zip_member_is_rejected(self):
        files=self.read_zip('ingestion');files['unexpected']=b'bad';self.write_zip('ingestion',files)
        with self.assertRaisesRegex(stage.Stop,'CLOSED_ZIP_MEMBERS_REQUIRED'):self.run_stage()
    def test_declared_path_traversal_is_also_rejected(self):
        files=self.read_zip('ingestion');files['../escaped']=b'bad';self.case['artifacts']['ingestion']['members'].append('../escaped');self.write_zip('ingestion',files)
        with self.assertRaisesRegex(stage.Stop,'CLOSED_MEMBER_NAMES_REQUIRED'):self.run_stage()
        self.assertFalse((self.root/'escaped').exists())
    def test_inner_checksum_manifest_is_bound_even_when_outer_zip_is_reviewed(self):
        files=self.read_zip('ingestion');files['source-commit.txt']=b'b'*40+b'\n';self.write_zip('ingestion',files)
        with self.assertRaisesRegex(stage.Stop,'ALL_CI_MEMBER_CHECKSUMS_REQUIRED'):self.run_stage()
    def test_docker_default_hostname_is_classified_but_nonempty_unbound_inspect_is_rejected(self):
        files=self.read_zip('ingestion');value=stage.decode(files['image-config.json']);value[0]['Config']['Hostname']='unreviewed'
        files['image-config.json']=stage.encode(value);files['SHA256SUMS']=''.join(stage.sha(data)+'  '+name+'\n'for name,data in files.items()if name!='SHA256SUMS').encode();self.write_zip('ingestion',files)
        with self.assertRaisesRegex(stage.Stop,'ONLY_EXPLICIT_DOCKER_INSPECT_DEFAULTS_ALLOWED'):self.run_stage()
    def test_wrong_image_launch_is_rejected_without_loading(self):
        self.case['artifacts']['ingestion']['entrypoint']=['wrong']
        with self.assertRaisesRegex(stage.Stop,'REVIEWED_IMAGE_LAUNCH_REQUIRED'):self.run_stage()
    def test_raw_image_config_digest_substitution_is_rejected(self):
        target=self.base/'bad.tar.gz';ident,raw=image({'User':'10005:10005','Entrypoint':['wrong'],'Cmd':['server']});target.write_bytes(raw)
        with self.assertRaisesRegex(stage.Stop,'ONE_EXACT_IMAGE_REQUIRED'):stage.verify_image(target,self.case['artifacts']['mcp'])
    def test_tar_symlink_is_rejected_without_extracting(self):
        path=self.base/'linked.tar.gz'
        with tarfile.open(path,'w:gz')as archive:
            entry=tarfile.TarInfo('link');entry.type=tarfile.SYMTYPE;entry.linkname='/etc/shadow';archive.addfile(entry)
        with self.assertRaisesRegex(stage.Stop,'IMAGE_ARCHIVE_LINK_FORBIDDEN'):stage.verify_image(path,self.case['artifacts']['mcp'])
    def test_readonly_staging_cli_handler_has_closed_nonisolated_failure(self):
        import subprocess,sys
        value=subprocess.run([sys.executable,str(SOURCE),str(self.downloads)],capture_output=True,text=True)
        self.assertEqual(value.returncode,2);self.assertEqual(json.loads(value.stdout)['status'],'STOP_RECONCILE');self.assertNotIn('Traceback',value.stderr)

if __name__=='__main__':unittest.main()
