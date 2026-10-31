"""Four real proposal compilers, sealed isolated CLI and create-only custody.

Source inputs, archives, Ed25519 and files are real test fixtures. Application
generations/plans are synthetic; there is no target admission or execution.
"""
import copy,hashlib,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]+[str(ROOT/'tools'/p) for p in
    ('semantic_application_cutover','semantic_frame_compiler','semantic_policy_token_owner',
     'semantic_lease_recovery','semantic_transaction_profiles','semantic_cohort_admission/cohort-draft')]
import test_m2_discovery_cohort_images as image_fixture
import test_chatbot_cohort_gateway_runtime as gateway_fixture
from test_chatbot_cohort_plan import fixture as old_container
from test_m2_discovery_native_profile import fixture as registry_fixture
from tools.m2_discovery_installation_profile import private_review as m,private_review_capsule as capsule
from tools.m2_discovery_installation_profile.parent_authority import review_scope


class PrivateReview(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.images_case=image_fixture.Images();cls.images,*_=cls.images_case.fixture()
        cls.gateway_case=gateway_fixture.GatewayRuntime();cls.gateway,*_=cls.gateway_case.fixture()
        cls.baseline=(ROOT/capsule.BASELINE).read_bytes()
        cls.raw,cls.manifest=capsule.build(ROOT,'b'*40)
    @classmethod
    def tearDownClass(cls):
        cls.gateway_case.doCleanups();cls.images_case.doCleanups()
    def fixture(self):
        images=copy.deepcopy(self.images.plan);r=copy.deepcopy(self.images.window.request)
        s=copy.deepcopy(self.images.window.profile.selection);g=copy.deepcopy(self.gateway.plan)
        s['files']['discoveryReceiptKey']['sha256']=g['proposalKeyHash']
        old,_,_=old_container('mcp');old['Id']='e'*64;a=images['images'][1]['audit']
        package={'schema':'ouf.unsigned-offline-candidate-package.v1','module':'mcp','runtimeUser':'10005:10005',
            'imageId':a['imageId'],'sourceCommit':a['sourceCommit'],
            'artifactFormat':'DOCKER_SAVE_OFFLINE_ARCHIVE_NOT_HOST_OCI_DECLARATION',
            'imageScanGate':'PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED','notReleaseAcceptance':True,
            'signatureIssued':False,'targetApplyAuthorized':False,'vpsOperations':0}
        images['images'][1]['modulePackageHash']=m.digest(package)
        root=str(self.images.parent.binding['path'])+'-private-review'
        context={k:v for k,v in registry_fixture()[4].items() if k not in
            ('containerId','networkNamespaceName','rootfsPath')}
        context['rootfsLayout']='docker-containerd-overlayfs-v1'
        return {'schema':m.SCHEMA,'sourceClosureHash':'1'*64,'installationInputsHash':'2'*64,
            'desiredProfileHash':'3'*64,'cohortManifestHash':images['cohortManifestHash'],
            'registry':{'request':r,'selection':s,'contextTemplate':context},'images':images,
            'gateway':{'plan':g,'journalDirectory':root+'/gateway'},
            'mcp':{'old':old,'package':package,'cohortId':'private-review-test',
                'environmentDelta':{'set':{'MCP_OIDC_CLIENT_ID':s['mcp_workload']},'remove':[]},
                'journalDirectory':root+'/mcp','readinessDirectory':root+'/mcp-readiness'}}
    def compile(self,inputs):return m.assemble(inputs,m.digest(inputs),self.baseline)
    def files(self):
        t=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(t.cleanup);root=Path(t.name);root.chmod(0o700)
        inputs=self.fixture();source=root/'inputs.json';source.write_bytes(m.encoded(inputs));source.chmod(0o600)
        out=root/'output';out.mkdir(mode=0o700)
        return inputs,source,out

    def test_deterministic_four_owner_fragment_is_not_a_parent_review_or_authority(self):
        inputs=self.fixture();before=copy.deepcopy(inputs);a=self.compile(inputs)
        self.assertEqual(a,self.compile(inputs));self.assertEqual(inputs,before)
        self.assertEqual(set(a['cohortReviewFragment']),{'images','gatewayRuntime','mcp'})
        self.assertNotIn('policy',a['registry']);self.assertFalse(a['registry']['structuralValidation']['actualContainerIdBound'])
        with self.assertRaises(ValueError):review_scope(a)
        for k in ('completeParentReview','inputsAuthenticated','archiveCustodyProven','nativeExecutorIntegrated',
            'fullCohortProven','runtimeAuthorityIssued','targetApplyAuthorized','applicationE2EProven'):
            self.assertIs(a[k],False)

    def test_cross_owner_manifest_image_key_and_workload_drift_are_denied(self):
        for case in ('manifest','registry_image','mcp_package','key','workload','gateway_image'):
            with self.subTest(case=case):
                inputs=self.fixture()
                if case=='manifest':inputs['cohortManifestHash']='f'*64
                elif case=='registry_image':inputs['registry']['request']['Image']='sha256:'+'f'*64
                elif case=='mcp_package':inputs['mcp']['package']['sourceCommit']='e'*40
                elif case=='key':inputs['gateway']['plan']['proposalKeyHash']='a'*64
                elif case=='workload':inputs['mcp']['environmentDelta']['set']['MCP_OIDC_CLIENT_ID']='other-workload'
                else:inputs['gateway']['plan']['creationRequest']['Image']='sha256:'+'e'*64
                with self.assertRaises(ValueError):self.compile(inputs)

    def test_observed_oci_flags_and_extra_inputs_cannot_select_a_different_compiler(self):
        for case in ('observedOci','targetApplyAuthorized','template','baseline'):
            inputs=self.fixture()
            if case=='baseline':
                with self.assertRaises(ValueError):m.assemble(inputs,m.digest(inputs),self.baseline+b' ')
            else:
                inputs['registry'][case]=True
                with self.assertRaises(ValueError):self.compile(inputs)

    def test_review_is_precreation_and_cannot_bind_a_borrowed_container_or_rootfs(self):
        for key,value in (('containerId','a'*64),('rootfsPath','/borrowed/rootfs'),('networkNamespaceName','retained')):
            inputs=self.fixture();inputs['registry']['contextTemplate'][key]=value
            with self.assertRaisesRegex(ValueError,'CID_FREE'):self.compile(inputs)

    def test_journals_must_be_distinct_and_cannot_shadow_input_artifacts(self):
        for case in ('same','nested','file'):
            inputs=self.fixture()
            p=inputs['mcp']['journalDirectory']
            inputs['gateway']['journalDirectory']=p if case=='same' else p+'/child' if case=='nested' else '/fixture'
            with self.assertRaises(ValueError):self.compile(inputs)

    def test_private_publication_then_inspection_has_no_overwrite_or_history_reset(self):
        inputs,source,out=self.files();h=m.digest(inputs)
        first=m.prepare(str(source),h,str(out),self.baseline)
        saved={p.name:(p.read_bytes(),p.stat().st_ino) for p in out.iterdir()}
        self.assertEqual(m.prepare(str(source),h,str(out),self.baseline,inspect=True),first)
        with self.assertRaises(ValueError):m.prepare(str(source),h,str(out),self.baseline)
        self.assertEqual({p.name:(p.read_bytes(),p.stat().st_ino) for p in out.iterdir()},saved)

    def test_partial_claim_is_retained_and_never_completed_on_retry_or_inspect(self):
        inputs,source,out=self.files();h=m.digest(inputs);original=m.new_file
        def fail(fd,name,raw):
            if name=='assembly.private.json':raise OSError('PRIVATE_SENTINEL_DO_NOT_PRINT')
            return original(fd,name,raw)
        with patch.object(m,'new_file',side_effect=fail),self.assertRaises(OSError):m.prepare(str(source),h,str(out),self.baseline)
        claim=(out/'preparation.claim.json').read_bytes()
        for inspect in (False,True):
            with self.assertRaises((ValueError,FileNotFoundError)):
                m.prepare(str(source),h,str(out),self.baseline,inspect=inspect)
        self.assertEqual(list(p.name for p in out.iterdir()),['preparation.claim.json'])
        self.assertEqual((out/'preparation.claim.json').read_bytes(),claim)

    def test_input_hash_mode_symlink_and_output_overlap_fail_before_any_claim(self):
        for case in ('hash','mode','symlink','overlap'):
            inputs,source,out=self.files();h=m.digest(inputs);path=source
            if case=='hash':h='f'*64
            elif case=='mode':source.chmod(0o644)
            elif case=='symlink':path=source.with_name('alias');path.symlink_to(source)
            else:out=source.parent
            with self.assertRaises((ValueError,RuntimeError,OSError)):
                m.prepare(str(path),h,str(out),self.baseline)
            self.assertFalse((out/'preparation.claim.json').exists())

    def test_tampered_output_is_not_repaired_or_accepted_by_inspection(self):
        inputs,source,out=self.files();h=m.digest(inputs);m.prepare(str(source),h,str(out),self.baseline)
        artifact=out/'assembly.private.json';artifact.write_text('{}');artifact.chmod(0o600)
        with self.assertRaises(ValueError):m.prepare(str(source),h,str(out),self.baseline,inspect=True)
        self.assertEqual(artifact.read_text(),'{}')

    def test_public_projection_never_contains_private_keys_paths_or_references(self):
        inputs=self.fixture();public=json.dumps(m.receipt(self.compile(inputs)))
        for text in (gateway_fixture.KEY,'fixture-mcp','https://','/fixture/',inputs['gateway']['journalDirectory']):
            self.assertNotIn(text,public)

    def test_sealed_cli_runs_without_repository_and_emits_only_public_receipt(self):
        inputs,source,out=self.files();program=out.parent/'capsule.py';program.write_bytes(self.raw)
        args=[sys.executable,'-I','-B','-S',str(program),'prepare','--input',str(source),
            '--input-sha256',m.digest(inputs),'--output-directory',str(out)]
        result=subprocess.run(args,cwd=out,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        self.assertEqual(result.returncode,0,(result.stdout,result.stderr))
        receipt=json.loads(result.stdout);self.assertEqual(receipt['proposalCount'],4)
        self.assertFalse(receipt['completeParentReview']);self.assertNotIn(gateway_fixture.KEY,result.stdout.decode())
        args[5]='inspect';read=subprocess.run(args,cwd=out,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        self.assertEqual(read.returncode,0,(read.stdout,read.stderr));self.assertEqual(read.stdout,result.stdout)

    def test_sealed_cli_denies_payload_drift_and_missing_isolation_without_private_errors(self):
        inputs,source,out=self.files();program=out.parent/'capsule.py'
        for case in ('payload','isolation','bad_arguments'):
            raw=self.raw
            if case=='payload':raw=raw.replace(b"PAYLOAD='",b"PAYLOAD='!",1)
            program.write_bytes(raw)
            args=[sys.executable]+(['-I','-B','-S'] if case!='isolation' else [])+[str(program),'prepare',
                '--input',str(source),'--input-sha256',m.digest(inputs),'--output-directory',str(out)]
            if case=='bad_arguments':args += ['--PRIVATE_ARGUMENT_SENTINEL='+str(source)]
            result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
            self.assertEqual(result.returncode,1);self.assertNotIn(str(source),result.stdout.decode())
            self.assertNotIn('PRIVATE_ARGUMENT_SENTINEL',result.stdout.decode())
            self.assertEqual(result.stderr,b'');self.assertFalse((out/'preparation.claim.json').exists())

    def test_changed_compiler_binding_cannot_adopt_a_previous_private_assembly(self):
        inputs,source,out=self.files();program=out.parent/'capsule.py';program.write_bytes(self.raw)
        args=[sys.executable,'-I','-B','-S',str(program),'prepare','--input',str(source),
            '--input-sha256',m.digest(inputs),'--output-directory',str(out)]
        self.assertEqual(subprocess.run(args,stdout=subprocess.PIPE,timeout=30).returncode,0)
        before={p.name:p.read_bytes() for p in out.iterdir()}
        for case in ('revision','loader'):
            if case=='revision':other,_=capsule.build(ROOT,'c'*40)
            else:
                with patch.object(capsule,'RUNTIME',capsule.RUNTIME+'\n'):other,_=capsule.build(ROOT,'b'*40)
            program.write_bytes(other);args[5]='inspect'
            result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
            self.assertEqual(result.returncode,1);self.assertEqual(result.stderr,b'')
            self.assertEqual({p.name:p.read_bytes() for p in out.iterdir()},before)

    def test_input_drift_after_payload_retains_partial_output_without_receipt(self):
        inputs,source,out=self.files();h=m.digest(inputs);original=m.new_file
        def change(fd,name,raw):
            original(fd,name,raw)
            if name=='assembly.private.json':source.write_text('{}');source.chmod(0o600)
        with patch.object(m,'new_file',side_effect=change),self.assertRaisesRegex(ValueError,'HASH_DRIFT'):
            m.prepare(str(source),h,str(out),self.baseline)
        self.assertEqual(set(p.name for p in out.iterdir()),{'assembly.private.json','preparation.claim.json'})

    def test_packager_denies_changed_source_before_emitting_a_capsule(self):
        for change_manifest in (False,True):
            with self.subTest(change_manifest=change_manifest):
                t=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(t.cleanup);alternate=Path(t.name)
                manifest='tools/m2_discovery_installation_profile/private_review_sources.json'
                pins=json.loads((ROOT/manifest).read_bytes())
                for relative in {v['path'] for v in pins.values()}|{manifest,capsule.BASELINE}:
                    target=alternate/relative;target.parent.mkdir(parents=True,exist_ok=True)
                    target.write_bytes((ROOT/relative).read_bytes())
                altered=alternate/'tools/m2_discovery_installation_profile/private_review.py'
                altered.write_bytes(altered.read_bytes()+b'\n')
                if change_manifest:
                    for row in pins.values():
                        if row['path']==str(altered.relative_to(alternate)):
                            row['sha256']=hashlib.sha256(altered.read_bytes()).hexdigest()
                    (alternate/manifest).write_text(json.dumps(pins,indent=2,sort_keys=True)+'\n')
                with self.assertRaisesRegex(ValueError,'SOURCE_REQUIRED'):capsule.build(alternate,'b'*40)

if __name__=='__main__':unittest.main()
