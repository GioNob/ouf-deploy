"""Bounded source/metadata/package tests; no target root or runtime effects."""
import contextlib,hashlib,importlib.util,io,json,os,sys,tarfile,tempfile,types,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('gated_private_plan',ROOT/'scripts/prepare-gated-v11-private-plan.py');planner=importlib.util.module_from_spec(spec);spec.loader.exec_module(planner)
class Plan(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.root.chmod(0o700)
    def test_metadata_never_reads_private_file_content_or_follows_links(self):
        directory=self.root/'legacy';directory.mkdir();key=directory/'private-key.pem';key.write_bytes(b'SYNTHETIC_KEY_CONTENT_NOT_FOR_REPORT');key.chmod(0o600)
        outside=self.root/'outside';outside.mkdir();(outside/'hidden').write_bytes(b'outside');(directory/'linked').symlink_to(outside)
        with patch.object(Path,'open',side_effect=AssertionError('PRIVATE_CONTENT_READ')):
            metadata=planner.metadata(directory)
        self.assertEqual(len(metadata),3);self.assertEqual(sum(v['kind']=='symlink' for v in metadata),1)
        self.assertNotIn('SYNTHETIC_KEY_CONTENT',json.dumps(metadata));self.assertNotIn('hidden',json.dumps(metadata))
    def test_metadata_bounds_and_changed_scope_are_denied(self):
        directory=self.root/'legacy';directory.mkdir();(directory/'one').write_bytes(b'x');(directory/'two').write_bytes(b'x')
        with self.assertRaisesRegex(ValueError,'BOUND_EXCEEDED'):planner.metadata(directory,max_entries=2)
        with self.assertRaises(ValueError):planner.metadata(Path('/'))
    def image(self):
        value={'config':{'User':'10001:10001','Entrypoint':['java','-XX:MaxRAMPercentage=75','-jar','/app/application.jar'],'Cmd':None}}
        raw=planner.encoded(value);digest=planner.sha(raw);archive=io.BytesIO()
        with tarfile.open(fileobj=archive,mode='w') as stream:
            item=tarfile.TarInfo('blobs/sha256/'+digest);item.size=len(raw);stream.addfile(item,io.BytesIO(raw))
        path=self.root/'semantic.zip'
        with zipfile.ZipFile(path,'w') as package:package.writestr('semantic/image.docker.tar',archive.getvalue())
        return path,value,digest,planner.sha(path.read_bytes())
    def test_exact_zip_and_image_configuration_integrity_without_publisher_claim(self):
        path,value,config,zip_hash=self.image();self.assertEqual(planner.image_configuration(path,zip_hash,config),value)
        with self.assertRaisesRegex(ValueError,'ZIP_BYTES_DRIFT'):planner.image_configuration(path,'0'*64,config)
        with self.assertRaisesRegex(ValueError,'CONFIGURATION_REQUIRED'):planner.image_configuration(path,zip_hash,'0'*64)
    def test_all_planner_sources_are_sealed_before_any_module_exec(self):
        paths={'atomic':'tools/semantic_application_cutover/atomic_review_intake.py','publisher':'scripts/publish-native-v11-review-intake.py',
               'journal':'tools/semantic_application_cutover/transition_journal.py','gate':'tools/semantic_application_cutover/gated_creation_plan.py'}
        sources={n:(ROOT/p).read_bytes() for n,p in paths.items()}
        self.assertEqual(set(planner.modules(sources)),set(paths))
        for name in paths:
            with self.assertRaisesRegex(ValueError,'SOURCE_HASH_MISMATCH'):planner.modules({**sources,name:sources[name]+b'\n'})
    def test_root_private_atomic_entry_has_no_runtime_or_secret_output_and_is_repeatable(self):
        sys.path.insert(0,str(ROOT/'tools/semantic_application_cutover'))
        import atomic_review_intake as atomic
        import gated_creation_plan as gate
        base=self.root/'snapshots';base.mkdir(mode=0o700);parent=base/'parent';parent.mkdir(mode=0o700)
        legacy=[]
        for i in range(2):
            source=self.root/('legacy-'+str(i));source.mkdir();(source/'key.pem').write_bytes(b'SYNTHETIC_PRIVATE_KEY_NOT_FOR_OUTPUT')
            legacy.append({'Type':'bind','Source':str(source),'Destination':'/retained-'+str(i),'RW':False})
        request={'Image':'sha256:'+'a'*64,'User':'10001:10001','Env':['SENSITIVE_FIXTURE=NEVER_PRINT_THIS_VALUE'],
                 'HostConfig':{'Runtime':'runc','Privileged':False,'NetworkMode':'fixture','RestartPolicy':{'Name':'no','MaximumRetryCount':0}}}
        declaration={'retainedNativeCreationFrame':{'Mounts':legacy}}
        files={'private-runtime-declaration.json':planner.encoded(declaration),'creation-request.private.json':planner.encoded(request),
               'observation.private.json':b'{}','receipt.json':b'{}'}
        manifest={'fileHashes':{n:planner.sha(raw) for n,raw in files.items()}}
        for name,raw in {**files,'intake.json':planner.encoded(manifest)}.items():
            path=parent/name;path.write_bytes(raw);path.chmod(0o600)
        values={n:json.loads(raw) for n,raw in files.items()}
        publisher=types.SimpleNamespace(NAMES=tuple(files),EXPECTED={'requestHash':planner.sha(files['creation-request.private.json']),'declarationHash':planner.sha(files['private-runtime-declaration.json'])},validate=lambda actual:values)
        config={'config':{'User':'10001:10001','Entrypoint':['java','-XX:MaxRAMPercentage=75','-jar','/app/application.jar'],'Cmd':None}}
        scoped_sys=types.SimpleNamespace(flags=types.SimpleNamespace(isolated=1),dont_write_bytecode=True,argv=['fixture'])
        with patch.multiple(planner,BASE=base,PARENT=parent,PARENT_HASH=planner.sha(planner.encoded(manifest)),sys=scoped_sys),\
             patch.object(planner,'modules',return_value={'atomic':atomic,'publisher':publisher,'gate':gate}),\
             patch.object(planner,'image_configuration',return_value=config),patch.dict(planner.__dict__,{'__sealed_program_sha__':'f'*64}):
            first=io.StringIO()
            with contextlib.redirect_stdout(first):self.assertEqual(planner.main(),0)
            report=json.loads(first.getvalue().split('=',1)[1]);self.assertEqual(report['protectedFileWrites'],5)
            self.assertFalse(report['applicationCutoverAuthorized']);self.assertFalse(report['completeSixMountClosureProven'])
            self.assertEqual(report['privateKeysRead'],0);self.assertEqual(report['mountedSourceContentBytesRead'],0)
            self.assertNotIn('NEVER_PRINT_THIS_VALUE',first.getvalue());self.assertNotIn('PRIVATE_KEY_NOT_FOR_OUTPUT',first.getvalue())
            second=io.StringIO()
            with contextlib.redirect_stdout(second):self.assertEqual(planner.main(),0)
            reread=json.loads(second.getvalue().split('=',1)[1]);self.assertEqual(reread['intakeHash'],report['intakeHash']);self.assertEqual(reread['protectedFileWrites'],0)

if __name__=='__main__':unittest.main()
