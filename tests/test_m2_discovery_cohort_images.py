"""Real archives/Ed25519/journals; Engine and CLI effects explicitly modeled.

Remaining cohort sections are inert fixtures, not runtime/acceptance proofs.
"""
import copy,hashlib,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),
    str(ROOT/'tools/semantic_frame_compiler'),str(ROOT/'tools/semantic_lease_recovery'),
    str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_m2_discovery_gate_peer_window as gates
from test_m2_discovery_native_profile import fixture as registry_definition
from test_chatbot_cohort_image_identity import tiny_archive
from image_custody import archive,tagless_archive,native_identity,runtime_image_id
from tools.m2_discovery_installation_profile import cohort_images as m

class Images(unittest.TestCase):
    def fixture(self):
        temporary=tempfile.TemporaryDirectory(dir=ROOT,prefix='discovery-image-fixture-');self.addCleanup(temporary.cleanup)
        root=Path(temporary.name);root.chmod(0o700);rows=[]
        for module,user in (('semantic','10001:10001'),('mcp','10005:10005')):
            source=root/(module+'-source.tar');audit=tiny_archive(source,source=('a' if module=='semantic' else 'b')*40,user=user)
            derived=root/(module+'-tagless.tar')
            with source.open('rb') as incoming,derived.open('w+b') as out:
                result=tagless_archive(incoming,out,audit,containerd=True)
                value=archive(out,result['derivedArchiveSha256'],audit['imageId'],audit['sourceCommit'])
            derived.chmod(0o600);value['nativeIdentity']=native_identity(value)
            rows.append({'module':module,'archivePath':str(derived),'audit':value,
                'originalArchiveSha256':audit['archiveSha256'],'modulePackageHash':('c' if module=='semantic' else 'd')*64})
        definition=registry_definition();definition[0]['Image']=runtime_image_id(rows[0]['audit'])
        fixture=gates.Window();w,auth,*_=fixture.fixture(definition=definition);self.addCleanup(fixture.doCleanups)
        journals={}
        for module in m.MODULES:
            directory=auth.root/('selected-image-'+module);directory.mkdir(mode=0o700);journals[module]=m.Journal(directory)
        executable=Path('/usr/bin/true').resolve();docker={'path':str(executable),'sha256':hashlib.sha256(executable.read_bytes()).hexdigest()}
        info={'ServerVersion':'29.8.1','Driver':'overlayfs','DriverStatus':[['driver-type','io.containerd.snapshotter.v1']],
            'CgroupDriver':'systemd'}
        images={};calls=[];w.engine.path='/run/docker.sock';w.engine.check_socket=lambda:None
        def request(method,path,body=None):
            self.assertEqual(method,'GET')
            if path=='/v1.44/info':return 200,copy.deepcopy(info)
            identity=path.removeprefix('/v1.44/images/').removesuffix('/json')
            return (200,copy.deepcopy(images[identity])) if identity in images else (404,None)
        w.engine.request=request
        plan={'schema':m.PLAN,'registryCreationRequestHash':w.request_hash,'cohortManifestHash':'e'*64,
            'images':rows,'nativeEngineProfile':m.engine_image_profile(w.engine),'dockerBinding':docker,
            'journalDirectories':{k:str(j.root) for k,j in journals.items()},'maximumImportSecondsPerImage':180,
            'maximumImportAttemptsPerImage':1,'retagAllowed':False,'automaticReplayAllowed':False,'runtimeAuthorityIssued':False}
        scope=m.image_scope(plan)
        auth.review['components']['cohortInstallation']={'schema':m.COMPONENT,
            **{k:auth.review[k] for k in ('sourceClosureHash','installationInputsHash','desiredProfileHash')},
            'images':scope,'mcp':{'schema':'explicit-inert-fixture','imageId':runtime_image_id(rows[1]['audit'])},
            'gatewayRuntime':{'schema':'explicit-inert-fixture'},'currentAdmission':{'schema':'explicit-inert-fixture'},
            'requiresFullCurrentCohortBeforeRelease':True,'automaticReplayAllowed':False,'budgetReset':False}
        parent=auth.fixture();w.parent=parent;w.parent_hash=parent.sha
        owner=m.DiscoveryImages(window=w,plan=plan,journals=journals,docker_binding=docker)
        def cli(args,**kwargs):
            selected=next(row for row in rows if str(journals[row['module']].root)==args[args.index('--config')+1])
            raw=kwargs['stdin'].read();self.assertEqual(hashlib.sha256(raw).hexdigest(),selected['audit']['archiveSha256'])
            calls.append(selected['module']);audit=selected['audit'];identity=runtime_image_id(audit)
            images[identity]={'Id':identity,'Os':'linux','Architecture':'amd64','Config':copy.deepcopy(audit['imageConfig']),
                'RootFS':{'Type':'layers','Layers':[r['diffId'] for r in audit['layers']]}}
            return types.SimpleNamespace(returncode=0)
        return owner,auth,images,calls,cli,info

    def test_two_real_archives_and_signed_parent_import_once_then_only_observe(self):
        owner,auth,images,calls,cli,_=self.fixture();owner.initialize()
        with patch.object(m,'subprocess',types.SimpleNamespace(run=cli,DEVNULL=m.subprocess.DEVNULL)):
            first=owner.apply();history={k:j.read() for k,j in owner.journals.items()}
            self.assertEqual(owner.apply(),first)
        self.assertEqual(calls,list(m.MODULES));self.assertFalse(first['fullCohortProven'])
        self.assertTrue(all(row['effectAttemptCount']==1 for row in history.values()))
        self.assertEqual({k:j.read() for k,j in owner.journals.items()},history)

    def test_lost_load_reply_reconciles_without_reloading_and_preserves_dispatch(self):
        owner,auth,images,calls,cli,_=self.fixture();owner.initialize();first=True
        def lose(args,**kwargs):
            nonlocal first
            result=cli(args,**kwargs)
            if first:first=False;raise TimeoutError('SYNTHETIC_LOST_IMAGE_LOAD_REPLY')
            return result
        with patch.object(m,'subprocess',types.SimpleNamespace(run=lose,DEVNULL=m.subprocess.DEVNULL)):
            with self.assertRaises(TimeoutError):owner.apply()
            self.assertEqual(owner.journals['semantic'].read()['state'],'IN_FLIGHT')
            self.assertEqual(len(owner.apply()['images']),2)
        self.assertEqual(calls,list(m.MODULES))
        self.assertTrue(all((j.root/'image-load-dispatch.json').exists() for j in owner.journals.values()))

    def test_unproven_image_load_never_retries_or_dispatches_dependent_image(self):
        owner,auth,images,calls,cli,_=self.fixture();owner.initialize()
        def fail(args,**kwargs):calls.append('failed');return types.SimpleNamespace(returncode=1)
        with patch.object(m,'subprocess',types.SimpleNamespace(run=fail,DEVNULL=m.subprocess.DEVNULL)):
            with self.assertRaises(ValueError):owner.apply()
            with self.assertRaises(ValueError):owner.apply()
        self.assertEqual(calls,['failed']);self.assertEqual(owner.journals['mcp'].read()['effectAttemptCount'],0)

    def test_parent_revocation_and_native_store_drift_each_block_before_initialization(self):
        for kind in ('parent','engine'):
            owner,auth,images,calls,cli,info=self.fixture()
            if kind=='parent':auth.write(Path(owner.parent.binding['path']),b'REVOKED')
            else:info['Driver']='overlay2'
            with self.assertRaises(ValueError):owner.initialize()
            self.assertFalse(any(j.record.exists() for j in owner.journals.values()));self.assertEqual(calls,[])

    def test_executable_or_journal_scope_cannot_be_rebound(self):
        owner,auth,images,calls,cli,_=self.fixture();owner.docker={**owner.docker,'sha256':'f'*64}
        with self.assertRaises(ValueError):owner.initialize()
        self.assertEqual(calls,[])

    def test_regressed_mutable_record_cannot_bypass_durable_load_dispatch(self):
        owner,auth,images,calls,cli,_=self.fixture();owner.initialize()
        def fail(args,**kwargs):calls.append('failed');return types.SimpleNamespace(returncode=1)
        with patch.object(m,'subprocess',types.SimpleNamespace(run=fail,DEVNULL=m.subprocess.DEVNULL)):
            with self.assertRaises(ValueError):owner.apply()
            row=owner.plan['images'][0];journal=owner.journals['semantic']
            # Deliberate disposable fixture regression. Production has no such
            # reset/repair path; the independent O_EXCL dispatch must survive it.
            auth.write(journal.record,m.encoded(m.Import.initial(row['audit'],owner.parent.sha)))
            with self.assertRaises(FileExistsError):owner.apply()
        self.assertEqual(calls,['failed'])
        self.assertTrue((journal.root/'image-load-dispatch.json').exists())

if __name__=='__main__':unittest.main()
