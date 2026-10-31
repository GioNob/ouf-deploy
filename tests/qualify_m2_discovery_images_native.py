"""Disposable real Docker/CLI imports; parent and application context synthetic.

Seed images contain one inert text file and are never executed. No application
admission, package publisher trust, complete cohort or target acceptance follows.
"""
import hashlib,io,json,os,shutil,stat,subprocess,sys,tarfile,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_application_cutover'),
    str(ROOT/'tools/semantic_lease_recovery'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft'),
    str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_frame_compiler')]
import test_m2_discovery_gate_peer_window as gates
from test_m2_discovery_native_profile import fixture as definition
from tools.m2_discovery_installation_profile import cohort_images as m
from tools.m2_discovery_installation_profile.selected_image_preparation import prepare_archives,read_prepared_archives
from image_custody import runtime_image_id


class NativeImages(unittest.TestCase):
    def test_real_cli_lost_reply_read_reconciliation_and_revocation(self):
        self.assertEqual(os.environ.get('GITHUB_ACTIONS'),'true')
        self.assertEqual(os.geteuid(),0)
        source_binary=Path(shutil.which('docker')).resolve()
        socket=Path('/var/run/docker.sock').resolve();info=socket.lstat()
        engine=m.Engine(str(socket),(info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)))
        profile=m.engine_image_profile(engine)
        self.assertEqual(profile['ServerVersion'],'29.8.1')
        self.assertEqual(profile['profile'],'CONTAINERD_MANIFEST')
        temporary=tempfile.TemporaryDirectory(dir=ROOT,prefix='disposable-selected-images-');self.addCleanup(temporary.cleanup)
        root=Path(temporary.name);root.chmod(0o700);config=root/'seed-cli';config.mkdir(mode=0o700)
        # Hosted /opt ancestry is writable by the runner. Bind an exact copy
        # in this root-custodied CI tree; production custody guards stay intact.
        binary=root/'docker';shutil.copyfile(source_binary,binary);binary.chmod(0o755)
        self.assertEqual(hashlib.sha256(binary.read_bytes()).digest(),hashlib.sha256(source_binary.read_bytes()).digest())
        def docker(*args,data=None,check=True):
            return subprocess.run([str(binary),'--host','unix://'+str(socket),'--config',str(config),*args],
                input=data,check=check,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45,
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','DOCKER_API_VERSION':'1.44'}).stdout
        inputs={}
        for module,user in (('semantic','10001:10001'),('mcp','10005:10005')):
            commit=hashlib.sha256((str(root)+module).encode()).hexdigest()[:40]
            stream=io.BytesIO()
            with tarfile.open(fileobj=stream,mode='w') as tar:
                raw=('inert native '+module).encode();member=tarfile.TarInfo('fixture.txt')
                member.size=len(raw);member.mode=0o444;tar.addfile(member,io.BytesIO(raw))
            identity=docker('import','--change','LABEL org.opencontainers.image.revision='+commit,
                '--change','USER '+user,'--change','WORKDIR /','--change','ENV PATH=/usr/bin:/bin',
                '--change','ENTRYPOINT ["/fixture-never-run"]','--change','CMD ["fixture"]',
                '--change','STOPSIGNAL SIGTERM','-','ouf-selected-native:'+commit,data=stream.getvalue()).decode().strip()
            self.addCleanup(lambda image=identity:docker('image','rm','-f',image,check=False))
            source=root/(module+'.source.tar');docker('save','-o',str(source),identity)
            with tarfile.open(source) as tar:
                entry=json.load(tar.extractfile('manifest.json'))[0]
                config_id='sha256:'+hashlib.sha256(tar.extractfile(entry['Config']).read()).hexdigest()
            original_hash=hashlib.sha256(source.read_bytes()).hexdigest()
            source.chmod(0o600)
            inputs[module]={'archivePath':str(source),'archiveSha256':original_hash,
                'imageId':config_id,'sourceCommit':commit,
                'modulePackageHash':m.digest({'syntheticFixture':module,'commit':commit})}
            docker('image','rm','-f',identity)
        prepared=root/'prepared';prepared.mkdir(mode=0o700)
        preparation=prepare_archives(inputs=inputs,output_directory=prepared,engine=engine)
        self.assertEqual(read_prepared_archives(inputs=inputs,output_directory=prepared,engine=engine),preparation)
        with self.assertRaises(FileExistsError):prepare_archives(inputs=inputs,output_directory=prepared,engine=engine)
        self.assertEqual(preparation['imageLoads'],0)
        rows=preparation['images']
        for row in rows:
            self.addCleanup(lambda image=runtime_image_id(row['audit']):docker('image','rm','-f',image,check=False))
        declared=definition();declared[0]['Image']=runtime_image_id(rows[0]['audit'])
        fixture=gates.Window();window,auth,*_=fixture.fixture(definition=declared);self.addCleanup(fixture.doCleanups)
        window.engine=engine
        journals={}
        for module in m.MODULES:
            folder=auth.root/('native-image-'+module);folder.mkdir(mode=0o700);journals[module]=m.Journal(folder)
        binding={'path':str(binary),'sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}
        plan={'schema':m.PLAN,'registryCreationRequestHash':window.request_hash,'cohortManifestHash':m.digest(rows),
            'images':rows,'nativeEngineProfile':profile,'dockerBinding':binding,
            'journalDirectories':{k:str(j.root) for k,j in journals.items()},'maximumImportSecondsPerImage':180,
            'maximumImportAttemptsPerImage':1,'retagAllowed':False,'automaticReplayAllowed':False,'runtimeAuthorityIssued':False}
        auth.review['components']['cohortInstallation']={'schema':m.COMPONENT,
            **{k:auth.review[k] for k in ('sourceClosureHash','installationInputsHash','desiredProfileHash')},
            'images':m.image_scope(plan),'mcp':{'schema':'synthetic-inert','imageId':runtime_image_id(rows[1]['audit'])},
            'gatewayRuntime':{'schema':'synthetic-inert'},'currentAdmission':{'schema':'synthetic-inert'},
            'requiresFullCurrentCohortBeforeRelease':True,'automaticReplayAllowed':False,'budgetReset':False}
        parent=auth.fixture();window.parent=parent;window.parent_hash=parent.sha
        owner=m.DiscoveryImages(window=window,plan=plan,journals=journals,docker_binding=binding);owner.initialize()
        real_run=subprocess.run;calls=[]
        def lose_first_reply(args,**kwargs):
            calls.append(args[-1]);result=real_run(args,**kwargs)
            if len(calls)==1:raise TimeoutError('SYNTHETIC_LOST_REPLY_AFTER_REAL_DOCKER_LOAD')
            return result
        with patch.object(m,'subprocess',types.SimpleNamespace(run=lose_first_reply,DEVNULL=subprocess.DEVNULL)):
            with self.assertRaises(TimeoutError):owner.apply()
            first=journals['semantic'].read()
            self.assertEqual((first['state'],first['effectAttemptCount']),('IN_FLIGHT',1))
            proof=owner.apply();history={k:j.read() for k,j in journals.items()}
            self.assertEqual(owner.apply(),proof)
            self.assertEqual({k:j.read() for k,j in journals.items()},history)
            self.assertEqual(calls,['load','load'])
            for row in rows:
                actual=owner.inspect(runtime_image_id(row['audit']))
                self.assertEqual(actual.get('RepoTags') or [],[])
            auth.write(Path(parent.binding['path']),b'REVOKED_SYNTHETIC_NATIVE_IMAGE_REVIEW')
            with self.assertRaises(ValueError):owner.apply()
            self.assertEqual(calls,['load','load'])
        self.assertTrue(all(j.read()['state']=='VERIFIED' and j.read()['effectAttemptCount']==1 for j in journals.values()))
        self.assertTrue(all((j.root/'image-load-dispatch.json').exists() for j in journals.values()))


if __name__=='__main__':
    if os.environ.get('GITHUB_ACTIONS')!='true' or os.geteuid()!=0:raise SystemExit('DISPOSABLE_ROOT_NATIVE_CI_ONLY')
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(NativeImages))
    if not result.wasSuccessful() or result.skipped:raise SystemExit(1)
    print(json.dumps({'schema':'ouf.m2-selected-images-native-ci.v1','actualDockerVersion':'29.8.1',
        'actualEngineAndCliAndArchiveIdentity':True,'actualOwnedLoads':2,'inertFixtureSeeds':2,
        'actualCreateOnlySelectedArchivePreparationAndReadReconciliation':True,
        'lostRealLoadReplyReadReconciledWithoutReload':True,'secondApplyLeavesJournalsUnchanged':True,
        'revocationBlocksFurtherWork':True,'syntheticParentApplicationAndPackageReview':True,
        'applicationContainersStarted':0,'fullCohortProven':False,'applicationE2EProven':False,
        'targetApplyAuthorized':False,'runtimeAuthorityIssued':False,'releaseAcceptance':False},sort_keys=True))
