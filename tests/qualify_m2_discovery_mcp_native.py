"""Disposable Docker MCP lifecycle, not a real MCP application or target proof.

The application is a static HTTP fixture. Registry admission, packages and HUMAN
authority are synthetic; signatures, files, Engine effects and health GETs are real.
"""
import copy,hashlib,io,json,os,shutil,stat,subprocess,sys,tarfile,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
import test_m2_discovery_mcp_runtime as fixture
import test_m2_discovery_gate_peer_window as gates
from test_m2_discovery_native_profile import fixture as definition
from tools.m2_discovery_installation_profile import cohort_images as images_module
from tools.m2_discovery_installation_profile.selected_image_preparation import prepare_archives
from engine_creation import CreationDenied

SERVER=r'''
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
int main(void) {
    int s=socket(AF_INET,SOCK_STREAM,0), one=1;
    if(s<0)return 1;
    setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
    struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(8080),.sin_addr={.s_addr=htonl(INADDR_ANY)}};
    if(bind(s,(struct sockaddr*)&a,sizeof(a)) || listen(s,16))return 2;
    int readiness_requests=0;
    for(;;) {
        int c=accept(s,0,0); if(c<0)return 3;
        char b[4096]; ssize_t n=read(c,b,sizeof(b));
        int ready=n>=(ssize_t)(sizeof("GET /health/ready HTTP/")-1)
            && !memcmp(b,"GET /health/ready HTTP/",sizeof("GET /health/ready HTTP/")-1);
        const char *r=ready
            ? (readiness_requests++==0
                ? "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                : "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            : "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        size_t left=strlen(r); while(left) {ssize_t w=write(c,r,left);if(w<=0)break;r+=w;left-=w;}
        close(c);
    }
}
'''


class NativeMcp(unittest.TestCase):
    def test_real_replacement_lost_start_reply_and_reentry_without_another_effect(self):
        self.assertEqual(os.environ.get('GITHUB_ACTIONS'),'true');self.assertEqual(os.geteuid(),0)
        temporary=tempfile.TemporaryDirectory(dir=ROOT,prefix='disposable-mcp-native-');self.addCleanup(temporary.cleanup)
        root=Path(temporary.name);root.chmod(0o700)
        binary=root/'docker';shutil.copyfile(Path(shutil.which('docker')).resolve(),binary);binary.chmod(0o755)
        config=root/'docker-config';config.mkdir(mode=0o700)
        def docker(*args,data=None,check=True):
            return subprocess.run([str(binary),'--host','unix:///var/run/docker.sock','--config',str(config),*args],
                input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45,check=check,
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','DOCKER_API_VERSION':'1.44'}).stdout
        socket=Path('/var/run/docker.sock').resolve();s=socket.lstat()
        engine=images_module.Engine(str(socket),(s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)))
        profile=images_module.engine_image_profile(engine)
        self.assertEqual(profile['ServerVersion'],'29.8.1');self.assertEqual(profile['profile'],'CONTAINERD_MANIFEST')
        source=root/'fixture.c';source.write_text(SERVER)
        server=root/'server';subprocess.run(['cc','-static','-O2','-o',str(server),str(source)],check=True,timeout=30)
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w') as tar:
            raw=server.read_bytes();member=tarfile.TarInfo('fixture-server');member.size=len(raw);member.mode=0o555
            tar.addfile(member,io.BytesIO(raw))
        inputs={};native_ids={}
        for module,user in (('semantic','10001:10001'),('mcp','10005:10005')):
            commit=hashlib.sha256((str(root)+module).encode()).hexdigest()[:40]
            identity=docker('import','--change','LABEL org.opencontainers.image.revision='+commit,
                '--change','USER '+user,'--change','WORKDIR /','--change','ENV PATH=/usr/bin:/bin',
                '--change','ENTRYPOINT ["/fixture-server"]','--change','STOPSIGNAL SIGTERM',
                '-','ouf-discovery-mcp-native:'+commit,data=stream.getvalue()).decode().strip()
            self.addCleanup(lambda image=identity:docker('image','rm','-f',image,check=False))
            archive=root/(module+'.source.tar');docker('save','-o',str(archive),identity);archive.chmod(0o600)
            with tarfile.open(archive) as tar:
                manifest=json.load(tar.extractfile('manifest.json'))[0]
                config_id='sha256:'+hashlib.sha256(tar.extractfile(manifest['Config']).read()).hexdigest()
            native_ids[module]=identity
            inputs[module]={'archivePath':str(archive),'archiveSha256':hashlib.sha256(archive.read_bytes()).hexdigest(),
                'imageId':config_id,'sourceCommit':commit,'modulePackageHash':images_module.digest({'syntheticPackage':module})}
        prepared=root/'prepared';prepared.mkdir(mode=0o700)
        prepared_images=prepare_archives(inputs=inputs,output_directory=prepared,engine=engine)['images']
        docker('network','create','ouf-backend');self.addCleanup(lambda:docker('network','rm','ouf-backend',check=False))
        data=root/'fixture-data';data.write_text('nonsecret preservation fixture');data.chmod(0o444)
        cid=docker('run','-d','--name','ouf-mcp','--network','ouf-backend','--network-alias','ouf-mcp',
            '--restart','unless-stopped','--memory','64m','--pids-limit','16','--read-only','--cap-drop','ALL',
            '--security-opt','no-new-privileges','--mount','type=bind,src='+str(data)+',dst=/fixture-data,readonly',
            native_ids['mcp']).decode().strip()
        self.addCleanup(lambda:docker('rm','-f','ouf-mcp','ouf-mcp-before-discovery-test',cid,check=False))
        old=json.loads(docker('inspect',cid))[0]
        declared=definition();declared[0]['Image']=images_module.runtime_image_id(prepared_images[0]['audit'])
        gate=gates.Window();window,auth,*_=gate.fixture(definition=declared);self.addCleanup(gate.doCleanups)
        window.engine=engine;journals={}
        for module in images_module.MODULES:
            folder=auth.root/('native-import-'+module);folder.mkdir(mode=0o700);journals[module]=images_module.Journal(folder)
        binding={'path':str(binary),'sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}
        plan={'schema':images_module.PLAN,'registryCreationRequestHash':window.request_hash,
            'cohortManifestHash':images_module.digest(prepared_images),'images':prepared_images,'nativeEngineProfile':profile,
            'dockerBinding':binding,'journalDirectories':{k:str(j.root) for k,j in journals.items()},
            'maximumImportSecondsPerImage':180,'maximumImportAttemptsPerImage':1,
            'retagAllowed':False,'automaticReplayAllowed':False,'runtimeAuthorityIssued':False}
        auth.review['components']['cohortInstallation']={'schema':images_module.COMPONENT,
            **{k:auth.review[k] for k in ('sourceClosureHash','installationInputsHash','desiredProfileHash')},
            'images':images_module.image_scope(plan),
            'mcp':{'schema':'synthetic-placeholder','imageId':images_module.runtime_image_id(prepared_images[1]['audit'])},
            'gatewayRuntime':{'schema':'synthetic-inert'},'currentAdmission':{'schema':'synthetic-inert'},
            'requiresFullCurrentCohortBeforeRelease':True,'automaticReplayAllowed':False,'budgetReset':False}
        parent=auth.fixture();window.parent=parent;window.parent_hash=parent.sha
        images=images_module.DiscoveryImages(window=window,plan=plan,journals=journals,docker_binding=binding)
        calls=[];lose=[True];request=engine.request
        def observed_request(method,path,body=None):
            result=request(method,path,body)
            if method=='POST':
                calls.append(path)
                if path.endswith('/start') and lose[0]:
                    lose[0]=False;raise CreationDenied('ENGINE_OUTCOME_REQUIRES_RECONCILIATION')
            return result
        engine.request=observed_request
        def stop_old():
            docker('update','--restart','no',cid);docker('stop','--time','1',cid)
        context=SimpleNamespace(images=images,auth=auth,old=old,stop_old=stop_old,
            monotonic=time.monotonic,boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        case=fixture.Mcp();self.addCleanup(case.doCleanups)
        owner,*_=case.fixture(native_context=context)
        with self.assertRaisesRegex(CreationDenied,'ENGINE_OUTCOME_REQUIRES_RECONCILIATION'):owner.apply()
        self.assertFalse(lose[0]);self.assertEqual(owner.record()['effects'][-1]['step'],'mcp.start')
        # Reconstruct the production owner, preserving the same clocks/history.
        resumed=fixture.m.DiscoveryMcpRuntime(images=owner.images,plan=owner.plan,journal=owner.journal,
            readiness_journal=owner.readiness_journal,monotonic=time.monotonic,boot=context.boot)
        with self.assertRaises(fixture.m.CohortPaused):resumed.apply()
        waiting=resumed.readiness_journal.read();waiting_history=resumed.record()
        self.assertEqual((waiting['state'],waiting['attempts']),('RETRY_WAIT',1))
        def forbidden_health(*args):self.fail('no HTTP attempt is allowed during persisted backoff')
        resumed.health=forbidden_health
        with self.assertRaises(fixture.m.CohortPaused):resumed.apply()
        self.assertEqual(resumed.readiness_journal.read(),waiting)
        self.assertEqual(resumed.record(),waiting_history)
        self.assertEqual(len(calls),3)
        # Only the synthetic authority wall clock is advanced. The production
        # monotonic clock/backoff elapses on the runner; no budget is rewritten.
        delay=max(waiting['nextWall']-auth.now,waiting['nextMonotonic']-time.monotonic())+.05
        self.assertLess(delay,7);time.sleep(max(0,delay));auth.now+=delay
        resumed=fixture.m.DiscoveryMcpRuntime(images=owner.images,plan=owner.plan,journal=owner.journal,
            readiness_journal=owner.readiness_journal,monotonic=time.monotonic,boot=context.boot)
        result=resumed.apply();history=resumed.record();ready=resumed.readiness_journal.read()
        self.assertTrue(result['replacementVerified']);self.assertFalse(result['fullCohortProven'])
        self.assertEqual([p.rsplit('/',1)[-1].split('?')[0] for p in calls],['rename','create','start','update'])
        self.assertEqual(resumed.apply(),result);self.assertEqual(resumed.record(),history)
        self.assertEqual(resumed.readiness_journal.read(),ready);self.assertEqual(len(calls),4)
        actual=json.loads(docker('inspect','ouf-mcp'))[0]
        self.assertEqual(actual['Mounts'],old['Mounts']);self.assertEqual(data.read_text(),'nonsecret preservation fixture')
        self.assertEqual(actual['HostConfig']['RestartPolicy'],old['HostConfig']['RestartPolicy'])
        self.assertEqual(ready['attempts'],2)
        self.assertEqual(ready['startedWall'],waiting['startedWall'])
        self.assertEqual(ready['startedMonotonic'],waiting['startedMonotonic'])
        auth.write(Path(resumed.parent.binding['path']),b'REVOKED_SYNTHETIC_MCP_NATIVE_REVIEW')
        with self.assertRaises(ValueError):resumed.apply()
        self.assertEqual(len(calls),4)


if __name__=='__main__':
    if os.environ.get('GITHUB_ACTIONS')!='true' or os.geteuid()!=0:raise SystemExit('DISPOSABLE_ROOT_NATIVE_CI_ONLY')
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(NativeMcp))
    if not result.wasSuccessful() or result.skipped:raise SystemExit(1)
    print(json.dumps({'schema':'ouf.m2-discovery-mcp-native-ci.v1','actualDockerVersion':'29.8.1',
        'actualEngineLifecycleAndHealthHttp':True,'actualEd25519AndJournals':True,
        'lostStartReplyReadReconciledAfterOwnerReconstruction':True,'repeatLeavesJournalsUnchanged':True,
        'actualHttp503RetryAfterThen204':True,'persistedBackoffBlocksExtraHealthAndLifecycle':True,
        'originalReadinessStartAndCumulativeAttemptsPreserved':True,
        'lifecycleDispatches':4,'revocationBlocksFurtherWork':True,'staticHttpApplicationFixture':True,
        'syntheticRegistryAdmissionParentAndPackages':True,'realMcpApplicationProven':False,
        'fullCohortProven':False,'applicationE2EProven':False,'targetApplyAuthorized':False,
        'runtimeAuthorityIssued':False,'releaseAcceptance':False},sort_keys=True))
