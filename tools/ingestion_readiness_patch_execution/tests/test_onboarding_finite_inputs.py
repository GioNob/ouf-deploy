"""Protected metadata capture; historical review and provenance are FIXTURES.

Native case uses seven real Docker containers/PIDs/namespaces and Engine GETs.
It does not qualify target history, DB admission, full bootstrap or deployment.
"""
import copy
import gzip
import hashlib
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[3] if Path(__file__).parent.name=='tests' else Path(__file__).parent
SCRIPT=ROOT/'scripts/prepare-onboarding-finite-session-inputs-20261024.py'
if not SCRIPT.exists():SCRIPT=ROOT/'prepare-onboarding-finite-session-inputs-20261024.py'
REPAIR=ROOT/'scripts/repair-registry-network-projection-20261024.py'
if not REPAIR.exists():REPAIR=ROOT/'repair.py'
CAPSULE=ROOT/'releases/semantic-registry-checkpoint-successor-20261023.py'
if not CAPSULE.exists():CAPSULE=ROOT/'capsule.py'

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

m=module('finite_input_reader',SCRIPT)
r=module('finite_input_dependencies',REPAIR)
r.CAPSULE=str(CAPSULE)
r.load_legacy()
from tools.ingestion_readiness_patch_execution import runtime_bindings

def private(path,value):
    data=value if isinstance(value,bytes)else m.encoded(value)
    path.write_bytes(data);path.chmod(0o400);return m.sha(data)

class GuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.root.chmod(0o700)
        for key in m.PROGRESS:m.PROGRESS[key]=0

    def test_root_custody_symlink_hardlink_and_mutation_rejected(self):
        p=self.root/'value';private(p,b'private fixture')
        self.assertEqual(m.raw(p,100),b'private fixture')
        link=self.root/'link';link.symlink_to(p)
        with self.assertRaises(OSError):m.raw(link,100)
        os.link(p,self.root/'hardlink')
        with self.assertRaises(m.Stop):m.raw(p,100)
        (self.root/'hardlink').unlink()
        with self.assertRaisesRegex(m.Stop,'CHANGED_DURING_READ'):
            with m.opened(p,100):p.chmod(0o600);p.write_bytes(b'changed fixture')

    def test_private_modes_and_bounded_unique_json(self):
        p=self.root/'value';private(p,b'{}');p.chmod(0o644)
        with self.assertRaisesRegex(m.Stop,'PRIVATE_METADATA_MODE'):m.raw(p,100)
        p.chmod(0o400)
        with self.assertRaises(m.Stop):m.raw(p,1)
        for raw in (b'{"a":1,"a":2}',b'{"a":NaN}'):
            with self.assertRaises(m.Stop):m.decode(raw)

    def test_exclusive_fsynced_evidence_and_retained_file_recheck(self):
        m.new_file(self.root,'claim.json',{'complete':False})
        before=(self.root/'claim.json').read_bytes()
        with self.assertRaises(FileExistsError):m.new_file(self.root,'claim.json',{})
        self.assertEqual((self.root/'claim.json').read_bytes(),before)
        self.assertEqual(stat.S_IMODE((self.root/'claim.json').stat().st_mode),0o400)
        facts=m.Facts();facts.json(self.root/'claim.json')
        (self.root/'claim.json').chmod(0o600);(self.root/'claim.json').write_bytes(b'{}')
        with self.assertRaises(m.Stop):facts.recheck()
        with self.assertRaises(m.Stop):m.new_file(self.root,'../escape',{})

    def test_labels_never_establish_lifecycle_owner(self):
        self.assertEqual(m.lifecycle_declaration({'Config':{'Labels':{'io.kubernetes.pod.name':'fixture'}}}),
                         'KUBERNETES_LABELS_ONLY')
        self.assertEqual(m.lifecycle_declaration({'Config':{'Labels':{'com.docker.compose.project':'fixture'}}}),
                         'COMPOSE_LABELS_ONLY')
        self.assertEqual(m.lifecycle_declaration({'Config':{'Labels':None}}),'NO_RECOGNIZED_MANAGER_LABEL')

    def test_claim_rejected_before_candidate_or_engine_access(self):
        (self.root/m.SCOPE).mkdir(mode=0o700)
        with patch.object(m,'PACKAGE',str(self.root)),patch.object(m,'candidate',side_effect=AssertionError('not reached')):
            with self.assertRaisesRegex(m.Stop,'ALREADY_CLAIMED'):m.prepare(r)
        self.assertEqual(m.PROGRESS['engineGetAttempts'],0)

    def fixture_candidate(self):
        config={'os':'linux','architecture':'amd64','config':{'User':'10003:10003','Labels':{'base':'fixture'}},
                'rootfs':{'type':'layers','diff_ids':['sha256:'+'a'*64]}}
        data=m.encoded(config);iid='sha256:'+m.sha(data);buffer=io.BytesIO()
        with tarfile.open(fileobj=buffer,mode='w')as archive:
            entry=tarfile.TarInfo('blobs/sha256/'+iid[7:]);entry.size=len(data);archive.addfile(entry,io.BytesIO(data))
        archive=gzip.compress(buffer.getvalue(),mtime=0)
        private(self.root/'image.tar.gz',archive)
        manifest={'schema':'ouf.onboarding-tested-image.v1','repository':'GioNob/ouf-source-onboarding',
            'reviewedSourceCommit':m.SOURCE_COMMIT,'testedCommit':m.TESTED_COMMIT,'imageId':iid,
            'archiveName':'image.tar.gz','archiveSha256':m.sha(archive),'archiveBytes':len(archive),
            'qualifiedInCiOnly':True,'targetApplyAuthorized':False,'humanBudgetGranted':False,'releaseAcceptance':False}
        mh=private(self.root/'manifest.json',manifest)
        return dict(PACKAGE=str(self.root),IMAGE_ID=iid,ARCHIVE_HASH=m.sha(archive),ARCHIVE_BYTES=len(archive),MANIFEST_HASH=mh)

    def test_manifest_not_application_labels_is_provenance_and_archive_tamper_rejected(self):
        pins=self.fixture_candidate()
        with patch.multiple(m,**pins):
            result=m.candidate(m.Facts())
            self.assertFalse(result['applicationRevisionLabelPresent'])
            p=self.root/'image.tar.gz';p.chmod(0o600);data=p.read_bytes();p.write_bytes(data[:-1]+bytes([data[-1]^1]))
            with self.assertRaisesRegex(m.Stop,'ARCHIVE_HASH'):m.candidate(m.Facts())

    def test_false_target_authority_manifest_rejected(self):
        pins=self.fixture_candidate();value=json.loads((self.root/'manifest.json').read_bytes())
        value['targetApplyAuthorized']=True;(self.root/'manifest.json').chmod(0o600)
        pins['MANIFEST_HASH']=private(self.root/'manifest.json',value)
        with patch.multiple(m,**pins),self.assertRaisesRegex(m.Stop,'CI_MANIFEST'):m.candidate(m.Facts())

@unittest.skipUnless(os.environ.get('OUF_NATIVE_ONBOARDING_INPUTS')=='1','isolated root Docker runner required')
class NativeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.root.chmod(0o700);self.ids=[];self.net=None;self.image=None
        self.addCleanup(self.cleanup_fixture)
        for key in m.PROGRESS:m.PROGRESS[key]=0

    def docker(self,*args):
        return subprocess.check_output(['docker',*args],stderr=subprocess.DEVNULL)

    def inspect(self,cid):
        # Retained fixture bindings must use the production API1.44 shape,
        # rather than the runner CLI's newer default API version.
        selected=str(Path('/var/run/docker.sock').resolve())
        class Local(http.client.HTTPConnection):
            def connect(connection):
                connection.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                connection.sock.settimeout(4);connection.sock.connect(selected)
        connection=Local('fixture-engine',timeout=4)
        try:
            connection.request('GET','/v1.44/containers/'+cid+'/json')
            response=connection.getresponse();self.assertEqual(response.status,200)
            return json.loads(response.read())
        finally:connection.close()

    def cleanup_fixture(self):
        for cid in self.ids:subprocess.run(['docker','rm','-f',cid],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
        if self.net:subprocess.run(['docker','network','rm',self.net],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
        if self.image:subprocess.run(['docker','image','rm',self.image],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)

    def test_actual_seven_container_capture_restored_frame_and_replay_refusal(self):
        # This isolated test creates fixtures; the production reader only GETs.
        (self.root/'hold.c').write_text('#include <unistd.h>\nint main(void){for(;;)sleep(60);}\n')
        subprocess.run(['gcc','-static','-Os','-o',str(self.root/'hold'),str(self.root/'hold.c')],check=True)
        (self.root/'Dockerfile').write_text('FROM scratch\nCOPY hold /hold\nUSER 10003:10003\nENTRYPOINT ["/hold"]\n')
        self.docker('build','-q','-t','ouf-finite-inputs-fixture:'+self.root.name,str(self.root))
        self.image='ouf-finite-inputs-fixture:'+self.root.name
        image=json.loads(self.docker('image','inspect',self.image))[0];iid=image['Id']
        self.net='ouf-finite-inputs-'+self.root.name
        # Explicit addresses ONLY inside this disposable CI network.
        self.docker('network','create','--subnet','172.29.246.0/24',self.net)
        rows={}
        for ordinal,name in enumerate(('gateway','onboarding','mcp','udp','ingestion','postgres','registry'),10):
            cid=self.docker('run','-d','--name',self.net+'-'+name,'--network',self.net,'--ip','172.29.246.'+str(ordinal),iid).decode().strip()
            self.ids.append(cid);rows[name]=self.inspect(cid)
        archive=gzip.compress(self.docker('save',iid),mtime=0)
        package=self.root/'package';package.mkdir(mode=0o700)
        private(package/'image.tar.gz',archive)
        manifest={'schema':'ouf.onboarding-tested-image.v1','repository':'GioNob/ouf-source-onboarding',
            'reviewedSourceCommit':m.SOURCE_COMMIT,'testedCommit':m.TESTED_COMMIT,'imageId':iid,
            'archiveName':'image.tar.gz','archiveSha256':m.sha(archive),'archiveBytes':len(archive),
            'qualifiedInCiOnly':True,'targetApplyAuthorized':False,'humanBudgetGranted':False,'releaseAcceptance':False,
            'fixtureHistoryOnly':True}
        mh=private(package/'manifest.json',manifest)
        context=self.root/'context';context.mkdir(mode=0o700)
        retained=self.root/'registry-prepared';retained.mkdir(mode=0o700)
        registry_root=self.root/'registry-journal';registry_root.mkdir(mode=0o700)
        getroot=self.root/'get';getroot.mkdir(mode=0o700)
        engine_path=str(Path('/var/run/docker.sock').resolve());s=Path(engine_path).stat()
        engine={'socketPath':engine_path,'socketBinding':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)]}
        request=copy.deepcopy(rows['ingestion']['Config']);request.pop('MacAddress',None);request['Image']=iid;request['Hostname']=''
        request['HostConfig']=copy.deepcopy(rows['ingestion']['HostConfig'])
        endpoints={}
        for name,endpoint in rows['ingestion']['NetworkSettings']['Networks'].items():
            endpoints[name]={k:copy.deepcopy(endpoint.get(k))for k in('NetworkID','IPAMConfig','MacAddress')}
            endpoints[name]['Aliases']=[v for v in endpoint.get('Aliases')or[] if v not in(self.ids[4],self.ids[4][:12])]
        request['NetworkingConfig']={'EndpointsConfig':endpoints}
        frame={'schema':'ouf.ingestion-local-docker-frame-template.v1','module':'ingestion',
            'preserveObservedAddressesAndMacs':True,'targetApplyAuthorized':False,'runtimeAuthorityIssued':False,
            'name':rows['ingestion']['Name'][1:],'requestTemplate':request,'oldMounts':[],
            'restoreRestartPolicy':rows['ingestion']['HostConfig']['RestartPolicy']}
        packet={'frames':{'ingestion':frame},'candidate':{'imageConfig':image['Config']},
            'expectedRuntimeBindings':{'ingestion':{'containerId':'f'*64}}}
        pp=context/'packet.json';private(pp,packet)
        stages=[{'name':n,'intentHash':m.sha(n.encode())}for n in
                ['ingestion.CREATE_REPLACEMENT','ingestion.START_REPLACEMENT','ingestion.RESTORE_RESTART']+
                ['FIXTURE_'+str(n)for n in range(9)]]
        effects=[dict(stage=s['name'],intentHash=s['intentHash'],state='APPLIED')for s in stages]
        effects[0]['nativeResource']={'containerId':self.ids[4]}
        effects[1]['nativeResource']={'containerId':self.ids[4],'pid':rows['ingestion']['State']['Pid'],
                                      'startedAt':rows['ingestion']['State']['StartedAt']}
        unchanged={name:{'binding':runtime_bindings.observed(rows[name],runtime_bindings.NATIVE),
                          'bindingProfile':runtime_bindings.NATIVE,'restartCount':0}for name in('gateway','onboarding','mcp','udp')}
        owner={'networkNamespace':m.process(rows['onboarding'])['namespaces']['net']}
        db={'engineBinding':engine,'postgresRuntimeBinding':runtime_bindings.observed(rows['postgres'],runtime_bindings.NATIVE),
            'runtimeBindingProfile':runtime_bindings.NATIVE,'postgresRestartCount':0,'fixtureIngestionOnly':True}
        native={'logicalOperationRef':m.OPERATION,'stages':stages,'packetBinding':{'path':str(pp),'sha256':m.digest(packet)},
            'runtimeGuardProfile':{'unchangedApplications':unchanged},'ownerControlProfile':owner,
            'engineBinding':engine,'databaseControlProfile':db}
        private(context/'review.json',{'executionReview':native})
        private(context/'recovery.json',{'nextStage':12,'effects':effects})
        registry_process=m.process(rows['registry']);ns=registry_process['namespaces']['net']
        private(registry_root/'recovery.json',{'nextStage':11,'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'effects':[{'state':'APPLIED'}]*11+[{'state':'CLAIMED'}],
            'newGeneration':{'pid':registry_process['pid'],'startTicks':registry_process['startTicks'],
                             'namespaceDevice':ns['device'],'namespaceInode':ns['inode']}})
        ph=private(retained/'prepared.json',{'nativeContext':{'executionRoot':str(registry_root),'engineBinding':engine,
            'plan':{'stages':[{'intent':{'registryId':self.ids[6]}}]}},'registryInputs':{'creationRequest':{'Image':iid}}})
        private(getroot/'acceptance-result.json',{'status':'POST_NETWORK_ORIGINAL_CALLER_GET_OBSERVED','complete':True,
            'originalRequestResource200Proven':True,'allConfiguredReferencesProven':True})
        unchanged_bytes={p:p.read_bytes()for d in(context,retained,registry_root,getroot)for p in d.iterdir()}
        pins={'PACKAGE':str(package),'CONTEXT':str(context),'REGISTRY_PREP':str(retained),'REGISTRY_PREP_HASH':ph,
            'GET_ROOT':str(getroot),'MANIFEST_HASH':mh,'ARCHIVE_HASH':m.sha(archive),'ARCHIVE_BYTES':len(archive),'IMAGE_ID':iid}
        with patch.multiple(m,**pins):
            result=m.prepare(r)
            self.assertEqual(result['engineGetAttempts'],14)
            self.assertTrue(result['currentCohortStable']);self.assertFalse(result['databaseAdmissionProven'])
            self.assertFalse(result['targetApplyAuthorized']);self.assertFalse(result['lifecycleOwnershipProven'])
            self.assertFalse(result['candidateApplicationRevisionLabelPresent'])
            scope=package/m.SCOPE;bundle=json.loads((scope/'inputs.json').read_bytes())
            self.assertEqual(result['privateInputsHash'],m.sha((scope/'inputs.json').read_bytes()))
            self.assertEqual(bundle['legacyIngestionDatabaseControlProfile'],db)
            self.assertTrue(bundle['legacyDatabaseProfileMustNotBeReboundToOnboarding'])
            self.assertEqual(len(list(scope.glob('engine-attempt-*'))),14)
            self.assertEqual(len(list(scope.glob('engine-response-*'))),14)
            self.assertTrue(all(stat.S_IMODE(p.stat().st_mode)==0o400 for p in scope.iterdir()))
            with self.assertRaisesRegex(m.Stop,'ALREADY_CLAIMED'):m.prepare(r)
            self.assertEqual(m.PROGRESS['engineGetAttempts'],14)
        # A fresh fixture scope never authorizes accepting changed metadata.
        # Engine bytes and process observations are real; substitutions are explicit negative fixtures.
        original_get=m.Engine.get
        for role,second_pass in [('onboarding',False),('postgres',False),('ingestion',False),('registry',False),('udp',True)]:
            other=self.root/('negative-'+role);other.mkdir(mode=0o700)
            private(other/'image.tar.gz',archive);private(other/'manifest.json',manifest)
            badpins={**pins,'PACKAGE':str(other)}
            for key in m.PROGRESS:m.PROGRESS[key]=0
            def substituted(engine,cid,selected=rows[role]['Id'],late=second_pass):
                actual,ref=original_get(engine,cid)
                if cid==selected and (not late or engine.calls>7):
                    actual=copy.deepcopy(actual)
                    if role=='registry':actual['Image']='sha256:'+'f'*64
                    elif role=='ingestion':actual['RestartCount']+=1
                    else:actual['Config']['Labels']={'unreviewed':'changed fixture'}
                return actual,ref
            with patch.multiple(m,**badpins),patch.object(m.Engine,'get',substituted):
                with self.assertRaises(Exception):m.prepare(r)
                self.assertTrue((other/m.SCOPE/'claim.json').exists())
                self.assertFalse((other/m.SCOPE/'complete.json').exists())
                attempted=m.PROGRESS['engineGetAttempts'];self.assertGreater(attempted,0)
                with self.assertRaisesRegex(m.Stop,'ALREADY_CLAIMED'):m.prepare(r)
                self.assertEqual(m.PROGRESS['engineGetAttempts'],attempted)
        self.assertEqual(unchanged_bytes,{p:p.read_bytes()for p in unchanged_bytes})
        for name,row in rows.items():
            after=self.inspect(row['Id'])
            self.assertEqual(runtime_bindings.observed(after,runtime_bindings.NATIVE),runtime_bindings.observed(row,runtime_bindings.NATIVE))
            self.assertEqual(after['RestartCount'],row['RestartCount'])

    def test_actual_unix_socket_id_substitution_consumes_attempt_and_no_retry_marker_overwrite(self):
        sock=self.root/'engine.sock';server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        server.bind(str(sock));sock.chmod(0o600);server.listen(1);self.addCleanup(server.close)
        s=sock.stat();binding={'socketPath':str(sock),'socketBinding':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,0o600]}
        ids={str(n)*64 for n in range(1,8)};engine=m.Engine(binding,ids,self.root);received=[]
        def serve():
            connection,_=server.accept()
            with connection:
                received.append(connection.recv(8192))
                body=m.encoded({'Id':'f'*64})
                connection.sendall(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body)
        worker=threading.Thread(target=serve,daemon=True);worker.start()
        with self.assertRaisesRegex(m.Stop,'ID_SUBSTITUTED'):engine.get('1'*64)
        worker.join(5);self.assertFalse(worker.is_alive());self.assertEqual(engine.calls,1)
        self.assertTrue((self.root/'engine-attempt-01.json').exists())
        self.assertFalse((self.root/'engine-response-01.json').exists())
        self.assertTrue(received[0].startswith(b'GET /v1.44/containers/'+b'1'*64+b'/json HTTP/1.1'))
        with self.assertRaises(m.Stop):engine.get('f'*64)
        engine.calls=14
        with self.assertRaises(m.Stop):engine.get('1'*64)

if __name__=='__main__':unittest.main()
