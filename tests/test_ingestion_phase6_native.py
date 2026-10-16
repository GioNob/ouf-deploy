"""Real Docker inherited Env and exact never-started identity; disposable CI only."""
import copy,hashlib,json,os,shutil,stat,subprocess,unittest
from unittest.mock import patch
from pathlib import Path
import test_chatbot_cohort_containers as bootstrap
from engine_creation import Engine
from tools.chatbot_file_cohort import plan as p,ingestion_recovery as r
from tools.chatbot_file_cohort.containers import CohortContainers

@unittest.skipUnless(os.environ.get('OUF_NATIVE_INGESTION')=='1','explicit disposable Docker CI only')
class NativeIngestion(unittest.TestCase):
    def test_eight_requested_eleven_observed_defaults_and_existing_id_starts_once(self):
        f=bootstrap.crypto.SignedCutover();f.setUp();self.addCleanup(f.doCleanups)
        binary=Path(shutil.which('docker')).resolve()
        def docker(*args):
            v=subprocess.run([str(binary),*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90)
            self.assertEqual(v.returncode,0,v.stderr[:2048].decode(errors='replace'));return v.stdout.decode().strip()
        root=f.root/'ingestion-native';root.mkdir(mode=0o700)
        (root/'pause.c').write_text('#include <unistd.h>\nint main(void){for(;;)pause();}\n')
        v=subprocess.run([shutil.which('cc'),'-static','-O2',str(root/'pause.c'),'-o',str(root/'pause')],capture_output=True,timeout=30)
        self.assertEqual(v.returncode,0,v.stderr.decode());(root/'pause').chmod(0o755)
        prefix='FROM scratch\nCOPY pause /pause\nUSER '+p.USERS['ingestion']+'\nENTRYPOINT ["/pause"]\nENV PATH=/ BASE_B=two BASE_C=three\n'
        images=[]
        for version,suffix in [('old',''),('new','ENV IMAGE_A=four IMAGE_B=five IMAGE_C=six\n')]:
            (root/'Dockerfile').write_text(prefix+suffix)
            tag='ouf-ingestion-env:'+version+'-'+hashlib.sha256(str(root).encode()).hexdigest()[:20]
            docker('build','--pull=false','-t',tag,str(root));image=docker('image','inspect','--format','{{.Id}}',tag);images.append(image)
            self.addCleanup(lambda image=image:docker('image','rm','-f',image))
        nid=docker('network','create','ouf-backend');self.addCleanup(lambda:docker('network','rm',nid))
        args=['run','-d','--name','ouf-ingestion','--restart','unless-stopped','--network','ouf-backend',
            '--network-alias','ouf-ingestion','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges']
        for i in range(5):args+=['--env','APP_'+str(i)+'=fixture']
        old_id=docker(*args,images[0]);self.addCleanup(lambda:docker('rm','-f',old_id))
        path='/var/run/docker.sock';s=os.stat(path,follow_symlinks=False)
        engine=Engine(path,(s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)))
        code,old=engine.request('GET','/v1.44/containers/'+old_id+'/json');self.assertEqual(code,200)
        code,image=engine.request('GET','/v1.44/images/'+images[1]+'/json');self.assertEqual(code,200)
        package={'module':'ingestion','sourceCommit':'a'*40,'artifactKind':'DOCKER_SAVE','imageId':images[1],
            'scanGate':'PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED'}
        row=p.compile_replacement('ingestion',old,image,package,'native-phase6',{})
        self.assertEqual(len(row['creationRequest']['Env']),8);self.assertEqual(len(image['Config']['Env']),6)
        docker('update','--restart=no',old_id);docker('stop',old_id);docker('rename',old_id,row['retiredName'])
        mutations=[];request=engine.request
        def tracked(method,path,*body):
            if method!='GET':mutations.append((method,path))
            return request(method,path,*body)
        engine.request=tracked
        code,created=engine.request('POST','/v1.44/containers/create?name='+row['name'],row['creationRequest'])
        self.assertEqual(code,201);created_id=created['Id'];self.addCleanup(lambda:docker('rm','-f',created_id))
        reader=CohortContainers.__new__(CohortContainers);reader.engine=engine
        actual=reader.candidate(row);self.assertEqual(len(actual['Config']['Env']),11)
        previous={'ingestionAttempt':{'prepared':{'cohortPlan':{'replacements':[row]}}}}
        before=len(mutations)
        with patch.object(r,'CREATED',created_id),patch.object(r,'NATIVE',p.digest(Engine.runtime_binding(actual))):
            r.native_readback(previous,engine);r.native_readback(previous,engine)
            self.assertEqual(len(mutations),before)
            code,_=engine.request('POST','/v1.44/containers/'+created_id+'/start');self.assertEqual(code,204)
            running=reader.running(row);self.assertEqual(running['Id'],created_id)
            with self.assertRaises(Exception):r.native_readback(previous,engine)
        self.assertEqual(len(mutations),2);self.assertTrue(running['State']['Pid']>1);self.assertEqual(running['RestartCount'],0)
        print(json.dumps({'check':'NATIVE_CREATED_INGESTION_ENV','requestEnv':8,'imageDefaultEnv':6,'observedEnv':11,
            'creates':1,'readbackLifecycleOperations':0,'starts':1,'sameCreatedContainer':True,'targetAccess':False}),flush=True)

if __name__=='__main__':unittest.main()
