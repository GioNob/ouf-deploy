"""Actual Docker 29.8.1 peers and CAP_NET_ADMIN-only probe; admission profiles synthetic."""
import copy,ctypes,hashlib,json,os,socket,stat,struct,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.m2_discovery_installation_profile import native_generation_probe as m

def main():
    assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
    def cli(*args):
        return subprocess.check_output(['docker',*args],text=True,stderr=subprocess.PIPE,timeout=30,
            env={**os.environ,'DOCKER_API_VERSION':'1.44'}).strip()
    assert cli('version','--format','{{.Server.Version}}')=='29.8.1'
    root=Path(tempfile.mkdtemp(prefix='ouf-native-lease-probe-',dir='/var/lib'));root.chmod(0o700);ids=[]
    try:
        cli('pull','alpine:3.22');peers={}
        for role in ('registry','provider'):
            cid=cli('run','-d','--network','bridge','--user','10001:10001','--cap-drop','ALL',
                '--security-opt','no-new-privileges:true','alpine:3.22','sleep','300')
            ids.append(cid);row=json.loads(cli('inspect',cid))[0]
            namespace=Path(row['NetworkSettings']['SandboxKey']).resolve();ns=namespace.stat()
            peers[role]={'containerId':cid,'imageId':row['Image'],
                'dockerBindingHash':m.digest({k:row[k] for k in m.DOCKER_FIELDS}),
                'pid':row['State']['Pid'],'startedAt':row['State']['StartedAt'],'startTicks':m.ticks(row['State']['Pid']),
                'namespace':{'path':str(namespace),'identity':[ns.st_dev,ns.st_ino]},
                'allowedPausedStates':[False,True] if role=='registry' else [False]}
        selected=Path('/var/run/docker.sock').resolve();s=selected.stat()
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
            sock.connect(str(selected));credentials=list(struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)))
        profiles={role:{k:('1' if role=='registry' else '2')*64 for k in
            ('nodeRecipeHash','applicationHash','imageConfigurationHash','rootfsSealHash')} for role in peers}
        snapshot={'schema':'ouf.discovery-lease-generation-observation.v1','desiredProfileHash':'3'*64,
            'nativeProfileHash':m.digest(profiles),'profiles':profiles,
            'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'generationRef':'',
            'engineBinding':{'socketPath':str(selected),'socketBinding':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)],
                'peerCredentials':credentials,'startTicks':m.ticks(credentials[0])},'peers':peers}
        snapshot['generationRef']=m.generation_reference(snapshot)
        def write(value):
            raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode();sha=hashlib.sha256(raw).hexdigest()
            target=root/(sha+'.json');target.write_bytes(raw);target.chmod(0o600)
            return {'nativeObservationHash':sha,**{k:value[k] for k in
                ('nativeProfileHash','generationRef','desiredProfileHash','bootId')}}
        receipt=write(snapshot);probe=m.NativeLeaseGenerationProbe(root)
        cli('pause',peers['registry']['containerId'])
        paused=probe(receipt)
        cli('unpause',peers['registry']['containerId']);running=probe(receipt)
        assert paused==running
        read_fd,write_fd=os.pipe();pid=os.fork()
        if pid==0:
            os.close(read_fd);code=1
            try:
                libc=ctypes.CDLL(None,use_errno=True)
                for number in range(64):
                    if number!=12 and libc.prctl(24,number,0,0,0)!=0 and ctypes.get_errno()!=22:
                        raise RuntimeError('CAPABILITY_BOUND_DROP_FAILED')
                assert libc.prctl(38,1,0,0,0)==0
                class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
                class Data(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
                header=Header(0x20080522,0);data=(Data*2)();data[0].effective=data[0].permitted=1<<12
                assert libc.capset(ctypes.byref(header),data)==0
                status={k:v.strip() for k,v in (line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)}
                assert all(int(status[k],16)==1<<12 for k in ('CapEff','CapPrm','CapBnd'))
                assert status['NoNewPrivs']=='1' and int(status['CapAmb'],16)==0
                assert probe(receipt)==running
                result={'ok':True,'onlyCapNetAdmin':True};code=0
            except Exception as error:
                result={'ok':False,'errorType':type(error).__name__,'reason':str(error)[:120]}
            os.write(write_fd,json.dumps(result).encode());os.close(write_fd);os._exit(code)
        os.close(write_fd);result=json.loads(os.read(read_fd,4096));os.close(read_fd);_,status=os.waitpid(pid,0)
        assert status==0 and result['ok'],result
        def denied(value):
            try:probe(value);raise AssertionError('unadmitted generation accepted')
            except (ValueError,OSError):pass
        bad=copy.deepcopy(snapshot);bad['peers']['provider']['startTicks']+=1
        bad['generationRef']=m.generation_reference(bad);denied(write(bad))
        bad=copy.deepcopy(snapshot);bad['peers']['provider']['namespace']['identity'][1]+=1
        bad['generationRef']=m.generation_reference(bad);denied(write(bad))
        cli('pause',peers['provider']['containerId']);denied(receipt);cli('unpause',peers['provider']['containerId'])
        cli('update','--memory','33554432','--memory-swap','33554432',peers['provider']['containerId']);denied(receipt)
        cli('stop','--time','1',peers['provider']['containerId']);denied(receipt)
        print(json.dumps({'schema':'ouf.m2-native-lease-generation-probe-ci.v1','actualDockerVersion':'29.8.1',
            'actualPeers':2,'registryGatePausedAndSameGenerationRunningAccepted':True,
            'onlyCapNetAdminNoSysPtraceSucceeded':True,'readsPidStatAndDockerNamespaceBindings':True,
            'reusedPidTickAndNamespaceMismatchDenied':True,'providerPauseStoppedAndConfigurationDriftDenied':True,
            'engineMutationsByProbe':0,'getsPerSuccessfulProbe':4,
            'independentAdmissionProfilesAndReceiptSynthetic':True,
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'applicationE2EProven':False},sort_keys=True))
    finally:
        for cid in ids:subprocess.run(['docker','rm','-f',cid],capture_output=True,timeout=15)
        __import__('shutil').rmtree(root)

if __name__=='__main__':main()
