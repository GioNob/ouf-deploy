"""Real API1.44 legacy Config MAC lifecycle; disposable CI containers only."""
import copy,http.client,importlib.util,json,socket,subprocess,uuid
from pathlib import Path
s=importlib.util.spec_from_file_location('mac',Path(__file__).resolve().parents[1]/'tools/acquisition_read_native/retained_mac.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Unix(http.client.HTTPConnection):
    def connect(self):self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(15);self.sock.connect('/var/run/docker.sock')
def api(method,path,body=None):
    c=Unix('ci-local-engine',timeout=15)
    try:
        c.request(method,'/v1.44'+path,None if body is None else json.dumps(body).encode(),{'Content-Type':'application/json'});r=c.getresponse();raw=r.read(1048577);assert len(raw)<=1048576 and r.status in(200,201,204),(r.status,raw[:500]);return json.loads(raw)if raw else None
    finally:c.close()
def cli(*args):return subprocess.check_output(['docker',*args],stderr=subprocess.PIPE,text=True).strip()
def qualify(mode):
    net='ouf-legacy-mac-'+uuid.uuid4().hex[:12];ids=[]
    try:
        image=cli('image','inspect','busybox:1.37.0','--format','{{.Id}}');nid=cli('network','create',net);name='ouf-legacy-old-'+uuid.uuid4().hex[:12];mac='02:42:ac:44:01:07'
        request={'Image':image,'Cmd':['sleep','120'],'HostConfig':{'NetworkMode':net,'RestartPolicy':{'Name':'no','MaximumRetryCount':0}},'NetworkingConfig':{'EndpointsConfig':{net:{'NetworkID':nid,'MacAddress':mac}}}}
        if mode=='EXPLICIT_LEGACY_CONFIG':request['MacAddress']=mac
        old=api('POST','/containers/create?name='+name,request)['Id'];ids.append(old);api('POST','/containers/'+old+'/start');before=api('GET','/containers/'+old+'/json')
        assert before['Config'].get('MacAddress')==mac,'NATIVE_LEGACY_CONFIG_MAC_NOT_REPRESENTED';assert before['NetworkSettings']['Networks'][net]['MacAddress']==mac
        api('POST','/containers/'+old+'/stop?t=2');api('POST','/networks/'+nid+'/disconnect',{'Container':old,'Force':False});after=api('GET','/containers/'+old+'/json')
        assert before['Id']==after['Id']and before['Image']==after['Image']and before['Mounts']==after['Mounts']and before['State']['StartedAt']==after['State']['StartedAt'],'NATIVE_OLD_IDENTITY_FRAME_DRIFT'
        if mode=='ENDPOINT_ONLY_COMPAT_CONFIG':
            assert'MacAddress'not in after['Config'],'NATIVE_ENDPOINT_COMPAT_MAC_ABSENCE_NOT_REPRODUCED';proof=m.verify_detached(before,after,expected_name='/'+name)['profile']
        else:
            assert after['Config']==before['Config'],'NATIVE_EXPLICIT_LEGACY_CONFIG_CHANGED';assert after['NetworkSettings']['Networks']=={};assert after['State']['Running']is False and after['State']['StartedAt']==before['State']['StartedAt'];proof='UNCHANGED_EXPLICIT_LEGACY_CONFIG'
        api('POST','/containers/'+old+'/rename?name='+name+'-retained');replacement=copy.deepcopy(request);replacement.pop('MacAddress',None);new=api('POST','/containers/create?name='+name,replacement)['Id'];ids.append(new);api('POST','/containers/'+new+'/start');actual=api('GET','/containers/'+new+'/json');assert actual['NetworkSettings']['Networks'][net]['MacAddress']==mac;assert api('GET','/containers/'+old+'/json')['State']['Running']is False
        print(json.dumps({'schema':'ouf.synthetic-legacy-mac-lifecycle-ci.v1','complete':True,'creationProfile':mode,'legacyConfigMacInitiallyPresent':True,'legacyConfigMacAbsentAfterStopDetach':'MacAddress'not in after['Config'],'sameOldCidImageMountsStartedAt':before['Id']==after['Id']and before['Image']==after['Image']and before['Mounts']==after['Mounts']and before['State']['StartedAt']==after['State']['StartedAt'],'newEndpointMacPreserved':True,'oldRetainedStopped':True,'strictProjectionVerified':proof,'productionRuntimeAccess':False}),flush=True)
    finally:
        for cid in ids:subprocess.run(['docker','rm','-f',cid],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
        subprocess.run(['docker','network','rm',net],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
cli('pull','busybox:1.37.0')
for mode in('EXPLICIT_LEGACY_CONFIG','ENDPOINT_ONLY_COMPAT_CONFIG'):qualify(mode)
