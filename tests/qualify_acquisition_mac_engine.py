"""Synthetic real Engine API1.44 endpoint MAC transfer; no production access."""
import http.client,json,os,socket,subprocess,uuid
class Unix(http.client.HTTPConnection):
    def __init__(self):super().__init__('localhost',timeout=15)
    def connect(self):self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(15);self.sock.connect('/var/run/docker.sock')
def call(method,path,body=None):
    c=Unix()
    try:
        c.request(method,'/v1.44'+path,None if body is None else json.dumps(body),{'Content-Type':'application/json'});r=c.getresponse();raw=r.read(1048577);assert len(raw)<=1048576 and 200<=r.status<300,(r.status,raw[:1000]);return json.loads(raw)if raw else None
    finally:c.close()
def cli(*args):return subprocess.check_output(['docker',*args],stderr=subprocess.STDOUT,text=True).strip()
network='ouf-mac-fixture-'+uuid.uuid4().hex[:12];containers=[]
try:
    cli('pull','busybox:1.37.0');image=cli('image','inspect','busybox:1.37.0','--format','{{.Id}}');nid=cli('network','create',network)
    def create(mac=None):
        ep={'NetworkID':nid};
        if mac:ep['MacAddress']=mac
        value=call('POST','/containers/create',{'Image':image,'Cmd':['sleep','120'],'HostConfig':{'NetworkMode':network,'RestartPolicy':{'Name':'no'},'ReadonlyRootfs':True,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges:true']},'NetworkingConfig':{'EndpointsConfig':{network:ep}}});cid=value['Id'];containers.append(cid);call('POST','/containers/'+cid+'/start');return cid
    mac='02:42:ac:44:01:07';old=create(mac);read_a=create();read_b=create()
    def inspect(cid):return call('GET','/containers/'+cid+'/json')
    def endpoint(cid):return inspect(cid)['NetworkSettings']['Networks'][network]
    assert endpoint(old)['MacAddress']==mac
    assert len({endpoint(cid)['MacAddress']for cid in(old,read_a,read_b)})==3
    assert inspect(old)['State']['Running']is True
    call('POST','/containers/'+old+'/stop?t=2');call('POST','/networks/'+nid+'/disconnect',{'Container':old,'Force':False})
    replacement=create(mac);assert endpoint(replacement)['MacAddress']==mac;assert inspect(old)['State']['Running']is False;assert not inspect(old)['NetworkSettings']['Networks']
    print(json.dumps({'schema':'ouf.synthetic-engine-endpoint-mac-qualification.v1','complete':True,'apiVersion':'1.44','fixtureImageId':image,'readReplicaMacsDistinct':True,'originalUnchangedWhileReadReplicasStart':True,'retainedMcpMacTransferAfterStopAndDetach':True,'productionRuntimeAccess':False}))
finally:
    for cid in reversed(containers):
        subprocess.run(['docker','rm','-f',cid],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
    subprocess.run(['docker','network','rm',network],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
