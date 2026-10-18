"""Real Docker29 endpoint moves/restart; synthetic HTTP services, no OUF authority."""
import copy,importlib.util,ipaddress,json,os,re,subprocess,tempfile,time,unittest,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('network_owner',ROOT/'tools/host_network_reconciliation.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
spec=importlib.util.spec_from_file_location('network_bootstrap',ROOT/'scripts/reconcile-host-network-20261018.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
@unittest.skipUnless(os.environ.get('OUF_NETWORK_NATIVE_TEST')=='1','isolated Docker fixture only')
class Native(unittest.TestCase):
 def start_fixture_daemon(self,root):
  # A stopped transient systemd-run unit is collected; recreate the same
  # isolated test unit rather than trying to start a unit that no longer exists.
  args=['systemd-run','--unit=ouf-network-contract-daemon','--property=Restart=no','--setenv=PATH=/opt/ouf-network-docker-29:/usr/sbin:/usr/bin:/sbin:/bin','/opt/ouf-network-docker-29/dockerd','--config-file=/tmp/ouf-network-contract-daemon.json','--host=unix:///var/run/docker.sock','--data-root='+str(root),'--exec-root=/run/docker','--pidfile=/run/ouf-network-contract.pid','--containerd=/run/containerd/containerd.sock']
  deadline=time.monotonic()+10
  while True:
   state=subprocess.run(['systemctl','show','--property=LoadState','--value','ouf-network-contract-daemon'],capture_output=True,text=True,timeout=3)
   if state.stdout.strip()=='not-found':break
   if time.monotonic()>=deadline:raise AssertionError('isolated transient unit not collected')
   time.sleep(0.2)
  r=subprocess.run(args,capture_output=True,timeout=45);self.assertEqual(r.returncode,0,'isolated fixture unit recreation failed')
 def cli(self,*args):
  r=subprocess.run(['docker',*args],stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=90)
  self.assertEqual(r.returncode,0,'fixture command failed: '+args[0]);return r.stdout.strip()
 def inspect(self,cid):return json.loads(self.cli('inspect',cid))[0]
 def test_native_cold_load_initializes_legacy_null_dns_to_empty_only(self):
  root=Path(self.cli('info','--format','{{.DockerRootDir}}'));self.assertRegex(str(root),r'^/var/lib/ouf-network-contract-[0-9]+$');self.assertEqual(self.cli('version','--format','{{.Server.Version}}'),'29.8.1')
  self.cli('pull','busybox:1.37.0');cid=self.cli('create','--name','ouf-dns-representation-'+os.environ['GITHUB_RUN_ID'],'--network','none','busybox:1.37.0','sleep','3600');self.assertRegex(cid,r'^[a-f0-9]{64}$')
  stopped=False
  try:
   api=m.Engine('/var/run/docker.sock','29.8.1');before=api.get('/containers/'+cid+'/json')
   # Model an old persisted null field in this dedicated, non-OUF CI daemon.
   # No production path or installed host is eligible for this fixture.
   r=subprocess.run(['systemctl','stop','ouf-network-contract-daemon'],capture_output=True,timeout=45);self.assertEqual(r.returncode,0);stopped=True
   path=root/'containers'/cid/'hostconfig.json';self.assertTrue(path.is_file());persisted=json.loads(path.read_bytes());persisted['Dns']=None
   raw=json.dumps(persisted,sort_keys=True,separators=(',',':')).encode();fd,name=tempfile.mkstemp(prefix='.fixture-null-dns-',dir=path.parent)
   with os.fdopen(fd,'wb')as stream:os.fchmod(stream.fileno(),0o600);stream.write(raw);stream.flush();os.fsync(stream.fileno())
   os.replace(name,path);before['HostConfig']['Dns']=None
   self.start_fixture_daemon(root);stopped=False
   deadline=time.monotonic()+30
   while True:
    try:fresh=m.Engine('/var/run/docker.sock','29.8.1');after=fresh.get('/containers/'+cid+'/json');break
    except (OSError,ValueError):
     if time.monotonic()>=deadline:raise
     time.sleep(0.2)
   self.assertEqual(after['HostConfig']['Dns'],[]);proof=b.preboot_application_proof(before,after,m);self.assertTrue(proof['emptyDnsRepresentationOnly']);self.assertEqual(before['Id'],after['Id']);self.assertFalse(after['State']['Running'])
   after['HostConfig']['Dns']=['192.0.2.53']
   with self.assertRaises(ValueError):b.preboot_application_proof(before,after,m)
   print(json.dumps({'syntheticFixtureOnly':True,'nativeColdLoadNullToEmptyDnsProven':True,'actualDaemonVersion':'29.8.1','nonemptyDnsRejected':True,'targetMutations':0},sort_keys=True))
  finally:
   if stopped:self.start_fixture_daemon(root)
   subprocess.run(['docker','rm','-f',cid],capture_output=True,timeout=20)
 def test_real_collision_correction_dns_secondary_network_and_daemon_restart(self):
  root=self.cli('info','--format','{{.DockerRootDir}}');self.assertRegex(root,r'^/var/lib/ouf-network-contract-[0-9]+$');self.assertEqual(self.cli('version','--format','{{.Server.Version}}'),'29.8.1')
  prefix='ouf-network-'+os.environ['GITHUB_RUN_ID'];containers=[];networks=[];payload=tempfile.TemporaryDirectory(dir='/root');data=Path(payload.name)/'data';data.mkdir(mode=0o700);(data/'canary').write_text('retained fixture payload')
  try:
   backend=self.cli('network','create','--internal',prefix+'-backend');networks.append(backend)
   control=self.cli('network','create',prefix+'-control');networks.append(control)
   net=json.loads(self.cli('network','inspect',backend))[0];subnet=ipaddress.IPv4Network(net['IPAM']['Config'][0]['Subnet']);gateway=net['IPAM']['Config'][0]['Gateway'];old=str(subnet.network_address+2)
   self.cli('pull','busybox:1.37.0');image=self.cli('image','inspect','--format','{{.Id}}','busybox:1.37.0')
   app=self.cli('create','--name',prefix+'-application','--restart','unless-stopped','--network',net['Name'],'--ip',old,image,'sleep','3600');containers.append(app)
   self.cli('start',app);self.cli('stop','--time','1',app)
   gw=self.cli('run','-d','--name',prefix+'-gateway','--restart','unless-stopped','--network',prefix+'-control',image,'sh','-c','mkdir -p /www; echo fixture > /www/index.html; exec httpd -f -p 8000 -h /www');containers.append(gw)
   self.cli('network','connect',net['Name'],gw)
   store=self.cli('run','-d','--name',prefix+'-store','--restart','unless-stopped','--network',net['Name'],'--volume',str(data)+':/data:rw',image,'sh','-c','echo fixture > /data/index.html; exec httpd -f -p 8000 -h /data');containers.append(store)
   client=self.cli('run','-d','--name',prefix+'-client','--restart','unless-stopped','--network',net['Name'],'--publish','127.0.0.1:18080:8000',image,'sh','-c','mkdir -p /www; echo fixture > /www/index.html; exec httpd -f -p 8000 -h /www');containers.append(client);self.cli('network','connect',prefix+'-control',client)
   rows=[self.inspect(cid)for cid in (gw,store,app)];self.assertEqual(rows[0]['NetworkSettings']['Networks'][net['Name']]['IPAddress'],old)
   p={'schema':'ouf.host-network-reconciliation.v1','engineVersion':'29.8.1','socketPath':'/var/run/docker.sock','maximumContainers':128,'configurationOwnerUids':[0], 'network':{'id':backend,'name':net['Name'],'subnet':str(subnet),'gateway':gateway,'internal':True},'reservedIPv4':[old,rows[1]['NetworkSettings']['Networks'][net['Name']]['IPAddress']],'moves':[],'restart':{'containerId':app,'imageId':image,'name':prefix+'-application'}}
   for row,index in zip(rows[:2],(15,16)):
    p['moves'].append({'containerId':row['Id'],'imageId':row['Image'],'name':row['Name'][1:],'oldIPv4':row['NetworkSettings']['Networks'][net['Name']]['IPAddress'],'newIPv4':str(subnet.network_address+index),'servicePorts':[8000],'configurationDestinations':[]})
   client_row=self.inspect(client);client_ip=client_row['NetworkSettings']['Networks'][net['Name']]['IPAddress'];p['moves'].append({'containerId':client,'imageId':image,'name':client_row['Name'][1:],'oldIPv4':client_ip,'newIPv4':client_ip,'servicePorts':[8000],'configurationDestinations':[]})
   print(json.dumps({'syntheticFixtureOnly':True,'beforePublishedPorts':self.inspect(client)['NetworkSettings']['Ports']},sort_keys=True))
   self.assertEqual(urllib.request.urlopen('http://127.0.0.1:18080',timeout=5).read().strip(),b'fixture','initial fixture published port must work before correction')
   api=m.Engine(p['socketPath'],p['engineVersion']);original_write=api.write;write_count=[0]
   def lost_response(path,value):
    original_write(path,value);write_count[0]+=1
    if write_count[0]in (1,2):raise TimeoutError('synthetic response loss after real effect')
   api.write=lost_response
   plan=m.compile_plan(p,api,lambda r,p:None);claims=[]
   try:result=m.apply(plan,api,lambda name,request:claims.append(name))
   except Exception:
    for move in plan['moves']:
     actual=api.get('/containers/'+move['pin']['containerId']+'/json');before=move['before'];changed={}
     for field in ('Config','HostConfig'):
      changed[field]={key:{'before':before[field].get(key),'after':actual[field].get(key)}for key in set(before[field])|set(actual[field])if before[field].get(key)!=actual[field].get(key)}
     print(json.dumps({'syntheticFixtureOnly':True,'claims':claims,'role':move['pin']['name'],'changedConfiguration':changed,'beforeOther':{key:val for key,val in before['NetworkSettings']['Networks'].items()if key!=net['Name']},'afterOther':{key:val for key,val in actual['NetworkSettings']['Networks'].items()if key!=net['Name']},'processPreserved':m.process(actual)==m.process(before)},sort_keys=True))
    raise
   self.assertTrue(result['complete']);self.assertEqual(len(claims),7);self.assertEqual(write_count[0],7)
   for before in rows[:2]:
    after=self.inspect(before['Id']);self.assertEqual(after['State']['Pid'],before['State']['Pid']);self.assertEqual(after['State']['StartedAt'],before['State']['StartedAt']);self.assertEqual(after['Mounts'],before['Mounts'])
   self.assertEqual(self.inspect(gw)['NetworkSettings']['Networks'][prefix+'-control'],rows[0]['NetworkSettings']['Networks'][prefix+'-control'])
   for role in ('gateway','store'):self.assertEqual(self.cli('exec',client,'wget','-q','-T','5','-O','-','http://'+prefix+'-'+role+':8000'),'fixture')
   self.assertEqual(self.cli('exec',store,'cat','/data/canary'),'retained fixture payload');self.assertEqual(urllib.request.urlopen('http://127.0.0.1:18080',timeout=5).read().strip(),b'fixture')
   # Fresh transport required after daemon restart; no old socket binding is adopted.
   r=subprocess.run(['systemctl','restart','ouf-network-contract-daemon'],capture_output=True,timeout=90);self.assertEqual(r.returncode,0,'fixture daemon restart failed')
   deadline=time.monotonic()+30
   while time.monotonic()<deadline:
    probes=[subprocess.run(['docker','inspect',cid],capture_output=True,text=True,timeout=3)for cid in containers]
    if all(reply.returncode==0 and json.loads(reply.stdout)[0]['State']['Running']for reply in probes):break
    time.sleep(0.2)
   else:self.fail('fixture daemon did not restore all selected containers within30seconds')
   with self.assertRaisesRegex(ValueError,'ENGINE_SOCKET_REPLACED'):api.get('/containers/'+app+'/json')
   for cid,pin in [(gw,p['moves'][0]),(store,p['moves'][1])]:
    after=self.inspect(cid);self.assertTrue(after['State']['Running']);e=after['NetworkSettings']['Networks'][net['Name']];self.assertEqual(e['IPAddress'],pin['newIPv4']);self.assertEqual(e['IPAMConfig'],{'IPv4Address':pin['newIPv4']})
   self.assertTrue(self.inspect(app)['State']['Running']);self.assertEqual(self.inspect(app)['NetworkSettings']['Networks'][net['Name']]['IPAddress'],old)
   for role in ('gateway','store'):self.assertEqual(self.cli('exec',client,'wget','-q','-T','5','-O','-','http://'+prefix+'-'+role+':8000'),'fixture')
   self.assertEqual(self.cli('exec',store,'cat','/data/canary'),'retained fixture payload');self.assertEqual(urllib.request.urlopen('http://127.0.0.1:18080',timeout=5).read().strip(),b'fixture')
  finally:
   for cid in reversed(containers):
    if re.fullmatch('[a-f0-9]{64}',cid):subprocess.run(['docker','rm','-f',cid],capture_output=True,timeout=20)
   for nid in reversed(networks):
    if re.fullmatch('[a-f0-9]{64}',nid):subprocess.run(['docker','network','rm',nid],capture_output=True,timeout=20)
   payload.cleanup()
if __name__=='__main__':unittest.main()
