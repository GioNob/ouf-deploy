"""Real Docker29 endpoint moves/restart; synthetic HTTP services, no OUF authority."""
import importlib.util,ipaddress,json,os,re,subprocess,tempfile,time,unittest,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('network_owner',ROOT/'tools/host_network_reconciliation.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
@unittest.skipUnless(os.environ.get('OUF_NETWORK_NATIVE_TEST')=='1','isolated Docker fixture only')
class Native(unittest.TestCase):
 def cli(self,*args):
  r=subprocess.run(['docker',*args],stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=90)
  self.assertEqual(r.returncode,0,'fixture command failed: '+args[0]);return r.stdout.strip()
 def inspect(self,cid):return json.loads(self.cli('inspect',cid))[0]
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
   store=self.cli('run','-d','--name',prefix+'-store','--restart','unless-stopped','--network',net['Name'],'--publish','127.0.0.1:18080:8000','--volume',str(data)+':/data:rw',image,'sh','-c','echo fixture > /data/index.html; exec httpd -f -p 8000 -h /data');containers.append(store)
   client=self.cli('run','-d','--name',prefix+'-client','--restart','unless-stopped','--network',net['Name'],image,'sleep','3600');containers.append(client)
   rows=[self.inspect(cid)for cid in (gw,store,app)];self.assertEqual(rows[0]['NetworkSettings']['Networks'][net['Name']]['IPAddress'],old)
   p={'schema':'ouf.host-network-reconciliation.v1','engineVersion':'29.8.1','socketPath':'/var/run/docker.sock','maximumContainers':128,'configurationOwnerUids':[0], 'network':{'id':backend,'name':net['Name'],'subnet':str(subnet),'gateway':gateway,'internal':True},'reservedIPv4':[old,rows[1]['NetworkSettings']['Networks'][net['Name']]['IPAddress']],'moves':[],'restart':{'containerId':app,'imageId':image,'name':prefix+'-application'}}
   for row,index in zip(rows[:2],(15,16)):
    p['moves'].append({'containerId':row['Id'],'imageId':row['Image'],'name':row['Name'][1:],'oldIPv4':row['NetworkSettings']['Networks'][net['Name']]['IPAddress'],'newIPv4':str(subnet.network_address+index),'servicePorts':[8000],'configurationDestinations':[]})
   client_row=self.inspect(client);client_ip=client_row['NetworkSettings']['Networks'][net['Name']]['IPAddress'];p['moves'].append({'containerId':client,'imageId':image,'name':client_row['Name'][1:],'oldIPv4':client_ip,'newIPv4':client_ip,'servicePorts':[8000],'configurationDestinations':[]})
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
    if all(self.inspect(cid)['State']['Running']for cid in containers):break
    time.sleep(0.2)
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
