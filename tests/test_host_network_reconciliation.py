import copy,importlib.util,io,json,tempfile,types,unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
m=load('network_owner',ROOT/'tools/host_network_reconciliation.py')
b=load('network_bootstrap',ROOT/'scripts/reconcile-host-network-20261018.py')
def fixture():
 network={'name':'fixture-net','id':'9'*64,'subnet':'10.80.0.0/24','gateway':'10.80.0.1','internal':True}
 def row(letter,name,ip,static=False,running=True,other=False):
  e={'NetworkID':network['id'],'IPAddress':ip if running else'','IPAMConfig':{'IPv4Address':ip}if static else None,'Aliases':[name],'MacAddress':'02:00:00:00:00:'+letter*2,'DriverOpts':None,'GwPriority':0,'Links':None}
  return {'Id':letter*64,'Image':'sha256:'+'f'*64,'Name':'/'+name,'Config':{'Env':['PASSWORD=SECRET_CANARY']},'HostConfig':{'NetworkMode':network['name'],'RestartPolicy':{'Name':'unless-stopped'},'Privileged':False,'AutoRemove':False},'Mounts':[],'State':{'Running':running,'Paused':False,'Restarting':False,'Dead':False,'Pid':100 if running else 0,'StartedAt':'fixture'},'NetworkSettings':{'Networks':{network['name']:e,**({'control':{'NetworkID':'8'*64,'IPAddress':'10.90.0.2'}}if other else{})}}}
 rows=[row('a','gateway','10.80.0.5',other=True),row('b','store','10.80.0.6'),row('c','application','10.80.0.5',static=True,running=False),row('d','independent','10.80.0.7',static=True)]
 p={'schema':'ouf.host-network-reconciliation.v1','engineVersion':'fixture','socketPath':'/fixture.sock','network':network,'maximumContainers':128,'configurationOwnerUids':[0], 'reservedIPv4':['10.80.0.5','10.80.0.6'],'moves':[],'restart':{k:rows[2][v]for k,v in [('containerId','Id'),('imageId','Image')]}}
 p['restart']['name']='application'
 for i,new in [(0,'10.80.0.15'),(1,'10.80.0.16')]:
  p['moves'].append({'containerId':rows[i]['Id'],'imageId':rows[i]['Image'],'name':rows[i]['Name'][1:],'oldIPv4':rows[i]['NetworkSettings']['Networks'][network['name']]['IPAddress'],'newIPv4':new,'servicePorts':[9000],'configurationDestinations':[]})
 class API:
  def __init__(self):self.rows={r['Id']:r for r in copy.deepcopy(rows)};self.writes=[];self.fail_after=None;self.fail_before=None;self.pin=(1,2,0,0,0o660)
  def get(self,path):
   if path.startswith('/networks/'):return {'Id':network['id'],'Name':network['name'],'Driver':'bridge','Internal':True,'EnableIPv6':False,'IPAM':{'Driver':'default','Config':[{'Subnet':network['subnet'],'Gateway':network['gateway']}]}}
   if path=='/containers/json?all=1':return [{'Id':cid}for cid in self.rows]
   return copy.deepcopy(self.rows[path.split('/')[2]])
  def write(self,path,value):
   self.writes.append(path)
   if self.fail_before==len(self.writes):raise TimeoutError('SECRET_CANARY')
   cid=value['Container']if value else path.split('/')[2];r=self.rows[cid]
   if path.endswith('/disconnect'):r['NetworkSettings']['Networks'].pop(network['name'])
   elif path.endswith('/connect'):
    cfg=value['EndpointConfig'];r['NetworkSettings']['Networks'][network['name']]={'NetworkID':network['id'],'IPAddress':cfg['IPAMConfig']['IPv4Address'],**copy.deepcopy(cfg),'GwPriority':0}
   else:
    r['State'].update(Running=True,Pid=300);r['NetworkSettings']['Networks'][network['name']]['IPAddress']=r['NetworkSettings']['Networks'][network['name']]['IPAMConfig']['IPv4Address']
   if self.fail_after==len(self.writes):raise TimeoutError('SECRET_CANARY')
 return p,API(),rows
class Plan(unittest.TestCase):
 def test_exact_five_effects_preserve_processes_control_network_and_independent(self):
  p,api,rows=fixture();before=copy.deepcopy(rows);claims=[];plan=m.compile_plan(p,api,lambda r,p:None)
  result=m.apply(plan,api,lambda name,request:claims.append((name,m.digest(request))))
  self.assertTrue(result['complete']);self.assertEqual(len(api.writes),5);self.assertEqual(len(claims),5)
  self.assertEqual(api.rows[rows[0]['Id']]['State'],before[0]['State']);self.assertEqual(api.rows[rows[0]['Id']]['NetworkSettings']['Networks']['control'],before[0]['NetworkSettings']['Networks']['control']);self.assertEqual(api.rows[rows[3]['Id']],before[3])
  self.assertNotIn('SECRET_CANARY',json.dumps(result));self.assertFalse(result['applicationReadinessProven'])
 def test_reservations_include_stopped_containers(self):
  p,api,_=fixture();api.rows['d'*64]['NetworkSettings']['Networks']['fixture-net']['IPAMConfig']={'IPv4Address':'10.80.0.15'}
  with self.assertRaisesRegex(ValueError,'ALREADY_OWNED'):m.compile_plan(p,api,lambda r,p:None)
  self.assertEqual(api.writes,[])
 def test_nonmatching_identity_configuration_or_endpoint_prevents_effects(self):
  for change in ('identity','static','ip','paused','network'):
   p,api,_=fixture();r=api.rows['a'*64]
   if change=='identity':r['Image']='sha256:'+'e'*64
   if change=='static':r['NetworkSettings']['Networks']['fixture-net']['IPAMConfig']={'IPv4Address':'10.80.0.5'}
   if change=='ip':r['NetworkSettings']['Networks']['fixture-net']['IPAddress']='10.80.0.99'
   if change=='paused':r['State']['Paused']=True
   if change=='network':r['HostConfig']['NetworkMode']='host'
   with self.subTest(change=change),self.assertRaises(ValueError):m.compile_plan(p,api,lambda r,p:None)
   self.assertEqual(api.writes,[])
 def test_lost_disconnect_or_connect_response_never_replayed(self):
  for after in (1,2,3,4,5):
   p,api,_=fixture();plan=m.compile_plan(p,api,lambda r,p:None);api.fail_after=after;claims=[]
   with self.subTest(after=after):result=m.apply(plan,api,lambda n,r:claims.append(n))
   self.assertTrue(result['complete']);self.assertEqual(len(api.writes),5);self.assertEqual(len(claims),5)
 def test_changed_other_network_or_mount_after_compile_blocks_before_write(self):
  for change in ('network','mount'):
   p,api,_=fixture();plan=m.compile_plan(p,api,lambda r,p:None)
   if change=='network':api.rows['a'*64]['NetworkSettings']['Networks']['control']['IPAddress']='10.90.0.9'
   else:api.rows['a'*64]['Mounts']=[{'Source':'changed'}]
   with self.assertRaises(ValueError):m.apply(plan,api,lambda n,r:None)
   self.assertEqual(api.writes,[])
 def test_profile_does_not_invent_subnets_or_duplicate_destinations(self):
  for change in ('reserved','duplicate','outside','unknown'):
   p,api,_=fixture()
   if change=='reserved':p['moves'][0]['newIPv4']='10.80.0.6'
   if change=='duplicate':p['moves'][1]['newIPv4']=p['moves'][0]['newIPv4']
   if change=='outside':p['moves'][0]['newIPv4']='10.90.0.15'
   if change=='unknown':p['ignoredSecurityOverride']=True
   with self.assertRaises(ValueError):m.compile_plan(p,api,lambda r,p:None)
   self.assertEqual(api.writes,[])
 def test_literal_moving_service_reference_is_blocked_but_dns_is_preserved(self):
  p,_,_=fixture();b.reject_literal_dependencies(b'http://gateway:9000',p,m)
  for raw in (b'http://10.80.0.5:9000',b'upstream=10.80.0.6'):
   with self.assertRaises(ValueError):b.reject_literal_dependencies(raw,p,m)
class Bootstrap(unittest.TestCase):
 def setup_case(self):
  temp=tempfile.TemporaryDirectory(dir='/root');self.addCleanup(temp.cleanup);root=Path(temp.name);root.chmod(0o700)
  lock=root/'common.lock';lock.write_bytes(b'');lock.chmod(0o600)
  p,api,rows=fixture();selection={'dockerUnit':'docker','guardUnit':'guard'}
  report={'readComplete':True,'knownBootSource':True,'compilerMatchesProfile':True,'restorerMatchesProfile':True,'nftExecutableMatches':True,'units':{'docker':{'ActiveState':'active'},'guard':{'Result':'success'}},'ownerJournal':{'passed':True,'metadata':{'leaseAuthorized':False,'startAuthorized':False,'state':'QUIESCED'}},'bootJournal':{'passed':True,'metadata':{'startAuthorized':False,'state':'RUNTIME_EMPTY'}},'loadedBinding':{'profile':'fixture-boot','sha256':'a'*64}}
  reader=types.SimpleNamespace(collect=lambda _:copy.deepcopy(report),parse=json.loads,sealed=lambda path,h:json.dumps({'coordinatedConfiguration':'fixture-owner','coordinatedConfigurationHash':'b'*64}if path=='fixture-boot'else{'commonLockFile':str(lock)}).encode())
  contracts=types.SimpleNamespace(collect=lambda _:{'complete':True},read=lambda _:{'beforeApplications':{'udp':copy.deepcopy(rows[2])}})
  return root,p,api,reader,contracts,selection,report
 def test_real_private_journal_claims_and_no_relaunch(self):
  root,p,api,reader,contracts,selection,_=self.setup_case();pointer=root/'incident.json';out=io.StringIO()
  with patch.object(m,'Engine',return_value=api),redirect_stdout(out):result=b.run(m,reader,contracts,p,selection,{'preparedPlan':{'path':'fixture','sha256':'f'*64}},root,pointer)
  self.assertTrue(result['complete']);journal=json.loads((Path(result['contextPath'])/'journal.json').read_bytes());self.assertEqual(journal['state'],'COMPLETE');self.assertEqual(len(journal['claims']),5);self.assertNotIn('SECRET_CANARY',out.getvalue());self.assertEqual(pointer.stat().st_mode&0o777,0o600)
  before=len(api.writes)
  with self.assertRaisesRegex(ValueError,'INCIDENT_EXISTS'):b.run(m,reader,contracts,p,selection,{},root,pointer)
  self.assertEqual(len(api.writes),before)
 def test_ambiguous_effect_remains_fenced_in_persistent_incident(self):
  root,p,api,reader,contracts,selection,_=self.setup_case();api.fail_before=1
  with patch.object(m,'Engine',return_value=api),redirect_stdout(io.StringIO()):result=b.run(m,reader,contracts,p,selection,{'preparedPlan':{'path':'fixture','sha256':'f'*64}},root,root/'incident.json')
  self.assertFalse(result['complete']);self.assertEqual(result['writesClaimed'],1);self.assertNotIn('SECRET_CANARY',json.dumps(result));journal=json.loads((Path(result['contextPath'])/'journal.json').read_bytes());self.assertEqual(journal['state'],'STOPPED');self.assertEqual(len(api.writes),1)
 def test_active_native_provider_authority_blocks_before_engine_or_private_claim(self):
  root,p,api,reader,contracts,selection,report=self.setup_case();report['ownerJournal']['metadata']['leaseAuthorized']=True
  with patch.object(m,'Engine',return_value=api),self.assertRaises(ValueError):b.run(m,reader,contracts,p,selection,{},root,root/'incident.json')
  self.assertEqual(api.writes,[]);self.assertFalse((root/'incident.json').exists())
if __name__=='__main__':unittest.main()
