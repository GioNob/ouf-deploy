import copy,importlib.util,pathlib,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
def module(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=module('wide',ROOT/'scripts/upgrade-ingestion-wide-20261108.py')
r=module('engine',ROOT/'scripts/upgrade-semantic-application-20261108.py')
mac=module('legacy',ROOT/'tools/acquisition_read_native/retained_mac.py')
APP=['java','-jar','/app/app.jar','--spring.flyway.enabled=false']
def old():
 return {'Id':'a'*64,'Image':'sha256:old','Name':'/fixture','Path':'java','Args':APP[1:],
  'Config':{'MacAddress':'02:42:ac:11:01:01','User':'10002:10002','WorkingDir':'/app',
   'Env':['JAVA_VERSION=old','CREDENTIAL=keep','SPRING_FLYWAY_ENABLED=false'],'Entrypoint':['java'],'Cmd':APP[1:],'Labels':{}},
  'HostConfig':{'NetworkMode':'backend','RestartPolicy':{'Name':'no','MaximumRetryCount':0},'Binds':['/fixture:/run/fixture:ro'],'OomKillDisable':None},
  'Mounts':[{'Type':'bind','RW':False,'Destination':'/run/fixture','Source':'/fixture'}],
  'State':{'Running':True,'Pid':5,'StartedAt':'now'},
  'NetworkSettings':{'Networks':{'backend':{'MacAddress':'02:42:ac:11:01:01','IPAddress':'10.0.1.2','IPAMConfig':None,'Aliases':['ingestion']}}}}
def db():return {'readOnly':True,'databaseOid':21554,'applicationRoleSuperuser':False,'exactCandidateMigrationHistory':True,
 'migrations':[{'version':'18','checksum':1281376280,'installedOn':'fixed'}],
 'activity':{'runStates':{'SUCCEEDED':3},'handoffStates':{'ACKED':34},'unexpiredPartitionLeases':0},
 'retainedRows':{t:{'rows':1,'fingerprint':'a'*32} for t in m.TABLES}}
class Guards(unittest.TestCase):
 def test_request_preserves_bindings_args_and_credentials(self):
  o=old();before=copy.deepcopy(o);req=m.request(o,'sha256:new',APP,mac)
  self.assertEqual(o,before);self.assertNotIn('MacAddress',req);self.assertEqual(req['Cmd'],APP)
  self.assertIn('CREDENTIAL=keep',req['Env']);self.assertIn('JAVA_VERSION=jdk-21.0.13+9',req['Env'])
  self.assertEqual(req['HostConfig']['Binds'],o['HostConfig']['Binds']);ep=req['NetworkingConfig']['EndpointsConfig']['backend']
  self.assertEqual(ep['MacAddress'],o['Config']['MacAddress']);self.assertEqual(ep['IPAMConfig']['IPv4Address'],'10.0.1.2')
 def test_initial_mac_rejects_missing_null_empty_malformed_multicast_zero_mismatch(self):
  for v in (None,'','bad','ff:42:ac:11:01:01','00:00:00:00:00:00','02:42:ac:11:01:99',False):
   o=old();o['Config']['MacAddress']=v
   with self.assertRaises(RuntimeError):m.request(o,'new',APP,mac)
  o=old();o['Config'].pop('MacAddress')
  with self.assertRaises(RuntimeError):m.request(o,'new',APP,mac)
 def test_phase_specific_absence_and_no_other_old_frame_change(self):
  o=old();a=copy.deepcopy(o);a['State'].update(Running=False,Pid=0);a['NetworkSettings']['Networks']={};a['Config'].pop('MacAddress')
  m.detached(mac,o,a,o['Name'])
  for field in ('null','empty','legacy','id','image','mount','started','host','env','hostname','running','endpoint','args','path'):
   b=copy.deepcopy(a)
   if field in ('null','empty','legacy'):b['Config']['MacAddress']={'null':None,'empty':'','legacy':o['Config']['MacAddress']}[field]
   if field=='id':b['Id']='b'*64
   if field=='image':b['Image']='sha256:other'
   if field=='mount':b['Mounts'][0]['Source']='/elsewhere'
   if field=='started':b['State']['StartedAt']='later'
   if field=='host':b['HostConfig']['Privileged']=True
   if field=='env':b['Config']['Env'].append('OTHER=1')
   if field=='hostname':b['Config']['Hostname']='other'
   if field=='running':b['State'].update(Running=True,Pid=10)
   if field=='endpoint':b['NetworkSettings']=copy.deepcopy(o['NetworkSettings'])
   if field=='args':b['Args']=['changed']
   if field=='path':b['Path']='changed'
   with self.assertRaises(RuntimeError,msg=field):m.detached(mac,o,b,o['Name'])
 def test_changed_running_replacement_rejected(self):
  o=old();req=m.request(o,'sha256:new',APP,mac);a=copy.deepcopy(o);a['Id']='b'*64;a['Image']=req['Image']
  a['HostConfig']=copy.deepcopy(req['HostConfig']);a['HostConfig']['OomKillDisable']=None
  a['Config']={k:v for k,v in req.items() if k not in ('HostConfig','NetworkingConfig')};a['Config']['MacAddress']=o['Config']['MacAddress']
  ep=req['NetworkingConfig']['EndpointsConfig']['backend'];a['NetworkSettings']['Networks']['backend']=dict(ep,IPAddress=ep['IPAMConfig']['IPv4Address'],Aliases=ep['Aliases']+[a['Id'][:12]])
  r.verify_replacement(o,req,a,True)
  for mode in ('mac','ip','alias','network','legacy','mount','env'):
   b=copy.deepcopy(a);e=b['NetworkSettings']['Networks']['backend']
   if mode=='mac':e['MacAddress']='02:42:ac:12:99:99'
   if mode=='ip':e['IPAddress']='10.0.2.99'
   if mode=='alias':e['Aliases']=[]
   if mode=='network':b['NetworkSettings']['Networks']['extra']=copy.deepcopy(e)
   if mode=='legacy':b['Config']['MacAddress']=None
   if mode=='mount':b['Mounts'][0]['Source']='/elsewhere'
   if mode=='env':b['Config']['Env'].append('CHANGED=1')
   with self.assertRaises(RuntimeError):r.verify_replacement(o,req,b,True)
 def test_flyway_disabled_both_declarations_required(self):
  for env,app in [({},APP),({'SPRING_FLYWAY_ENABLED':'true'},APP),({'SPRING_FLYWAY_ENABLED':'false'},APP[:-1]),({'SPRING_FLYWAY_ENABLED':'false'},APP+['--spring.flyway.enabled=true'])]:
   with self.assertRaises(RuntimeError):m.app_check(env,app)
 def test_history_work_and_checkpoint_change_rejected(self):
  before=db();m.verify_database(before,'21554');m.verify_database(copy.deepcopy(before),'21554',before)
  for mode in ('oid','role','history','activity','lease','fingerprint','count'):
   v=copy.deepcopy(before)
   if mode=='oid':v['databaseOid']=1
   if mode=='role':v['applicationRoleSuperuser']=True
   if mode=='history':v['migrations'][0]['installedOn']='changed'
   if mode=='activity':v['activity']['runStates']['READY']=1
   if mode=='lease':v['activity']['unexpiredPartitionLeases']=1
   if mode=='fingerprint':v['retainedRows']['ing_partition']['fingerprint']='b'*32
   if mode=='count':v['retainedRows']['handoff_outbox']['rows']=2
   with self.assertRaises(RuntimeError):m.verify_database(v,'21554',before)
if __name__=='__main__':unittest.main(verbosity=2)
