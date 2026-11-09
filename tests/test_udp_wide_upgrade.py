import copy,importlib.util,pathlib,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
def module(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=module('onb_upgrade',ROOT/'scripts/upgrade-udp-wide-20261109.py')
mac=module('legacy',ROOT/'tools/acquisition_read_native/retained_mac.py')
def old():
 return {'Id':'a'*64,'Image':'sha256:old','Name':'/fixture','Path':'java','Args':['-jar','/app/app.jar'],
  'Config':{'MacAddress':'02:42:ac:11:01:01','User':'10004:10004','WorkingDir':'/app','Env':['JAVA_VERSION=old','CREDENTIAL=keep'],
            'Entrypoint':['java'],'Cmd':['-jar','/app/app.jar'],'Labels':{}},
  'HostConfig':{'NetworkMode':m.BACKEND,'RestartPolicy':{'Name':'no','MaximumRetryCount':0},'Binds':['/fixture:/run/fixture:ro'],'OomKillDisable':None},
  'Mounts':[{'Type':'bind','RW':False,'Destination':'/run/fixture','Source':'/fixture'}],
  'State':{'Running':True,'Pid':5,'StartedAt':'now'},
  'NetworkSettings':{'Networks':{m.BACKEND:{'MacAddress':'02:42:ac:11:01:01','IPAddress':'10.0.1.2','IPAMConfig':None,'Aliases':['onboarding']},
                               m.PRIVATE:{'MacAddress':'02:42:ac:12:01:01','IPAddress':'10.0.2.2','IPAMConfig':None,'Aliases':['onboarding-storage']}}}}
class Guards(unittest.TestCase):
 def test_request_preserves_both_endpoints_and_credentials(self):
  o=old();before=copy.deepcopy(o);r=m.request(o,'sha256:new',['java','-jar','/app/app.jar','--keep=value'],mac)
  self.assertEqual(o,before);self.assertNotIn('MacAddress',r)
  self.assertIn('CREDENTIAL=keep',r['Env']);self.assertIn('JAVA_VERSION=jdk-21.0.13+9',r['Env'])
  self.assertEqual(r['HostConfig']['Binds'],o['HostConfig']['Binds'])
  for n,e in r['NetworkingConfig']['EndpointsConfig'].items():
   self.assertEqual(e['MacAddress'],o['NetworkSettings']['Networks'][n]['MacAddress'])
   self.assertEqual(e['IPAMConfig']['IPv4Address'],o['NetworkSettings']['Networks'][n]['IPAddress'])
 def test_initial_mac_rejects_missing_empty_null_wrong_multicast_duplicate(self):
  for v in (None,'','ff:42:ac:11:01:01','00:00:00:00:00:00','02:42:ac:11:01:99',False):
   o=old();o['Config']['MacAddress']=v
   with self.assertRaises(RuntimeError):m.two_network_policy(o,mac)
  for mode in ('absent','private','duplicate','one-net'):
   o=old()
   if mode=='absent':o['Config'].pop('MacAddress')
   if mode=='private':o['Config']['MacAddress']=o['NetworkSettings']['Networks'][m.PRIVATE]['MacAddress']
   if mode=='duplicate':o['NetworkSettings']['Networks'][m.PRIVATE]['MacAddress']=o['Config']['MacAddress']
   if mode=='one-net':o['NetworkSettings']['Networks'].pop(m.PRIVATE)
   with self.assertRaises(RuntimeError):m.two_network_policy(o,mac)
 def test_phase_specific_absence_and_no_other_old_frame_change(self):
  o=old();a=copy.deepcopy(o);a['State'].update(Running=False,Pid=0)
  m.old_guard(o,a,[m.BACKEND,m.PRIVATE],o['Name'],mac)
  a['NetworkSettings']['Networks'].pop(m.PRIVATE);m.old_guard(o,a,[m.BACKEND],o['Name'],mac)
  bad=copy.deepcopy(a);bad['Config'].pop('MacAddress')
  with self.assertRaises(RuntimeError):m.old_guard(o,bad,[m.BACKEND],o['Name'],mac)
  a['NetworkSettings']['Networks']={};a['Config'].pop('MacAddress');m.old_guard(o,a,[],o['Name'],mac)
  for field in ('null','empty','legacy','id','image','mount','started','host','env','hostname','running','endpoint','args'):
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
   with self.assertRaises(RuntimeError,msg=field):m.old_guard(o,b,[],o['Name'],mac)
 def test_changed_running_replacement_network_or_mac_rejected(self):
  o=old();req=m.request(o,'sha256:new',['java','-jar','/app/app.jar'],mac)
  a=copy.deepcopy(o);a['Id']='b'*64;a['Image']=req['Image'];a['HostConfig']=copy.deepcopy(req['HostConfig']);a['HostConfig']['OomKillDisable']=None
  a['Config']={k:v for k,v in req.items() if k not in ('HostConfig','NetworkingConfig')}
  a['Config']['MacAddress']=o['Config']['MacAddress']
  for n,e in req['NetworkingConfig']['EndpointsConfig'].items():
   a['NetworkSettings']['Networks'][n]=dict(e,IPAddress=e['IPAMConfig']['IPv4Address'],Aliases=e['Aliases']+[a['Id'][:12]])
  m.verify_replacement(o,req,a,True)
  for mode in ('mac','ip','alias','network','legacy'):
   b=copy.deepcopy(a);ep=b['NetworkSettings']['Networks'][m.PRIVATE]
   if mode=='mac':ep['MacAddress']='02:42:ac:12:99:99'
   if mode=='ip':ep['IPAddress']='10.0.2.99'
   if mode=='alias':ep['Aliases']=[]
   if mode=='network':b['NetworkSettings']['Networks'].pop(m.PRIVATE)
   if mode=='legacy':b['Config']['MacAddress']=None
   with self.assertRaises(RuntimeError):m.verify_replacement(o,req,b,True)
if __name__=='__main__':unittest.main(verbosity=2)

class DatabaseGuards(unittest.TestCase):
 def value(self):
  return {'readOnly':True,'databaseOid':'1','exactCandidateMigrationHistory':True,'applicationRoleSuperuser':False,'migrations':[1],
   'activity':{'handoff_intake':{'PROCESSED':34},'materialization_job':{'SUCCEEDED':34},'lake_object':{'VERIFIED':110},
    'lake_maintenance_schedule':{'READY':1},'lake_shadow_rebuild_plan':{},'unexpiredLeases':{'materialization_job':0,'lake_object':0,'lake_maintenance_schedule':0,'lake_shadow_rebuild_plan':0},'maintenanceDue':0},
   'maintenanceWithinWindow':0,'retainedRows':{t:{'rows':0,'fingerprint':'a'*32} for t in m.TABLES}}
 def test_completed_work_and_history(self):
  v=self.value();m.verify_database(v,'1',copy.deepcopy(v))
 def test_active_pending_paused_failed_and_maintenance_rejected(self):
  for table,state in [('handoff_intake','DURABLE'),('materialization_job','PAUSED'),('materialization_job','RUNNING'),('materialization_job','FAILED'),('lake_object','DURABLE'),('lake_maintenance_schedule','RUNNING'),('lake_shadow_rebuild_plan','DRAFT')]:
   v=self.value();v['activity'][table][state]=1
   with self.assertRaises(RuntimeError):m.verify_database(v,'1')
  for key in ('maintenanceWithinWindow','lease'):
   v=self.value()
   if key=='lease':v['activity']['unexpiredLeases']['lake_object']=1
   else:v[key]=1
   with self.assertRaises(RuntimeError):m.verify_database(v,'1')
 def test_every_table_and_history_mutation_detected(self):
  prior=self.value()
  for table in m.TABLES:
   v=copy.deepcopy(prior);v['retainedRows'][table]['fingerprint']='b'*32
   with self.assertRaises(RuntimeError):m.verify_database(v,'1',prior)
  v=copy.deepcopy(prior);v['migrations'].append(2)
  with self.assertRaises(RuntimeError):m.verify_database(v,'1',prior)
