"""Postboot lineage, preserved sources, root-private output and stopped-executor custody.

No production reads. Native application/DB/authority regressions run separately.
"""
import copy,hashlib,importlib.util,json,os,sys,tempfile,types,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
p=load('postboot_policy','scripts/source-revision-postboot-policy.py')
b=load('postboot_prepare','scripts/source-revision-postboot-prepare.py')
e=load('postboot_executor','scripts/execute-source-revision-postboot.py')
r=load('postboot_reader','scripts/prepare-source-revision-inputs.py')
h=load('host_policy','tools/host_network_reconciliation.py')
hb=load('host_bootstrap','scripts/reconcile-host-network-20261018.py')
from test_host_network_reconciliation import fixture as host_fixture

def runtime(row):
 return {'containerId':row['Id'],'imageId':row['Image'],'pid':row['State']['Pid'],'startedAt':row['State']['StartedAt']}
def fixture():
 _,_,rows=host_fixture();before={};observed={}
 for i,module in enumerate(('onboarding','mcp','udp','postgres','ingestion')):
  row=copy.deepcopy(rows[3]);row['Id']=str(i+1)*64;row['Name']='/'+module
  row['Config']['Labels']={'org.opencontainers.image.revision':'a'*40};row['HostConfig']['Dns']=None
  before[module]=row;actual=copy.deepcopy(row);actual['State']['Pid']+=100;actual['HostConfig']['Dns']=[]
  observed[row['Id']]=actual
 engine={'socketPath':'/fixture.sock','socketBinding':[1,2,0,0,0o660]}
 original={'engine':engine,'databasePlan':{'postgresRuntimeBinding':runtime(before['postgres']),'modules':['unchanged']},'authorization':{'history':'KEEP'}}
 historical={'schema':'ouf.source-revision-private-inputs.v1','engine':copy.deepcopy(engine),'databasePlan':copy.deepcopy(original['databasePlan']),
  'runtimeAuthorityIssued':False,'readyForExecution':False,'packageRootCustodyProven':True,
  'beforeApplications':{m:before[m] for m in ('onboarding','mcp','udp')},
  'unchangedApplications':{'ingestion':runtime(before['ingestion'])},
  'selection':{'currentApplications':{m:{'imageId':before[m]['Image'],'sourceCommit':'a'*40} for m in ('onboarding','mcp','udp')}},
  'retainedReplacements':{m:{'request':{'HostConfig':copy.deepcopy(before[m]['HostConfig'])}} for m in ('onboarding','mcp')},
  'gateway':{'transport':{'old':True},'beforeRoutes':{'keep':'unchanged'}},'candidates':{'archives':'REUSE'},'gatewayPackage':{'archive':'REUSE'}}
 new_engine={**engine,'socketBinding':[1,3,0,0,0o660]}
 args=[original,historical,observed,new_engine,{'new':True},runtime,runtime,lambda old,new:hb.preboot_application_proof(old,new,h)]
 return args

class Policy(unittest.TestCase):
 def test_projection_preserves_originals_authorization_and_archives(self):
  args=fixture();saved=copy.deepcopy(args[:5]);original,current,proof=p.project(*args)
  self.assertEqual(args[:5],saved);self.assertEqual(original['authorization'],args[0]['authorization'])
  self.assertEqual(current['candidates'],args[1]['candidates']);self.assertEqual(current['selection'],args[1]['selection'])
  self.assertEqual(current['retainedReplacements']['onboarding']['request']['HostConfig']['Dns'],[])
  self.assertEqual(current['engine'],original['engine']);self.assertFalse(proof['readyForExecution'])
 def test_nonempty_dns_and_unrelated_configuration_never_rebound(self):
  for change in ('dns','env','image','source','paused','socket'):
   args=fixture();actual=args[2]['1'*64]
   if change=='dns':actual['HostConfig']['Dns']=['8.8.8.8']
   if change=='env':actual['Config']['Env']=['UNREVIEWED=1']
   if change=='image':actual['Image']='other'
   if change=='source':actual['Config']['Labels']['org.opencontainers.image.revision']='b'*40
   if change=='paused':actual['State']['Paused']=True
   if change=='socket':args[3]['socketPath']='/other.sock'
   with self.subTest(change=change),self.assertRaises(ValueError):p.project(*args)
 def test_thirteen_completed_claims_from_real_host_owner(self):
  profile,api,rows=host_fixture()
  for letter,ip in (('d','10.80.0.7'),('e','10.80.0.8'),('f','10.80.0.9'),('1','10.80.0.10')):
   row=copy.deepcopy(rows[3]);row['Id']=letter*64;row['Name']='/pin-'+letter
   row['NetworkSettings']['Networks']['fixture-net'].update(IPAddress=ip,IPAMConfig=None,MacAddress='02:00:00:00:00:'+letter*2)
   api.rows[row['Id']]=row;profile['moves'].append({'containerId':row['Id'],'imageId':row['Image'],'name':row['Name'][1:],'oldIPv4':ip,'newIPv4':ip,'servicePorts':[8000],'configurationDestinations':[]})
  plan=h.compile_plan(profile,api,lambda *a:None);plan['prebootPreparedBinding']={'path':'old','sha256':'a'*64}
  selection={'hostContext':'/fixture','hostPlanSha256':h.digest(plan),'historicalPrivateInputs':plan['prebootPreparedBinding']}
  claims=[];h.apply(plan,api,lambda n,req:claims.append({'name':n,'requestSha256':h.digest(req)}))
  pointer={'schema':'ouf.host-network-reconciliation-incident.v1','contextPath':'/fixture','planSha256':h.digest(plan)}
  journal={'schema':'ouf.host-network-reconciliation-journal.v1','state':'COMPLETE','planSha256':h.digest(plan),'claims':claims,'maximumEngineWrites':13,'runtimeAuthorityIssued':False}
  self.assertEqual(p.completed_host(plan,journal,pointer,selection,h)['completedClaims'],13)
  for field,value in [('state','STOPPED'),('claims',claims[:-1]),('maximumEngineWrites',14),('runtimeAuthorityIssued',True)]:
   with self.subTest(field=field),self.assertRaises(ValueError):p.completed_host(plan,{**journal,field:value},pointer,selection,h)

class Consumer(unittest.TestCase):
 def pair(self):
  args=fixture();original,current,proof=p.project(*args)
  old={'path':'/old','sha256':r.digest(args[1])};ob={'path':'/original','sha256':r.digest(original)}
  current['postbootReconciliation']={**proof,'historicalPrivateInputs':old,'currentOriginalPreparationBinding':ob,'hostPlanSha256':'a'*64,'hostContext':'/host'}
  cb={'path':'/current','sha256':r.digest(current)}
  case={'schema':'ouf.source-revision-postboot-update-selection.v2','preparedPlanBinding':cb,'postbootOriginalPreparationBinding':ob,'historicalPreparedPlanBinding':old,'completedHostPlanSha256':'a'*64,'completedHostContext':'/host'}
  docs={'/old':args[1],'/original':original,'/current':current}
  def read(path,limit,sha):
   value=docs[str(path)]
   if r.digest(value)!=sha:raise ValueError('HASH_DRIFT')
   return copy.deepcopy(value)
  return case,args[0],docs,read
 def test_executor_reloads_reconciled_original_and_never_falls_back(self):
  case,old,docs,read=self.pair();self.assertEqual(e.select_prepared(case,old,read),docs['/original'])
  self.assertNotEqual(docs['/original']['engine'],old['engine'])
  del case['postbootOriginalPreparationBinding']
  with self.assertRaises(KeyError):e.select_prepared(case,old,read)
 def test_old_case_denied(self):
  case,old,docs,read=self.pair();case['schema']='ouf.source-revision-update-selection.v1'
  with self.assertRaisesRegex(ValueError,'EXPLICIT_POSTBOOT'):e.select_prepared(case,old,read)
 def test_hash_valid_but_unreviewed_original_authorization_change_denied(self):
  case,old,docs,read=self.pair();docs['/original']['authorization']={'history':'RESET'}
  case['postbootOriginalPreparationBinding']['sha256']=r.digest(docs['/original'])
  case['preparedPlanBinding']['sha256']=r.digest(docs['/current'])
  with self.assertRaisesRegex(ValueError,'UNREVIEWED_ORIGINAL'):e.select_prepared(case,old,read)
 def test_stale_hash_missing_file_and_wrong_parent_denied(self):
  for change in ('hash','missing','parent','archive'):
   case,old,docs,read=self.pair()
   if change=='hash':case['postbootOriginalPreparationBinding']['sha256']='0'*64
   if change=='missing':del docs['/original']
   if change=='parent':case['completedHostPlanSha256']='0'*64
   if change=='archive':docs['/current']['candidates']={'archives':'other'};case['preparedPlanBinding']['sha256']=r.digest(docs['/current'])
   with self.subTest(change=change),self.assertRaises((ValueError,KeyError)):e.select_prepared(case,old,read)

class Files(unittest.TestCase):
 def temporary(self):return tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT.parent)))
 def shared(self):
  def root(path):
   for pth in (Path(path),*Path(path).parents):
    st=pth.lstat()
    if st.st_uid!=0 or st.st_mode&0o022:raise ValueError('CUSTODY')
  def write(path,raw):
   fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
  return types.SimpleNamespace(root_directory=root,encoded=r.encoded,write_new=write)
 def test_private_document_writer_supports_new_names_without_overwrite(self):
  with self.temporary() as temp:
   context=Path(temp);v={'private':'CANARY'};binding=b.document(context,'current-original-preparation.json',v,self.shared(),r)
   self.assertEqual(json.loads(r.read(binding['path'],binding['sha256'])),v)
   self.assertEqual((context/'current-original-preparation.json').stat().st_mode&0o777,0o600)
   with self.assertRaises(FileExistsError):b.document(context,'current-original-preparation.json',v,self.shared(),r)
   with self.assertRaises(ValueError):b.document(context,'../elsewhere',v,self.shared(),r)
 def test_seven_stopped_sources_and_unknown_authority_or_directory(self):
  for change in (None,'authority','empty-directory','bytes','link'):
   with self.subTest(change=change),self.temporary() as temp:
    root=Path(temp);compiler=root/'gateway-compiler';compiler.mkdir(mode=0o700)
    sources={str(i)+'.py':b'pass\n' for i in range(7)}
    for n,raw in sources.items():self.shared().write_new(compiler/n,raw)
    if change=='authority':self.shared().write_new(root/'authority.json',b'{}')
    if change=='empty-directory':(compiler/'extra').mkdir(mode=0o700)
    if change=='bytes':(compiler/'1.py').write_bytes(b'changed')
    if change=='link':(compiler/'1.py').unlink();(compiler/'1.py').symlink_to(compiler/'0.py')
    if change:
     with self.assertRaises(ValueError):b.reconcile_partial(root,sources,r)
    else:self.assertTrue(b.reconcile_partial(root,sources,r)['authorityArtifactsAbsent'])
 def test_freeze_has_exact_qualified_sources_new_executor_and_case(self):
  old=load('legacy_executor','scripts/execute-source-revision-update-20261018.py')
  self.assertEqual(e.OVERLAYS,old.OVERLAYS)
  files={name:(ROOT/path).read_bytes() for name,path in old.OVERLAYS.values()}
  package={'schema':'ouf.source-revision-executable-package.v1','sourceCommit':'a'*40,'sourceHashes':{m:hashlib.sha256(files[n]).hexdigest() for m,(n,_) in e.OVERLAYS.items()}}
  loader=(ROOT/'tools/source_revision_update/runtime.py').read_bytes();package['loaderSha256']=hashlib.sha256(loader).hexdigest()
  with self.temporary() as temp:
   case,_,_,_=Consumer().pair();executor=(ROOT/'scripts/execute-source-revision-postboot.py').read_bytes()
   successor,binding=b.freeze_code(Path(temp),case,{'successorSourceCommit':'b'*40},executor,files,package,loader,self.shared(),r,e.OVERLAYS)
   self.assertEqual(successor['sourceHashes'],package['sourceHashes']);self.assertEqual(len(list((Path(temp)/'executor-code').iterdir())),81)
   self.assertEqual(json.loads((Path(binding['directory'])/'case.json').read_bytes()),case)
   self.assertEqual(successor['caseSha256'],r.digest(case));self.assertEqual(binding['packageSha256'],r.digest(successor))
if __name__=='__main__':unittest.main()

class Orchestration(unittest.TestCase):
 def test_complete_preparation_and_mid_compile_process_change(self):
  from unittest.mock import patch
  import signal,io
  from contextlib import redirect_stdout
  for changed in (False,True):
   with self.subTest(changed=changed),Files().temporary() as temp:
    root=Path(temp);shared=Files().shared();shared.digest=r.digest
    def put(name,value):
     path=root/name;shared.write_new(path,r.encoded(value));return {'path':str(path),'sha256':r.digest(value)}
    args=fixture();original,historical,observed=args[:3]
    historical['databaseFacts']={'onboarding':{'migrations':['retained']}}
    # Use the actual root-private writer/reader for every produced input/code byte.
    hist=put('historical.json',historical)
    program=root/'docker';shared.write_new(program,b'fixture command bytes')
    original_case={'preparedPlanBinding':hist,'candidateOwnerSourceCommit':'b'*40}
    boot=put('boot.json',{'coordinatedConfiguration':str(root/'coordinated.json'),'coordinatedConfigurationHash':r.digest({'commonLockFile':str(root/'guard.lock')})})
    put('coordinated.json',{'commonLockFile':str(root/'guard.lock')});shared.write_new(root/'guard.lock',b'lock')
    native={'loadedBinding':{'profile':boot['path'],'sha256':boot['sha256']}}
    host={'profile':{'socketPath':'/fixture.sock','engineVersion':'fixture'},'moves':[],
     'engineSocketBinding':[1,3,0,0,0o660],'unaffected':{cid:{'immutable':h.immutable(row),'process':h.process(row),'networks':h.digest(row['NetworkSettings'])} for cid,row in observed.items()},
     'restartBefore':observed['3'*64],'nativeBootBinding':native['loadedBinding'],'configurationFileBindings':{}}
    hostbind=put('plan.json',host);put('journal.json',{'state':'COMPLETE'});pointer=put('pointer.json',{'fixture':True})
    partial=root/'stopped';partial.mkdir(mode=0o700);compiler=partial/'gateway-compiler';compiler.mkdir(mode=0o700)
    seven={str(i)+'.py':b'pass\n' for i in range(7)}
    for name,raw in seven.items():shared.write_new(compiler/name,raw)
    archive=root/'gateway.tar';shared.write_new(archive,b'fixture tar bytes')
    historical['gatewayPackage']={'path':str(archive),'sha256':hashlib.sha256(archive.read_bytes()).hexdigest()}
    historical['gateway']['transport']={'configBinding':{'path':'/fixture/config'}}
    # Rewrite fixture before it becomes immutable input; production never does this.
    Path(hist['path']).write_bytes(r.encoded(historical));hist['sha256']=r.digest(historical)
    profile={'schema':'ouf.source-revision-postboot-preparation-selection.v1','maximumSeconds':300,
     'privateParent':str(root),'hostContext':str(root),'hostPlanSha256':hostbind['sha256'],'hostIncidentPointer':pointer['path'],
     'historicalPrivateInputs':hist,'previousPreparationStop':str(partial),'successorSourceCommit':'a'*40,'stagedExecutor':{'fixture':'qualified'}}
    files={name:(ROOT/path).read_bytes() for name,path in e.OVERLAYS.values()}
    package={'schema':'ouf.source-revision-executable-package.v1','sourceCommit':'b'*40,
     'sourceHashes':{m:hashlib.sha256(files[n]).hexdigest() for m,(n,_) in e.OVERLAYS.items()},'loaderSha256':'e'*64}
    loader=(ROOT/'tools/source_revision_update/runtime.py').read_bytes();package['loaderSha256']=hashlib.sha256(loader).hexdigest()
    paths=json.loads((ROOT/'tools/chatbot_file_cohort/source_paths.json').read_bytes())
    sources={n:b'pass\n' if path.startswith('ouf-onboarding:') else (ROOT/path).read_bytes() for n,path in paths.items()}
    sources.update({m:files[n] for m,(n,_) in e.OVERLAYS.items()})
    memory={};exec(compile(loader,'<memory>','exec'),memory)
    closure={'executables':{'docker':{'path':str(program),'sha256':hashlib.sha256(program.read_bytes()).hexdigest()}},'stdlibHash':'f'*64,'stdlibFileCount':1}
    ns={'read':lambda path,maximum,sha:json.loads(r.read(path,sha,maximum))}
    loaded=(ns,original,original_case,closure,files,package,loader,memory,sources,{'ouf-deploy':'b'*40,'ouf-onboarding':'b'*40},e.OVERLAYS)
    class Engine:
     def __init__(self,*a):self.pin=(1,3,0,0,0o660)
     def get(self,path):return copy.deepcopy(observed[path.split('/')[2]])
     def check_socket(self):pass
    class Admin:
     def __init__(self,*a):pass
     @staticmethod
     def observe(*a,**k):return {'configBinding':{'path':'/fixture/config'},'newGeneration':True}
     def routes(self):return historical['gateway']['beforeRoutes']
     def check(self):pass
    calls=[]
    def compile_private(orig,cl,case,context,read,helper):
     calls.append('compile')
     self.assertEqual(read(case['postbootOriginalPreparationBinding']['path'],8388608,case['postbootOriginalPreparationBinding']['sha256']),orig)
     self.assertEqual(cl['declaration']['bootstrapBindings']['caseSha256'],r.digest(case))
     self.assertEqual(orig['authorization'],original['authorization'])
     plan={'fixture':'native-plan'};shared.write_new(context/'prepared-plan.json',r.encoded(plan))
     if changed:observed['1'*64]['State']['Pid']+=1
     return plan,None,None
    prep=types.SimpleNamespace(gateway=types.SimpleNamespace(source_members=lambda *a:seven),package_files=lambda *a:lambda *a:b'{}',compile_private=compile_private)
    modules={'tools.source_revision_update.authority':types.SimpleNamespace(closure_valid=lambda cl:None),'engine_creation':types.SimpleNamespace(Engine=Engine),'tools.chatbot_file_cohort.gateway':types.SimpleNamespace(NamespaceAdmin=Admin,MOUNT_SET_BINDING='fixture'),
     'tools.linked_property_rollout.preparation':shared,'tools.source_revision_update.preparation':prep,
     'tools.source_revision_update.native':types.SimpleNamespace(runtime=runtime),'tools.source_revision_update.database':types.SimpleNamespace(raw_runtime=runtime)}
    owner=types.SimpleNamespace(Engine=Engine,immutable=h.immutable,process=h.process,digest=h.digest,verify_move=lambda *a,**k:None)
    policy=types.SimpleNamespace(project=p.project,completed_host=lambda *a:{'hostContext':str(root),'hostPlanSha256':hostbind['sha256'],'historicalAuthorityReused':False})
    bootstrap=types.SimpleNamespace(provider_guard=lambda *a:native,preboot_application_proof=hb.preboot_application_proof)
    owner.require=h.require
    boot_reader=types.SimpleNamespace(sealed=lambda path,sha:r.read(path,sha))
    facts={'revisionTablePresent':False,'migrationRolePrivileges':{'create':True},'migrations':['retained']}
    out=io.StringIO()
    try:
     with patch.object(b,'load_staged',return_value=loaded),patch.object(b.importlib,'import_module',side_effect=lambda name:modules[name]),patch.object(r,'facts',return_value=facts),redirect_stdout(out):
      if changed:
       with self.assertRaisesRegex(ValueError,'GENERATION_CHANGED'):b.run(profile,r,owner,boot_reader,bootstrap,policy,{},(ROOT/'scripts/execute-source-revision-postboot.py').read_bytes())
       self.assertFalse(list(root.glob('source-revision-postboot-prepared-*/postboot-preparation-result.json')))
      else:
       result=b.run(profile,r,owner,boot_reader,bootstrap,policy,{},(ROOT/'scripts/execute-source-revision-postboot.py').read_bytes())
       self.assertFalse(result['readyForExecution']);self.assertFalse(result['runtimeAuthorityIssued'])
       self.assertTrue(Path(result['contextPath'],'postboot-preparation-result.json').is_file())
     self.assertEqual(calls,['compile']);self.assertNotIn('SECRET_CANARY',out.getvalue());self.assertNotIn('KEEP',out.getvalue())
    finally:signal.alarm(0)
