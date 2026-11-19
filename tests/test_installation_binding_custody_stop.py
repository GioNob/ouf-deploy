import ast,base64,copy,hashlib,importlib.util,json,os,stat,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
SCRIPT=HERE/'read.py'
if not SCRIPT.exists():SCRIPT=HERE.parents[0]/'scripts/read-installation-binding-custody-stop.py'
if not SCRIPT.exists():SCRIPT=Path(__file__).resolve().parents[1]/'scripts/read-installation-binding-custody-stop.py'
spec=importlib.util.spec_from_file_location('custody_stop',SCRIPT);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
FIXTURE=HERE/'gateway_fixture.py'
if not FIXTURE.exists():FIXTURE=Path(__file__).resolve().parents[1]/'tests/fixtures/installation-binding-custody-gateway.py'
class Read(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=HERE);self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.root.chmod(0o700)
  self.first=self.root/'installation-binding-apply-execution-46iexg9c';self.second=self.root/'installation-binding-apply-execution-7x21g1fg'
  self.first.mkdir(mode=0o700);self.second.mkdir(mode=0o700)
  self.ouf=self.root/'ouf';self.ouf.mkdir(mode=0o750)
  self.native_uid=os.environ.get('OUF_NATIVE_UIDS')=='1'
  if self.native_uid:os.chown(self.ouf,1000,1000)
  else:
   # Local filesystem rejects nonzero chown; virtualize only this inode's UID/GID. CI uses real chown.
   identity=self.ouf.stat();original_fstat=os.fstat;original_stat=os.stat;original_lstat=Path.lstat
   def selected(info):
    if(info.st_dev,info.st_ino)!=(identity.st_dev,identity.st_ino):return info
    fields={k:getattr(info,k)for k in dir(info)if k.startswith('st_')};fields.update(st_uid=1000,st_gid=1000);return types.SimpleNamespace(**fields)
   for obj,key,fn in[(os,'fstat',lambda *a,**kw:selected(original_fstat(*a,**kw))),(os,'stat',lambda *a,**kw:selected(original_stat(*a,**kw))),(Path,'lstat',lambda *a,**kw:selected(original_lstat(*a,**kw)))]:
    p=patch.object(obj,key,fn);p.start();self.addCleanup(p.stop)
  self.directory=self.ouf/'installation';self.directory.mkdir(mode=0o700);self.profile=self.directory/'active-projection.json'
  self.custody={'parents':{str(self.ouf):(1000,1000,0o750),str(self.directory):(0,0,0o700)},'file':(0,0,0o600)}
  self.gateway=FIXTURE.read_text().replace("'/opt/ouf/installation/active-projection.json':",repr(str(self.profile))+':').replace("'/opt/ouf': (1000, 1000, 0o750)",repr(str(self.ouf))+': (1000, 1000, 0o750)').replace("'/opt/ouf/installation': (0, 0, 0o700)",repr(str(self.directory))+': (0, 0, 0o700)')
  self.old=m.encoded({'revision':5,'opaque':'NEVER_PRINT_PROFILE_VALUE'});self.new=m.encoded({'revision':6,'opaque':'NEVER_PRINT_PROFILE_VALUE','services':{'bindings':{'ouf-ingestion-runtime':'verified-alias'}}})
  self.raw(self.profile,self.new);self.raw(self.second/'source-projection.json',self.old);self.raw(self.first/'owner-active-projection.json',self.new)
  self.export=m.sha(self.new);self.binding={'path':str(self.profile),'sha256':m.sha(self.old),'metadata':[]}
  hb={'expiresAt':1792436155};active={'installationId':'ouf-lab-netcup-01','revision':6,'checksum':m.PAYLOAD,'generation':6,'etag':'"6:'+m.PAYLOAD+':6"'}
  result={'schema':'ouf.installation-binding-owner-result.v1','complete':True,'active':active,'ownerPosts':3,'projectionExports':1,'oauthAttemptsAfter':255,'gatewayWrites':0,'activeProjectionWrites':0,'sourceActivated':False,'projectionBinding':{'path':str(self.first/'owner-active-projection.json'),'sha256':self.export}}
  self.write(self.first/'owner-result.json',result)
  self.p1={'kind':'INSTALLATION_BINDING_APPLY','schema':'ouf.installation-binding-native-plan.v1','authorityDirectory':str(self.first),'projectionBinding':self.binding,'humanBinding':hb}
  self.p2={'kind':'INSTALLATION_PROJECTION_ROUTE_APPLY','schema':'ouf.installation-binding-native-plan.v1','authorityDirectory':str(self.second),'projectionBinding':self.binding,'humanBinding':hb,
   'ownerActivationBinding':{'path':str(self.first/'owner-result.json'),'sha256':m.digest(result)},'projectionHash':self.export,'exportedProjectionBinding':result['projectionBinding']}
  sources={'fixture.'+str(i):b'raise RuntimeError("RETAINED_MAIN_MUST_NOT_RUN")\n'for i in range(218)};sources['tools.chatbot_file_cohort.gateway']=b'raise RuntimeError("TOP_LEVEL_MUST_NOT_RUN")\n'+self.gateway.encode()
  closure={'declaration':{'moduleCount':219,'entryModule':'tools.installation_binding_apply.entry','sourceHashes':{k:m.sha(v)for k,v in sources.items()}}};self.closure=m.digest(closure)
  source_raw=m.encoded({k:base64.b64encode(v).decode()for k,v in sources.items()});self.raw(self.first/'sources.json',source_raw)
  package={'sourceCommit':m.SOURCE,'closure':closure,'declarationHash':m.digest(closure['declaration']),'fileHashes':{'sources.json':m.sha(source_raw)}};self.package=m.digest(package);self.write(self.first/'package.json',package)
  self.write(self.first/'runtime.claim.json',{'packageHash':self.package,'automaticReplayAllowed':False})
  review1=self.scope(self.first,self.p1,6,False);review2=self.scope(self.second,self.p2,1,True)
  for key,value in {'FIRST':self.first,'SECOND':self.second,'PACKAGE':self.package,'CLOSURE':self.closure,'OWNER_REVIEW':review1,'ROUTE_REVIEW':review2,'EXPORT':self.export,'ACTIVE_PATH':str(self.profile),'APPROVED_CUSTODY':self.custody}.items():
   p=patch.object(m,key,value);p.start();self.addCleanup(p.stop)
  for obj,key,value in [(m.sys,'flags',types.SimpleNamespace(isolated=1,no_site=1)),(m.sys,'dont_write_bytecode',True),(m.signal,'signal',lambda *_:None),(m.signal,'alarm',lambda *_:None)]:
   p=patch.object(obj,key,value);p.start();self.addCleanup(p.stop)
 def tearDown(self):
  if self.native_uid:os.chown(self.ouf,0,0)
 def raw(self,path,raw):path.write_bytes(raw);path.chmod(0o600)
 def write(self,path,value):self.raw(path,m.encoded(value))
 def scope(self,context,plan,n,claimed):
  key='installationBindingApply'if context==self.first else'installationProjectionRouteApply';scope={'planHash':m.digest(plan),'logicalRef':m.digest(str(context))}
  review={'scopes':{key:scope},'sourceClosureHash':self.closure};rh=m.digest(review);self.write(context/'execution-plan.json',plan);self.write(context/'review.json',review);self.write(context/'decision.json',{'reviewHash':rh})
  stages=m.STAGES[plan['kind']];effects=[{'stage':s,'state':'APPLIED','intentHash':m.digest({'planHash':m.digest(plan),'stage':s})}for s in stages[:n]]
  if claimed:effects.append({'stage':stages[n],'state':'CLAIMED','intentHash':m.digest({'planHash':m.digest(plan),'stage':stages[n]})})
  self.write(context/'recovery.json',{'schema':'ouf.installation-binding-native-journal.v1','scopeHash':m.digest(scope),'authorityHash':'a'*64,'budgetReset':False,'nextStage':n,'effects':effects,'incidentState':'RECOVERED'if n==len(stages)else'OPEN','version':3*n+1,'expiresAt':1792430000})
  self.write(context.parent/('installation-binding-native-'+scope['logicalRef']+'.claim.json'),{'context':str(context),'scopeHash':m.digest(scope),'authorityHash':'a'*64,'automaticReplayAllowed':False,'budgetReset':False})
  # Sentinels must never be opened by this reader.
  for name in('authority.json','human-access.jwt'):
   if not os.path.lexists(context/name):(context/name).symlink_to('/not/a/readable/secret')
  return rh
 def test_new_profile_bytes_after_rename_and_claimed_journal_are_reported_without_replay(self):
  before={p:p.read_bytes()for d in(self.first,self.second)for p in d.iterdir()if not p.is_symlink()};result=m.main()
  self.assertTrue(result['publicationBytesPresentButJournalUnreconciled']);self.assertTrue(result['noGatewayDispatchByThisActionProven'])
  self.assertEqual(result['profile']['state'],'APPROVED_NEW_EXPORT');self.assertFalse(result['profile']['legacyRootOnlyAncestryPassed']);self.assertTrue(result['profile']['approvedCustodyPassed'])
  self.assertFalse(result['authorityFilesOpened']);self.assertEqual(result['oauthRequests'],0);self.assertEqual(result['journalWrites'],0)
  self.assertTrue(all(p.read_bytes()==v for p,v in before.items()));self.assertNotIn('NEVER_PRINT',json.dumps(result))
 def test_old_projection_is_distinguished_without_concluding_publication(self):
  self.raw(self.profile,self.old);result=m.main();self.assertEqual(result['profile']['state'],'RETAINED_OLD_PROJECTION');self.assertFalse(result['publicationBytesPresentButJournalUnreconciled'])
 def test_unknown_custodied_projection_is_reported_as_drift(self):
  self.raw(self.profile,b'{"other":true}');result=m.main();self.assertEqual(result['profile']['state'],'OTHER_CUSTODIED_BYTES');self.assertFalse(result['publicationBytesPresentButJournalUnreconciled'])
 def test_wrong_known_ancestor_or_symlink_is_rejected(self):
  self.ouf.chmod(0o770)
  with self.assertRaises(Exception):m.main()
  self.ouf.chmod(0o750);self.profile.unlink();self.profile.symlink_to(self.second/'source-projection.json')
  with self.assertRaises(Exception):m.main()
 def test_source_or_journal_tampering_is_rejected(self):
  row=json.loads((self.second/'recovery.json').read_bytes());row['effects'][-1]['intentHash']='0'*64;self.write(self.second/'recovery.json',row)
  with self.assertRaises(Exception):m.main()
 def test_gateway_claim_prevents_false_zero_dispatch_assertion(self):
  self.scope(self.second,self.p2,2,True);result=m.main();self.assertFalse(result['noGatewayDispatchByThisActionProven']);self.assertEqual(result['projectionRouteScope']['gatewayStageClaims'],1)
 def test_changed_sealed_source_bytes_are_rejected(self):
  sources=json.loads((self.first/'sources.json').read_bytes());sources['fixture.0']=base64.b64encode(b'pass').decode();self.write(self.first/'sources.json',sources)
  with self.assertRaises(Exception):m.main()
 def test_gated_ast_has_no_dispatch_or_write_calls(self):
  calls=[ast.unparse(n.func)for n in ast.walk(ast.parse(SCRIPT.read_bytes()))if isinstance(n,ast.Call)]
  self.assertFalse(any(c.endswith(('.request','.login','.refresh_if_due','.issue_action','.write','.mkdir','.execv','.compare_and_save'))for c in calls))
  opens=[n for n in ast.walk(ast.parse(SCRIPT.read_bytes()))if isinstance(n,ast.Call)and ast.unparse(n.func)=='os.open'];self.assertEqual(len(opens),1);self.assertIn('os.O_RDONLY',ast.unparse(opens[0].args[1]))
if __name__=='__main__':unittest.main()
