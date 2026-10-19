import copy,hashlib,importlib.util,json,os,socket,tempfile,threading,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('completed_read',ROOT/'scripts/read-source-revision-completed-20261019.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Read(unittest.TestCase):
 def temp(self):return tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT.parent)))
 def write(self,path,value):
  path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);path.write_bytes(m.encoded(value));path.chmod(0o600)
 def history(self):
  plan={'gateway':{'afterRoutes':{'x':{}}}};review={'scopes':{'sourceRevisionUpdate':{'planHash':m.digest(plan)}}};authority=b'opaque-authority'
  effects=[{'stage':s,'state':'APPLIED','intentHash':m.digest({'planHash':m.digest(plan),'stage':s}),'evidence':{}}for s in m.STAGES]
  effects[-1]['evidence']={'applications':{'onboarding':{},'mcp':{}},'routeMapHash':m.digest(plan['gateway']['afterRoutes'])}
  row={'schema':'ouf.source-revision-update-journal.v1','scopeHash':m.digest(review['scopes']['sourceRevisionUpdate']),'authorityHash':m.sha(authority),'budgetReset':False,'nextStage':len(m.STAGES),'effects':effects,'incidentState':'RECOVERED','version':57,'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
  return row,plan,review,authority
 def test_closed_history_rejects_claims_reordering_budget_authority_and_boot_drift(self):
  row,p,r,a=self.history();self.assertEqual(m.completed_history(row,p,r,a),row['effects'][-1]['evidence'])
  for mutate in [lambda x:x['effects'][0].update(state='CLAIMED'),lambda x:x.update(budgetReset=True),lambda x:x.update(authorityHash='other'),lambda x:x.update(bootId='other'),lambda x:x.update(version=56),lambda x:x['effects'].reverse()]:
   bad=copy.deepcopy(row);mutate(bad)
   with self.assertRaises(m.ReadDenied):m.completed_history(bad,p,r,a)
 def test_private_reader_refuses_links_writable_files_duplicate_and_nonfinite_json(self):
  with self.temp()as tmp:
   p=Path(tmp)/'private';self.write(p,{'secret':'CREDENTIAL_CANARY'});self.assertEqual(m.document(p),{'secret':'CREDENTIAL_CANARY'})
   p.chmod(0o640)
   with self.assertRaises((ValueError,m.ReadDenied)):m.read(p)
   p.chmod(0o600);q=p.parent/'linked';q.symlink_to(p)
   with self.assertRaises((ValueError,m.ReadDenied)):m.read(q)
   os.link(p,p.parent/'hardlink')
   with self.assertRaises((ValueError,m.ReadDenied)):m.read(p)
   for raw in [b'{"a":1,"a":2}',b'{"a":NaN}']:
    with self.assertRaises((ValueError,m.ReadDenied)):m.parse(raw)
 def test_engine_uses_real_bounded_get_and_refuses_socket_identity_drift(self):
  with self.temp()as tmp:
   p=Path(tmp)/'engine.sock';server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);server.bind(str(p));p.chmod(0o600);server.listen();requests=[]
   def serve():
    c,_=server.accept()
    with c:
     requests.append(c.recv(4096));raw=b'{"Config":{"Env":["SECRET=CREDENTIAL_CANARY"]}}';c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(raw)).encode()+b'\r\nConnection: close\r\n\r\n'+raw)
   s=p.stat();binding={'socketPath':str(p),'socketBinding':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode&0o777]};thread=threading.Thread(target=serve);thread.start()
   try:self.assertIn('Config',m.engine_get(binding,'containers','a'*64))
   finally:thread.join(5);server.close()
   self.assertTrue(requests[0].startswith(b'GET /v1.44/containers/'+b'a'*64+b'/json '))
   binding['socketBinding'][1]+=1
   with self.assertRaises(m.ReadDenied):m.engine_get(binding,'containers','a'*64)
 def test_original_81_files_and_exact_two_successors_qualify_without_execution(self):
  with self.temp()as tmp:
   root=Path(tmp);base=root/'base';prep=root/'prep';kfy=root/'source-revision-postboot-prepared-kfy691gh';code=prep/'executor-code';code.mkdir(parents=True,mode=0o700)
   raw=b'raise RuntimeError("MUST_NOT_EXECUTE_CREDENTIAL_CANARY")\n';source_hash=m.sha(raw);basepkg={'sourceHashes':{k:source_hash for k in m.FROZEN_NAMES},'executorSha256':source_hash,'loaderSha256':source_hash}
   successors={k:source_hash for k in m.SOURCE_SUCCESSORS};pkg={**basepkg,'sourceHashes':{**basepkg['sourceHashes'],**successors},'sourceCommit':m.SOURCE,'caseSha256':m.digest({})}
   self.write(base/'executor-code/package.json',basepkg)
   for name in set(m.FROZEN_NAMES.values())|{'runtime.py','execute.py'}:
    f=code/name;f.write_bytes(raw);f.chmod(0o600)
   self.write(code/'case.json',{});self.write(code/'package.json',pkg)
   result={'schema':'ouf.source-revision-postboot-preparation-result.v1','contextPath':str(prep),'runtimeAuthorityIssued':False,'readyForExecution':False,'retainedHumanAttempts':189,'executorCodeBinding':{'sourceCommit':m.SOURCE,'packageSha256':m.digest(pkg)},'caseBinding':{'path':str(code/'case.json'),'sha256':m.digest({})}}
   for field,name in [('currentOriginalPreparationBinding','current-original-preparation.json'),('preparedInputsBinding','postboot-private-inputs.json')]:
    self.write(kfy/name,{});result[field]={'path':str(kfy/name),'sha256':m.digest({})}
   for field,name in [('nativePlanBinding','prepared-plan.json'),('continuationPlanBinding','continuation-plan.json'),('nativeLoginReviewBinding','native-login-review-candidate.json')]:
    self.write(prep/name,{});result[field]={'path':str(prep/name),'sha256':m.digest({})}
   self.write(prep/'postboot-preparation-result.json',result)
   with patch.multiple(m,ROOT=root,BASE=base,PREPARED=prep,BASE_PACKAGE=m.digest(basepkg),SOURCE_SUCCESSORS=successors,ORIGINAL=m.digest({}),INPUTS=m.digest({})):
    self.assertEqual(m.frozen_preparation(),(result,{}))
    (code/'source_revision_entry.py').write_bytes(b'changed')
    with self.assertRaises((ValueError,m.ReadDenied)):m.frozen_preparation()
 def test_database_readback_uses_three_readonly_transactions_and_refuses_drift(self):
  actual={'Id':'a'*64,'Image':'fixture','State':{'Pid':1,'StartedAt':'same','Running':True},'Config':{},'HostConfig':{},'Mounts':[],'NetworkSettings':{}}
  pin={'containerId':actual['Id'],'imageId':'fixture','pid':1,'startedAt':'same',**{n+'Hash':m.digest(actual[k])for n,k in [('config','Config'),('hostConfig','HostConfig'),('mounts','Mounts'),('networkSettings','NetworkSettings')]}}
  before={s:{'database':s,'databaseOid':1,'role':'admin','migrations':[]}for s in ('onboarding','udp','mcp')};plan={'engine':{'socketPath':'/selected'},'programs':{'docker':{}},'database':{'postgresRuntimeBinding':pin,'before':before}}
  original={'databasePlan':{'mcpAuditRoleAdministration':{'admin':'admin'},'modules':[{'module':s,'database':s,'user':'app'}for s in before]}};calls=[]
  def run(argv,**kw):
   calls.append(argv);s=argv[argv.index('-d')+1];fact={**before[s],'transactionReadOnly':True,'migrations':[]}
   if s=='onboarding':fact.update(migrations=[{'installed_rank':34,'version':'34','script':m.MIGRATION['script'],'checksum':m.MIGRATION['checksum'],'success':True}],revisionTablePresent=True,revisionTableOwned=True,revisionAppendOnly=True)
   return 0,m.encoded(fact),b'',1
  with patch.object(m,'engine_get',return_value=actual),patch.object(m,'executable',return_value='/qualified/docker'),patch.object(m,'bounded',side_effect=run):
   report=m.database_readback(plan,original)
  self.assertEqual(report['readOnlySessions'],3)
  for a in calls:self.assertIn('default_transaction_read_only=on',' '.join(a));self.assertTrue(a[-1].startswith('BEGIN READ ONLY;'));self.assertTrue(a[-1].endswith('ROLLBACK;'));self.assertNotIn('UPDATE ',a[-1]);self.assertNotIn('INSERT ',a[-1])
  original['databasePlan']['modules'][0]['user']='x;DROP TABLE x'
  with patch.object(m,'engine_get',return_value=actual),patch.object(m,'executable',return_value='/qualified/docker'),patch.object(m,'bounded',side_effect=run):
   with self.assertRaises(m.ReadDenied):m.database_readback(plan,original)
 def test_backup_receipt_does_not_open_dump_or_claim_current_checksum(self):
  with self.temp()as tmp:
   root=Path(tmp);p=root/'onboarding.dump';p.write_bytes(b'CREDENTIAL_CANARY'*30);p.chmod(0o600)
   self.write(root/'backup.json',{'path':str(p),'payloadParsed':True,'restorePerformed':False,'databaseOid':1,'historyHash':m.digest([]),'bytes':p.stat().st_size})
   with patch.object(m,'EXECUTION',root):report=m.backup_metadata({'database':{'before':{'onboarding':{'databaseOid':1,'migrations':[]}}}})
   self.assertFalse(report['dumpOpened']);self.assertFalse(report['currentFullChecksumVerified']);self.assertNotIn('CANARY',json.dumps(report))
 def test_document_drift_blocks_and_sql_has_owner_appendonly_checks(self):
  with self.temp()as tmp:
   p=Path(tmp)/'journal';self.write(p,{'version':1});snap={p:p.read_bytes()};self.write(p,{'version':2})
   with self.assertRaises(m.ReadDenied):m.same_documents(snap)
  sql=m.sql('onboarding','app');self.assertIn('source_property_revision_append_only',sql);self.assertIn('ROLLBACK;',sql)
 def test_get_child_has_fixed_get_only_no_credential_in_argv(self):
  self.assertIn("conn.request('GET','/apisix/admin/routes'",m.GET_CHILD);self.assertNotIn("'PUT'",m.GET_CHILD)
  src=(ROOT/'scripts/read-source-revision-completed-20261019.py').read_text();self.assertNotIn("'human-access.jwt'",src);self.assertNotIn('admin_login',src);self.assertNotIn('claim_zero_effect_successor(',src)
if __name__=='__main__':unittest.main()

class CompletedMain(unittest.TestCase):
 temp=Read.temp
 write=Read.write
 def test_complete_main_uses_exact_successor_fence_and_never_prints_private_values(self):
  with self.temp()as tmp:
   root=Path(tmp);execution=root/'source-revision-execution-uow4n8lp';prep=root/'prepared';old=root/'source-revision-execution-dvf517sr'
   claim=root/'source-revision-update-logical.claim.json';self.write(claim,{'historical':'retained'})
   plan={'engine':{},'authorityDirectory':str(execution),'logicalUpdateRef':'logical','logicalScopeSuccessor':{'context':str(old),'claimBinding':{'path':str(claim),'sha256':m.digest({'historical':'retained'})},'authorityBinding':{'sha256':'a'*64}},'gateway':{'beforeRoutes':{'old':{}},'afterRoutes':{'old':{},'prepare':{},'read':{}},'transport':{}},'retainedMcpMetadata':[],'retainedMcpMetadataCustody':{}}
   review={'authorityDirectory':str(execution),'sourceClosureHash':'closure','scopes':{'sourceRevisionUpdate':{'planHash':m.digest(plan)}}}
   authority={'sourceClosureHash':'closure','scopedExecution':{'reviewHash':m.digest(review)},'canary':'CREDENTIAL_CANARY'}
   auth={'owner':'same'};ar={'schema':'ouf.chatbot-file-authorization-journal.v1','planHash':m.digest(auth),'authorityHash':m.digest(authority),'budgetReset':False,'effects':{'one':{'state':'APPLIED'}}}
   effects=[{'stage':s,'state':'APPLIED','intentHash':m.digest({'planHash':m.digest(plan),'stage':s}),'evidence':{}}for s in m.STAGES];effects[-1]['evidence']={'applications':{'onboarding':{},'mcp':{}},'routeMapHash':m.digest(plan['gateway']['afterRoutes'])}
   row={'schema':'ouf.source-revision-update-journal.v1','scopeHash':m.digest(review['scopes']['sourceRevisionUpdate']),'authorityHash':m.digest(authority),'budgetReset':False,'nextStage':len(m.STAGES),'effects':effects,'incidentState':'RECOVERED','version':57,'bootId':'fixture-boot','expiresAt':0}
   child={'schema':'ouf.source-revision-logical-scope-successor-claim.v1','logicalUpdateRef':'logical','predecessorClaimSha256':m.digest({'historical':'retained'}),'predecessorAuthoritySha256':'a'*64,'planHash':m.digest(plan),'authorityHash':m.digest(authority),'context':str(execution),'priorCumulativeReadinessAttempts':0,'predecessorEffects':0,'budgetReset':False,'automaticReplayAllowed':False}
   for name,v in [('execution-plan.json',plan),('review.json',review),('authority.json',authority),('recovery.json',row),('authorization-plan.json',auth),('authorization/recovery.json',ar),('backup.json',{})]:self.write(execution/name,v)
   self.write(old/'logical-successor.claim.json',child);original=root/'original.json';self.write(original,{'value':'PRIVATE_CANARY'})
   result={'sourceClosureSha256':'closure','currentOriginalPreparationBinding':{'path':str(original)}};self.write(prep/'postboot-preparation-result.json',result)
   actual_read=Path.read_text
   def text(path,*a,**kw):return 'fixture-boot'if str(path)=='/proc/sys/kernel/random/boot_id'else actual_read(path,*a,**kw)
   def scope():
    return patch.multiple(m,ROOT=root,EXECUTION=execution,PREPARED=prep,AUTH_PLAN=m.digest(auth),ORIGINAL=m.digest({'value':'PRIVATE_CANARY'}))
   with scope(),patch.object(Path,'read_text',text),patch.object(m.signal,'alarm'),patch.object(m.signal,'signal'),patch.object(m,'frozen_preparation',return_value=(result,{})),patch.object(m,'applications',return_value=({'onboarding':{'runtimeBindingVerified':True}},{})),patch.object(m,'readiness',return_value={}),patch.object(m,'gateway_read',return_value=plan['gateway']['afterRoutes']),patch.object(m,'database_readback',return_value={'readOnlySessions':3}),patch.object(m,'backup_metadata',return_value={}):
    report=m.main();self.assertTrue(report['complete']);self.assertNotIn('CANARY',json.dumps(report));self.assertFalse(report['freshChatClientTokenScopesProven']);self.assertFalse(report['authorityAcceptedForExecution'])
    child['context']='wrong';self.write(old/'logical-successor.claim.json',child)
    with self.assertRaises(m.ReadDenied):m.main()
 def test_selected_0440_mcp_metadata_is_verified_without_chmod(self):
  with self.temp()as tmp:
   path=Path(tmp)/'permit.json';path.write_bytes(b'PRIVATE_CANARY');os.chown(path,0,10005);path.chmod(0o440)
   b={'path':str(path),'sha256':m.sha(path.read_bytes())};pin={**b,'metadata':m.custody_pin(path.stat())}
   result=m.retained_metadata_file(b,pin);self.assertTrue(result['custodyPreserved']);self.assertEqual(path.stat().st_mode&0o777,0o440)
   path.write_bytes(b'changed')
   with self.assertRaises(m.ReadDenied):m.retained_metadata_file(b,pin)

class RootShim(unittest.TestCase):
 def test_exact_hash_before_protected_reads_and_tampered_bytes_denied(self):
  import subprocess,sys
  text=(ROOT/'scripts/launch-source-revision-completed-read-20261019.sh').read_text();payload=text.split("<<'OUF_HUMAN_HISTORY_READ' | tee",1)[1].split('\n',1)[1].rsplit('\nOUF_HUMAN_HISTORY_READ',1)[0]
  for tamper in (False,True):
   with tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT',str(ROOT.parent)))as temp:
    p=Path(temp)/'helper';p.write_bytes(b'print("PRIVATE_CANARY")'if tamper else(ROOT/'scripts/read-source-revision-completed-20261019.py').read_bytes())
    harness="""import os,sys,json
payload,p=sys.argv[1:];original=os.open;original_lstat=os.lstat;calls=[]
def guarded(path,*a,**kw):
 if str(path).startswith('/etc/ouf/'):
  calls.append(str(path));raise RuntimeError('PRIVATE_CANARY')
 return original(path,*a,**kw)
def guarded_lstat(path,*a,**kw):
 if str(path).startswith('/etc/ouf/'):
  calls.append(str(path));raise RuntimeError('PRIVATE_CANARY')
 return original_lstat(path,*a,**kw)
os.open=guarded;os.lstat=guarded_lstat;sys.argv=['shim',p]
try:exec(compile(payload,'<shim>','exec'),{'__name__':'__main__'})
except SystemExit as e:print(json.dumps({'privateReads':len(calls),'exit':str(e.code)}))
"""
    r=subprocess.run([sys.executable,'-I','-B','-S','-c',harness,payload,str(p)],capture_output=True,timeout=20)
    self.assertEqual(r.returncode,0,r.stderr.decode());self.assertEqual(r.stderr,b'');self.assertNotIn(b'PRIVATE_CANARY',r.stdout)
    rows=[json.loads(x)for x in r.stdout.splitlines()];self.assertEqual(rows[-1]['privateReads'],0 if tamper else 1)
    if not tamper:self.assertFalse(rows[0]['complete'])
