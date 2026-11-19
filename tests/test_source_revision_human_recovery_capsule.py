import ast,contextlib,copy,hashlib,importlib.util,io,json,os,signal,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
import test_source_revision_custody_capsule as previous
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=load('human_recovery_capsule','scripts/prepare-source-revision-human-recovery.py');stage=load('human_recovery_stage','scripts/stage-source-revision-human-recovery.py')
class Capsule(unittest.TestCase):
 def temp(self):return tempfile.TemporaryDirectory(dir=os.environ['OUF_TEST_ROOT'])
 def tearDown(self):signal.alarm(0)
 def test_four_staged_source_files_exact_and_non_overwritable(self):
  with self.temp()as temp,contextlib.redirect_stdout(io.StringIO()):
   target=Path(temp)/'code';stage.stage(ROOT,target,'a'*40);manifest=json.loads((target/'manifest.json').read_bytes());self.assertEqual(set(p.name for p in target.iterdir()),{'manifest.json','prepare.py','entry.py','login.py'});self.assertEqual(manifest['schema'],'ouf.source-revision-human-recovery-code.v1')
   for name,sha in manifest['files'].items():self.assertEqual(m.sha(m.stage_read(target/name,sha)),sha)
   with self.assertRaises(ValueError):stage.stage(ROOT,target,'a'*40)
 def test_all81_file_reload_preserves_actual_retained_original_paths(self):
  with patch.object(previous,'m',m):previous.Capsule().test_full_81_file_reload_reads_retained_original_from_its_actual_context()
 def report(self):return {'executionReconciliation':{'contextFiles':9,'contextClosureSha256':m.STOP_CLOSURE,'authorityAndLoginArtifactsAbsent':True,'retainedFilesPreserved':True},'preparedClosure':{'frozenFilesVerified':81,'originalScopeUnchanged':True,'successorClaimAbsent':True},'humanSession':{'state':'BLOCKED','operation':'REFRESH','attempts':189,'remainingAttempts':67,'reason':'HUMAN_OAUTH_REVOKED_OR_PERMANENT_OR_UNKNOWN','frozenIdentityAndBudgetPredicate':'ACCEPTED','currentBootMatches':True,'budgetReset':False,'successorClaimPresent':False,'wallClockNotBeforeLastObservation':True}}
 def test_exact_blocked189_reconciliation_required_before_any_new_capsule(self):
  for change in (None,('humanSession','attempts',190),('humanSession','operation','USERINFO'),('humanSession','state','READY'),('humanSession','reason','HUMAN_OAUTH_OUTCOME_UNPROVEN'),('humanSession','successorClaimPresent',True),('executionReconciliation','contextClosureSha256','0'*64),('executionReconciliation','authorityAndLoginArtifactsAbsent',False)):
   with self.subTest(change=change):
    report=self.report()
    if change:report[change[0]][change[1]]=change[2]
    with patch.object(m,'DIAGNOSTIC_SOURCE','def main():return '+repr(report)):
     if change:
      with self.assertRaises(ValueError):m.reconcile()
     else:self.assertEqual(m.reconcile()[0],report)
 def test_embedded_native_sources_change_only_nested_watchdogs(self):
  source=(ROOT/'scripts/prepare-source-revision-custody-continuation.py').read_text();tree=ast.parse(source);original=ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id=='VERIFIER_SOURCE'))
  marker='None  # The enclosing private preparer owns the single absolute300s watchdog.'
  self.assertEqual(m.VERIFIER_SOURCE,original.replace('signal.alarm(300)',marker));self.assertEqual(m.DIAGNOSTIC_SOURCE,(ROOT/'scripts/read-source-revision-custody-human-stop-20261019.py').read_text().replace('signal.alarm(180)',marker))
  old=(ROOT/'scripts/resume-source-revision-iam-20261019.py').read_text();self.assertEqual(m.ADMIN_SOURCE,old[old.index('\ndef reserve('):old.index('\ndef run(')])
  self.assertEqual(set(m.MODULES),{'tools.source_revision_update.entry','tools.source_revision_update.login'});self.assertEqual(m.BASE_PROFILE['packageSha256'],'afc2dbbfa72c14a64b00e9a0fba04fa731bd2ec51b08f5b65211a74a3dafd30d')
  nodes=ast.parse((ROOT/'scripts/prepare-source-revision-human-recovery.py').read_text());run=next(n for n in nodes.body if isinstance(n,ast.FunctionDef)and n.name=='run');alarms=[n for n in ast.walk(run)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and isinstance(n.func.value,ast.Name)and n.func.value.id=='signal'and n.func.attr=='alarm'];self.assertEqual([ast.literal_eval(n.args[0])for n in alarms],[300,0])
 def bridge(self,mode):
  calls=[];requests=[]
  class Paused(Exception):
   def __init__(self,reason):self.reason=reason
  class Engine:
   def __init__(self,*args):calls.append('engine-pin')
   def check_socket(self):calls.append('socket-check')
  class Transport:
   def __init__(self,*args):pass
   def oauth(self):
    requests.append('metadata-get')
    if len(requests)==1 and mode!='ready':raise Paused('EXISTING_IAM_SESSION_EXPIRED'if mode=='expired'else'UNKNOWN_OR_PERMANENT')
  auth=types.SimpleNamespace(OwnerTransport=Transport,AuthorizationPaused=Paused);engine=types.SimpleNamespace(Engine=Engine);original_import=m.importlib.import_module
  def importer(name):return auth if name=='tools.chatbot_file_cohort.authorization'else engine if name=='engine_creation'else original_import(name)
  original={'authorization':{'plan':{'selection':{'fixed':'metadata'}}},'engine':{'socketPath':'/exact/socket','socketBinding':[1,2,0,0,384]}};case={'postbootBlockedHuman':{'binding':{'tokenPath':'/exact/never-open-bearer'}}};iam={'calls':calls,'maximumLoginAttempts':1}
  admin="def admin_login(original,profile,iam):\n assert profile['preparationResultSha256']=='r'*64\n iam['calls'].append('terminal-iam-once')\n"
  with patch.object(m.importlib,'import_module',side_effect=importer),patch.object(m,'ADMIN_SOURCE',admin),patch.object(m,'IAM_PROFILE',iam),patch.dict(os.environ,{},clear=False),contextlib.redirect_stdout(io.StringIO()):
   if mode=='unknown':
    with self.assertRaises(ValueError):m.iam_gate(original,case,'r'*64)
   else:m.iam_gate(original,case,'r'*64)
   self.assertEqual(os.environ['DOCKER_HOST'],'unix:///exact/socket')
  self.assertEqual(calls.count('terminal-iam-once'),1 if mode=='expired'else 0);self.assertEqual(len(requests),2 if mode=='expired'else 1)
 def test_current_iam_metadata_does_not_open_login(self):self.bridge('ready')
 def test_only_expired_iam_requests_one_terminal_login_then_metadata_read(self):self.bridge('expired')
 def test_unknown_iam_failure_never_opens_password_prompt(self):self.bridge('unknown')
