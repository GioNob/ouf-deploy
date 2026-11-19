import base64,copy,hashlib,importlib.util,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
source=HERE/'read_stop.py'
if not source.exists():source=ROOT/'scripts/read-ingestion-owner-reference-stop-20261019.py'
spec=importlib.util.spec_from_file_location('pure_stop_reader',source);r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
class ReadStop(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(dir=HERE);self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.root.chmod(0o700)
  self.context=self.root/'ingestion-owner-reference-execution-tr33g8bg';self.context.mkdir(mode=0o700)
  self.predecessor=self.root/'old-human';self.predecessor.mkdir(mode=0o700)
  self.review={'schema':'ouf.human-ingestion-owner-rollout-budget-review.v6','priorOAuthAttempts':259,'maximumCumulativeOAuthAttempts':272,'budgetReset':False}
  self.review_hash=r.digest(self.review);self.decision={'schema':'ouf.human-ingestion-owner-rollout-budget-decision.v6','reviewHash':self.review_hash,
   'decision':'APPROVE_EXACT272_AND_NEW7200_WINDOW_FRESH_LOGIN_NO_RUNTIME_AUTHORITY','approvedAt':1000,'expiresAt':8200}
  self.destination=self.root/('human-ingestion-owner-rollout272-'+self.review_hash);self.destination.mkdir(mode=0o700)
  self.before={'selectionHash':'hash','issuer':'issuer','subject':'PRIVATE_SUBJECT','tenant':'tenant','clientId':'client','scopes':['s'],
   'sessionDirectory':str(self.predecessor)}
  self.binding={**self.before,'sessionDirectory':str(self.destination),'tokenPath':str(self.destination/'human-access.jwt'),
   'createdAt':1000,'expiresAt':8200,'retryProfile':{'id':'ouf.human.ingestion-owner-rollout272.v6','maximumAttempts':272}}
  self.row={'schema':'ouf.chatbot-human-session.private.v1','budgetReset':False,'binding':self.binding,
   'governedWindowRenewal':{'review':self.review,'decision':self.decision},'attempts':272,'state':'VERIFYING',
   'accessToken':'NEVER_PRINT_ACCESS','refreshToken':'NEVER_PRINT_REFRESH','deviceCode':'NEVER_PRINT_DEVICE'}
  self.write(self.destination/'recovery.json',self.row)
  self.write(self.predecessor/'successor-window.claim.json',{'destination':str(self.destination),'reviewHash':self.review_hash,
   'decisionHash':r.digest(self.decision),'windowExpiresAt':8200,'priorOAuthAttempts':259,'maximumCumulativeOAuthAttempts':272,'budgetReset':False})
  claim={'context':str(self.context),'priorOAuthAttempts':259,'automaticReplayAllowed':False};self.claimpath=self.root/'preparation.claim.json';self.write(self.claimpath,claim)
  case={'humanBinding':self.before,'preparationClaimBinding':{'path':str(self.claimpath),'sha256':r.digest(claim)}}
  sources={f'fixture.{n}':base64.b64encode(b'raise RuntimeError("NEVER_EXECUTE_RETAINED_CODE")').decode()for n in range(232)}
  hashes={k:hashlib.sha256(base64.b64decode(v)).hexdigest()for k,v in sources.items()}
  raw={'case.json':r.encoded(case),'sources.json':r.encoded(sources),'bootstrap.py':b'raise Exception("DO_NOT_EXECUTE")',
   'runtime.py':b'raise Exception("DO_NOT_EXECUTE")','reader.py':b'raise Exception("DO_NOT_EXECUTE")'}
  for k,v in raw.items():self.write(self.context/k,v)
  closure={'declaration':{'moduleCount':232,'sourceHashes':hashes}};self.closure_hash=r.digest(closure)
  package={'fileHashes':{k:hashlib.sha256(v).hexdigest()for k,v in raw.items()},'closure':closure,'executionPins':{'caseSha256':r.digest(case)}}
  self.package_hash=r.digest(package);self.write(self.context/'package.json',package)
  self.write(self.context/'runtime.claim.json',{'packageHash':self.package_hash,'automaticReplayAllowed':False})
  self.write(self.context/'login-review.json',self.review);self.write(self.context/'login-decision.json',self.decision)
 def write(self,path,value):
  path.write_bytes(value if type(value)is bytes else r.encoded(value));path.chmod(0o600)
 def inspect(self):return r.inspect(self.context,self.package_hash,self.closure_hash,self.review_hash)
 def test_only_whitelisted_projection_no_writes_dispatch_or_secret_output(self):
  before={str(p):(p.read_bytes(),p.stat().st_mtime_ns)for p in self.root.rglob('*')if p.is_file()}
  result=self.inspect();text=r.encoded(result).decode()
  self.assertTrue(result['complete']);self.assertEqual(result['human']['attempts'],272)
  for secret in ('NEVER_PRINT_ACCESS','NEVER_PRINT_REFRESH','NEVER_PRINT_DEVICE','PRIVATE_SUBJECT'):self.assertNotIn(secret,text)
  self.assertEqual(before,{str(p):(p.read_bytes(),p.stat().st_mtime_ns)for p in self.root.rglob('*')if p.is_file()})
 def test_refuses_changed_source_bytes_before_any_credential_read(self):
  self.write(self.context/'runtime.py',b'changed')
  with self.assertRaisesRegex(ValueError,'RETAINED_HASH_MISMATCH'):self.inspect()
 def test_refuses_human_state_or_budget_drift(self):
  for change in ({'attempts':271},{'state':'READY'},{'budgetReset':True}):
   self.write(self.destination/'recovery.json',{**self.row,**change})
   with self.subTest(change=change),self.assertRaises(ValueError):self.inspect()
 def test_refuses_identity_or_successor_path_drift(self):
  row=copy.deepcopy(self.row);row['binding']['subject']='different';self.write(self.destination/'recovery.json',row)
  with self.assertRaisesRegex(ValueError,'EXACT_SUCCESSOR_IDENTITY_HISTORY_REQUIRED'):self.inspect()
 def test_does_not_open_authority_or_bearer_even_when_unexpected(self):
  for path in (self.context/'authority.json',self.destination/'human-access.jwt'):
   self.write(path,b'PRIVATE_NEVER_OPEN')
   with self.assertRaises(ValueError):self.inspect()
   path.unlink()
 def test_symlink_hardlink_world_writable_custody_denied(self):
  path=self.destination/'recovery.json';original=path.read_bytes();path.unlink();target=self.root/'elsewhere';self.write(target,original)
  path.symlink_to(target)
  with self.assertRaises(ValueError):self.inspect()
  path.unlink();os.link(target,path)
  with self.assertRaises(ValueError):self.inspect()
  path.unlink();self.write(path,original);path.chmod(0o644)
  with self.assertRaises(ValueError):self.inspect()
 def test_mutation_between_journal_reads_is_rejected(self):
  original=r.parsed;reads=0
  def parsed(path,*args):
   nonlocal reads
   value=original(path,*args)
   if Path(path)==self.destination/'recovery.json':
    reads+=1
    if reads==2:value={**value,'lastObservedAt':42}
   return value
  with patch.object(r,'parsed',side_effect=parsed),self.assertRaisesRegex(ValueError,'DIAGNOSTIC_SNAPSHOT_CHANGED'):self.inspect()
 def test_no_import_or_execution_of_retained_code(self):
  result=self.inspect();self.assertFalse(result['runtimeMainCalled']);self.assertFalse(result['preparerMainCalled'])
if __name__=='__main__':unittest.main()
