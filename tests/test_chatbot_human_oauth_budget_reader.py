import copy,fcntl,hashlib,importlib.util,json,os,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('human_reader',ROOT/'scripts/read-chatbot-human-oauth-budget-20261017.py')
m=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(m)
class Reader(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(dir='/root'if os.environ.get('OUF_NATIVE_UIDS')=='1'else ROOT);self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name);self.root.chmod(0o700)
  self.human=self.root/'human-session-window2';self.human.mkdir(mode=0o700)
  self.bootfile=Path('/proc/sys/kernel/random/boot_id')
  if not self.bootfile.exists():
   self.assertNotEqual(os.environ.get('OUF_NATIVE_UIDS'),'1','Native CI requires procfs')
   self.bootfile=self.root/'fixture-boot';self.bootfile.write_text('11111111-1111-1111-1111-111111111111')
  self.boot=self.bootfile.read_text().strip()
  binding={'sessionDirectory':str(self.human),'tokenPath':str(self.human/'human-access.jwt'),
   'clientId':'ouf-human-admin','subject':'b93d8cf6-cd14-4ee6-91d7-84cd76c4f500',
   'createdAt':100,'expiresAt':7300}
  renewal={'priorOAuthAttempts':42,'maximumCumulativeOAuthAttempts':128,'predecessorDirectory':str(self.root/'human-session')}
  self.row={'schema':'ouf.chatbot-human-session.private.v1','binding':binding,'budgetReset':False,
   'governedWindowRenewal':{'review':renewal,'decision':{'reviewHash':m.digest(renewal),'approvedAt':100,'expiresAt':7300}},
   'attempts':48,'state':'READY','operation':'USERINFO','monotonicDeadline':1,'bootId':self.boot,
   'accessToken':'SECRET_BEARER_CANARY','refreshToken':'SECRET_REFRESH_CANARY','publishedAccessToken':'SECRET_PUBLISHED_CANARY'}
  self.authority={'semanticTokenOnlyExecution':{'reviewHash':m.REVIEW,'humanSessionHash':m.digest(binding)}}
  self.write(self.root/'authority.json',self.authority);self.write(self.human/'recovery.json',self.row)
  self.write(self.human/'human-access.jwt',{'THIS_FILE_MUST_NOT_BE_READ':'SECRET_FILE_CANARY'})
  (self.human/'invocation.lock').touch(mode=0o600)
  self.outputs=[]
  for name,value in [('BOOT_FILE',self.bootfile),('HUMAN',self.human),('CONTEXT',self.root),('AUTHORITY',m.digest(self.authority))]:
   p=patch.object(m,name,value);p.start();self.addCleanup(p.stop)
  p=patch.object(m.signal,'alarm');p.start();self.addCleanup(p.stop)
  p=patch.object(m,'emit',side_effect=lambda check,**kw:self.outputs.append({'check':check,**kw}));p.start();self.addCleanup(p.stop)
 def write(self,path,value):path.write_bytes(m.encoded(value));path.chmod(0o600)
 def project(self,row=None):return m.project(self.authority,self.row if row is None else row,time.time(),time.monotonic(),self.boot)
 def test_projection_preserves_oauth_budget_without_credential_hashes_or_values(self):
  value=self.project();self.assertEqual(value['attempts'],48);self.assertEqual(value['remainingOAuthAttempts'],80)
  self.assertTrue(value['humanSessionCumulativeBudgetProven']);self.assertFalse(value['newLoginAuthorized'])
  self.assertTrue(value['expiredAtRead']);self.assertTrue(value['sameBoot'])
  self.assertNotIn('SECRET',json.dumps(value));self.assertFalse(any('hash'in k.lower()for k in value))
 def test_unknown_outcome_is_projected_without_authorizing_replay(self):
  for operation,ambiguous in [('REFRESH',True),('DEVICE_START',True),('DEVICE_POLL',True),('USERINFO',False),('DISCOVERY',False)]:
   row=copy.deepcopy(self.row);row.update(state='REQUESTING',operation=operation)
   value=self.project(row);self.assertEqual(value['ambiguousRequestObserved'],ambiguous);self.assertFalse(value['newLoginAuthorized'])
 def test_regressed_reset_boolean_over_budget_and_identity_drift_are_denied(self):
  for key,value in [('attempts',41),('attempts',True),('attempts',129),('budgetReset',True),('operation','SECRET_CANARY'),('state','UNKNOWN')]:
   row=copy.deepcopy(self.row);row[key]=value
   with self.subTest(key=key,value=value),self.assertRaises(m.ReadDenied):self.project(row)
  self.row['binding']['subject']='other'
  with self.assertRaises(m.ReadDenied):self.project()
 def test_reboot_is_reported_without_monotonic_expiry_claim(self):
  result=m.project(self.authority,self.row,time.time(),time.monotonic(),'00000000-0000-0000-0000-000000000000')
  self.assertFalse(result['sameBoot']);self.assertFalse(result['monotonicExpired'])
 def test_actual_private_journal_reader_never_opens_bearer_file(self):
  opened=[];read=m.read
  def observed(path,*args,**kw):opened.append(Path(path).name);return read(path,*args,**kw)
  with patch.object(m,'read',side_effect=observed):m.main()
  self.assertEqual(set(opened),{'authority.json','recovery.json'})
  self.assertNotIn('SECRET',json.dumps(self.outputs));self.assertEqual(self.outputs[-2]['attempts'],48)
  self.assertEqual(self.outputs[-2]['credentialBearingJournalsRead'],1)
 def test_exclusive_human_invocation_blocks_projection(self):
  fd=os.open(self.human/'invocation.lock',os.O_RDONLY)
  try:
   fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
   with self.assertRaisesRegex(m.ReadDenied,'HUMAN_INVOCATION_STILL_HELD'):m.main()
  finally:os.close(fd)
 def test_mid_read_counter_change_fails_before_success_projection(self):
  read=m.read;count=0
  def drift(path,*args,**kw):
   nonlocal count
   value=read(path,*args,**kw)
   if Path(path).name=='recovery.json':
    count+=1
    if count==2:value['attempts']+=1
   return value
  with patch.object(m,'read',side_effect=drift),self.assertRaisesRegex(m.ReadDenied,'HUMAN_JOURNAL_CHANGED_DURING_READ'):m.main()
  self.assertFalse(any(v['check']=='PERSISTED_HUMAN_BUDGET'for v in self.outputs))
 def test_real_isolated_cli_is_credential_free(self):
  source=(ROOT/'scripts/read-chatbot-human-oauth-budget-20261017.py').read_text()
  source=source.replace('/proc/sys/kernel/random/boot_id',str(self.bootfile))
  source=source.replace('/etc/ouf/deploy-snapshots/semantic-token-execution-usx0tsem',str(self.root))
  source=source.replace('ccac6ea4c195de2c65937fb0df581adee5a610f167cb2c125662733932312eed',m.digest(self.authority))
  path=self.root/'reader.py';path.write_text(source)
  result=subprocess.run([sys.executable,'-I','-B','-S',str(path)],capture_output=True,timeout=5)
  self.assertEqual(result.returncode,0,result.stdout+result.stderr)
  self.assertNotIn(b'SECRET',result.stdout+result.stderr)
  rows=[json.loads(v)for v in result.stdout.splitlines()];self.assertEqual(rows[-2]['attempts'],48)
if __name__=='__main__':unittest.main()
