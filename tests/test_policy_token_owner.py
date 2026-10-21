import copy,fcntl,json,os,ssl,sys,tempfile,unittest,subprocess,threading
from http.server import HTTPServer,BaseHTTPRequestHandler
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.semantic_policy_token_owner.producer import (
 Binding,CredentialFile,DomainOwner,HttpsGrant,TokenRenewalAdapter,RenewalOperation,token_response)
from tools.semantic_lease_recovery.bounded_recovery import Policy,Recovery,Temporary,Permanent
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.semantic_policy_token_owner.supervisor import ScheduledRecovery,RenewalWorker

class Clock:
 def __init__(self):self.wall=100000.;self.mono=100.
 def __call__(self):return self.wall,self.mono
 def advance(self,n):self.wall+=n;self.mono+=n
class Owner(DomainOwner):
 def __init__(self,clock):self.clock=clock;self.until=0;self.revoked=False;self.pauses=0;self.admission_error=None
 def guard(self,binding_hash):
  if self.revoked:raise Permanent('AUTHORITY_REVOKED')
 def prepare(self,binding_hash,deadline):
  if self.clock.mono<self.until:raise Temporary('DEPENDENCY_UNAVAILABLE',no_effect=True)
 def admit(self,*args):
  if self.admission_error:raise self.admission_error
  return True
 def pause(self):self.pauses+=1
class Response:
 status=200
 def __init__(self,value):self.raw=json.dumps(value).encode()
 def read(self,n):return self.raw[:n]
 def __enter__(self):return self
 def __exit__(self,*args):pass
class Opener:
 def __init__(self):self.calls=0;self.error=None;self.value={'access_token':'FIXTURE_TOKEN','token_type':'Bearer','expires_in':120};self.callback=None
 def open(self,request,timeout):
  self.calls+=1
  if self.callback:self.callback()
  if self.error:raise self.error
  return Response(self.value)

class TokenOwner(unittest.TestCase):
 def test_real_tls_trust_hostname_redirect_and_single_request(self):
  with tempfile.TemporaryDirectory(dir=ROOT) as d:
   cert=Path(d)/'cert.pem';key=Path(d)/'key.pem'
   subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
    '-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost',
    '-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   calls=[];reply={'code':200}
   class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
     calls.append(self.path);self.rfile.read(int(self.headers['Content-Length']))
     self.send_response(reply['code']);self.send_header('Location','/redirected');self.end_headers()
     if reply['code']==200:self.wfile.write(b'{"access_token":"FIXTURE_TLS","token_type":"Bearer","expires_in":120}')
    def do_GET(self):calls.append(self.path);self.send_response(500);self.end_headers()
    def log_message(self,*args):pass
   server=HTTPServer(('127.0.0.1',0),Handler);server.timeout=.2
   context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
   server.socket=context.wrap_socket(server.socket,server_side=True)
   thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.05},daemon=True);thread.start()
   try:
    clock=Clock();port=server.server_port
    binding=Binding(f'https://localhost:{port}/token','client','scope','/run/fixture','token',10001)
    with self.assertRaises(Temporary):HttpsGrant(clock).request(binding,'FIXTURE_SECRET',130)
    self.assertEqual(calls,[])
    trusted=ssl.create_default_context(cafile=str(cert));transport=HttpsGrant(clock,context=trusted)
    wrong=Binding(f'https://127.0.0.1:{port}/token','client','scope','/run/fixture','token',10001)
    with self.assertRaises(Temporary):transport.request(wrong,'FIXTURE_SECRET',130)
    self.assertEqual(calls,[])
    self.assertEqual(transport.request(binding,'FIXTURE_SECRET',130)['expires_in'],120)
    self.assertEqual(calls,['/token']);reply['code']=302
    with self.assertRaises(Temporary):transport.request(binding,'FIXTURE_SECRET',130)
    self.assertEqual(calls,['/token','/token']);reply['code']=401
    with self.assertRaises(Permanent):transport.request(binding,'FIXTURE_SECRET',130)
    self.assertEqual(calls,['/token','/token','/token'])
   finally:server.shutdown();thread.join(2);server.server_close()

 def fixture(self,policy=None,*,scheduled=False):
  temp=tempfile.TemporaryDirectory(dir=ROOT);self.addCleanup(temp.cleanup);root=Path(temp.name);root.chmod(0o700)
  credential=root/'credential';credential.write_text('FIXTURE_SECRET');credential.chmod(0o400)
  out=root/'output';out.mkdir(mode=0o750);out.chmod(0o750)
  try:os.chown(out,0,10001)
  except OSError:
   if os.environ.get('OUF_NATIVE_UIDS')=='1':raise
   self.skipTest('Native group10001 fixture unavailable locally')
  state=root/'state';state.mkdir(mode=0o700)
  clock=Clock();owner=Owner(clock);opener=Opener()
  binding=Binding('https://fixture.invalid/token','fixture-client','fixture-scope',str(out),'token.jwt',10001)
  adapter=TokenRenewalAdapter(binding,CredentialFile(credential),owner,HttpsGrant(clock,opener=opener),clock)
  journal=Journal(state);recovery=(ScheduledRecovery if scheduled else Recovery)(journal,adapter,policy or Policy(), 'a'*64,'b'*64,clock,lambda:.5)
  journal.initialize(recovery.initial()) # TEST ONLY; production component has no initialization API.
  return root,clock,owner,opener,adapter,journal,(RenewalWorker(recovery) if scheduled else RenewalOperation(recovery))

 def test_scheduled_success_preserves_budget_and_shortens_interval_for_short_expiry(self):
  root,clock,owner,opener,adapter,journal,worker=self.fixture(scheduled=True)
  opener.value['expires_in']=100
  first=worker.tick();self.assertEqual(first['state'],'ACTIVE')
  self.assertEqual(first['nextRenewalMonotonic']-clock.mono,50)
  clock.advance(49);worker.tick();self.assertEqual(opener.calls,1)
  clock.advance(1);second=worker.tick();self.assertEqual(second['state'],'ACTIVE')
  self.assertEqual((second['attempts'],second['publicationCount']),(2,2))
  self.assertEqual((first['startedWall'],first['startedMonotonic']),
                   (second['startedWall'],second['startedMonotonic']))
  self.assertFalse(worker.status(second)['applicationReady'])

 def test_scheduled_restart_requires_reconciliation_and_no_timer_budget_reset(self):
  root,clock,owner,opener,adapter,journal,worker=self.fixture(scheduled=True)
  first=worker.tick();clock.advance(60)
  restarted=RenewalWorker(ScheduledRecovery(Journal(journal.root),adapter,Policy(),'a'*64,'b'*64,clock,lambda:.5))
  row=restarted.tick();self.assertEqual(row['state'],'RECONCILE_REQUIRED')
  self.assertEqual(row['attempts'],first['attempts']);self.assertEqual(opener.calls,1)

 def test_successful_timer_cycles_cannot_bypass_finite_operation_cap(self):
  root,clock,owner,opener,adapter,journal,worker=self.fixture(Policy(max_attempts=2),scheduled=True)
  worker.tick();clock.advance(60);second=worker.tick();self.assertEqual(second['attempts'],2)
  self.assertEqual(worker.tick()['state'],'PAUSED_EXHAUSTED');clock.advance(10000)
  self.assertEqual(worker.tick()['attempts'],2);self.assertEqual(opener.calls,2)

 def test_scheduled_dependency_outage_keeps_original_history_after_new_worker(self):
  root,clock,owner,opener,adapter,journal,worker=self.fixture(scheduled=True)
  original=worker.tick();clock.advance(60);owner.until=clock.mono+14400
  row=worker.tick();self.assertEqual(row['state'],'RETRY_WAIT');self.assertEqual(opener.calls,1)
  replacement=RenewalWorker(ScheduledRecovery(Journal(journal.root),adapter,Policy(),'a'*64,'b'*64,clock,lambda:.5))
  self.assertEqual(replacement.tick()['attempts'],row['attempts'])
  while True:
   clock.advance(row['nextMonotonic']-clock.mono);row=replacement.tick()
   if row['state']=='ACTIVE':break
   self.assertEqual(row['state'],'RETRY_WAIT');self.assertEqual(opener.calls,1)
  self.assertEqual(row['publicationCount'],2);self.assertEqual(opener.calls,2)
  self.assertEqual(row['startedWall'],original['startedWall'])

 def test_scheduled_revocation_and_expired_token_do_not_grant(self):
  root,clock,owner,opener,adapter,journal,worker=self.fixture(scheduled=True)
  worker.tick();owner.revoked=True
  self.assertEqual(worker.tick()['state'],'BLOCKED');self.assertEqual(opener.calls,1)
  root,clock,owner,opener,adapter,journal,worker=self.fixture(scheduled=True)
  worker.tick();clock.advance(121)
  self.assertEqual(worker.tick()['state'],'RECONCILE_REQUIRED');self.assertEqual(opener.calls,1)

 def test_worker_wait_has_no_journal_lock_and_retains_invocation_fence(self):
  root,clock,owner,opener,adapter,journal,worker=self.fixture(scheduled=True)
  class Stop:
   stopped=False
   def is_set(inner):return inner.stopped
   def wait(inner,seconds):
    self.assertLessEqual(seconds,5)
    fd=os.open(journal.lock,os.O_RDWR)
    try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    finally:os.close(fd)
    with self.assertRaises(BlockingIOError):
     with Journal(journal.root).invocation():pass
    inner.stopped=True;return True
  result=worker.serve(Stop(),lambda status:self.assertTrue(status['live']))
  self.assertEqual(result['state'],'CANCELLED');self.assertEqual(opener.calls,1)

 def test_worker_observer_failure_revokes_and_restart_does_not_replay(self):
  root,clock,owner,opener,adapter,journal,worker=self.fixture(scheduled=True)
  class Stop:
   def is_set(self):return False
  def fail(status):raise RuntimeError('FIXTURE_PRIVATE_OBSERVER')
  with self.assertRaises(RuntimeError):worker.serve(Stop(),fail)
  self.assertGreater(owner.pauses,0)
  restarted=RenewalWorker(ScheduledRecovery(Journal(journal.root),adapter,Policy(),'a'*64,'b'*64,clock,lambda:.5))
  self.assertEqual(restarted.tick()['state'],'RECONCILE_REQUIRED');self.assertEqual(opener.calls,1)

 def test_worker_storage_failure_before_tick_guard_denies_without_private_error(self):
  root,clock,owner,opener,adapter,journal,worker=self.fixture(scheduled=True)
  worker.tick();original=journal.read
  def fail():raise OSError('FIXTURE_PRIVATE_STORAGE_ERROR')
  journal.read=fail
  with self.assertRaisesRegex(RuntimeError,'^TOKEN_WORKER_STATE_UNPROVEN$'):worker.tick()
  self.assertGreater(owner.pauses,0);self.assertFalse(worker.active_here)
  journal.read=original
  self.assertEqual(worker.tick()['state'],'RECONCILE_REQUIRED');self.assertEqual(opener.calls,1)

 def test_finite_expiry_and_boolean_expiry_denied(self):
  binding=Binding('https://fixture.invalid/token','client','scope','/run/fixture','token',10001)
  for seconds in (None,True,0,30,3601):
   with self.assertRaises(Permanent):token_response({'access_token':'T','token_type':'Bearer','expires_in':seconds},binding)
  self.assertEqual(token_response({'access_token':'T','token_type':'Bearer','expires_in':120},binding),('T',120))

 def test_credential_symlink_parent_permissions_and_hardlink_denied_without_body_read(self):
  with tempfile.TemporaryDirectory(dir=ROOT) as d:
   root=Path(d);root.chmod(0o700);secret=root/'secret';secret.write_bytes(b'FIXTURE');secret.chmod(0o400)
   self.assertEqual(CredentialFile(secret).read(),'FIXTURE')
   link=root/'alias';link.symlink_to(secret)
   with self.assertRaises(Permanent):CredentialFile(link).read()
   os.link(secret,root/'hardlink')
   with self.assertRaises(Permanent):CredentialFile(secret).read()
   (root/'hardlink').unlink();root.chmod(0o770)
   with self.assertRaises(Permanent):CredentialFile(secret).read()

 def test_https_no_insecure_context_and_private_error_redacted(self):
  context=ssl._create_unverified_context()
  with self.assertRaises(Permanent):HttpsGrant(Clock(),context=context)
  for endpoint in ('http://fixture.invalid/token','https://user:password@fixture.invalid/token','https://fixture.invalid/token?secret=x'):
   with self.assertRaises(Permanent):Binding(endpoint,'client','scope','/run/fixture','token',10001)

 def test_native_publication_modes_and_no_secrets_in_journal_or_status(self):
  root,clock,owner,opener,adapter,journal,operation=self.fixture()
  def no_shared_lock():
   fd=os.open(journal.lock,os.O_RDWR)
   try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
   finally:os.close(fd)
  opener.callback=no_shared_lock
  row=operation.step();self.assertEqual(row['state'],'ACTIVE')
  info=(root/'output'/'token.jwt').stat();self.assertEqual((info.st_uid,info.st_gid,info.st_mode&0o777),(0,10001,0o440))
  self.assertEqual((root/'output'/'token.jwt').read_text(),'FIXTURE_TOKEN')
  encoded=json.dumps(row)+json.dumps(operation.public_status(row))
  for private in ('FIXTURE_SECRET','FIXTURE_TOKEN'):self.assertNotIn(private,encoded)
  self.assertFalse(operation.public_status(row)['applicationReady'])
  operation.step();self.assertEqual(opener.calls,1)

 def test_four_hour_outage_finite_retry_then_single_grant(self):
  root,clock,owner,opener,adapter,journal,operation=self.fixture();owner.until=clock.mono+14400
  while True:
   row=operation.step()
   if row['state']=='ACTIVE':break
   self.assertEqual(row['state'],'RETRY_WAIT');self.assertEqual(opener.calls,0)
   before=row['attempts'];operation.step();self.assertEqual(journal.read()['attempts'],before)
   clock.advance(row['nextMonotonic']-clock.mono)
  self.assertLess(row['attempts'],128);self.assertEqual(opener.calls,1)

 def test_timeout_after_grant_never_replayed_on_restart(self):
  root,clock,owner,opener,adapter,journal,operation=self.fixture();opener.error=TimeoutError('PRIVATE_RESPONSE')
  row=operation.step();self.assertEqual(row['state'],'RECONCILE_REQUIRED')
  self.assertNotIn('PRIVATE_RESPONSE',json.dumps(row))
  recovered=Recovery(Journal(journal.root),adapter,Policy(),'a'*64,'b'*64,clock,lambda:.5)
  RenewalOperation(recovered).step();self.assertEqual(opener.calls,1);self.assertEqual(recovered.journal.read()['attempts'],1)

 def test_post_grant_no_effect_probe_is_not_proof_of_no_grant(self):
  root,clock,owner,opener,adapter,journal,operation=self.fixture()
  owner.admission_error=Temporary('DEPENDENCY_TIMEOUT',no_effect=True)
  row=operation.step();self.assertEqual(row['state'],'RECONCILE_REQUIRED');self.assertEqual(opener.calls,1)
  self.assertFalse((root/'output'/'token.jwt').exists())

 def test_missing_expiry_remote_effect_requires_reconciliation(self):
  root,clock,owner,opener,adapter,journal,operation=self.fixture();opener.value.pop('expires_in')
  row=operation.step();self.assertEqual(row['state'],'RECONCILE_REQUIRED');self.assertEqual(opener.calls,1)

 def test_revocation_while_waiting_and_after_grant_blocks_publication(self):
  root,clock,owner,opener,adapter,journal,operation=self.fixture();owner.until=10**9
  operation.step();owner.revoked=True
  self.assertEqual(operation.step()['state'],'BLOCKED');self.assertEqual(opener.calls,0)
  root,clock,owner,opener,adapter,journal,operation=self.fixture()
  opener.callback=lambda:setattr(owner,'revoked',True)
  self.assertEqual(operation.step()['state'],'BLOCKED');self.assertFalse((root/'output'/'token.jwt').exists())

 def test_exhaustion_cancellation_and_concurrent_invocation_preserve_history(self):
  root,clock,owner,opener,adapter,journal,operation=self.fixture(Policy(max_attempts=1));owner.until=10**9
  self.assertEqual(operation.step()['state'],'PAUSED_EXHAUSTED');clock.advance(10000)
  self.assertEqual(operation.step()['attempts'],1);self.assertEqual(opener.calls,0)
  with journal.invocation():
   with self.assertRaises(BlockingIOError):operation.step()
  self.assertEqual(operation.step(cancelled=True)['state'],'CANCELLED')
  self.assertEqual(journal.read()['attempts'],1)

 def test_storage_failure_after_file_publication_never_regrants(self):
  root,clock,owner,opener,adapter,journal,operation=self.fixture()
  original=journal.compare_and_save
  def save(previous,next_row):
   if next_row['state']=='ACTIVE':raise OSError('PRIVATE_STORAGE')
   return original(previous,next_row)
  journal.compare_and_save=save
  self.assertEqual(operation.step()['state'],'RECONCILE_REQUIRED')
  self.assertEqual(Journal(journal.root).read()['state'],'RECONCILE_REQUIRED')
  self.assertTrue((root/'output'/'token.jwt').exists())
  restarted=Recovery(Journal(journal.root),adapter,Policy(),'a'*64,'b'*64,clock,lambda:.5)
  self.assertEqual(RenewalOperation(restarted).step()['state'],'RECONCILE_REQUIRED');self.assertEqual(opener.calls,1)

 def test_real_process_death_after_publication_reconciles_without_grant_replay(self):
  root,clock,owner,opener,adapter,journal,operation=self.fixture()
  grant_log=root/'grant-count'
  def count_grant():
   with grant_log.open('ab') as stream:stream.write(b'G');stream.flush();os.fsync(stream.fileno())
  opener.callback=count_grant;original=journal.compare_and_save
  def die(previous,next_row):
   if next_row['state']=='ACTIVE':os._exit(73)
   return original(previous,next_row)
  child=os.fork()
  if child==0:
   journal.compare_and_save=die
   try:operation.step()
   finally:os._exit(74)
  _,status=os.waitpid(child,0);self.assertEqual(os.waitstatus_to_exitcode(status),73)
  self.assertEqual(Journal(journal.root).read()['state'],'PUBLISHING')
  self.assertTrue((root/'output'/'token.jwt').exists())
  restarted=Recovery(Journal(journal.root),adapter,Policy(),'a'*64,'b'*64,clock,lambda:.5)
  self.assertEqual(RenewalOperation(restarted).step()['state'],'RECONCILE_REQUIRED')
  self.assertEqual(grant_log.read_bytes(),b'G');self.assertEqual(opener.calls,0)

 def test_output_drift_blocks_before_any_grant(self):
  root,clock,owner,opener,adapter,journal,operation=self.fixture()
  (root/'output'/'unapproved').write_bytes(b'PRIVATE')
  self.assertEqual(operation.step()['state'],'BLOCKED');self.assertEqual(opener.calls,0)

 def test_preparation_timeout_includes_duration_in_finite_budget(self):
  root,clock,owner,opener,adapter,journal,operation=self.fixture(Policy(max_elapsed=30))
  owner.prepare=lambda *args:clock.advance(31)
  self.assertEqual(operation.step()['state'],'PAUSED_EXHAUSTED');self.assertEqual(opener.calls,0)

if __name__=='__main__':unittest.main()
