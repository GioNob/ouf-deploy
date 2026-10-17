"""Real Docker socket and network namespace; synthetic APISIX Admin contract.

No production app authentication claim: target final probes enforce that boundary.
The HUMAN/worker guard is a signed test fixture in this transport qualification.
"""
import copy,json,os,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools/semantic_policy_token_owner'),str(ROOT/'tools/semantic_application_cutover'),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
import test_cutover_authority_native as crypto
from test_resolution_routes_plan import templates
from engine_creation import Engine
from tools.chatbot_file_cohort.gateway import NamespaceAdmin,MOUNT_SET_BINDING
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.resolution_ths_update.plan import compile_routes,ROUTES
from tools.resolution_ths_update.owner import ReadinessUpdate,scope,digest,UpdatePaused
from tools.resolution_ths_update.native import NativePorts
ADMIN='''import http.server,json,socket
routes=INITIAL
writes=0
class H(http.server.BaseHTTPRequestHandler):
 def reply(self,status,body):
  raw=json.dumps(body).encode();self.send_response(status);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
 def do_GET(self):
  if self.headers.get('X-API-KEY')!='EXISTING_FIXTURE_ADMIN_KEY_123456':return self.reply(403,{})
  return self.reply(200,{'total':len(routes),'list':[{'value':v}for v in routes.values()],'writes':writes})
 def do_PUT(self):
  global writes
  if self.headers.get('X-API-KEY')!='EXISTING_FIXTURE_ADMIN_KEY_123456':return self.reply(403,{})
  rid=self.path.rsplit('/',1)[-1]
  if rid in routes:return self.reply(409,{})
  routes[rid]=json.loads(self.rfile.read(int(self.headers['Content-Length'])));writes+=1
  if writes==1:
   self.connection.shutdown(socket.SHUT_RDWR);self.connection.close();return
  return self.reply(201,{'value':routes[rid]})
 def log_message(self,*a):pass
http.server.HTTPServer(('0.0.0.0',9180),H).serve_forever()
'''
class FixtureGuardPorts(NativePorts):
 def guard_current(self,stage):
  self.action.guard('resolutionRoutesUpdate',scope(self.plan));self.engine.check_socket();self.gateway.check()
 def anonymous_probes(self):return {'page':302,'owner':401}
@unittest.skipUnless(os.environ.get('OUF_READINESS_DOCKER_NATIVE')=='1','explicit real-Docker namespace qualification')
class Transport(unittest.TestCase):
 def cli(self,*args):
  result=subprocess.run(['docker',*args],capture_output=True,timeout=180);self.assertEqual(result.returncode,0,result.stderr.decode()[-1000:]);return result.stdout.decode().strip()
 def test_three_signed_puts_lost_first_response_readonly_reconciliation_no_replay(self):
  self.assertEqual(os.geteuid(),0);self.assertTrue(hasattr(os,'setns'))
  base=tempfile.TemporaryDirectory(dir=os.environ.get('OUF_TEST_ROOT','/root'));self.addCleanup(base.cleanup);root=Path(base.name);root.chmod(0o700)
  c=crypto.SignedCutover()
  with patch.object(crypto,'ROOT',root):c.setUp()
  self.addCleanup(c.doCleanups);self.cli('pull','python:3.13-alpine')
  config=root/'apisix.yaml';config.write_text('deployment:\n  admin:\n    admin_key:\n      - name: existing\n        key: EXISTING_FIXTURE_ADMIN_KEY_123456\n        role: admin\n');config.chmod(0o600)
  cid=self.cli('run','-d','--name','ouf-apisix','--read-only','-v',str(config)+':/usr/local/apisix/conf/config.yaml:ro','python:3.13-alpine','python3','-B','-u','-c',ADMIN.replace('INITIAL',repr(templates())))
  self.addCleanup(lambda:self.cli('rm','-f',cid))
  sock=Path('/var/run/docker.sock').resolve();s=sock.stat();engine=Engine(str(sock),(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode&0o777))
  transport=NamespaceAdmin.observe(engine,str(config),MOUNT_SET_BINDING);admin=NamespaceAdmin(engine,transport)
  until=time.monotonic()+20
  while True:
   try:before=admin.routes();break
   except Exception:
    if time.monotonic()>until:raise
    time.sleep(.2)
  context=c.root/'routes';context.mkdir(mode=0o700)
  plan={'schema':'ouf.resolution-ths-route-plan.v1','authorityDirectory':str(context),'beforeRoutes':before,'routes':compile_routes(before),'gatewayTransport':transport,
   'maximumExecutionSeconds':900,'maximumEffectAttemptsPerStage':1,'maximumGatewayWrites':3,
   **{k:False for k in('automaticReplayAllowed','databaseMigrationsAllowed','grantChangesAllowed','semanticDispatchAllowed','automaticRollbackAllowed','containerLifecycleAllowed','identityDecisionsAllowed')}}
  plan['logicalUpdateRef']=digest({'beforeRoutes':digest(before),'routes':plan['routes']})
  c.authority=crypto.encoded({'schema':'ouf.semantic-cutover-execution-authority.v1',**{k:v for k,v in c.expected.items()if k!='intakeHash'},'issuedAt':c.now,'expiresAt':c.now+480,'resolutionRoutesUpdate':scope(plan)})
  c.approval['expiresAt']=c.now+500;c.approval['executionAuthorityHash']=crypto.sha(c.authority);c.write(c.mandate,crypto.encoded(c.approval));c.approved=crypto.sha(c.mandate.read_bytes())
  for role in c.grant['roles']:c.sign(role)
  action=AggregateAction(c.gate(),c.authority,c.expected['sourceClosureHash']);ports=FixtureGuardPorts(action,engine,plan,None);update=ReadinessUpdate(action,Journal(context),plan,ports);update.initialize()
  with self.assertRaises(Exception):update.run()
  self.assertEqual(update.record()['nextStage'],1);self.assertEqual(admin.request('GET','/apisix/admin/routes')[1]['writes'],1)
  with self.assertRaises(UpdatePaused):update.run()
  update.reconcile_claim();result=update.run();self.assertTrue(result['complete']);self.assertFalse(result['acceptanceGranted'])
  self.assertEqual(admin.routes(),{**before,**plan['routes']});self.assertEqual(admin.request('GET','/apisix/admin/routes')[1]['writes'],3)
  update.run();self.assertEqual(admin.request('GET','/apisix/admin/routes')[1]['writes'],3)
  with self.assertRaises(Exception):ports.claim_logical_scope()
if __name__=='__main__':unittest.main()
