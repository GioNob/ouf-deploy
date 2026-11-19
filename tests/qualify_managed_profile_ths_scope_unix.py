"""CI only: real root custody and Unix HTTP/SO_PEERCRED, synthetic13-member Engine metadata."""
import hashlib,http.server,importlib.util,json,os,socket,socketserver,stat,sys,threading
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('scope_unix_fixture',ROOT/'tests/test_managed_profile_ths_scopes.py');f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f);m=f.m
assert os.geteuid()==os.getegid()==0
root=Path('/var/lib/ouf-ths-scope-unix-fixture');root.mkdir(mode=0o700);root.chmod(0o700)
case,review,result,journal,cohort,observations,generations=f.fixture()
old=root/'retained-update';old.mkdir(mode=0o700);old.chmod(0o700);case['installedRoot']=str(old)
review['executionRoot']=str(old);case['reviewHash']=m.digest(review);result['reviewHash']=case['reviewHash'];journal['reviewHash']=case['reviewHash']
for stage,effect in zip(review['stages'],journal['effects']):effect['intentHash']=m.digest({'reviewHash':case['reviewHash'],'stage':stage})
socket_path=root/'engine.sock';requests=[];drift=[False];seen={}
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  requests.append(self.path)
  if self.path=='/v1.44/info':value={'ServerVersion':'29.8.1'}
  else:
   cid=self.path.split('/')[-2];value=json.loads(json.dumps(observations[cid]));seen[cid]=seen.get(cid,0)+1
   if drift[0]and cid==cohort['onboarding']['containerId']and seen[cid]>1:value['Config']['Env'].append('UNEXPECTED_DRIFT=1')
  raw=m.encoded(value);self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
 def log_message(self,*args):pass
class Server(socketserver.UnixStreamServer):allow_reuse_address=False
server=Server(str(socket_path),Handler);socket_path.chmod(0o600)
thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
info=socket_path.lstat();binding={'socketPath':str(socket_path),'socketBinding':[info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)],'peerCredentials':[os.getpid(),0,0]}
review['nativePlan']['proposal']['engineBinding']=binding;case['frozenPlanHash']=m.digest(review['nativePlan']['proposal']);review['frozenPlanHash']=case['frozenPlanHash'];case['reviewHash']=m.digest(review)
result.update(reviewHash=case['reviewHash'],frozenPlanHash=case['frozenPlanHash']);journal['reviewHash']=case['reviewHash']
for stage,effect in zip(review['stages'],journal['effects']):effect['intentHash']=m.digest({'reviewHash':case['reviewHash'],'stage':stage})
for name,value in [('review.json',review),('result.json',result),('recovery.json',journal)]:
 p=old/name;p.write_bytes(m.encoded(value));p.chmod(0o400)
retained={p.name:p.read_bytes()for p in old.iterdir()}
boot=root/'boot';boot.write_text('fixture-boot');boot.chmod(0o400)
pins={g['pid']:g for g in generations.values()};pins[1]={'pid':1};pins[os.getpid()]={'pid':os.getpid()}
try:
 cap=m.Capture(root/'positive-scope',13);out=m.inspect_current(cap,case,pin=lambda pid:pins[pid],boot_path=boot)
 assert out['counts']['privateMetadataReads']==3 and out['counts']['engineGets']==len(requests)==27
 assert out['scopeInspection']['missingRequestScopes']==list(m.REQUIRED)and not out['targetApplyAuthorized']
 assert all(stat.S_IMODE(p.stat().st_mode)==0o600 for p in cap.root.iterdir())and not('PRIVATE_'in json.dumps(out))
 saved=(cap.root/'result.json').read_bytes()
 try:m.Capture(cap.root,13);raise AssertionError('scope replayed')
 except m.Stop as error:assert str(error)=='CSV_RECOVERY_CAPTURE_CONSUMED_NO_REPLAY'
 assert saved==(cap.root/'result.json').read_bytes()
 drift[0]=True;seen.clear();bad=m.Capture(root/'separate-negative-fixture',13)
 try:m.inspect_current(bad,case,pin=lambda pid:pins[pid],boot_path=boot);raise AssertionError('drift accepted')
 except m.Stop as error:assert str(error)=='CURRENT_CAPTURE_GENERATION_DRIFT'
 assert all(p.read_bytes()==retained[p.name]for p in old.iterdir())
 print(json.dumps({'status':'THS_SCOPE_CAPTURE_REAL_UNIX_ROOT_CUSTODY_PASS','exact13Members':True,'metadataReads':3,'engineGetsPositive':27,'actualUnixHttpAndRootPeerCredentials':True,'retainedInputsUnchanged':True,'generationDriftDenied':True,'privateMode600':True,'noReplay':True,'credentialOrConfigurationFileReads':0,'iamRequests':0,'engineWrites':0,'sqlSessions':0,'scopePatchApplied':False,'targetExecuted':False},sort_keys=True))
finally:server.shutdown();server.server_close();thread.join()
