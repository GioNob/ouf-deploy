"""Real Linux SO_PEERCRED PID1 in disposable Docker PID namespace; no VPS."""
import hashlib,importlib.util,json,os,signal,socket,stat
from pathlib import Path
BASE=Path(__file__).resolve().parents[1]
def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
assert os.getpid()==1 and os.geteuid()==os.getegid()==0
signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(TimeoutError('PID1_FIXTURE_DEADLINE')));signal.alarm(15)
p=module('pid1_plan',BASE/'tools/acquisition_read_native/plan_helper.py')
t=module('pid1_transport',BASE/'tools/onboarding_diagnostic_update/transport.py')
c=module('pid1_core',BASE/'tools/onboarding_diagnostic_update/authority.py')
d=module('pid1_database',BASE/'tools/onboarding_diagnostic_update/database.py')
root=Path('/var/lib/ouf-pid1-peer-ci');root.mkdir(mode=0o700);path=root/'peer.sock'
listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.settimeout(10);listener.bind(str(path));path.chmod(0o600);listener.listen(1)
s=path.lstat();old={'socketPath':str(path),'socketBinding':[s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)]}
captured={**old,'peerCredentials':[1,0,0]};expected={'retainedEngineBindingHash':c.digest(old),'capturedEngineBindingHash':c.digest(captured),'peerCredentialsHash':c.digest([1,0,0])}
profile={'schema':'ouf.current-onboarding-database-snapshot-profile.v1','runtimeBindingProfile':'ouf.runtime-binding.native-mount-order.v1','engineBinding':old}
pid=os.fork()
if pid==0:
 try:
  listener.close();proof=d.retained_transport(c,profile,captured,expected)
  engine=t.Engine(p,captured);status,raw=engine.raw('GET','/v1.44/info')
  assert status==200 and json.loads(raw)=={'CI_ONLY_PID1_PEER':True}and not proof['historicalMetadataRewritten']
  os._exit(0)
 except BaseException:
  import traceback
  traceback.print_exc();os._exit(2)
conn,_=listener.accept();conn.settimeout(5);request=b''
while b'\r\n\r\n'not in request:
 request+=conn.recv(4096);assert len(request)<=8192
assert request.startswith(b'GET /v1.44/info HTTP/')
body=b'{"CI_ONLY_PID1_PEER":true}'
conn.sendall(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body);conn.close();listener.close()
_,status=os.waitpid(pid,0);assert os.waitstatus_to_exitcode(status)==0
print(json.dumps({'schema':'ouf.pid1-unix-peer-native-ci.v1','complete':True,'actualLinuxPeerCredentials':[1,0,0],
 'capturedTupleHash':c.digest([1,0,0]),'exactLiveTupleAndRootUidChecked':True,'historicalHashesUnchanged':True,
 'dockerEngineRequestIssued':False,'applicationWorkloadSynthetic':True,'humanAuthorityIssued':False,'targetRuntimeAccess':False}),flush=True)
