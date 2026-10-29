"""Native test worker: real SIGTERM, production cumulative cancellation, owned nft sets.

Not the deployed R12 entrypoint or a fixture of its complete transport authority.
"""
import hashlib,json,os,re,signal,subprocess,sys,threading,time
from pathlib import Path
root=Path(__file__).parent
sys.path.insert(0,str(root))
from bounded_recovery import Policy
from lease_recovery_budget import LeaseRecovery
from recovery_journal import Journal

def enc(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def read(p):return json.loads(p.read_bytes())
def write(p,v):
    tmp=p.parent/('.fixture-'+str(os.getpid()));fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:os.write(fd,enc(v));os.fsync(fd)
    finally:os.close(fd)
    os.replace(tmp,p);fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
auth=read(root/'authorization.json');owner=read(root/'fixture-owner.json');stop=threading.Event()
assert sys.argv==[str(root/'activate.py'),'--supervise',str(root/'authorization.json'),hashlib.sha256(enc(auth)).hexdigest()]
for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,lambda *_:stop.set())
inv=root/'worker-invocation-claim.json';fd=os.open(inv,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
os.write(fd,enc({'contextRef':auth['contextRef'],'pid':os.getpid(),'hostBootId':auth['hostBootId']}));os.fsync(fd);os.close(fd)
class Adapter:
    def pause(self):
        assert re.fullmatch('[A-Za-z][A-Za-z0-9_]{0,31}',owner['kernel']['tableName'])
        transaction='\n'.join('flush set '+f+' '+owner['kernel']['tableName']+' provider_'+str(i) for f in ('inet','bridge') for i in range(2))+'\n'
        result=subprocess.run([owner['nftPath'],'-f','-'],input=transaction.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
        if result.returncode:
            write(root/'fixture-revocation-error.json',{'nativeExitCode':result.returncode,'stderrSha256':hashlib.sha256(result.stderr).hexdigest(),'stderrBytes':len(result.stderr),'fixtureStderr':result.stderr.decode('utf-8',errors='replace')[:2048]})
            raise RuntimeError('FIXTURE_NATIVE_REVOCATION_FAILED')
        lease=read(Path(owner['journalFile']));write(Path(owner['journalFile']),{**lease,'state':'QUIESCED','leaseAuthorized':False,'leaseAddresses':[[],[]]})
r=LeaseRecovery(Journal(root/'retry'),Adapter(),Policy(),auth['contextRef'],auth['generationRef'],lambda:(time.time(),time.monotonic()),lambda:0.5)
row=r.journal.read()
status={'schema':'ouf.provider-resilient-worker-status.v1','workerPid':os.getpid(),'incidentRef':auth['incidentRef'],'doNotRerunApply':True,'startAuthorized':False,'state':row['state'],'ready':row['state']=='ACTIVE','live':True,'setsRevoked':row['state']!='ACTIVE','attempts':row['attempts'],'refreshCount':row['publicationCount']}
write(root/'worker-status.json',status)
# Finite wait in a real systemd process; no DNS/dependency probe while paused.
if not stop.wait(120):raise RuntimeError('FIXTURE_TIMEOUT')
with r.journal.invocation():row=r.step(cancelled=True)
write(root/'worker-status.json',{**status,'state':row['state'],'ready':False,'live':False,'setsRevoked':True,'attempts':row['attempts'],'refreshCount':row['publicationCount']})
