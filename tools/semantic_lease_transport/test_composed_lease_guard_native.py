"""CI-only isolated two-role packet proof. No target acceptance or TLS claim."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

base=Path(__file__).resolve().parent
root=base.parent/'semantic_cohort_admission/cohort-draft'
if not root.exists():root=base.parent/'admission-integration/cohort-draft'
sys.path.insert(0,str(root))
from tools.materialize_southbound_kernel import materialize as kernel_rules
from tools.materialize_semantic_shared_faces import materialize,validate_global_guard
from tools.semantic_provider_preexec import digest
from tools.semantic_provider_lease_nft import NftBackend,structure_hash

SERVER='''import socket,threading,time
 def_dummy=0
'''.replace(' def_dummy=0\n','')+'''
def serve(client):
 try:
  while True:
   data=client.recv(4096)
   if not data:break
   client.sendall(data)
 finally:client.close()
def listen(port):
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',port));s.listen()
 while True:
  c,_=s.accept();threading.Thread(target=serve,args=(c,),daemon=True).start()
threading.Thread(target=listen,args=(443,),daemon=True).start()
threading.Thread(target=listen,args=(8443,),daemon=True).start()
time.sleep(30)
'''
PROBE='''import socket,sys
s=socket.socket();s.settimeout(.35)
if len(sys.argv)>3:s.bind((sys.argv[3],0))
try:
 s.connect((sys.argv[1],int(sys.argv[2])));s.sendall(b'proof');data=s.recv(5)
 print('ALLOW' if data==b'proof' else 'WRONG_REPLY')
except (TimeoutError,OSError):print('DENY')
finally:s.close()
'''
PERSISTENT='''import socket,sys,time
from pathlib import Path
s=socket.socket();s.settimeout(1);s.connect(('198.19.60.10',443));s.sendall(b'before');assert s.recv(6)==b'before'
Path(sys.argv[1]).write_text('READY')
end=time.monotonic()+12
while not Path(sys.argv[2]).exists():
 assert time.monotonic()<end;time.sleep(.02)
s.settimeout(.6);s.sendall(b'after')
try:data=s.recv(5)
except TimeoutError:print('ESTABLISHED_EXPIRED_DENIED');sys.exit(0)
raise SystemExit('EXPIRED_ESTABLISHED_FLOW_STILL_ACCEPTED')
'''

def require(ok,reason):
 if not ok:raise RuntimeError(reason)
def main():
 require(os.geteuid()==0,'CI_ROOT_REQUIRED')
 suffix=uuid.uuid4().hex[:6];bridge='lcb'+suffix;names=['lcn'+str(i)+suffix for i in range(3)]
 ip=str(Path(shutil.which('ip')).resolve());nft=str(Path(shutil.which('nft')).resolve());python=str(Path(sys.executable).resolve())
 def run(*argv,raw=None,check=True):
  r=subprocess.run(argv,input=raw,capture_output=True,text=True,timeout=10)
  require(len(r.stdout)<=2000000 and len(r.stderr)<=8192,'CI_OUTPUT_UNBOUNDED')
  if check:require(r.returncode==0,'CI_COMMAND_FAILED:'+Path(argv[0]).name+':'+r.stderr[:1200])
  return r
 hosts=[];processes=[];tables=[]
 with tempfile.TemporaryDirectory(prefix='ouf-lease-packets-',dir='/root') as directory:
  directory=Path(directory)
  try:
   run(ip,'link','add',bridge,'type','bridge');run(ip,'link','set',bridge,'up')
   attachments=[]
   for i,namespace in enumerate(names):
    run(ip,'netns','add',namespace)
    for k in ('all','default'):run(ip,'netns','exec',namespace,'sysctl','-q','-w','net.ipv6.conf.'+k+'.disable_ipv6=1')
    host='lch'+str(i)+suffix;peer='lcp'+str(i)+suffix;hosts.append(host)
    run(ip,'link','add',host,'type','veth','peer','name',peer);run(ip,'link','set',host,'master',bridge);run(ip,'link','set',host,'up')
    run(ip,'link','set',peer,'netns',namespace);run(ip,'-n',namespace,'link','set',peer,'name','eth0')
    address='198.19.60.'+str(i+2 if i<2 else 10);mac='02:42:c6:13:00:'+format(i+2,'02x')
    run(ip,'-n',namespace,'link','set','eth0','address',mac)
    run(ip,'-n',namespace,'addr','add',address+'/24','dev','eth0');run(ip,'-n',namespace,'link','set','eth0','up');run(ip,'-n',namespace,'link','set','lo','up')
    if i<2:
     index=json.loads(run(ip,'-j','link','show','dev',host).stdout)[0]['ifindex']
     attachments.append({'workloadRef':'ci-role-'+str(i),'interface':host,'ifindex':index,
      'bridge':bridge,'mac':mac,'ipv4':address,'bindingRef':'ci-egress-'+str(i)})
   for last in (11,12):run(ip,'-n',names[2],'addr','add','198.19.60.'+str(last)+'/24','dev','eth0')
   kernel={'tableName':'lcg_'+suffix,'guardedInterfaces':[bridge],'existingInterfaces':[],
    'staticFlows':[{'purpose':'DNS','source':a['ipv4'],'destination':'198.19.60.'+str(10+i),'protocol':'udp','port':53} for i,a in enumerate(attachments)],
    'providerFlows':[{'endpointRef':ref,'endpoint':'https://'+host+path,'source':attachments[i]['ipv4'],
     'addresses':[],'leaseSeconds':4,'resolutionEvidenceRef':'ci-lease','allowedPrivateAddresses':['198.19.60.'+str(10+i)]}
     for i,(ref,host,path) in enumerate([('schema','schema.example','/sparql'),('identity','identity.example','/realms/ci')])]}
   tables.append(kernel['tableName']);run(nft,'-f','-',raw=kernel_rules(kernel,empty_provider_sets=True)['nftRules'])
   backend=NftBackend([nft],kernel,structure_hash({f:json.loads(run(nft,'-j','list','table',f,kernel['tableName']).stdout) for f in ('inet','bridge')}),5)
   backend.verify_ownership(kernel)
   for i,a in enumerate(attachments):
    policy={'schema':'ouf.semantic-shared-faces.v2','tableName':'lcs_'+str(i)+suffix,'attachments':[a],
     'flows':[],'globalLeaseGuard':{'configurationHash':digest(kernel),'tableName':kernel['tableName'],'bridges':[bridge]}}
    validate_global_guard(policy,kernel);tables.append(policy['tableName']);run(nft,'-f','-',raw=materialize(policy)['nftRules'])
   server=subprocess.Popen([ip,'netns','exec',names[2],python,'-c',SERVER],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);processes.append(server)
   time.sleep(.15)
   def probe(role,address,port=443,source=None):
    args=[ip,'netns','exec',names[role],python,'-c',PROBE,address,str(port)]
    if source:args.append(source)
    return run(*args).stdout.strip()
   require(probe(0,'198.19.60.10')=='DENY' and probe(1,'198.19.60.11')=='DENY','CI_EMPTY_LEASE_BYPASS')
   # Wrong source identities are dropped before destination delegation.
   run(ip,'-n',names[0],'addr','add','198.19.60.9/24','dev','eth0')
   require(probe(0,'198.19.60.10',source='198.19.60.9')=='DENY','CI_SOURCE_SPOOF_BYPASS')
   run(ip,'-n',names[0],'addr','del','198.19.60.9/24','dev','eth0')
   transaction='\n'.join('add element '+family+' '+kernel['tableName']+' provider_'+str(i)+' { 198.19.60.'+str(10+i)+' timeout 4s }' for family in ('inet','bridge') for i in range(2))+'\n'
   run(nft,'-f','-',raw=transaction);backend.verify_ownership(kernel)
   require(probe(0,'198.19.60.10')=='ALLOW','CI_PROVIDER_VALID_LEASE_DENIED')
   require(probe(1,'198.19.60.11')=='ALLOW','CI_IDENTITY_VALID_LEASE_DENIED')
   # A valid global lease cannot excuse a forged child MAC at the port layer.
   run(ip,'-n',names[0],'link','set','eth0','address','02:42:c6:13:00:99')
   require(probe(0,'198.19.60.10')=='DENY','CI_MAC_SPOOF_BYPASS')
   run(ip,'-n',names[0],'link','set','eth0','address',attachments[0]['mac'])
   ready=directory/'ready';expired=directory/'expired'
   client=subprocess.Popen([ip,'netns','exec',names[0],python,'-c',PERSISTENT,str(ready),str(expired)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);processes.append(client)
   deadline=time.monotonic()+2
   while not ready.exists():
    require(client.poll() is None and time.monotonic()<deadline,'CI_ESTABLISHED_PROOF_NOT_READY');time.sleep(.02)
   require(probe(0,'198.19.60.11')=='DENY' and probe(1,'198.19.60.10')=='DENY','CI_CROSS_PURPOSE_LEASE_BYPASS')
   require(probe(0,'198.19.60.12')=='DENY' and probe(0,'198.19.60.10',8443)=='DENY','CI_UNREGISTERED_DESTINATION_OR_PORT_BYPASS')
   deadline=time.monotonic()+6
   def positive_lease_elements():
    # nft may retain an already expired element until its GC interval. The
    # production reader rejects expires=0; do not weaken that fail-closed rule.
    # This fixture observes the kernel expiration boundary directly instead.
    values=[]
    for table in backend.tables().values():
     for row in table['nftables']:
      for entry in row.get('set',{}).get('elem',[]):
       ttl=entry['elem']['expires']
       require(type(ttl) is int and ttl>=0,'CI_MALFORMED_LEASE_EXPIRY')
       values.append(ttl>0)
    return any(values)
   while positive_lease_elements():
    require(time.monotonic()<deadline,'CI_LEASE_EXPIRATION_NOT_OBSERVED');time.sleep(.1)
   expired.touch();out,err=client.communicate(timeout=3)
   require(client.returncode==0 and 'ESTABLISHED_EXPIRED_DENIED' in out,'CI_ESTABLISHED_EXPIRY_BYPASS:'+err[:400])
   require(probe(0,'198.19.60.10')=='DENY' and probe(1,'198.19.60.11')=='DENY','CI_EXPIRED_NEW_CONNECTION_BYPASS')
   print('COMPOSED_LEASE_PACKETS=PASS TWO_REAL_NAMESPACES=true PROVIDER_AND_IDENTITY_SCOPES=true EMPTY_AND_EXPIRED_LEASES_DENY=true ESTABLISHED_EXPIRY_DENIES=true CROSS_PURPOSE_SOURCE_MAC_AND_PORT_DENY=true TARGET_RUNTIME_OPERATIONS=0 TARGET_START_AUTHORIZED=false TLS_AUTHENTICATION_NOT_CLAIMED=true')
  finally:
   for process in processes:
    if process.poll() is None:process.kill()
    process.wait(timeout=3)
   for table in tables:
    for family in ('inet','bridge'):run(nft,'delete','table',family,table,check=False)
   for host in hosts:run(ip,'link','delete',host,check=False)
   run(ip,'link','delete',bridge,check=False)
   for namespace in names:run(ip,'netns','delete',namespace,check=False)
if __name__=='__main__':main()
