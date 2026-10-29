"""Installation-specific issuer log read, no OAuth, exec, login or refresh."""
import ast,base64,contextlib,hashlib,http.client,ipaddress,json,os,re,signal,socket,stat,struct,sys,time
from pathlib import Path
CONTEXT=Path('/etc/ouf/deploy-snapshots/mcp-ingestion-read-transport-execution-srz6__wf')
SOURCE='0be8fb13db3ff1ea014920bbbbb3738a8a434240'
ROUTES='d5a4040e30e289c150f9d2862ff41e83e22809a9e2202ac19388e744f2c5e927'
MCP='8b199a6767bd39dadf82f6d70f964ab6da9c914a3b327229214d88991893647b'
def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def digest(v):return sha(encoded(v))
def read(path,expected=None,maximum=8388608):
 path=Path(path);require(path.is_absolute()and path.resolve()==path,'EXACT_PRIVATE_PATH_REQUIRED')
 for parent in path.parents:
  row=parent.lstat();require(stat.S_ISDIR(row.st_mode)and row.st_uid==0 and not row.st_mode&0o022,'PRIVATE_ROOT_ANCESTRY_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  row=os.fstat(fd);require(stat.S_ISREG(row.st_mode)and row.st_uid==row.st_gid==0
   and stat.S_IMODE(row.st_mode)==0o600 and row.st_nlink==1 and 0<row.st_size<=maximum,'PRIVATE_CUSTODY_REQUIRED')
  with os.fdopen(os.dup(fd),'rb')as f:raw=f.read(maximum+1)
  pin=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  require(len(raw)==row.st_size and pin(row)==pin(os.fstat(fd))==pin(path.lstat())
   and(expected is None or sha(raw)==expected),'PRIVATE_BYTES_CHANGED');return raw
 finally:os.close(fd)
def parsed(path,expected=None,maximum=8388608):return json.loads(read(path,expected,maximum))

def history(parse=parsed):
 package=parse(CONTEXT/'package.json');package_hash=digest(package)
 require(package['sourceCommit']==SOURCE and package['schema']=='ouf.mcp-ingestion-read-transport-package.v1'
  and package['closure']['declaration']['moduleCount']==205
  and package['closure']['declaration']['entryModule']=='tools.mcp_read_transport_gateway82_continuation.entry',
  'EXACT_COMPLETED205_PACKAGE_REQUIRED')
 require(parse(CONTEXT/'runtime.claim.json')=={'packageHash':package_hash,'automaticReplayAllowed':False},'EXACT_CONSUMED205_RUNTIME_CLAIM_REQUIRED')
 case=parse(CONTEXT/'case.json',package['fileHashes']['case.json'])
 preparation=parse(case['preparationClaimBinding']['path'],case['preparationClaimBinding']['sha256'])
 require(preparation['context']==str(CONTEXT)and preparation['maximumCumulativeOAuthAttempts']==256
  and preparation['budgetReset']is False and preparation['automaticReplayAllowed']is False,'EXACT_COMPLETED205_PREPARATION_REQUIRED')
 sources=parse(CONTEXT/'sources.json',package['fileHashes']['sources.json']);hashes=package['closure']['declaration']['sourceHashes']
 require(len(sources)==205 and set(sources)==set(hashes)
  and all(sha(base64.b64decode(v,validate=True))==hashes[n]for n,v in sources.items()),'EXACT205_SOURCE_HASHES_REQUIRED')
 p=parse(CONTEXT/'execution-plan.json');j=parse(CONTEXT/'recovery.json');r=parse(CONTEXT/'update-result.json')
 review=parse(CONTEXT/'review.json');decision=parse(CONTEXT/'decision.json');scope=review['scopes']['mcpReadTransportUpdate']
 stages=['VERIFY_INPUTS']+['mcp.'+n for n in('IMPORT_IMAGE','DISABLE_OLD_RESTART','STOP_OLD','DETACH_OLD_ENDPOINT','RENAME_OLD','CREATE_REPLACEMENT','START_REPLACEMENT','READINESS','RESTORE_RESTART_POLICY')]+['VERIFY_FINAL']
 require(scope['planHash']==digest(p)and decision['reviewHash']==digest(review)and review['sourceClosureHash']==digest(package['closure'])
  and j['schema']=='ouf.mcp-ingestion-read-transport-update-journal.v1'and j['scopeHash']==digest(scope)
  and j['nextStage']==len(stages)and len(j['effects'])==len(stages)and j['incidentState']=='RECOVERED'
  and [e['stage']for e in j['effects']]==stages and all(e['state']=='APPLIED'for e in j['effects'])
  and all(e['intentHash']==digest({'planHash':digest(p),'stage':e['stage']})for e in j['effects'])
  and j['budgetReset']is False and r['schema']=='ouf.mcp-ingestion-read-transport-update-result.v1'
  and r['status']=='MCP_TRANSPORT_UPDATE_READBACK_COMPLETE'and r['contextPath']==str(CONTEXT)
  and r['sourceCommit']=='1f2c28d7abadae78680b040ba7b58be62ef85ee9'and r['oauthAttemptsAfter']==236
  and r['result']['complete']is True and r['result']['applicationReady']is True
  and r['result']['journalVersion']==j['version']==27 and r['result']['acceptanceGranted']is False
  and r['finalEvidence']==j['effects'][-1]['evidence']and r['finalEvidence']['mcp']['health']['httpStatus']==204
  and r['finalEvidence']['mcp']['runtimeBinding']['containerId']==MCP
  and r['finalEvidence']['mcp']['runtimeBinding']['pid']==312624
  and r['finalEvidence']['mcp']['runtimeBinding']['startedAt']=='2026-10-19T13:07:59.712730076Z'
  and r['finalEvidence']['routeMapHash']==ROUTES
  and r['gatewayWrites']==r['databaseMigrationsPerformed']==r['grantChanges']==r['jobsRetried']==0
  and r['sourceActivated']is False and r['publicMetadataChanged']is False,'EXACT_COMPLETED_MCP236_READBACK_REQUIRED')
 require(p['gateway']['beforeRoutes']==p['gateway']['afterRoutes']and len(p['gateway']['afterRoutes'])==82
  and digest(p['gateway']['afterRoutes'])==ROUTES,'EXACT_RETAINED82_ROUTE_MAP_REQUIRED')
 return p,r,package_hash

def runtime(v,ordered=True):
 require(type(v)is dict and v['State']['Running']is True and not v['State'].get('Paused',False)
  and not v['State'].get('Restarting',False)and type(v['State']['Pid'])is int and v['State']['Pid']>0,'EXACT_RUNNING_GENERATION_REQUIRED')
 return {'containerId':v['Id'],'imageId':v['Image'],'pid':v['State']['Pid'],'startedAt':v['State']['StartedAt'],
  'configHash':digest(v['Config']),'hostConfigHash':digest(v['HostConfig']),
  'mountsHash':digest(sorted(v['Mounts'],key=lambda m:m['Destination'])if ordered else v['Mounts']),
  'networkSettingsHash':digest(v['NetworkSettings'])}

class Reader:
 def __init__(self,binding,containers):
  self.path=Path(binding['socketPath']);self.binding=tuple(binding['socketBinding']);self.calls=0
  require(len(containers)==3 and len(set(containers))==3 and all(re.fullmatch('[0-9a-f]{64}',v)for v in containers),'EXACT_THREE_CONTAINERS_REQUIRED')
  self.allowed={'/v1.44/containers/'+v+'/json'for v in containers}
 def check(self):
  require(self.path.is_absolute()and self.path.resolve()==self.path,'EXACT_ENGINE_SOCKET_PATH_REQUIRED')
  row=self.path.lstat();require(stat.S_ISSOCK(row.st_mode)and row.st_uid==0
   and stat.S_IMODE(row.st_mode)in(0o600,0o660)
   and(row.st_dev,row.st_ino,row.st_uid,row.st_gid,stat.S_IMODE(row.st_mode))==self.binding,'EXACT_RETAINED_ENGINE_SOCKET_REQUIRED')
 def get(self,path):
  require(path in self.allowed and self.calls<6,'EXACT_SIX_READ_ONLY_INSPECTS_REQUIRED')
  self.check();engine_path=str(self.path)
  class Connection(http.client.HTTPConnection):
   def connect(self):
    self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(self.timeout);self.sock.connect(engine_path)
  connection=Connection('retained-engine',timeout=10)
  try:
   self.calls+=1;connection.request('GET',path);reply=connection.getresponse();raw=reply.read(4194305)
   require(reply.status==200 and len(raw)<=4194304,'BOUNDED_SUCCESSFUL_ENGINE_INSPECT_REQUIRED');self.check();return json.loads(raw)
  finally:connection.close()

def selected(routes):
 result=[]
 for mode in('status','history'):
  capability='ouf.ingestion.'+mode;uri='/internal/capabilities/v1/execute/'+capability
  rows=[r for r in routes.values()if r.get('uri')==uri and r.get('methods')==['POST']]
  require(len(rows)==1,'ONE_RETAINED_INGESTION_EXECUTE_ROUTE_REQUIRED');route=rows[0]
  upstream=route['upstream'];nodes=upstream['nodes']
  require(upstream['scheme']=='http'and len(nodes)==1,'ONE_PROJECTED_HTTP_OWNER_TARGET_REQUIRED')
  target,weight=next(iter(nodes.items()));match=re.fullmatch(r'([A-Za-z0-9._-]{1,253}):([0-9]{1,5})',target)
  require(match is not None and 1<=int(match[2])<=65535 and weight==1,'EXACT_PROJECTED_OWNER_TARGET_REQUIRED')
  constants=[]
  for source in route['plugins']['serverless-post-function']['functions']:
   constants.extend(json.loads(v)for v in re.findall(r'^local DELEGATION_KEY_ENV = ("[^\n]*")$',source,re.M))
  require(len(constants)==1 and re.fullmatch('[A-Z][A-Z0-9_]{0,127}',constants[0]),'ONE_RETAINED_DELEGATION_KEY_REFERENCE_REQUIRED')
  result.append({'capability':capability,'host':match[1],'port':int(match[2]),'keyEnv':constants[0]})
 return result

PACKAGE='d5e2be3a877c33c082d52fb0180a7a4a8cc10c9f4385c4064713417b366c4d38'
PROFILE_PATH='/opt/ouf/installation/active-projection.json'

def root_file(path,maximum=65536,expected=None):
 path=Path(path);require(path.is_absolute()and path.resolve()==path,'EXACT_CONTROLLED_FILE_PATH_REQUIRED')
 for parent in path.parents:
  info=parent.lstat()
  if str(parent)=='/opt/ouf':
   require((info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))==(1000,1000,0o750),'EXACT_RETAINED_PROFILE_PARENT_REQUIRED')
  else:require(stat.S_ISDIR(info.st_mode)and info.st_uid==0 and not info.st_mode&0o022,'ROOT_CONTROLLED_ANCESTRY_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  info=os.fstat(fd);require(stat.S_ISREG(info.st_mode)and info.st_uid==0 and info.st_nlink==1
   and stat.S_IMODE(info.st_mode)in(0o400,0o440,0o444,0o600,0o640,0o644)and 0<info.st_size<=maximum,'BOUNDED_ROOT_CONTROLLED_FILE_REQUIRED')
  with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(maximum+1)
  pin=lambda row:tuple(getattr(row,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  require(len(raw)==info.st_size and pin(info)==pin(os.fstat(fd))==pin(path.lstat())
   and(expected is None or sha(raw)==expected),'ROOT_CONTROLLED_BYTES_CHANGED')
  return raw,list(pin(info))
 finally:os.close(fd)

def profile_binding(plan):
 binding=plan['gateway']['projectionBinding'];require(binding['path']==PROFILE_PATH,'EXACT_RETAINED_PROJECTION_PATH_REQUIRED')
 raw,pin=root_file(binding['path'],1048576,binding['sha256'])
 require(set(binding)=={'path','sha256','metadata'}and pin==binding['metadata'],'EXACT_APPROVED_PROJECTION_CUSTODY_REQUIRED')
 projection=json.loads(raw);bindings=projection.get('services',{}).get('bindings',{})
 require(type(bindings)is dict,'EXACT_APPROVED_SERVICE_BINDINGS_REQUIRED')
 key='ouf-ingestion-runtime';explicit=key in bindings;target=bindings[key]if explicit else key
 require(type(target)is str and target.strip()==target and re.fullmatch('[A-Za-z0-9._-]{1,253}',target),'EXACT_APPROVED_INGESTION_BINDING_REQUIRED')
 rows=selected(plan['gateway']['afterRoutes']);require(all(row['host']==target for row in rows),'RETAINED_ROUTES_DISAGREE_WITH_APPROVED_BINDING')
 return {'explicitIngestionServiceBindingPresent':explicit,'retainedRouteTargetsMatchApprovedProjection':True},target

def owner_alias(gateway,owner):
 shared=set(gateway['NetworkSettings']['Networks'])&set(owner['NetworkSettings']['Networks'])
 require(len(shared)==1,'EXACT_ONE_RETAINED_SHARED_NETWORK_REQUIRED')
 record=owner['NetworkSettings']['Networks'][next(iter(shared))];name=owner['Name'].lstrip('/')
 names=set(record.get('Aliases')or[])|set(record.get('DNSNames')or[])
 require(name in names and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,252}',name),'EXACT_VERIFIED_OWNER_DNS_ALIAS_REQUIRED')
 addresses={str(ipaddress.IPv4Address(record['IPAddress']))}
 return name,addresses

def dns_name(name):
 require(type(name)is str and len(name)<=253,'BOUNDED_APPROVED_DNS_NAME_REQUIRED');labels=name.rstrip('.').split('.')
 require(all(re.fullmatch('[A-Za-z0-9_-]{1,63}',label)for label in labels),'EXACT_APPROVED_DNS_LABELS_REQUIRED')
 return b''.join(bytes([len(label)])+label.lower().encode('ascii')for label in labels)+b'\x00'

def decode_name(raw,offset):
 labels=[];seen=set();following=None
 for _ in range(128):
  require(offset<len(raw)and offset not in seen,'BOUNDED_DNS_NAME_COMPRESSION_REQUIRED');seen.add(offset);size=raw[offset]
  if size&0xc0==0xc0:
   require(offset+1<len(raw),'COMPLETE_DNS_POINTER_REQUIRED');pointer=((size&0x3f)<<8)|raw[offset+1]
   if following is None:following=offset+2
   offset=pointer;continue
  require(size<=63 and offset+1+size<=len(raw),'COMPLETE_DNS_LABEL_REQUIRED');offset+=1
  if not size:return '.'.join(labels),following if following is not None else offset
  label=raw[offset:offset+size].decode('ascii');require(re.fullmatch('[A-Za-z0-9_-]{1,63}',label),'SAFE_DNS_LABEL_REQUIRED')
  labels.append(label.lower());offset+=size;require(sum(map(len,labels))+len(labels)<=254,'BOUNDED_DNS_NAME_REQUIRED')
 raise ValueError('BOUNDED_DNS_NAME_COMPRESSION_REQUIRED')

def dns_reply(raw,transaction,name):
 require(type(raw)is bytes and 12<=len(raw)<=4096,'BOUNDED_DNS_RESPONSE_REQUIRED')
 ident,flags,questions,answers,authority,additional=struct.unpack('!6H',raw[:12])
 require(ident==transaction and flags&0x8000 and not flags&0x7800 and questions==1
  and answers+authority+additional<=64,'EXACT_DNS_RESPONSE_HEADER_REQUIRED')
 question,offset=decode_name(raw,12);require(question==name.rstrip('.').lower()and offset+4<=len(raw)
  and struct.unpack('!2H',raw[offset:offset+4])==(1,1),'EXACT_DNS_QUESTION_REQUIRED');offset+=4
 if flags&0x200:return {'status':'TRUNCATED','addresses':set()}
 code=flags&15
 if code:return {'status':{2:'SERVFAIL',3:'NXDOMAIN',5:'REFUSED'}.get(code,'OTHER_DNS_ERROR'),'addresses':set()}
 records=[];aliases={}
 for index in range(answers+authority+additional):
  owner,offset=decode_name(raw,offset);require(offset+10<=len(raw),'COMPLETE_DNS_RECORD_REQUIRED')
  kind,klass,ttl,size=struct.unpack('!2HIH',raw[offset:offset+10]);offset+=10;end=offset+size
  require(end<=len(raw),'COMPLETE_DNS_RDATA_REQUIRED')
  if index<answers and klass==1:
   if kind==1:
    require(size==4,'EXACT_DNS_IPV4_RECORD_REQUIRED');records.append((owner,str(ipaddress.IPv4Address(raw[offset:end]))))
   elif kind==5:
    target,consumed=decode_name(raw,offset);require(consumed==end and owner not in aliases,'EXACT_DNS_CNAME_REQUIRED');aliases[owner]=target
  offset=end
 require(offset==len(raw),'NO_TRAILING_DNS_RESPONSE_BYTES_REQUIRED')
 eligible={name.rstrip('.').lower()};following=name.rstrip('.').lower()
 for _ in range(8):
  if following not in aliases:break
  following=aliases[following];require(following not in eligible,'DNS_CNAME_LOOP_DENIED');eligible.add(following)
 else:raise ValueError('BOUNDED_DNS_CNAME_CHAIN_REQUIRED')
 found={address for owner,address in records if owner in eligible}
 return {'status':'RESOLVED'if found else'NO_A_ANSWER','addresses':found}

def query_dns(name,resolver):
 require(resolver=='127.0.0.11','EXACT_DOCKER_EMBEDDED_RESOLVER_REQUIRED')
 transaction=int.from_bytes(os.urandom(2),'big');packet=struct.pack('!6H',transaction,0x100,1,0,0,0)+dns_name(name)+struct.pack('!2H',1,1)
 client=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);client.settimeout(2)
 try:
  client.connect((resolver,53));require(client.send(packet)==len(packet),'COMPLETE_LOCAL_DNS_REQUEST_REQUIRED')
  try:raw=client.recv(4097)
  except TimeoutError:return {'status':'TIMEOUT','addresses':set()}
  return dns_reply(raw,transaction,name)
 finally:client.close()

@contextlib.contextmanager
def gateway_namespace(pid,binding):
 require(hasattr(os,'setns')and len(list(Path('/proc/self/task').iterdir()))==1,'ISOLATED_SINGLE_THREAD_NAMESPACE_READER_REQUIRED')
 original=os.open('/proc/self/ns/net',os.O_RDONLY);target=None
 identity=lambda fd:{'device':os.fstat(fd).st_dev,'inode':os.fstat(fd).st_ino}
 try:
  target=os.open('/proc/'+str(pid)+'/ns/net',os.O_RDONLY);previous=identity(original)
  require(identity(target)==binding,'EXACT_RETAINED_GATEWAY_NAMESPACE_REQUIRED')
  os.setns(target,0)
  try:
   current=Path('/proc/self/ns/net').stat();require({'device':current.st_dev,'inode':current.st_ino}==binding,'GATEWAY_NAMESPACE_SWITCH_UNPROVEN')
   yield
  finally:
   os.setns(original,0);current=Path('/proc/self/ns/net').stat()
   require({'device':current.st_dev,'inode':current.st_ino}==previous,'HOST_NAMESPACE_RESTORE_UNPROVEN')
 finally:
  if target is not None:os.close(target)
  os.close(original)

def project_dns(role,result,owner_addresses):
 addresses=result['addresses']
 return {'targetRole':role,'status':result['status'],'ipv4AnswerCount':len(addresses),
  'hasRetainedOwnerAddress':bool(addresses&owner_addresses),'allAnswersBelongToRetainedOwner':bool(addresses)and addresses<=owner_addresses,
  'hasOtherAddress':bool(addresses-owner_addresses)}

def main():
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('FINITE_DNS_READ_DEADLINE')));signal.alarm(90)
 parsed(CONTEXT/'package.json',PACKAGE);plan,result,package_hash=history();transport=plan['gateway']['transport']
 expected={'gateway':transport['runtimeBinding'],'ingestion':plan['unchangedApplications']['ingestion'],'mcp':result['finalEvidence']['mcp']['runtimeBinding']}
 reader=Reader(plan['engine'],[v['containerId']for v in expected.values()]);values={}
 def inspect(name):
  actual=reader.get('/v1.44/containers/'+expected[name]['containerId']+'/json')
  sort=name!='gateway'or transport.get('runtimeBindingProfile')=='ouf.apisix-runtime-binding.mount-set.v1'
  require(runtime(actual,sort)==expected[name],'RETAINED_APPLICATION_GENERATION_CHANGED');return actual
 for name in expected:values[name]=inspect(name)
 profile,target=profile_binding(plan);alias,addresses=owner_alias(values['gateway'],values['ingestion'])
 require(alias!=target,'RETAINED_BINDING_NOW_MATCHES_OWNER_RECONCILE')
 gateway_id=expected['gateway']['containerId'];resolver_path=values['gateway']['ResolvConfPath']
 require(resolver_path=='/var/lib/docker/containers/'+gateway_id+'/resolv.conf','EXACT_RETAINED_DOCKER_RESOLVER_PATH_REQUIRED')
 raw,pin=root_file(resolver_path);servers=re.findall(r'^\s*nameserver\s+(\S+)\s*(?:#.*)?$',raw.decode('ascii'),re.M)
 require(servers==['127.0.0.11'],'EXACT_SINGLE_DOCKER_EMBEDDED_RESOLVER_REQUIRED')
 answers=[]
 with gateway_namespace(expected['gateway']['pid'],transport['networkNamespace']):
  for role,name in(('RETAINED_ROUTE_TARGET',target),('VERIFIED_OWNER_NETWORK_ALIAS',alias)):
   answers.append(project_dns(role,query_dns(name,servers[0]),addresses))
 require(root_file(resolver_path)==(raw,pin),'GATEWAY_RESOLVER_CHANGED_DURING_READ')
 profile_binding(plan)
 for name in expected:inspect(name)
 signal.alarm(0)
 return {'schema':'ouf.mcp-ingestion503-dns-read.v1','complete':True,'readOnly':True,'packageHash':package_hash,
  'contextPath':str(CONTEXT),'profileBinding':profile,'dnsResults':answers,'dnsQueries':2,'dnsRetries':0,
  'resolverProfile':'DOCKER_EMBEDDED_DNS_V1','networkNamespaceRestored':True,'currentContainerGenerationsVerified':True,
  'retainedRouteCount':82,'retainedRouteMapHash':ROUTES,'retainedSnapshotOnly':True,'liveGatewayRoutesRequeried':False,
  'engineGetRequests':reader.calls,'backendHttpProbes':0,'ownerRequests':0,'oauthRequests':0,'journalWrites':0,
  'humanCredentialJournalsRead':0,'bearerFilesOpened':0,'credentialFilesOpened':0,'credentialValuesPrinted':False,
  'rawDnsNamesOrAddressesPrinted':False,'rawLogLinesRead':0,'processDispatches':0,'containerLifecycleOperations':0,
  'gatewayWrites':0,'databaseCalls':0,'runtimeAuthorityIssued':False,'specific503CauseProven':False,
  'automaticReplayAllowed':False,'budgetReset':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
if __name__=='__main__':
 try:result=main()
 except(Exception,KeyboardInterrupt)as error:
  safe={n.value for n in ast.walk(ast.parse(Path(__file__).read_bytes()))if isinstance(n,ast.Constant)and type(n.value)is str and re.fullmatch('[A-Z][A-Z0-9_]{2,159}',n.value)}
  result={'schema':'ouf.mcp-ingestion503-dns-read.v1','complete':False,'exceptionClass':type(error).__name__,
   'reasonCode':str(error)if str(error)in safe else'PRIVATE_DETAILS_REDACTED','readOnly':True,'automaticReplayAllowed':False,'budgetReset':False}
 print(encoded(result).decode(),flush=True);raise SystemExit(0 if result['complete']else 2)
