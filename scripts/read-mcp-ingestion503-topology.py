"""Installation-specific issuer log read, no OAuth, exec, login or refresh."""
import ast,base64,hashlib,http.client,ipaddress,json,os,re,signal,socket,stat,sys,time
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

def listeners(raw):
 require(type(raw)is bytes and len(raw)<=1048576,'BOUNDED_TCP_TABLE_REQUIRED')
 lines=raw.decode('ascii').splitlines();require(lines and 'local_address'in lines[0],'KERNEL_TCP_HEADER_REQUIRED')
 result={}
 for line in lines[1:]:
  fields=line.split();require(len(fields)>=4,'COMPLETE_KERNEL_TCP_ROW_REQUIRED')
  if fields[3]!='0A':continue
  address,port=fields[1].split(':');require(re.fullmatch('[0-9A-Fa-f]{8}|[0-9A-Fa-f]{32}',address)is not None and re.fullmatch('[0-9A-Fa-f]{4}',port)is not None,'EXACT_KERNEL_LISTENER_REQUIRED')
  kind='WILDCARD'if not int(address,16)else'LOOPBACK'if address in('0100007F','00000000000000000000000001000000')else'SPECIFIC_ADDRESS'
  result.setdefault(int(port,16),set()).add(kind)
 return result

def read_listeners(pid):
 require(type(pid)is int and pid>0,'EXACT_INGESTION_PID_REQUIRED');output={};available=0
 for member in('tcp','tcp6'):
  path=Path('/proc')/str(pid)/'net'/member
  try:fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  except FileNotFoundError:
   require(member=='tcp6','INGESTION_TCP_TABLE_REQUIRED');continue
  try:
   with os.fdopen(os.dup(fd),'rb')as f:raw=f.read(1048577)
  finally:os.close(fd)
  available+=1
  for port,kinds in listeners(raw).items():output.setdefault(port,set()).update(kinds)
 return output,available

def topology(routes,gateway,owner,tables):
 selected_rows=selected(routes);gn=gateway['NetworkSettings']['Networks'];on=owner['NetworkSettings']['Networks']
 shared=set(gn)&set(on);env={};rows=[]
 for value in gateway['Config'].get('Env',[]):
  key,separator,contents=value.partition('=')
  if key in {r['keyEnv']for r in selected_rows}:
   require(separator and key not in env,'UNIQUE_SELECTED_GATEWAY_ENV_REQUIRED');env[key]=contents
 aliases=set();addresses=set()
 for name in shared:
  record=on[name];aliases.update(record.get('Aliases')or[]);aliases.update(record.get('DNSNames')or[])
  addresses.update(v for v in(record.get('IPAddress'),record.get('GlobalIPv6Address'))if v)
 aliases.add(owner.get('Name','').lstrip('/'))
 extras=gateway.get('HostConfig',{}).get('ExtraHosts')or[]
 for row in selected_rows:
  host,port=row['host'],row['port'];key=env.get(row['keyEnv'])
  mapped=any(value.startswith(host+':')and value[len(host)+1:].strip('[]')in addresses for value in extras)
  rows.append({'capability':row['capability'],'retainedUpstreamPort':port,'sharedNetworkCount':len(shared),
   'ownerAliasOnSharedNetwork':host in aliases and bool(shared),'literalOwnerAddressOnSharedNetwork':host in addresses,
   'extraHostMapsToRetainedOwner':mapped,'upstreamPortListeningInOwnerNamespace':port in tables,
   'listenerAddressClasses':sorted(tables.get(port,set())),
   'gatewayDelegationKeyEnvPresent':key is not None,'gatewayDelegationKeyHasExpectedShape':type(key)is str and re.fullmatch('[0-9a-fA-F]{64}',key)is not None})
 return rows

def main():
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('FINITE_TOPOLOGY_READ_DEADLINE')));signal.alarm(90)
 plan,result,package_hash=history();transport=plan['gateway']['transport']
 expected={'gateway':transport['runtimeBinding'],'ingestion':plan['unchangedApplications']['ingestion'],
  'mcp':result['finalEvidence']['mcp']['runtimeBinding']}
 reader=Reader(plan['engine'],[v['containerId']for v in expected.values()]);values={}
 def inspect(name):
  actual=reader.get('/v1.44/containers/'+expected[name]['containerId']+'/json')
  sort=name!='gateway'or transport.get('runtimeBindingProfile')=='ouf.apisix-runtime-binding.mount-set.v1'
  require(runtime(actual,sort)==expected[name],'RETAINED_APPLICATION_GENERATION_CHANGED');return actual
 for name in expected:values[name]=inspect(name)
 pid=expected['ingestion']['pid'];namespace=Path('/proc')/str(pid)/'ns/net';before=namespace.stat()
 tables,count=read_listeners(pid);projection=topology(plan['gateway']['afterRoutes'],values['gateway'],values['ingestion'],tables)
 after=namespace.stat();require((before.st_dev,before.st_ino)==(after.st_dev,after.st_ino),'INGESTION_NETWORK_NAMESPACE_CHANGED')
 for name in expected:inspect(name)
 signal.alarm(0)
 return {'schema':'ouf.mcp-ingestion503-topology-read.v1','complete':True,'readOnly':True,'contextPath':str(CONTEXT),
  'packageHash':package_hash,'completedMcpReadbackProvenAsFiles':True,'lastReportedOAuthAttempts':236,'currentHumanStateRequeried':False,
  'retainedRouteCount':82,'retainedRouteMapHash':ROUTES,'retainedSnapshotOnly':True,'liveGatewayRoutesRequeried':False,
  'currentContainerGenerationsVerified':True,'engineGetRequests':reader.calls,'ownerTcpTablesRead':count,'routeTopology':projection,
  'dnsResolutionProven':False,'backendHttpProbes':0,'issuerCauseProven':False,'specific503CauseProven':False,
  'rawLogLinesRead':0,'credentialValuesPrinted':False,'selectedContainerEnvironmentInspectedForKeyShapeOnly':True,'credentialHashesPrinted':False,'credentialFilesOpened':0,
  'humanCredentialJournalsRead':0,'bearerFilesOpened':0,'oauthRequests':0,'ownerRequests':0,'processDispatches':0,
  'journalWrites':0,'gatewayWrites':0,'containerLifecycleOperations':0,'databaseCalls':0,'runtimeAuthorityIssued':False,
  'automaticReplayAllowed':False,'budgetReset':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
if __name__=='__main__':
 try:result=main()
 except(Exception,KeyboardInterrupt)as error:
  safe={n.value for n in ast.walk(ast.parse(Path(__file__).read_bytes()))if isinstance(n,ast.Constant)and type(n.value)is str and re.fullmatch('[A-Z][A-Z0-9_]{2,159}',n.value)}
  result={'schema':'ouf.mcp-ingestion503-topology-read.v1','complete':False,'exceptionClass':type(error).__name__,
   'reasonCode':str(error)if str(error)in safe else'PRIVATE_DETAILS_REDACTED','readOnly':True,'automaticReplayAllowed':False,'budgetReset':False}
 print(encoded(result).decode(),flush=True);raise SystemExit(0 if result['complete']else 2)
