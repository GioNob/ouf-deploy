#!/usr/bin/env python3
"""Read declared discovery key/mount and current Gateway signer; no repair/start."""
import hashlib,importlib.util,json,os,re,shlex,stat,sys,tempfile
from datetime import datetime,timezone
from pathlib import Path
CID='11d9362c7db484a2204266062fd54b5c08fbf1da7382076fb2a164bc1a9dd070'
IMAGE='sha256:89e84f7a6208afa74039de7057c46ad5c9981fb283b22d9b93fa014e92d1b048'
ROOT=Path('/var/lib/ouf-storage-migration')
FAILED_LOG=ROOT/'semantic-exit-read-rbfh5_8f/replacement-logs.stdout.private'
FIELDS=('ouf.semantic.discovery-delegation.key-file','ouf.semantic.discovery-delegation.workload',
 'ouf.semantic.delegation.key-file','ouf.semantic.delegation.workload',
 'ouf.semantic.proposal-receipt.key-file','ouf.iam.issuer','ouf.iam.audience')
PATHS=['/internal/capabilities/v1/execute/semantic/search']+[
 '/internal/capabilities/v1/execute/semantic/discovery/'+x for x in ('request','status','candidates')]

def need(ok,code):
 if not ok:raise RuntimeError(code)
def canonical(s):return re.sub('[._-]','',s).lower()
def path_ok(s):return isinstance(s,str) and len(s)<=512 and re.fullmatch('/[A-Za-z0-9_./-]+',s) and str(Path(s))==s and '..' not in Path(s).parts
def selected(doc,h):
 env=h.environment(doc);found={k:[] for k in FIELDS}
 def add(k,v,origin):
  for f in FIELDS:
   if canonical(k)==canonical(f):found[f].append({'origin':origin,'value':v})
 for k,v in env.items():add(k,v,'ENV')
 def flatten(node,prefix='',depth=0):
  need(type(node) is dict and depth<=16,'JSON_CONFIG_SHAPE')
  for k,v in node.items():
   if type(v) is dict:flatten(v,prefix+k+'.',depth+1)
   else:add(prefix+k,v,'SPRING_APPLICATION_JSON')
 if env.get('SPRING_APPLICATION_JSON'):flatten(json.loads(env['SPRING_APPLICATION_JSON']))
 args=list(doc['Config'].get('Cmd') or [])+list(doc['Config'].get('Entrypoint') or [])
 for name in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','JAVA_OPTS'):args+=shlex.split(env.get(name,''))
 for arg in args:
  if arg.startswith(('-D','--')) and '=' in arg:add(*arg[2:].split('=',1),'ARGUMENT')
 return found

def host_metadata(path):
 """No content reads, no symlink traversal, including parent components."""
 fds=[]
 try:
  need(path_ok(path),'HOST_PATH_SHAPE')
  fd=os.open('/',os.O_PATH|os.O_DIRECTORY);fds.append(fd)
  parts=Path(path).parts[1:]
  for i,part in enumerate(parts):
   fd=os.open(part,os.O_PATH|os.O_NOFOLLOW|(os.O_DIRECTORY if i<len(parts)-1 else 0),dir_fd=fd);fds.append(fd)
  s=os.fstat(fd)
  return {'status':'HOST_METADATA_READ','regular':stat.S_ISREG(s.st_mode),'directory':stat.S_ISDIR(s.st_mode),
   'symlink':stat.S_ISLNK(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'modeOctal':format(stat.S_IMODE(s.st_mode),'04o'),
   'nonempty':s.st_size>0}
 except FileNotFoundError:return {'status':'HOST_PATH_MISSING'}
 except OSError as e:return {'status':'HOST_METADATA_UNAVAILABLE','errno':e.errno}
 finally:
  for fd in reversed(fds):os.close(fd)

def mount_summary(doc,path):
 if not path_ok(path):return {'status':'NO_NORMALIZED_ABSOLUTE_PATH'}
 covered=[m for m in doc['Mounts'] if path==m['Destination'] or path.startswith(m['Destination'].rstrip('/')+'/')]
 if not covered:return {'status':'NO_DECLARED_MOUNT','containerFilesystemInspected':False}
 covered.sort(key=lambda m:len(m['Destination']),reverse=True);m=covered[0]
 out={'status':'DECLARED_MOUNT','destination':m['Destination'],'type':m['Type'],'readOnly':not m['RW'],
      'containerFilesystemInspected':False,'metadataScope':'CURRENT_HOST_SOURCE_ONLY_CONTAINER_STOPPED'}
 if m['Type']=='bind':out['hostSource']=host_metadata(m['Source']+path[len(m['Destination']):])
 return out

def project(doc,values,missing):
 out={}
 for key,rows in values.items():
  result=[]
  for row in rows:
   v=row['value'];item={'origin':row['origin'],'nonempty':isinstance(v,str) and bool(v)}
   if key.endswith('key-file'):
    item.update(path=v if path_ok(v) else None,matchesFailedLogPath=v in missing,mount=mount_summary(doc,v))
   result.append(item)
  out[key]=result
 return out

def constants(route):
 functions=route.get('plugins',{}).get('serverless-post-function',{}).get('functions',[])
 need(len(functions)==1,'ONE_SIGNER_FUNCTION_REQUIRED');out={}
 for line in functions[0].splitlines()[:8]:
  m=re.fullmatch(r'local (DELEGATION_KEY_ENV|OWNER_KEY_ENV|ISSUER|AUDIENCE|MCP_WORKLOAD) = (".*")',line)
  if m:
   need(m[1] not in out,'DUPLICATE_SIGNER_CONSTANT');out[m[1]]=json.loads(m[2])
 need(len(out)==5 and all(isinstance(v,str) for v in out.values()),'FIXED_SIGNER_CONSTANTS_REQUIRED')
 for k in ('DELEGATION_KEY_ENV','OWNER_KEY_ENV'):need(re.fullmatch('[A-Z_][A-Z0-9_]{0,99}',out[k]),'SIGNER_ENV_NAME_INVALID')
 return out

def gateway_summary(rows,env,values,h):
 result={};selected=[]
 for path in PATHS:
  matches=[r for r in rows if r.get('uri')==path]
  entry={'matchingRouteCount':len(matches)};result[path]=entry
  if len(matches)!=1:continue
  row=matches[0];c=constants(row);selected.append(c)
  name=c['OWNER_KEY_ENV'];value=env.get(name)
  entry.update(ownerKeyEnvironmentName=name,ownerKeyEnvironmentPresent=value is not None,
   ownerKeyFormatValid=isinstance(value,str) and bool(re.fullmatch('[0-9a-fA-F]{64}',value)),
   distinctEnvironmentFromMcpDelegation=name!=c['DELEGATION_KEY_ENV'],
   postFunctionSha256=h.digest(row['plugins']['serverless-post-function']),
   declaredSemanticMatches={p:[r['value']==c[k] for r in values[p]] for p,k in (
    ('ouf.iam.issuer','ISSUER'),('ouf.iam.audience','AUDIENCE'),
    ('ouf.semantic.discovery-delegation.workload','MCP_WORKLOAD'))})
 return {'routes':result,'allSelectedRoutesUseSameOwnerKeyEnvironment':len(selected)==4 and len({c['OWNER_KEY_ENV'] for c in selected})==1,
  'otherDiscoveryKeyEnvironmentNames':[k for k in env if re.fullmatch('[A-Z_][A-Z0-9_]{0,99}',k) and 'DISCOVERY' in k and 'KEY' in k],
  'keyBytesComparedWithSemanticFile':False,'routeConfigurationOnlyNotFunctionalAuthorization':True}

def run(report):
 need(os.geteuid()==0 and sys.flags.isolated,'ISOLATED_ROOT_REQUIRED');os.umask(0o077)
 p=Path(__file__).with_name('read-discovery-contract-20261108.py');raw=p.read_bytes()
 need(hashlib.sha256(raw).hexdigest()=='468660ed73a24c7b8a842f5b99a9c268890c99bb4206ca2e4719865326b27277','HELPER_HASH_MISMATCH')
 spec=importlib.util.spec_from_file_location('contract',p);c=importlib.util.module_from_spec(spec);exec(compile(raw,str(p),'exec'),c.__dict__);h=c.helper()
 work=Path(tempfile.mkdtemp(prefix='semantic-key-binding-',dir=ROOT));report['privateEvidenceDirectory']=str(work)
 semantic=h.inspect(CID);c.save_private(work,'semantic.private.json',json.dumps(semantic).encode())
 need(semantic['Image']==IMAGE and not semantic['State']['Running'] and semantic['State']['Pid']==0,'OBSERVED_STOPPED_REPLACEMENT_REQUIRED')
 values=selected(semantic,h);c.save_private(work,'declarations.private.json',json.dumps(values).encode())
 missing=[]
 try:
  log=h.read(FAILED_LOG,4*1024*1024).decode('utf-8','replace')
  missing=list(dict.fromkeys(p.strip() for p in re.findall(r'java\.nio\.file\.NoSuchFileException: ([^\r\n]+)',log) if path_ok(p.strip())))
  report['failedLogRead']=True
 except Exception as e:report['failedLogRead']=False;report['failedLogReadReason']=c.safe_reason(e)
 report['missingPathsFromFailedLog']=missing
 report['semantic']={'containerId':CID,'imageMatchesCandidate':True,'running':False,
  'declarations':project(semantic,values,missing),'configurationScope':'DECLARATIONS_NOT_EFFECTIVE_SPRING_CONFIGURATION',
  'mounts':[{'destination':m['Destination'],'type':m['Type'],'readOnly':not m['RW']} for m in semantic['Mounts']],
  'springConfigImportPresent':bool(h.environment(semantic).get('SPRING_CONFIG_IMPORT'))}
 try:
  planraw=h.read(h.PLAN,1048576);need(hashlib.sha256(planraw).hexdigest()==h.PLAN_SHA,'PLAN_HASH_MISMATCH')
  role=h.parse(planraw)['roles']['apisix'];apisix=h.inspect(role['containerId'])
  need(apisix['State']['Running'],'APISIX_NOT_RUNNING')
  c.save_private(work,'apisix.private.json',json.dumps(apisix).encode())
  c.routes(apisix,PATHS,h,report,work)
  data=h.parse(h.read(work/'routes.private.json',8*1024*1024));rows=[]
  for e in data['list']:
   row=e.get('value',e)
   if isinstance(row.get('value'),dict):row=row['value']
   rows.append(row)
  report['gateway']=gateway_summary(rows,h.environment(apisix),values,h)
  report['gateway']['frameUnchangedDuringRead']=h.frame(apisix)==h.frame(h.inspect(apisix['Id']))
  report['gateway']['imageMatchesRetained']=apisix['Image']==role['nativeImage']
 except Exception as e:report['gateway']={'status':'READ_INCOMPLETE','reason':c.safe_reason(e)}
 report['semanticFrameUnchangedDuringRead']=h.frame(semantic)==h.frame(h.inspect(CID))
 report['status']='SEMANTIC_DISCOVERY_KEY_BINDING_READ' if report['gateway'].get('routes') else 'READ_PARTIAL'
 report['observedAt']=datetime.now(timezone.utc).isoformat()
 c.save_private(work,'report.json',json.dumps(report,sort_keys=True).encode())

def main():
 report={'schema':'ouf.semantic-discovery-key-binding-read.v1','status':'READ_INCOMPLETE',
  'serviceConfigurationChanged':False,'serviceStartDispatched':False,'serviceStops':0,'databaseRequests':0,
  'migrationDispatched':False,'businessRequestsIssued':0,'s3Requests':0,'gatewayWrites':0,'keyFileContentsRead':0,
  'credentialValuesEmitted':False,'rawLogsEmitted':False,'adminCredentialConfigurationsRead':0,
  'externalAdminKeyFilesRead':0,'adminRouteGetAttempts':0}
 try:run(report)
 except Exception as e:report['reason']=str(e) if type(e) is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}',str(e)) else type(e).__name__
 print(json.dumps(report,sort_keys=True))
if __name__=='__main__':main()
