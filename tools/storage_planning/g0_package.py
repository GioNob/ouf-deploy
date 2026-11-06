"""One bounded G0 observation package. Never migration, repair or admission.

check performs local reads only. collect is an operator entry point requiring
separate governed execution approval; a decisionRef records, never proves it.
"""
import argparse,ipaddress,json,os,re,stat,subprocess,sys,time
from urllib.parse import urlsplit
from pathlib import Path
from . import g0_database as db
from .g0_host import Engine,ROLES,snapshot,capacity
from . import g0_network as network
from .g0_reconciliation import census,reconcile
from .inventory_manifest import canonical,decode,require,sha

SECTIONS=('RUNTIME','OBJECTS','ACCESS','WRITERS','DB','CAPACITY','CUSTODY','WINDOW')
LIMITS={'attempts':1,'seconds':900,'engineGets':130,'engineBytes':32<<20,'s3Requests':3000,'s3WireBytes':128<<20,'s3Bodies':256,'s3BodyBytes':64<<20,'databaseExports':3,'databaseBytesEach':32<<20,'databaseRowsPerSection':10000,'priorControls':17,'priorEngineGets':52,'automaticReplayAllowed':False}
OPERATOR=('runtime','access','writers','capacity','custody','window')
def name(v):return type(v) is str and re.fullmatch('[A-Za-z0-9_-]{1,96}',v)
def digest(v):return type(v) is str and re.fullmatch('[a-f0-9]{64}',v)
def read_json(p,limit=1<<20):return decode(db.private_read(Path(p),limit))
def verify_package(root,expected):
 raw=(root/'package-manifest.json').read_bytes();require(digest(expected) and sha(raw)==expected,'G0_PACKAGE_MANIFEST_BINDING');m=decode(raw)
 require(m.get('schema')=='ouf.storage-g0-package.v1' and m.get('runtimeAuthorityIssued') is False and type(m.get('files')) is dict,'G0_PACKAGE_MANIFEST')
 for p,h in m['files'].items():
  rel=Path(p);require(not rel.is_absolute() and '..' not in rel.parts and digest(h),'G0_PACKAGE_MEMBER')
  path=root/rel;require(path.is_file() and not path.is_symlink() and sha(path.read_bytes())==h,'G0_PACKAGE_BYTES')
 actual={str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()};require(actual==set(m['files'])|{'package-manifest.json'},'G0_PACKAGE_EXACT_FILE_SET');return m
def inputs(path):
 raw=db.private_read(path,65536);c=decode(raw)
 require(type(c) is dict,'G0_PACKAGE_EXACT_INPUT')
 extra={'networkBindingFile'} if c.get('schema')=='ouf.storage-g0-package-input.v2' else set()
 require(set(c)=={'schema','operationId','installationRef','outputParent','roles','capacityPaths','connectionFiles','operatorEvidenceFiles','priorReceiptFiles','collectionDecisionRef'}|extra and c['schema'] in ('ouf.storage-g0-package-input.v1','ouf.storage-g0-package-input.v2'),'G0_PACKAGE_EXACT_INPUT')
 require(name(c['operationId']) and name(c['installationRef']),'G0_PACKAGE_IDENTITIES')
 if extra:require(type(c['networkBindingFile']) is str and Path(c['networkBindingFile']).is_absolute(),'G0_PACKAGE_NETWORK_PATH')
 require(type(c['roles']) is dict and set(c['roles'])==set(ROLES),'G0_PACKAGE_THIRTEEN_ROLES')
 for r in c['roles'].values():require(type(r) is dict and set(r)=={'containerId','nativeImage'} and digest(r['containerId']) and type(r['nativeImage']) is str and re.fullmatch('sha256:[a-f0-9]{64}',r['nativeImage']),'G0_PACKAGE_ROLE_BINDING')
 require(len({r['containerId'] for r in c['roles'].values()})==13,'G0_PACKAGE_DISTINCT_ROLES')
 require(type(c['capacityPaths']) is dict and set(c['capacityPaths'])=={'source','destination','backup'} and all(type(p) is str and Path(p).is_absolute() and str(Path(p))==os.path.normpath(p) for p in c['capacityPaths'].values()),'G0_PACKAGE_CAPACITY_PATHS')
 require(set(c['connectionFiles'])=={'s3','onboarding','udp','ingestion'} and set(c['operatorEvidenceFiles'])==set(OPERATOR),'G0_PACKAGE_COMPLETE_BINDING_SET')
 require(type(c['priorReceiptFiles']) is list and len(c['priorReceiptFiles'])==17 and all(type(x) is dict and set(x)=={'control','path','sha256'} and type(x['control']) is int and digest(x['sha256']) and type(x['path']) is str and Path(x['path']).is_absolute() for x in c['priorReceiptFiles']) and {x['control'] for x in c['priorReceiptFiles']}==set(range(1,18)),'G0_PACKAGE_CONSUMED_HISTORY_BINDINGS')
 require(type(c['outputParent']) is str and Path(c['outputParent']).is_absolute() and c['outputParent']==os.path.normpath(c['outputParent']),'G0_PACKAGE_OUTPUT_PARENT')
 return raw,c
def preflight(path,root,manifest_sha):
 verify_package(root,manifest_sha);raw,c=inputs(path);missing=[];configs={};operator={};bindings={}
 for key,p in c['connectionFiles'].items():
  require(type(p) is str and Path(p).is_absolute(),'G0_PACKAGE_PRIVATE_CONNECTION_PATH')
  b=db.private_read(Path(p),16384);v=decode(b);bindings['connection:'+key]=sha(b)
  require(v.get('operationId')==c['operationId']+'-'+key and v.get('installationRef')==c['installationRef'],'G0_PACKAGE_CONNECTION_SCOPE_BINDING')
  if key=='s3':
   require(set(v)=={'schema','operationId','installationRef','connection'} and v.get('schema')=='ouf.storage-g0-collection-input.v1' and type(v.get('connection')) is dict,'G0_PACKAGE_S3_CONFIG');conn=v['connection'];require(set(conn)<={'endpoint','region','accessKeyFile','secretKeyFile','allowLoopbackHttp','caCertificateFile','accessKeyFd','secretKeyFd'} and type(conn.get('region')) is str and bool(conn['region']),'G0_PACKAGE_S3_FIELDS');u=urlsplit(conn.get('endpoint',''))
   require(u.scheme in ('https','http') and u.hostname and not u.username and not u.password and not u.query and not u.fragment and u.path=='' and not conn.get('accessKeyFd') and not conn.get('secretKeyFd'),'G0_PACKAGE_S3_ENDPOINT')
   require(u.scheme=='https' or conn.get('allowLoopbackHttp') is True and ipaddress.ip_address(u.hostname).is_loopback,'G0_PACKAGE_S3_TLS_OR_LITERAL_LOOPBACK')
   for k in ('accessKeyFile','secretKeyFile'):db.private_read(Path(conn[k]),4096)
  else:
   require(set(v)=={'schema','operationId','installationRef','profile','host','hostaddr','port','database','user','passwordFile','sslmode','rootCertificateFile'} and v.get('schema')=='ouf.storage-g0-db-input.v1' and v.get('profile') in (('onboarding','onboarding-retained') if key=='onboarding' else (key,)),'G0_PACKAGE_DB_PROFILE');db.private_read(Path(v['passwordFile']),4096)
   require(all(type(v[k]) is str and re.fullmatch('[A-Za-z0-9_-]{1,128}',v[k]) for k in ('database','user')) and type(v['host']) is str and re.fullmatch('[A-Za-z0-9.-]{1,253}',v['host']) and type(v['port']) is int and 1<=v['port']<=65535,'G0_PACKAGE_DB_FIELDS')
   address=ipaddress.ip_address(v['hostaddr']);require(address.version==4 and (v['sslmode']=='verify-full' and bool(v['rootCertificateFile']) or v['sslmode']=='disable' and address.is_loopback and v['host']==v['hostaddr'] and v['rootCertificateFile']==''),'G0_PACKAGE_DB_TLS_OR_LITERAL_LOOPBACK')
  ca=(v['connection'].get('caCertificateFile') if key=='s3' else v.get('rootCertificateFile'))
  if ca:
   cert=Path(ca);st=cert.lstat();require(cert.is_absolute() and stat.S_ISREG(st.st_mode) and 0<st.st_size<=1<<20 and not st.st_mode&0o022,'G0_PACKAGE_CA_FILE')
  configs[key]=(Path(p),v)
 for key,p in c['operatorEvidenceFiles'].items():
  if p is None:missing.append('OPERATOR_'+key.upper());continue
  require(type(p) is str and Path(p).is_absolute(),'G0_PACKAGE_PRIVATE_EVIDENCE_PATH');b=db.private_read(Path(p),1<<20);v=decode(b);bindings['operator:'+key]=sha(b)
  require(type(v) is dict and v.get('installationRef')==c['installationRef'],'G0_PACKAGE_OPERATOR_INSTALLATION_BINDING')
  if key=='writers':census(v,c['installationRef'])
  else:require(v.get('schema')=='ouf.storage-g0-operator-evidence.v1' and v.get('section')==key.upper() and v.get('provenance') in ('OPERATOR_DECLARATION','TECHNICAL_OBSERVATION') and type(v.get('evidenceRefs')) is list and bool(v['evidenceRefs']) and type(v.get('ownerRef')) is str and bool(v['ownerRef']) and type(v.get('capturedAt')) is str and bool(v['capturedAt']),'G0_PACKAGE_OPERATOR_EVIDENCE')
  operator[key]=v
 mappings=operator.get('runtime',{}).get('storageBuckets');require(type(mappings) is dict and set(mappings)=={'onboarding','udp'} and all(type(b) is str and re.fullmatch('[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]',b) for b in mappings.values()),'G0_PACKAGE_OWNER_BUCKET_BINDINGS_REQUIRED_BEFORE_READS')
 if c.get('networkBindingFile') is not None:
  p=c['networkBindingFile'];require(type(p) is str and Path(p).is_absolute(),'G0_PACKAGE_NETWORK_PATH');b=db.private_read(Path(p),65536);v=decode(b);network.validate(v,c['operationId'],c['installationRef'],c['roles']);bindings['network']=sha(b)
  for key,(_,cfg) in configs.items():network.loopback_config('s3' if key=='s3' else 'db',cfg)
 for r in c['priorReceiptFiles']:
  b=db.private_read(Path(r['path']),2<<20);require(sha(b)==r['sha256'],'G0_PACKAGE_HISTORY_CHANGED');bindings['history:'+str(r['control'])]=sha(b)
 db.ancestors(Path(c['outputParent']));scope=Path(c['outputParent'])/c['operationId'];require(not scope.exists() and not scope.is_symlink(),'G0_PACKAGE_SCOPE_CONSUMED')
 for p in ([c['networkBindingFile']] if c.get('networkBindingFile') else [])+list(c['connectionFiles'].values())+[r['path'] for r in c['priorReceiptFiles']]+[p for p in c['operatorEvidenceFiles'].values() if p]:require(not Path(p).is_relative_to(scope) and not scope.is_relative_to(Path(p).parent),'G0_PACKAGE_NEW_SCOPE_SEPARATE_FROM_INPUTS')
 if not(type(c['collectionDecisionRef']) is str and 1<=len(c['collectionDecisionRef'])<=256):missing.append('COLLECTION_DECISION_REFERENCE')
 report={'schema':'ouf.storage-g0-package-preflight.v1','status':'LOCAL_INPUTS_BOUND_EXTERNAL_ADMISSION_REQUIRED','packageManifestSha256':manifest_sha,'inputSha256':sha(raw),'boundInputSha256':bindings,'operatorInputsMissing':missing,'limits':LIMITS,'targetReads':0,'runtimeAuthorityVerified':False,'runtimeAuthorityIssued':False,'targetCommandAuthorized':False,'g0Complete':False,'acceptanceCreditAdded':0}
 return c,configs,operator,scope,report
def access_findings(inventory):
 out=[]
 for b in inventory['bucketFeatures']:
  acl=b.get('acl',{});owner=(acl.get('value') or {}).get('Owner') or {};grants=(acl.get('value') or {}).get('Grants')
  if acl.get('status')!='PRESENT' or not owner.get('ID') or type(grants) is not list:out.append({'code':'ACL_OWNER_OR_GRANTS_UNPROVEN','bucketSha256':sha(b['bucket'].encode())});continue
  for g in grants:
   gr=g.get('Grantee') or {};kind=gr.get('Type');uri=gr.get('URI')
   code='ACL_OWNER_GRANT' if kind=='CanonicalUser' and gr.get('ID')==owner['ID'] else 'ACL_NONOWNER_GRANT_REVIEW'
   if kind=='Group' and uri in ('http://acs.amazonaws.com/groups/global/AllUsers','http://acs.amazonaws.com/groups/global/AuthenticatedUsers'):code='ACL_BROAD_GROUP_REVIEW'
   out.append({'code':code,'bucketSha256':sha(b['bucket'].encode()),'grantSha256':sha(canonical(g)),'permission':g.get('Permission')})
  for feature in ('policy','publicAccessBlock'):
   value=b.get(feature,{});out.append({'code':feature.upper()+'_'+str(value.get('status','UNKNOWN'))+'_REVIEW','bucketSha256':sha(b['bucket'].encode()),'evidenceSha256':sha(canonical(value))})
 return {'schema':'ouf.storage-g0-access-classification.v1','findings':out,'effectiveAuthorizationProven':False,'equivalentPublicAccessProtectionProven':False}
def collect(path,root,manifest_sha):
 c,configs,operator,scope,pre=preflight(path,root,manifest_sha)
 require('COLLECTION_DECISION_REFERENCE' not in pre['operatorInputsMissing'],'G0_PACKAGE_DECISION_REFERENCE_REQUIRED_NOT_AUTHORITY')
 scope.mkdir(mode=0o700);db.put_new(scope,'claim.private.json',canonical(pre|{'collectionDecisionRef':c['collectionDecisionRef'],'operationId':c['operationId'],'installationRef':c['installationRef']}));fd=os.open(scope.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 until=time.monotonic()+900;engine=None;network_children=None;children={};report={'schema':'ouf.storage-g0-package-result.v1','status':'HELD','technicalCaptureComplete':False,'phase':'CLAIMED','engineGets':0,'s3Requests':None,'databaseExportsAttempted':0,'priorControls':17,'priorEngineGets':52,'automaticReplayAllowed':False,'runtimeAuthorityIssued':False,'targetWrites':0,'g0Complete':False,'acceptanceCreditAdded':0,'sections':{s:{'status':'NOT_COLLECTED'} for s in SECTIONS}}
 def phase(p,seconds):
  require(time.monotonic()+seconds<=until,'G0_PACKAGE_CUMULATIVE_DEADLINE');report['phase']=p;db.put_new(scope,'phase-'+p+'.json',canonical({'phase':p,'reserved':True}))
 def stable():
  if c.get('networkBindingFile'):require(sha(db.private_read(Path(c['networkBindingFile']),65536))==pre['boundInputSha256']['network'],'G0_PACKAGE_NETWORK_CHANGED')
  for key,(p,_) in configs.items():require(sha(db.private_read(p,16384))==pre['boundInputSha256']['connection:'+key],'G0_PACKAGE_CONNECTION_CHANGED')
  for key,p in c['operatorEvidenceFiles'].items():
   if p:require(sha(db.private_read(Path(p),1<<20))==pre['boundInputSha256']['operator:'+key],'G0_PACKAGE_OPERATOR_CHANGED')
  for r in c['priorReceiptFiles']:require(sha(db.private_read(Path(r['path']),2<<20))==r['sha256'],'G0_PACKAGE_HISTORY_CHANGED')
 try:
  stable()
  frozen={}
  for key,(p,v) in configs.items():
   raw=db.private_read(p,16384);require(sha(raw)==pre['boundInputSha256']['connection:'+key],'G0_PACKAGE_CONNECTION_CHANGED');dest=scope/('input-'+key+'.private.json');db.put_new(scope,dest.name,raw);frozen[key]=dest
  if c.get('networkBindingFile'):
   raw=db.private_read(Path(c['networkBindingFile']),65536);require(sha(raw)==pre['boundInputSha256']['network'],'G0_PACKAGE_NETWORK_CHANGED');dest=scope/'network-binding.private.json';db.put_new(scope,dest.name,raw);network_children=network.NetworkChildren(root,dest,decode(raw),sha(raw))
  phase('HOST_BEFORE',60);engine=Engine(scope);engine.until=time.monotonic()+60;before=snapshot(engine,c['roles']);db.put_new(scope,'host-before.private.json',canonical(before));cap=capacity(c['capacityPaths']);db.put_new(scope,'capacity.private.json',canonical(cap));require(not before['findings'],'G0_PACKAGE_RUNTIME_BINDING_DRIFT')
  if network_children:network_children.runtime(before)
  phase('S3',310);p=scope/(c['operationId']+'-s3');children['s3']=p
  r=network_children.run('s3',frozen['s3'],p,310) if network_children else subprocess.run([str(root/'bin/inventory'),'g0-collect',str(frozen['s3']),str(p)],env={'PATH':'/usr/bin:/bin','GOMEMLIMIT':'256MiB','GOMAXPROCS':'1'},stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=310)
  require(len(r.stdout)<=8192 and len(r.stderr)<=8192,'G0_PACKAGE_MINIMIZED_CHILD_OUTPUT');summary=decode(r.stdout);report['s3Requests']=summary.get('requestsReserved');require(r.returncode==0 and summary.get('complete') is True,'G0_PACKAGE_BODY_COLLECTION_HELD')
  collection=read_json(p/'collection.private.json',32<<20);require(collection.get('installationRef')==c['installationRef'] and collection.get('operationId')==c['operationId']+'-s3' and collection.get('configSha256')==pre['boundInputSha256']['connection:s3'],'G0_PACKAGE_BODY_INPUT_BINDING')
  invraw=db.private_read(p/'inventory-before.private.json',32<<20);require(sha(invraw)==collection.get('inventoryBeforeSha256'),'G0_PACKAGE_INVENTORY_BINDING');inventory=decode(invraw);acl=access_findings(inventory);db.put_new(scope,'access-review.json',canonical(acl))
  exports={}
  for role in ('onboarding','udp','ingestion'):
   stable();phase('DB_'+role.upper(),125 if network_children else 120);q=scope/(c['operationId']+'-'+role);children[role]=q;report['databaseExportsAttempted']+=1
   if network_children:
    child=network_children.run('db',frozen[role],q,125);result=decode(child.stdout);require(child.returncode==0 and result.get('complete') is True,'G0_PACKAGE_DATABASE_NAMESPACE_HELD')
   else:result=db.export(frozen[role],q)
   require(result['complete'],'G0_PACKAGE_DATABASE_EXPORT_HELD');v=configs[role][1];profile=v['profile'];exports[profile]=db.parse_export(db.private_read(q/'export.private.jsonl',32<<20),profile);h=exports[profile]['header']
   require(h.get('database')==v['database'] and h.get('role')==v['user'] and h.get('serverAddress')==v['hostaddr'] and h.get('serverPort')==v['port'],'G0_PACKAGE_DATABASE_ENDPOINT_BINDING')
  # The buckets come from the explicitly bound connection/owner input, not a guessed default.
  mappings=operator.get('runtime',{}).get('storageBuckets');require(type(mappings) is dict and set(mappings)=={'onboarding','udp'},'G0_PACKAGE_OWNER_BUCKET_BINDINGS_REQUIRED')
  writers=operator.get('writers',{'schema':'ouf.storage-g0-writer-census.v1','installationRef':c['installationRef'],'paths':[]})
  phase('JOIN',10);joined=reconcile(collection,exports,mappings,writers);db.put_new(scope,'reconciliation.json',canonical(joined))
  phase('HOST_AFTER',60);engine.until=time.monotonic()+60;after=snapshot(engine,c['roles']);db.put_new(scope,'host-after.private.json',canonical(after));require(before==after,'G0_PACKAGE_HOST_DRIFT');stable()
  if network_children:network_children.runtime(after)
  report['technicalCaptureComplete']=True;report['status']='OBSERVATIONS_SEALED_G0_REVIEW_REQUIRED';report['phase']='SEALED'
  report['sections']={s:{'status':'OBSERVED_REVIEW_REQUIRED'} for s in SECTIONS}
  for key in OPERATOR:
   if key not in operator:report['sections'][key.upper()]['status']='MISSING_OPERATOR_EVIDENCE'
  report['sections']['OBJECTS']['verifiedBodies']=len(collection['objects']);report['sections']['DB']['findings']=joined['findingsCount'];report['sections']['ACCESS']['classifications']=len(acl['findings']);report['sections']['WRITERS']['intake']=joined['writerCensus']
  if joined['findingsCount']:report['status']='HELD_RECONCILIATION_FINDINGS'
  report['pointInTimeCommonCutProven']=False;report['writerQuiescenceProven']=False;report['operatorEvidenceAuthenticated']=False
 except Exception as e:
  reason=str(e);report['reason']=reason if re.fullmatch('G0_[A-Z0-9_]+',reason) else 'G0_PACKAGE_CAPTURE_UNPROVEN'
 finally:
  report['engineGets']=engine.requests if engine else 0;report['engineBytes']=engine.bytes if engine else 0;report['cumulativeEngineGets']=52+report['engineGets'];report['scopeConsumed']=True
  report['childScopes']={k:{'claimed':(p/'claim.private.json').exists(),'summaryPresent':(p/'summary.json').exists()} for k,p in children.items()}
  db.put_new(scope,'result.json',canonical(report))
 return report
def main(root):
 p=argparse.ArgumentParser();p.add_argument('action',choices=['check','collect']);p.add_argument('config',type=Path);p.add_argument('--package-sha256',required=True);a=p.parse_args()
 try:r=preflight(a.config,root,a.package_sha256)[-1] if a.action=='check' else collect(a.config,root,a.package_sha256);print(json.dumps(r,sort_keys=True));return 0 if a.action=='check' or r['technicalCaptureComplete'] else 1
 except Exception as e:
  reason=str(e);print(json.dumps({'status':'HELD','reason':reason if re.fullmatch('G0_[A-Z0-9_]+',reason) else 'G0_PACKAGE_INPUT_UNPROVEN','targetCommandAuthorized':False,'runtimeAuthorityIssued':False}));return 1
