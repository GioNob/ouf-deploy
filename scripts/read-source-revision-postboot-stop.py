"""Installation-specific read-only reconciliation of q7bq1ex3; no retry/apply."""
import hashlib,importlib,json,os,re,signal,stat,sys,types,traceback
from pathlib import Path
STAGE=Path('/home/oufadmin/ouf-deploy-runner/_work/ouf-deploy/ouf-source-revision-postboot-code-39163565894')
MANIFEST='a904ca6614bed530b80b1bac40469fbf8d3227d2c50371f8d874d89a1ce4a68f'
CONTEXT=Path('/etc/ouf/deploy-snapshots/source-revision-postboot-prepared-q7bq1ex3')
SOURCE='6c5d54953a661b0a01ad54a9aea52d5f23b8cbc1'
def require(ok):
 if not ok:raise ValueError('READ_RECONCILIATION_UNPROVEN')
def digest(raw):return hashlib.sha256(raw).hexdigest()
def read(path,sha=None,maximum=8388608):
 path=Path(path);require(path.is_absolute() and path.resolve()==path)
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);require(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<a.st_size<=maximum)
  with os.fdopen(os.dup(fd),'rb') as stream:raw=stream.read(maximum+1)
  pin=lambda s:tuple(getattr(s,k) for k in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  require(len(raw)==a.st_size and pin(a)==pin(os.fstat(fd))==pin(path.lstat()) and (sha is None or digest(raw)==sha));return raw
 finally:os.close(fd)
def classify(raw):
 """Only fixed classifications/counts; never source lines, keys or values."""
 require(type(raw)is bytes and 0<len(raw)<=1048576)
 counts={k:0 for k in ('directive','flowObject','flowArray','explicitKey','mergeKey','quotedLine','anchorAliasTag')}
 for line in raw.decode('utf-8').splitlines():
  t=line.lstrip()
  if not t or t.startswith('#'):continue
  for prefix,key in (('%','directive'),('{','flowObject'),('[','flowArray'),('?','explicitKey'),('<<:','mergeKey'),("'",'quotedLine'),('"','quotedLine')):
   if t.startswith(prefix):counts[key]+=1
  if re.search(r'(^|\s)[&*!][A-Za-z_]',t):counts['anchorAliasTag']+=1
 result={'syntaxCounts':counts,'strictJsonObject':False,'duplicateJsonKeys':False,'jsonParseFailed':False,'configurationValuesPrinted':False,'propertyNamesPrinted':False}
 duplicate=False
 def unique(rows):
  nonlocal duplicate
  value={}
  for k,v in rows:
   if k in value:duplicate=True
   value[k]=v
  return value
 try:
  obj=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))
  result['strictJsonObject']=type(obj)is dict and not duplicate;result['duplicateJsonKeys']=duplicate
  if type(obj)is dict:
   leaves=0;reserved=0;deep=False
   def visit(value,depth=0):
    nonlocal leaves,reserved,deep
    if depth>32:deep=True;return
    if type(value)is dict:
     for k,v in value.items():
      if re.sub('[^a-z0-9]','',k.lower()).startswith(('spring','loader')):reserved+=1
      visit(v,depth+1)
    elif type(value)is list:
     for v in value:visit(v,depth+1)
    else:leaves+=1
   visit(obj);result.update(jsonLeafCount=leaves,reservedSpringOrLoaderKeyCount=reserved,depthBoundExceeded=deep)
 except (ValueError,UnicodeError,RecursionError):result['jsonParseFailed']=True
 return result

# Closed public property vocabulary. Unknown/map-key segments are redacted.
PROPERTY_WORDS=frozenset('spring security oauth2 resourceserver jwt opaque token introspectionuri client registration provider clientid clientsecret clientauthenticationmethod authorizationgranttype redirecturi scope issueruri jwkseturi userinfouri usernameattribute authorizationuri tokenuri audiences jwsalgorithms principalclaimname authoritiesclaimname authorityprefix ouf authorization ths enabled publicorigin gatewaybaseurl gatewayurl tokenfile workflow resolution onboarding udpidentity managedfilepicker gatewayuploadurl server port address servlet contextpath session cookie secure httponly samesite timeout forwardheadersstrategy ssl management endpoints web exposure include exclude endpoint health showdetails probes metrics logging level root datasource url username password flyway baselineonmigrate validateonmigrate schemas defaultschema locations config import activate onprofile profiles active include loader path sql init mode'.split())
def property_metadata(raw,verifier):
 def unique(rows):
  obj={}
  for k,v in rows:require(k not in obj);obj[k]=v
  return obj
 obj=json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))
 require(type(obj)is dict)
 def reason(value):
  try:verifier(json.dumps(value,separators=(',',':'),allow_nan=False).encode());return 'ACCEPTED'
  except Exception as error:
   message=str(error)
   return message if type(error).__name__=='UpdateDenied' and re.fullmatch('[A-Z_]{1,100}',message) else 'UNCLASSIFIED_VERIFIER_FAILURE'
 rows=[];nodes=0
 def visit(value,path=(),depth=0):
  nonlocal nodes
  require(type(value)is dict and depth<=16)
  for key,item in value.items():
   nodes+=1;require(nodes<=512 and type(key)is str and len(key)<=128)
   segments=path+tuple(key.split('.'));require(len(segments)<=32)
   if type(item)is dict:visit(item,segments,depth+1);continue
   canonical=tuple(re.sub('[^a-z0-9]','',p.lower()) for p in segments)
   selected=item
   for part in reversed(segments):selected={part:selected}
   public=[]
   for i,part in enumerate(canonical):
    map_key=i==5 and canonical[:4]==('spring','security','oauth2','client') and canonical[4] in ('registration','provider')
    public.append('<map-key>' if map_key else part if part in PROPERTY_WORDS else '<redacted-key>')
   rows.append({'propertyShape':'.'.join(public),'valueType':type(item).__name__,
                'verifierResult':reason(selected),'literalInterpolationPresent':type(item)is str and any(v in item for v in ('${','#{'))})
 visit(obj)
 return {'wholeDocumentVerifierResult':reason(obj),'properties':rows,'configurationValuesPrinted':False,'unknownPropertyNamesPrinted':False,'mapKeyNamesPrinted':False}


def exact_tree(context,expected,reader):
 require(len(expected)<=100)
 directories={'.'}
 for name in expected:directories.update(str(p) for p in Path(name).parents)
 pins={};found={}
 def walk(p):
  info=p.lstat();require(stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700)
  relative=str(p.relative_to(context));require(relative in directories);pins[relative]=reader.pin(info)
  for child in p.iterdir():
   name=str(child.relative_to(context));st=child.lstat()
   if stat.S_ISDIR(st.st_mode):walk(child)
   else:
    require(name in expected and stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode)==0o600 and st.st_gid==0)
    found[name]=reader.read(child,maximum=8388608);require(found[name]==expected[name])
 walk(context);require(set(found)==set(expected) and set(pins)==directories)
 require(all(reader.pin((context/name).lstat())==pin for name,pin in pins.items()))
 return {name:digest(raw) for name,raw in sorted(found.items())}

def main():
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode)
 signal.alarm(180)
 manifest=json.loads(read(STAGE/'manifest.json',MANIFEST,65536));require(manifest['sourceCommit']==SOURCE)
 modules={}
 for name in ('reader','prepare'):
  raw=read(STAGE/(name+'.py'),manifest['files'][name+'.py'],262144)
  m=types.ModuleType('verified_diagnostic_'+name);m.__file__=str(STAGE/(name+'.py'));exec(compile(raw,'<verified-diagnostic-helper>','exec'),m.__dict__);modules[name]=m
 reader=modules['reader'];prepare=modules['prepare']
 profile=json.loads(read(STAGE/'selection.json',manifest['files']['selection.json'],65536));profile['successorSourceCommit']=SOURCE
 ns,original,oldcase,closure,files,package,loader,memory,sources,pins,overlays=prepare.load_staged(profile,reader,read(STAGE/'configuration.py',manifest['files']['configuration.py'],262144))
 executor_raw=read(STAGE/'executor.py',manifest['files']['executor.py'],262144)
 executor={'__name__':'read_only_consumer'};exec(compile(executor_raw,'<verified-consumer-declaration>','exec'),executor)
 code=CONTEXT/'executor-code';case_raw=reader.read(code/'case.json');case=json.loads(case_raw)
 require(case['historicalPreparedPlanBinding']==profile['historicalPrivateInputs'] and case['completedHostPlanSha256']==profile['hostPlanSha256'] and case['completedHostContext']==profile['hostContext'])
 require(case['postbootOriginalPreparationBinding']['path']==str(CONTEXT/'current-original-preparation.json') and case['preparedPlanBinding']['path']==str(CONTEXT/'postboot-private-inputs.json'))
 reconciled=executor['select_prepared'](case,original,ns['read'])
 private_raw=reader.read(CONTEXT/'postboot-private-inputs.json',case['preparedPlanBinding']['sha256']);private=json.loads(private_raw)
 require(private['runtimeAuthorityIssued']is False and private['readyForExecution']is False)
 require(private['postbootReconciliation']['currentOriginalPreparationBinding']==case['postbootOriginalPreparationBinding'])
 require(executor['OVERLAYS']==overlays)
 expected_package={**package,'sourceCommit':SOURCE,'executorSha256':digest(executor_raw),'caseSha256':digest(case_raw)}
 expected_code={**files,'runtime.py':loader,'execute.py':executor_raw,'case.json':case_raw,'package.json':reader.encoded(expected_package)}
 require(len(expected_code)==81)
 prep=importlib.import_module('tools.source_revision_update.preparation')
 compiler_sources=prep.gateway.source_members(reader.read(private['gatewayPackage']['path'],private['gatewayPackage']['sha256'],67108864),json.loads(prep.package_files(private)('gateway','source-inventory.json')))
 require(len(compiler_sources)==7)
 expected={**{'executor-code/'+k:v for k,v in expected_code.items()},**{'gateway-compiler/'+k:v for k,v in compiler_sources.items()},'current-original-preparation.json':reader.encoded(reconciled),'postboot-private-inputs.json':private_raw}
 before=exact_tree(CONTEXT,expected,reader)
 prior=prepare.reconcile_postboot_stop(profile['previousPostbootStop'],reader)
 require(case['configurationSuccessor']==profile['configurationSuccessor'] and case['previousPostbootStop']==prior)
 config=importlib.import_module('tools.source_revision_update.configuration')
 actual=private['beforeApplications']['onboarding'];env=config.env(actual['Config']['Env']);location=config.additional_location(env['SPRING_CONFIG_ADDITIONAL_LOCATION'])
 mounts=[m for m in actual['Mounts'] if m['Destination']==location];require(len(mounts)==1 and mounts[0]['Type']=='bind' and mounts[0]['RW']is False)
 host=json.loads(reader.read(Path(profile['hostContext'])/'plan.json',profile['hostPlanSha256']))
 expected_sha=host['configurationFileBindings'][mounts[0]['Source']]
 raw,binding=config.private_config(mounts[0]['Source']);require(digest(raw)==expected_sha)
 classification=classify(raw)
 properties=property_metadata(raw,config.owner_json_overlay)
 raw_after,binding_after=config.private_config(mounts[0]['Source'],binding);require(raw_after==raw and binding_after==binding)
 require(exact_tree(CONTEXT,expected,reader)==before and prepare.reconcile_postboot_stop(profile['previousPostbootStop'],reader)==prior)
 return {'schema':'ouf.postboot-stop-read.v1','complete':True,'contextPath':str(CONTEXT),'contextFiles':len(expected),'contextClosureSha256':reader.digest(before),'exactFrozenCodeFiles':81,'exactCompilerSources':7,'exactPrivateDocuments':2,'authorityArtifactsAbsent':True,'completionReceiptAbsent':True,'originalConsumerBindingVerified':True,'overlaySha256':expected_sha,'overlayMatchesCompletedHostPlan':True,'overlayClassification':classification,'propertyDiagnostics':properties,'previousStopReconciliation':prior,'targetGenerationRevalidated':False,'preparationRetried':False,'runtimeAuthorityIssued':False,'runtimeMutations':0,'databaseCalls':0,'engineCalls':0,'credentialValuesPrinted':False,'configurationValuesPrinted':False,'automaticRetry':False,'budgetReset':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
if __name__=='__main__':
 try:result=main()
 except (Exception,KeyboardInterrupt) as error:result={'schema':'ouf.postboot-stop-read.v1','complete':False,'exceptionClass':type(error).__name__,'frames':[{'file':Path(f.filename).name,'function':f.name,'line':f.lineno} for f in traceback.extract_tb(error.__traceback__)[-4:]],'rawErrorPrinted':False,'runtimeAuthorityIssued':False,'runtimeMutations':0,'automaticRetry':False,'budgetReset':False}
 print(json.dumps(result,sort_keys=True));sys.exit(0 if result['complete']else 2)
