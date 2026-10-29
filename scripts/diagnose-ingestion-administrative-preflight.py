"""Finite preflight of the existing native HUMAN session; no administrative effects.

Installation-specific retained context. Pure module/binding checks precede one
native refresh invocation, only inside the already approved HUMAN window. No
login, authority, grant, role, source, service or job operation is available.
Owner calls are constrained to GET and one exact MCP ROLES read; IAM is GET only.
"""
import ast,base64,hashlib,json,os,re,signal,stat,sys,tempfile,time
from pathlib import Path
CONTEXT=Path('/etc/ouf/deploy-snapshots/ingestion-read-authorization-execution-dyvd8zal')
ROOT=CONTEXT.parent
STAGE=Path('/home/oufadmin/ouf-deploy-runner/_work/ouf-deploy/ouf-ingestion-read-administrative-code-39222837925')
MANIFEST='633bbf2a17dc0395dd362694833b2264e7aef9501a06d5ce3fc54a4569e879c2'
SOURCE='1e1a9f9eddca649e64db36fe018f59f2f15a2105'
class PreflightDenied(Exception):pass

def require(ok,code):
 if not ok:raise PreflightDenied(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def digest(v):return sha(encoded(v))
def pin(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def raw_read(path,maximum=8388608,expected=None,*,private=True):
 path=Path(path);require(path.is_absolute()and path.resolve()==path,'EXACT_NATIVE_PATH_REQUIRED')
 if private:
  for p in path.parents:
   s=p.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'ROOT_NATIVE_ANCESTRY_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  first=os.fstat(fd);require(stat.S_ISREG(first.st_mode)and first.st_nlink==1 and 0<first.st_size<=maximum,'BOUNDED_NATIVE_FILE_REQUIRED')
  if private:require(first.st_uid==first.st_gid==0 and stat.S_IMODE(first.st_mode)==0o600,'NATIVE_PRIVATE_CUSTODY_REQUIRED')
  with os.fdopen(os.dup(fd),'rb')as f:raw=f.read(maximum+1)
  require(len(raw)==first.st_size and pin(first)==pin(os.fstat(fd))==pin(path.lstat())
   and(expected is None or sha(raw)==expected),'NATIVE_FILE_BINDING_CHANGED')
  return raw
 finally:os.close(fd)
def read(path,maximum=8388608,expected=None):return json.loads(raw_read(path,maximum,expected))
def write_new(directory,name,raw):
 require(Path(name).name==name,'SAFE_NATIVE_MEMBER_REQUIRED')
 fd=os.open(directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(os.dup(fd),'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
 finally:os.close(fd)
 fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)

def public_codes(raw):
 return {n.value for n in ast.walk(ast.parse(raw))if isinstance(n,ast.Constant)and isinstance(n.value,str)
  and re.fullmatch('[A-Z][A-Z0-9_]{2,159}',n.value)}

def load_capsule():
 manifest=json.loads(raw_read(STAGE/'manifest.json',expected=MANIFEST,private=False))
 require(manifest['sourceCommit']==SOURCE,'EXACT_STAGED_SOURCE_REQUIRED')
 receipt=read(CONTEXT/'preparation-result.json')
 require(receipt['schema']=='ouf.ingestion-read-administrative-preparation.v1'and receipt['contextPath']==str(CONTEXT)
  and receipt['sourceCommit']==SOURCE and receipt['runtimeAuthorityIssued']is False,'EXACT_COMPLETED_PRIVATE_PREPARATION_REQUIRED')
 package=read(CONTEXT/'package.json',expected=receipt['packageHash'])
 require(package['schema']=='ouf.ingestion-read-administrative-package.v1'and package['sourceCommit']==SOURCE
  and digest(package['closure'])==receipt['sourceClosureHash'],'EXACT_PRIVATE_PACKAGE_REQUIRED')
 files={name:raw_read(CONTEXT/name,expected=h)for name,h in package['fileHashes'].items()
  if name in('case.json','bootstrap.py','runtime.py','reader.py','sources.json')}
 require(set(files)==set(package['fileHashes'])=={'case.json','bootstrap.py','runtime.py','reader.py','sources.json'},'EXACT_PRIVATE_CODE_MEMBERS_REQUIRED')
 for name in('bootstrap.py','runtime.py','reader.py'):
  require(sha(files[name])==manifest['files'][name],'EXACT_STAGED_BOOTSTRAP_REQUIRED')
 case=json.loads(files['case.json'])
 require(digest(case)==package['executionPins']['caseSha256']and case['sourceId']=='teatri-csv-6609b245','EXACT_RETAINED_CASE_REQUIRED')
 claim=read(CONTEXT/'runtime.claim.json',65536)
 require(claim=={'packageHash':receipt['packageHash'],'automaticReplayAllowed':False},'ORIGINAL_RUNTIME_CLAIM_REQUIRED')
 for name in('authority.json','review.json','authorization-plan.json','issuance.claim.json','decision.json','human.json','administrative-result.json','authorization'):
  require(not os.path.lexists(CONTEXT/name),'ADMINISTRATIVE_AUTHORITY_OR_EFFECT_RECONCILIATION_REQUIRED')
 sources={n:base64.b64decode(v,validate=True)for n,v in json.loads(files['sources.json']).items()}
 for name in('entry','authority','authorization','login','iam'):
  require(sha(sources['tools.ingestion_read_authorization.'+name])==manifest['files'][name+'.py'],'EXACT_ADMINISTRATIVE_MODULE_REQUIRED')
 loader={'__name__':'verified_existing_capsule_loader'}
 exec(compile(files['runtime.py'],'<verified-existing-native-loader>','exec'),loader)
 entry,declaration=loader['load_entry'](SOURCE,sources,files['runtime.py'],package['declarationHash'],package['sourcePins'],package['executionPins'])
 require(declaration==package['closure']['declaration'],'EXACT_EXISTING_DECLARATION_REQUIRED')
 original=read(case['originalBinding']['path'],expected=case['originalBinding']['sha256'])
 codes=set()
 for name in('tools.ingestion_read_authorization.entry','tools.ingestion_read_authorization.authorization','tools.chatbot_file_cohort.human_session'):
  codes.update(public_codes(sources[name]))
 return entry,sources,case,original,package,receipt,codes

def existing_human(entry,case,selection,closure):
 reference=read(CONTEXT/'login-window-receipt.json',65536);review=read(CONTEXT/'login-review.json',65536)
 require(reference['reviewHash']==digest(review)and reference['budgetReset']is False
  and reference['maximumCumulativeOAuthAttempts']==256 and review['maximumCumulativeOAuthAttempts']==256
  and review['budgetReset']is False and review['runtimeAuthorityIssued']is False
  and reference['priorOAuthAttempts']==review['priorOAuthAttempts'],'EXACT_EXISTING_LOGIN_RECEIPT_REQUIRED')
 previous=case['humanBinding']
 require(review.get('selectionHash')==digest(selection)and review.get('predecessorDirectory')==previous['sessionDirectory']
  and review.get('predecessorBindingHash')==digest(previous)
  and review.get('operationBinding')=={'preparedReviewHash':case['preparedPlanBinding']['sha256'],'sourceClosureHash':digest(closure)},
  'EXACT_EXISTING_LOGIN_OPERATION_BINDING_REQUIRED')
 entry.authorization.validate_session_binding(previous,selection,profile=entry.authorization.INGESTION_READ_PROFILE)
 previous_dir=Path(previous['sessionDirectory']);following=Path(reference['directory'])
 require(following.parent==previous_dir.parent and following.name=='human-ingestion-read-successor-'+digest(review),
  'EXACT_EXISTING_HUMAN_SUCCESSOR_REQUIRED')
 claim=read(previous_dir/'successor-window.claim.json',65536)
 require(claim['reviewHash']==digest(review)and claim['destination']==str(following)
  and claim['budgetReset']is False and claim['automaticReplayAllowed']is False,'EXACT_EXISTING_HUMAN_CLAIM_REQUIRED')
 human=entry.HumanSession(selection,following,following/'human-access.jwt',reference['expiresAt'])
 row=human._read();human._check_identity_and_budget(row)
 renewal=row.get('governedWindowRenewal',{});decision=renewal.get('decision',{});binding=row['binding']
 require(renewal.get('review')==review and decision.get('reviewHash')==digest(review)and digest(decision)==claim['decisionHash']
  and decision.get('decision')=='OPEN_ONE_LOGIN_WINDOW_NO_RUNTIME_AUTHORITY'
  and binding['expiresAt']==reference['expiresAt']==decision['expiresAt']
  and binding['createdAt']==decision['approvedAt'] and row['attempts']>=reference['priorOAuthAttempts']
  and not os.path.lexists(following/'successor-window.claim.json'),'CURRENT_EXISTING_HUMAN_RENEWAL_REQUIRED')
 entry.authorization.validate_session_binding(binding,selection,profile=entry.authorization.INGESTION_READ_PROFILE)
 human._check(row)  # Includes the original wall/monotonic window; never extend it.
 require(row['state']!='BLOCKED','EXISTING_HUMAN_BLOCKED_NO_AUTOMATIC_LOGIN')
 return human,row

def constrain_transport(transport,admin,report):
 request,kc,tool=transport.request,transport.kc,transport.tool
 report['ownerGetCalls']=report['iamMetadataCalls']=report['mcpRolesReads']=report['mcpRoleDispatches']=0
 def only_request(path,method='GET',body=None,**kwargs):
  if path=='/mcp':
   require(method=='POST'and type(body)is dict and body.get('method')=='tools/call'
    and body.get('params',{}).get('name')=='authorization.permissions.read'
    and body['params'].get('arguments')=={'view':'ROLES'},'ONLY_EXACT_MCP_ROLE_READ_ALLOWED')
   report['mcpRoleDispatches']+=1;require(report['mcpRoleDispatches']<=1,'ONE_MCP_ROLE_DISPATCH_ONLY')
   report['phase']='MCP_ROLES_READ'
  else:
   require(method=='GET'and body is None and (path==admin+'/policies/active'
    or re.fullmatch(re.escape(admin)+r'/capabilities\?limit=200&offset=[0-9]{1,5}',path)),
    'ADMINISTRATIVE_WRITE_OR_NONPREFLIGHT_READ_DENIED')
   report['ownerGetCalls']+=1;require(report['ownerGetCalls']<=8,'FINITE_OWNER_READ_BUDGET_EXHAUSTED')
   report['phase']='OWNER_POLICY_OR_REGISTRATION_READ'
  return request(path,method,body,**kwargs)
 def only_kc(verb,path,*args,**kwargs):
  require(verb=='get'and kwargs.get('body')is None and (path in('client-scopes','clients')or re.fullmatch(r'clients/[A-Za-z0-9_-]{1,128}/(?:default|optional)-client-scopes',path)),
   'IAM_WRITE_OR_NONPREFLIGHT_READ_DENIED')
  if path=='client-scopes':require(not args,'EXACT_IAM_METADATA_ARGUMENTS_REQUIRED')
  elif path=='clients':require(len(args)==4 and args[0]=='-q'and args[1]in {'clientId='+v['clientId']for v in transport.selection['clients'].values()}and args[2:] ==('--fields','id,clientId,enabled,protocol'),'EXACT_IAM_METADATA_ARGUMENTS_REQUIRED')
  else:require(args==('--fields','id,name'),'EXACT_IAM_METADATA_ARGUMENTS_REQUIRED')
  report['iamMetadataCalls']+=1;require(report['iamMetadataCalls']<=8,'FINITE_IAM_READ_BUDGET_EXHAUSTED')
  report['phase']='IAM_SCOPE_METADATA_READ';return kc(verb,path,*args,**kwargs)
 def only_tool(name,arguments,key):
  require(name=='authorization.permissions.read'and arguments=={'view':'ROLES'},'ONLY_EXACT_MCP_ROLE_READ_ALLOWED')
  report['mcpRolesReads']+=1;require(report['mcpRolesReads']<=1,'ONE_MCP_ROLE_READ_ONLY')
  report['phase']='MCP_ROLES_READ';return tool(name,arguments,key)
 transport.request,transport.kc,transport.tool=only_request,only_kc,only_tool
 return transport

def summarize_observed(observed,cap='ingestion.operations.read'):
 scope=observed['oauth']['scopes'].get(cap);policy=observed['active']['policy']
 return {'policyRef':observed['active']['policyRef'],'capabilityRegistered':cap in observed['registrations'],
  'activeDescriptorPresent':any(c.get('capabilityId')==cap for c in policy['capabilities']),
  'nominalRoleCount':len(observed['roles']['roles']),'existingGrantCount':len(policy['grants']),
  'ingestionScopeExists':scope is not None,'ingestionScopeMapperCount':len((scope or {}).get('protocolMappers')or[]),
  'ingestionScopeDefaultForChatGPT':any(s['name']==cap for s in observed['oauth']['clients']['chatgpt']['default'])}

def bounded_preflight(entry,sources,case,selection,human,owner,report,save):
 report['phase']='NATIVE_REFRESH_WITHIN_EXISTING_APPROVED_WINDOW';before=human._read();human._check(before)
 require(before['state']!='BLOCKED','EXISTING_HUMAN_BLOCKED_NO_AUTOMATIC_LOGIN')
 report['oauthAttemptsBefore']=before['attempts'];report['nativeRefreshInvocations']=1
 human.refresh_if_due()  # Existing fenced issuer implementation; never login()/authenticate().
 binding=human.current();after=human._read();human._check(after)
 require(binding==before['binding']and before['attempts']<=after['attempts']<=256,'EXISTING_CUMULATIVE_HUMAN_ACCOUNTING_REQUIRED')
 report.update(oauthAttemptsAfter=after['attempts'],maximumCumulativeOAuthAttempts=256,budgetReset=False)
 report['phase']='OWNER_TRANSPORT_CONSTRUCTION'
 transport=entry.authorization.OwnerTransport(selection,human.token_path,human.token_path,human_session=human)
 constrain_transport(transport,entry.authorization.ADMIN,report)
 observed=transport.observe();save('observed-owner-baseline.json',observed)
 report['observedSummary']=summarize_observed(observed);report['phase']='COMPILE_INGESTION_READ_PLAN'
 plan=entry.authorization.compile_plan(observed,owner,selection,include_ingestion_status=False,
  source_id=case['sourceId'],session_binding=human.current())
 report['phase']='VALIDATE_EXACT_ADMINISTRATIVE_PLAN';entry.validate_plan(plan,case['sourceId'])
 save('candidate-authorization-plan.json',plan)
 report.update(phase='PREFLIGHT_COMPILED_NO_AUTHORITY',preflightPassed=True,planHash=digest(plan),
  registrationAdditions=len(plan['registrationAdditions']),descriptorAdditions=len(plan['addedDescriptors']),
  scopeCreations=len(plan['scopeCreations']),scopeBindings=len(plan['scopeBindings']),
  rolesUnchanged=plan['targetRoles']==plan['baseline']['roles'],grantPublicationAllowed=False)


def safe_failure(error,codes):
 reason=str(error);codes=set(codes)|{'AUTHORIZATION_HTTP_'+str(n)for n in(400,401,403,404,408,409,412,429,500,502,503,504)}
 return {'exceptionClass':type(error).__name__ if type(error).__name__ in {
  'ValueError','PreflightDenied','AuthorizationPaused','HumanSessionPaused','FileNotFoundError','PermissionError','RuntimeDenied','KeyError','TypeError'}else'OTHER_ERROR',
  'reasonCode':reason if reason in codes else'PRIVATE_DETAILS_REDACTED','rawErrorPrinted':False}

REPORT={'schema':'ouf.ingestion-administrative-existing-session-preflight.v1','phase':'START',
 'newHumanLoginAllowed':False,'budgetReset':False,'automaticReplayAllowed':False,'nativeRefreshInvocations':0,
 'ownerMutationsAllowed':False,'iamMutationsAllowed':False,'runtimeAuthorityIssued':False,
 'sourceActivated':False,'infrastructureEffects':0,'preflightPassed':False,
 'completedTechnicalPhases':8,'functionalMilestonesProven':4,'credentialValuesPrinted':False}
def main():
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 source_hash=globals().get('__qualified_source_sha256__','')
 source_bytes=globals().get('__qualified_source_bytes__')
 require(re.fullmatch('[0-9a-f]{64}',source_hash)and type(source_bytes)is bytes and sha(source_bytes)==source_hash,'EXACT_QUALIFIED_DIAGNOSTIC_SOURCE_REQUIRED')
 os.umask(0o077)
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(PreflightDenied('FINITE_PREFLIGHT_DEADLINE_EXHAUSTED')))
 signal.alarm(180);report=json.loads(encoded(REPORT));codes=public_codes(source_bytes)
 directory=None;human=None
 try:
  report['phase']='EXACT_STOPPED_CAPSULE_RECONCILIATION'
  entry,sources,case,original,package,receipt,native_codes=load_capsule();codes.update(native_codes)
  report['phase']='QUALIFIED_OWNER_PRIMITIVES';owner=entry.primitives(sources)
  selection=original['authorization']['plan']['selection']
  report['phase']='EXISTING_LOGIN_RECEIPT_AND_HUMAN_WINDOW';human,row=existing_human(entry,case,selection,package['closure'])
  report['oauthAttemptsBefore']=row['attempts'];report['originalHumanWindowExpiresAt']=human.expires_at
  claim_name='ingestion-read-preflight-'+digest({'context':str(CONTEXT),'packageHash':receipt['packageHash']})+'.claim.json'
  directory=Path(tempfile.mkdtemp(prefix='ingestion-read-preflight-',dir=ROOT))
  write_new(ROOT,claim_name,encoded({'schema':'ouf.ingestion-read-existing-session-preflight-claim.v1',
   'sourceHash':source_hash,'originalContext':str(CONTEXT),'packageHash':receipt['packageHash'],
   'context':str(directory),'humanBindingHash':digest(row['binding']),'priorOAuthAttempts':row['attempts'],
   'maximumCumulativeOAuthAttempts':256,'maximumSeconds':180,'maximumNativeRefreshInvocations':1,
   'maximumOwnerGETs':8,'maximumMcpRoleReads':1,'maximumIamGETs':8,'automaticReplayAllowed':False,'budgetReset':False}))
  report['diagnosticContextPath']=str(directory)
  bounded_preflight(entry,sources,case,selection,human,owner,report,
   lambda name,value:write_new(directory,name,encoded(value)))
 except (Exception,KeyboardInterrupt)as error:
  report['failure']=safe_failure(error,codes)
  if human is not None:
   try:
    final_row=human._read();human._check_identity_and_budget(final_row)
    report['oauthAttemptsAfter']=final_row['attempts']
    report['humanSessionState']=final_row['state']if final_row['state']in('READY','REQUESTING','VERIFYING','RETRY_WAIT','BLOCKED','NEW')else'UNCLASSIFIED'
   except Exception:report['nativeCounterObservationUnavailable']=True
 finally:
  signal.alarm(0)
  if directory is not None:write_new(directory,'diagnostic-result.json',encoded(report))
 return report

if __name__=='__main__':
 try:output=main()
 except (Exception,KeyboardInterrupt)as error:
  output={**REPORT,'failure':safe_failure(error,{'ISOLATED_ROOT_REQUIRED','EXACT_QUALIFIED_DIAGNOSTIC_SOURCE_REQUIRED'}),'preflightPassed':False}
 print(encoded(output).decode());raise SystemExit(0 if output.get('preflightPassed')else 2)
