"""Exact installation-specific read-only reconciliation of two-scope custody STOP.
No runtime/authority/HUMAN source is executed; only existing path-custody readers
are AST-selected from the authenticated sealed Gateway module.
"""
import ast,base64,hashlib,json,os,re,signal,stat,sys
from pathlib import Path
FIRST=Path('/etc/ouf/deploy-snapshots/installation-binding-apply-execution-46iexg9c')
SECOND=FIRST.parent/'installation-binding-apply-execution-7x21g1fg'
SOURCE='9600d850e5d4b4b42004e68028a5aa6e49c20d35'
PACKAGE='de440e91d204e30bd99daea42e4a19c9affee97e3044cf6ae2fa8bf613592efc'
CLOSURE='2fb31db4ffd6188bcdd0bb7b8cc71aaf284b0f5581413ca3a05081624442e56d'
OWNER_REVIEW='48ec259cd76cbd14e3c669f614c903d01a1cce431a83ab7e799f01b1be2800a3'
ROUTE_REVIEW='10ee2d0e2a16f0a4f95c2c46ef32ef0e4c8ac30bda7e48dd1de6a6610774fb58'
EXPORT='10b378c05f6ce38d46b8ba9d66a0fa1f9d5ceb0383975ca6c43ba604e9bf599d'
PAYLOAD='ded675196fa5b7f9c398b249f737ff19df26d66e81afa65ddcf9a5ecfb034a98'
ACTIVE_PATH='/opt/ouf/installation/active-projection.json'
APPROVED_CUSTODY={'parents':{'/opt/ouf':(1000,1000,0o750),'/opt/ouf/installation':(0,0,0o700)},'file':(0,0,0o600)}
STAGES={'INSTALLATION_BINDING_APPLY':['VERIFY_INPUTS','CREATE_REVISION','VALIDATE_ENVIRONMENT','ACTIVATE_EXPECTED','EXPORT_ACTIVE','VERIFY_FINAL'],
 'INSTALLATION_PROJECTION_ROUTE_APPLY':['VERIFY_INPUTS','PUBLISH_ACTIVE_PROJECTION','GATEWAY_STATUS_ROUTE','GATEWAY_HISTORY_ROUTE','VERIFY_FINAL']}
ARTIFACTS=('authority.json','issuance.claim.json','execution-plan.json','review.json','decision.json','recovery.json','update-result.json','source-projection.json')
def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def digest(v):return sha(encoded(v))
def read(path,expected=None,maximum=8388608):
 path=Path(path);require(path.is_absolute()and path.resolve()==path,'EXACT_PRIVATE_PATH_REQUIRED')
 for parent in path.parents:
  s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'PRIVATE_ROOT_ANCESTRY_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and 0<s.st_size<=maximum,'PRIVATE_CUSTODY_REQUIRED')
  with os.fdopen(os.dup(fd),'rb')as f:raw=f.read(maximum+1)
  pin=lambda v:tuple(getattr(v,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  require(len(raw)==s.st_size and pin(s)==pin(os.fstat(fd))==pin(path.lstat())and(expected is None or sha(raw)==expected),'PRIVATE_BYTES_CHANGED');return raw
 finally:os.close(fd)
def parsed(path,expected=None,maximum=8388608):return json.loads(read(path,expected,maximum))
def custody_reader(raw):
 tree=ast.parse(raw);wanted={'selected_directory_custody','selected_file_custody','private_config'}
 nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in wanted or isinstance(n,ast.Assign)and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)and n.targets[0].id in('_EXISTING_CONFIG_CUSTODY','EXTERNAL_ADMIN_KEY')]
 require(len(nodes)==5,'EXACT_FIVE_SEALED_CUSTODY_NODES_REQUIRED')
 namespace={'__builtins__':__builtins__,'os':os,'stat':stat,'hashlib':hashlib,'Path':Path,'require':require}
 exec(compile(ast.Module(body=nodes,type_ignores=[]),'<sealed-custody-readers-only>','exec'),namespace)
 return namespace

def journal_view(context,kind,review_hash):
 plan=parsed(context/'execution-plan.json');review=parsed(context/'review.json',review_hash);decision=parsed(context/'decision.json')
 key='installationBindingApply'if kind=='INSTALLATION_BINDING_APPLY'else'installationProjectionRouteApply'
 require(plan['kind']==kind and plan['schema']=='ouf.installation-binding-native-plan.v1'and plan['authorityDirectory']==str(context)
  and decision['reviewHash']==review_hash and review['scopes'][key]['planHash']==digest(plan),'EXACT_REVIEWED_PLAN_REQUIRED')
 scope=review['scopes'][key];row=parsed(context/'recovery.json');effects=row['effects'];n=row['nextStage'];stages=STAGES[kind]
 require(row['schema']=='ouf.installation-binding-native-journal.v1'and row['scopeHash']==digest(scope)and row['budgetReset']is False
  and type(n)is int and 0<=n<=len(stages)and len(effects)in(n,n+1)
  and [e['stage']for e in effects]==stages[:len(effects)]and all(e['state']=='APPLIED'for e in effects[:n])
  and(len(effects)==n or effects[-1]['state']=='CLAIMED')
  and all(e['intentHash']==digest({'planHash':digest(plan),'stage':e['stage']})for e in effects),'EXACT_DURABLE_EFFECT_HISTORY_REQUIRED')
 claim_path=context.parent/('installation-binding-native-'+scope['logicalRef']+'.claim.json');claim=parsed(claim_path)
 require(claim=={'context':str(context),'scopeHash':digest(scope),'authorityHash':row['authorityHash'],'automaticReplayAllowed':False,'budgetReset':False},'EXACT_LOGICAL_FENCE_REQUIRED')
 summary={'nextStage':n,'version':row['version'],'incidentState':row['incidentState'],'expiresAt':row['expiresAt'],
  'effects':[{'stage':e['stage'],'state':e['state']}for e in effects],
  'logicalActionClaimPresent':True,'gatewayStageClaims':sum(e['stage']in('GATEWAY_STATUS_ROUTE','GATEWAY_HISTORY_ROUTE')for e in effects)}
 return plan,review,row,summary

def main():
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('READ_DEADLINE')));signal.alarm(120)
 package=parsed(FIRST/'package.json',PACKAGE);closure=package['closure'];decl=closure['declaration']
 require(package['sourceCommit']==SOURCE and digest(closure)==CLOSURE and decl['moduleCount']==219
  and decl['entryModule']=='tools.installation_binding_apply.entry'and package['declarationHash']==digest(decl),'EXACT_SEALED219_PACKAGE_REQUIRED')
 require(parsed(FIRST/'runtime.claim.json')=={'packageHash':PACKAGE,'automaticReplayAllowed':False},'EXACT_CONSUMED_RUNTIME_CLAIM_REQUIRED')
 raw_sources=parsed(FIRST/'sources.json',package['fileHashes']['sources.json']);sources={k:base64.b64decode(v,validate=True)for k,v in raw_sources.items()}
 require(len(sources)==219 and set(sources)==set(decl['sourceHashes'])and all(sha(v)==decl['sourceHashes'][k]for k,v in sources.items()),'EXACT219_SOURCE_BYTES_REQUIRED')
 first,review1,journal1,summary1=journal_view(FIRST,'INSTALLATION_BINDING_APPLY',OWNER_REVIEW)
 second,review2,journal2,summary2=journal_view(SECOND,'INSTALLATION_PROJECTION_ROUTE_APPLY',ROUTE_REVIEW)
 require(review1['sourceClosureHash']==review2['sourceClosureHash']==CLOSURE,'EXACT_BOTH_REVIEW_SOURCE_BINDINGS_REQUIRED')
 require(journal1['incidentState']=='RECOVERED'and journal1['nextStage']==6 and all(e['state']=='APPLIED'for e in journal1['effects']),'COMPLETED_OWNER_SCOPE_REQUIRED')
 result=parsed(FIRST/'owner-result.json');active={'installationId':'ouf-lab-netcup-01','revision':6,'checksum':PAYLOAD,'generation':6,'etag':'"6:'+PAYLOAD+':6"'}
 require(result['schema']=='ouf.installation-binding-owner-result.v1'and result['complete']is True and result['active']==active
  and result['ownerPosts']==3 and result['projectionExports']==1 and result['oauthAttemptsAfter']==255
  and result['gatewayWrites']==result['activeProjectionWrites']==0 and result['sourceActivated']is False,'EXACT_COMPLETED_OWNER_RECEIPT_REQUIRED')
 require(second['ownerActivationBinding']=={'path':str(FIRST/'owner-result.json'),'sha256':digest(result)}
  and second['projectionHash']==EXPORT and second['exportedProjectionBinding']==result['projectionBinding']
  and second['projectionBinding']==first['projectionBinding']and second['humanBinding']==first['humanBinding']
  and second['humanBinding']['expiresAt']==1792436155,'EXACT_SECOND_SCOPE_PREDECESSOR_BINDINGS_REQUIRED')
 exported=read(FIRST/'owner-active-projection.json',EXPORT);require(result['projectionBinding']=={'path':str(FIRST/'owner-active-projection.json'),'sha256':EXPORT},'EXACT_OWNER_EXPORT_REQUIRED')
 old=read(SECOND/'source-projection.json');require(sha(old)==second['projectionBinding']['sha256'],'EXACT_RETAINED_OLD_PROJECTION_REQUIRED')
 require(second['projectionBinding']['path']==ACTIVE_PATH,'EXACT_APPROVED_ACTIVE_PROFILE_REQUIRED')
 namespace=custody_reader(sources['tools.chatbot_file_cohort.gateway']);current,binding=namespace['private_config'](ACTIVE_PATH)
 expected=namespace['_EXISTING_CONFIG_CUSTODY'].get(ACTIVE_PATH)
 require(expected==APPROVED_CUSTODY,'ORIGINAL_APPROVED_CUSTODY_REQUIRED')
 ancestry=[]
 for parent in Path(ACTIVE_PATH).parents:
  s=parent.lstat();ancestry.append({'approvedCustodyPasses':namespace['selected_directory_custody'](s,str(parent),expected),
   'legacyRootOnlyPasses':stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'mode':oct(stat.S_IMODE(s.st_mode)),'rootOwned':s.st_uid==0})
 legacy_pass=all(v['legacyRootOnlyPasses']for v in ancestry)
 position='APPROVED_NEW_EXPORT'if current==exported else'RETAINED_OLD_PROJECTION'if current==old else'OTHER_CUSTODIED_BYTES'
 publication=[e for e in journal2['effects']if e['stage']=='PUBLISH_ACTIVE_PROJECTION']
 signal.alarm(0)
 return {'schema':'ouf.installation-binding-custody-stop-read.v1','complete':True,'readOnly':True,
  'contextPath':str(SECOND),'ownerContextPath':str(FIRST),'packageHash':PACKAGE,'sourceClosureHash':CLOSURE,'sourceModuleCount':219,
  'ownerScope':summary1,'projectionRouteScope':summary2,'ownerActivationProvenAsFiles':True,'activeOwnerRevisionRetained':6,'activeOwnerGenerationRetained':6,
  'ownerActiveRequeried':False,'liveGatewayRoutesRequeried':False,'authorityFilesOpened':False,'humanCredentialJournalsRead':0,
  'bearerFilesOpened':0,'privateKeyFilesOpened':0,'credentialValuesPrinted':False,'credentialHashesPrinted':False,
  'profile':{'state':position,'currentSha256':sha(current),'expectedNewSha256':EXPORT,'approvedCustodyPassed':True,
   'legacyRootOnlyAncestryPassed':legacy_pass,'ancestry':ancestry,'publicationStageState':publication[0]['state']if publication else'NO_STAGE_CLAIM'},
  'publicationBytesPresentButJournalUnreconciled':position=='APPROVED_NEW_EXPORT'and bool(publication)and publication[0]['state']=='CLAIMED',
  'noGatewayDispatchByThisActionProven':summary2['gatewayStageClaims']==0,'runtimeMainCalled':False,'authorityIssuedByDiagnostic':False,
  'lastReportedOAuthAttempts':255,'maximumCumulativeOAuthAttempts':256,'currentHumanStateRequeried':False,
  'oauthRequests':0,'ownerRequests':0,'engineCalls':0,'gatewayWrites':0,'databaseCalls':0,'journalWrites':0,
  'runtimeCompletionProven':False,'newHumanLoginAllowed':False,'automaticReplayAllowed':False,'budgetReset':False,
  'completedInstallationReadbackReplayed':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}

import time
HUMAN_REVIEW='c0f7490ebe641e8a015e09799f6812eb1caf870388f1776a140a34a189cb11c1'
def human_readiness(row,binding,now,mono,boot):
 require(row.get('schema')=='ouf.chatbot-human-session.private.v1'and row.get('binding')==binding
  and binding['expiresAt']==1792436155 and binding['retryProfile']['maximumAttempts']==256
  and row.get('budgetReset')is False and row.get('bootId')==boot
  and type(row.get('attempts'))is int and 255<=row['attempts']<=256
  and len(binding['scopes'])==11,'EXACT255_SUCCESSOR_HUMAN_HISTORY_REQUIRED')
 states={'NEW','DEVICE_START','DEVICE_POLL','REQUESTING','RETRY_WAIT','VERIFYING','READY','BLOCKED'}
 require(row.get('state')in states and type(row.get('lastObservedAt'))in(int,float)
  and now+2>=row['lastObservedAt']and type(row.get('monotonicDeadline'))in(int,float),'CURRENT_HUMAN_CLOCK_OR_STATE_DRIFT')
 renewal=row.get('governedWindowRenewal',{});review=renewal.get('review',{});decision=renewal.get('decision',{})
 require(review.get('schema')=='ouf.human-explicit-test-continuation-review.v3'
  and digest(review)==HUMAN_REVIEW
  and review.get('priorOAuthAttempts')==251 and review.get('maximumCumulativeOAuthAttempts')==256
  and review.get('budgetReset')is False and decision.get('reviewHash')==digest(review)
  and binding['createdAt']==decision.get('approvedAt')and binding['expiresAt']==decision.get('expiresAt')
  and decision['expiresAt']-decision['approvedAt']==7200,'EXACT_NATIVE251_REAUTHENTICATION_CONSENT_REQUIRED')
 expires=row.get('accessExpiresAt');safe_expiry=expires if type(expires)in(int,float)and expires==expires and abs(expires)<1e12 else None
 window=now<binding['expiresAt']and mono<row['monotonicDeadline'];remaining=256-row['attempts']
 eligible=row['state']=='READY'and window and safe_expiry is not None and safe_expiry>now+240
 return {'state':row['state'],'attempts':row['attempts'],'maximumCumulativeOAuthAttempts':256,'remainingOAuthAttempts':remaining,
  'windowExpiresAt':binding['expiresAt'],'windowStillOpen':window,'accessExpiresAt':safe_expiry,
  'recordedAccessHas240SecondsMargin':eligible,'currentBearerOrSignatureVerificationPerformed':False,
  'minimumOAuthRequestsForVerifiedRefresh':2,'remainingBudgetCoversVerifiedRefresh':remaining>=2,
  'refreshInvoked':False,'newLoginAllowed':False,'newBudgetAuthorized':False,'budgetReset':False}

def continuation_readiness():
 result=main();plan=parsed(SECOND/'execution-plan.json');binding=plan['humanBinding']
 directory=Path(binding['sessionDirectory']);require(directory.is_absolute()and directory.resolve()==directory
  and FIRST.parent in directory.parents and len(directory.relative_to(FIRST.parent).parts)<=8
  and directory.name=='human-installation-binding-reauth251-c0f7490ebe641e8a015e09799f6812eb1caf870388f1776a140a34a189cb11c1'
  and binding['tokenPath']==str(directory/'human-access.jwt'),'EXACT_EXPLICIT_SUCCESSOR_DIRECTORY_REQUIRED')
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('READ_DEADLINE')));signal.alarm(60)
 row=parsed(directory/'recovery.json',maximum=65536)
 boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 human=human_readiness(row,binding,time.time(),time.monotonic(),boot);signal.alarm(0)
 return {**result,'schema':'ouf.installation-binding-continuation-readiness.v1','human':human,
  'humanCredentialJournalsRead':1,'currentHumanStateRequeried':True,'currentBearerOrSignatureVerificationPerformed':False}
