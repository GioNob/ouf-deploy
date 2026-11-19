"""Prepare one finite existing-window compatibility capsule. No issuer or native effects."""
import base64,hashlib,json,os,re,signal,stat,sys,tempfile,time
from pathlib import Path
CONTEXT=Path('/etc/ouf/deploy-snapshots/mcp-ingestion-read-transport-execution-wiqedn9w')
PACKAGE='4c63051ba4f22d3f83c33b96a5cc150824a6aadf79b9a6948ff09972b8c601be'
CLOSURE='2eb74254682d3fec8e49f2c5c08acaa83ff87b1f5d736b38124b7380e2a99a76'
SOURCE='c9d3ca870c95518c94f754640cd68dc8462c609e'
ARTIFACTS=('candidate-review.json','execution-plan.json','review.json','decision.json','human.json','authority.json','issuance.claim.json','recovery.json','update-result.json')
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
def write_new(directory,name,raw):
 require(Path(name).name==name,'SAFE_PRIVATE_MEMBER_REQUIRED')
 fd=os.open(directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(os.dup(fd),'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
 finally:os.close(fd)
 fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def main(delivery,commit):
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
 require(set(delivery)=={'prepare','entry','authority','continuation','runtime','bootstrap','transformer'}
  and re.fullmatch('[0-9a-f]{40}',commit),'EXACT_EXISTING_WINDOW_COMPATIBILITY_DELIVERY_REQUIRED')
 os.umask(0o077)
 signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('FINITE_COMPATIBILITY_PREPARATION_DEADLINE')));signal.alarm(120)
 print('OUF_MCP_COMPATIBILITY_PREPARATION_PHASE=RECONCILE_WIQEDN9W',flush=True)
 package=parsed(CONTEXT/'package.json',PACKAGE)
 require(package['sourceCommit']==SOURCE and digest(package['closure'])==CLOSURE
  and package['closure']['declaration']['moduleCount']==188,'EXACT_STOPPED188_PACKAGE_REQUIRED')
 require(parsed(CONTEXT/'runtime.claim.json')=={'packageHash':PACKAGE,'automaticReplayAllowed':False},'EXACT_CONSUMED188_RUNTIME_CLAIM_REQUIRED')
 require(not any(os.path.lexists(CONTEXT/n)for n in(*ARTIFACTS,'login-window-receipt.json')),
  'STOPPED188_AUTHORITY_OR_EFFECT_ALREADY_ADVANCED')
 old_case=parsed(CONTEXT/'case.json',package['fileHashes']['case.json']);case=dict(old_case)
 review=parsed(CONTEXT/'login-review.json');old_directory=Path(old_case['humanBinding']['sessionDirectory'])
 claim=parsed(old_directory/'successor-window.claim.json');directory=Path(claim['destination'])
 require(directory==old_directory.parent/('human-mcp-read-transport-successor-'+digest(review))
  and claim['reviewHash']==digest(review)and claim['budgetReset']is False,'EXACT_CONSENTED_SUCCESSOR_REQUIRED')
 row=parsed(directory/'recovery.json',maximum=65536);binding=row['binding'];renewal=row['governedWindowRenewal']
 require(row['state']=='NEW'and row['attempts']==217 and row['budgetReset']is False and not row.get('operation')
  and not any(row.get(k)for k in('accessToken','publishedAccessToken','refreshToken','deviceCode'))
  and binding['sessionDirectory']==str(directory)and binding['tokenPath']==str(directory/'human-access.jwt')
  and binding['createdAt']==1792408503 and binding['expiresAt']==1792415703
  and renewal['review']==review and digest(renewal['decision'])==claim['decisionHash']
  and renewal['decision']['reviewHash']==digest(review)and renewal['decision']['approvedAt']==1792408503
  and renewal['decision']['expiresAt']==1792415703,'EXACT_UNSTARTED217_AND_UNMODIFIED_LOGIN_CONSENT_REQUIRED')
 require(time.time()+1200<binding['expiresAt']and time.monotonic()+1200<row['monotonicDeadline'],
  'EXISTING_WINDOW_TOO_SHORT_NO_NEW_WINDOW_ALLOWED')
 require(not any(os.path.lexists(directory/n)for n in('human-access.jwt','successor-window.claim.json','mcp-read-transport-login-resume.claim.json')),
  'EXISTING_LOGIN_ALREADY_STARTED_OR_CLAIMED_RECONCILE')
 source_rows=parsed(CONTEXT/'sources.json',package['fileHashes']['sources.json'])
 sources={n:base64.b64decode(v,validate=True)for n,v in source_rows.items()}
 require(len(sources)==188 and set(sources)==set(package['closure']['declaration']['sourceHashes'])
  and all(sha(raw)==package['closure']['declaration']['sourceHashes'][n]for n,raw in sources.items()),'EXACT_STOPPED188_SOURCE_BYTES_REQUIRED')
 print('OUF_MCP_COMPATIBILITY_PREPARATION_PHASE=ADD_ONE_GUARD_SCHEMA_BRANCH',flush=True)
 transform_ns={'__name__':'qualified_frozen_human_schema_transformer'}
 exec(compile(delivery['transformer'],'<qualified-frozen-human-schema-transformer>','exec'),transform_ns)
 name='tools.chatbot_file_cohort.human_session';original=sources[name]
 require(sha(original)=='2e96cfc5278f25d0cbf62f445636df2e7e576d3971e1db785ed818c0ac14e285','EXACT_FROZEN_HUMAN_SOURCE_REQUIRED')
 sources[name]=transform_ns['transform'](original)
 for module in('entry','authority','continuation'):sources['tools.mcp_read_transport_compatibility.'+module]=delivery[module]
 memory={'__name__':'qualified_existing_window_compatibility_loader'}
 exec(compile(delivery['runtime'],'<qualified-existing-window-compatibility-loader>','exec'),memory);memory['compile_sources'](sources)
 require(len(sources)==191,'EXACT191_SOURCE_CLOSURE_REQUIRED')
 logical=digest({'oldContainerId':'c6fc3a462f4e1faf1e8121fee13ca445f7a3f7f1f39df65d738ea9cc1d4185f4',
  'candidateSourceCommit':'1f2c28d7abadae78680b040ba7b58be62ef85ee9',
  'candidateImageId':'sha256:a0a6f9562ba0b28ba3fef2b3a78bf46e90d9e14c99448d413bacf5d5cb75f182',
  'profile':'ouf.mcp-ingestion-read-transport-update.v1'})
 require(not os.path.lexists(CONTEXT.parent/('mcp-ingestion-read-transport-'+logical+'.claim.json')),
  'MCP_LOGICAL_UPDATE_ALREADY_CLAIMED_RECONCILE')
 destination=Path(tempfile.mkdtemp(prefix='mcp-ingestion-read-transport-execution-',dir=CONTEXT.parent))
 claim_name='mcp-read-transport-compatibility-preparation-'+digest({'originPackageHash':PACKAGE,
  'humanSourceSha256':sha(original),'windowExpiresAt':1792415703})+'.claim.json'
 preparation_claim={'context':str(destination),'candidateSourceCommit':'1f2c28d7abadae78680b040ba7b58be62ef85ee9',
  'priorOAuthAttempts':217,'maximumCumulativeOAuthAttempts':256,'budgetReset':False,'automaticReplayAllowed':False,
  'existingWindowExpiresAt':1792415703,'newLoginWindowAllowed':False,'technicalConsentRequired':True}
 write_new(CONTEXT.parent,claim_name,encoded(preparation_claim))
 case['preparationClaimBinding']={'path':str(CONTEXT.parent/claim_name),'sha256':digest(preparation_claim)}
 case['humanBinding']=binding;case['priorOAuthAttempts']=217
 case['existingWindowCompatibility']={'schema':'ouf.mcp-read-transport-existing-window-compatibility.v1',
  'originContext':str(CONTEXT),'originPackageHash':PACKAGE,'originClosureHash':CLOSURE,
  'originalHumanSourceSha256':sha(original),'patchedHumanSourceSha256':sha(sources[name]),
  'originalLoginReviewHash':digest(review),'windowExpiresAt':1792415703,'priorOAuthAttempts':217,
  'maximumCumulativeOAuthAttempts':256,'newLoginWindowAllowed':False,'approvedLoginConsentChanged':False,
  'budgetReset':False,'transformerSha256':sha(delivery['transformer'])}
 reader_raw=read(CONTEXT/'reader.py',package['fileHashes']['reader.py'])
 members={'case.json':encoded(case),'bootstrap.py':delivery['bootstrap'],'runtime.py':delivery['runtime'],
  'reader.py':reader_raw,'sources.json':encoded({n:base64.b64encode(v).decode()for n,v in sorted(sources.items())})}
 pins={**package['sourcePins'],'ouf-deploy':commit}
 execution={'executorSha256':sha(delivery['bootstrap']),'caseSha256':digest(case),'mode':'MCP_READ_TRANSPORT_UPDATE'}
 declaration=memory['declaration'](commit,sources,delivery['runtime'],pins,execution)
 closure={**package['closure'],'declaration':declaration}
 fresh={'schema':'ouf.mcp-ingestion-read-transport-package.v1','sourceCommit':commit,'sourcePins':pins,
  'executionPins':execution,'closure':closure,'declarationHash':digest(declaration),
  'fileHashes':{n:sha(raw)for n,raw in members.items()},'runtimeAuthorityIssued':False}
 for member,raw in members.items():write_new(destination,member,raw)
 write_new(destination,'package.json',encoded(fresh))
 report={'schema':'ouf.mcp-existing-window-compatibility-preparation.v1','contextPath':str(destination),
  'originContext':str(CONTEXT),'sourceCommit':commit,'packageHash':digest(fresh),'sourceClosureHash':digest(closure),
  'sourceModuleCount':191,'priorOAuthAttempts':217,'maximumCumulativeOAuthAttempts':256,'remainingAttempts':39,
  'existingWindowExpiresAt':1792415703,'newLoginWindowOpened':False,'originalLoginConsentChanged':False,
  'originalHumanSourceSha256':sha(original),'compatibleHumanSourceSha256':sha(sources[name]),
  'technicalConsentRequired':True,'runtimeAuthorityIssued':False,'imageRebuilt':False,'imageImported':False,
  'automaticReplayAllowed':False,'budgetReset':False,'completedInstallationReadbackReplayed':False,
  'completedTechnicalPhases':8,'functionalMilestonesProven':4}
 write_new(destination,'preparation-result.json',encoded(report))
 print('OUF_MCP_COMPATIBILITY_PREPARED='+encoded(report).decode(),flush=True)
 signal.alarm(0)
 os.execv(sys.executable,[sys.executable,'-I','-B','-S',str(destination/'bootstrap.py'),str(destination),digest(fresh)])
