"""Closed entry for explicit policy remainder and the separate single MCP update.

Only the sealed host bootstrap supplies retained private inputs and bindings.
No original eight-phase delivery, first grant, credential rotation, Gateway
write, semantic tool invocation, or automatic login restart is reachable here.
"""
import copy,dataclasses,hashlib,json,os,re,signal,stat,threading,time
from pathlib import Path
from urllib.parse import quote,urlsplit,urlunsplit
import iam_binding_candidate as evidence
import iam_governance_intake as governance
from iam_owner_action import publish
from cutover_authority import CutoverAuthority
from engine_creation import Engine
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.semantic_policy_token_owner.installed_owner import InstalledTokenOwner,compile_governed_session
from tools.semantic_policy_token_owner.reporter import OwnerReporter
from tools.semantic_policy_token_owner.worker_entry import serve
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.continued_owner import GovernedSemanticOwnerContinuation,TOKEN_STAGE_SOURCE
from tools.chatbot_file_cohort.human_session import HumanSession
from tools.chatbot_file_cohort.action_process import private_file
from tools.semantic_mcp_update import authority,session,permit,plan as compiler
from tools.semantic_mcp_update.owner import SingleMcpUpdate,UpdateDenied,UpdatePaused,require,digest,encoded,scope
from tools.semantic_mcp_update.native import NativePorts,env


def publish_json(context,name,value):
 with protected_directory(context)as directory:
  require(publish(directory,name,encoded(value)),'PRIVATE_EXECUTION_ARTIFACT_ALREADY_EXISTS')


def retained_registry(planned):
 before=planned.raw;planned.raw=encoded(planned.scopes())
 try:InstalledTokenOwner.guard_governed_registry(planned,planned.worker_scope)
 finally:planned.raw=before


def remainder_review(base,records,journal):
 review=copy.deepcopy(base);previous=records['owner-session.json'];row=records['recovery.json']
 require(row['controlledCumulativeGrantAttempts']==128 and previous['maximumCumulativeGrantAttempts']==197
  and row['attempts']==59 and row['publicationCount']==59,'EXACT_CONTROLLED128_REMAINDER_REQUIRED')
 review.update(schema='ouf.chatbot-semantic-functional-session-review.v2',preparedAt=int(time.time()),
  predecessorRecordHashes={k:digest(v)for k,v in records.items()},predecessorJournalDirectory=str(journal),
  predecessorFenceBinding=copy.deepcopy(previous['fenceBinding']))
 review['proposedFiniteBudget'].update(profile='ouf.semantic-functional-session-bounds.v2',priorControlledGrantAttempts=128,predecessorWorkerAttempts=59,
  maximumNewTokenGrantAttempts=69,maximumCumulativeGrantAttempts=197,
  reason='EXPLICIT_REMAINDER_WITHIN_EXISTING_CONTROLLED197_CEILING')
 review['runtimeAuthorityIssued']=False;review['humanApprovalGranted']=False;review['readyForExecution']=False
 return review


def token_main(prepared,sources,closure,resources,context,emit=print,*,transport=None):
 authority.closure_valid(closure)
 context=Path(context);records=resources['workerRecords'];first=resources['firstGrant']
 review=remainder_review(resources['baseWorkerReview'],records,resources['workerJournal'])
 review_binding={'path':str(context/'worker-review.json'),'sha256':digest(review)}
 publish_json(context,'worker-review.json',review)
 policy={'delays':[5,15,60,300,900],'max_attempts':69,'max_elapsed':3600,'attempt_timeout':30,'jitter':.2}
 worker_scope=compile_governed_session(review,records,first,policy,
  digest({'operation':review['logicalOperation'],'reviewHash':digest(review)}),digest(review['registryGeneration']),60)
 journal=Path(worker_scope['fenceBinding']['value']['journalPath'])
 with protected_directory(journal.parent)as directory:os.mkdir(journal.name,0o700,dir_fd=directory);os.fsync(directory)
 expected={'sourceClosureHash':digest(closure),'creationRequestHash':digest(review),
  'predecessorHistoryHash':digest(review['predecessorRecordHashes']),
  'predecessorIncidentRef':worker_scope['logicalOwnerScopeHash'],'intakeHash':digest(review)}
 verifier=DetachedAuthenticator(governance.POLICY,str(context),closure['executables']['openssl'])
 absent={'path':str(context/'UNISSUED-human.json'),'sha256':hashlib.sha256(b'UNISSUED_MCP_TOKEN_REMAINDER').hexdigest()}
 unissued=AggregateAction(CutoverAuthority(verifier,absent,absent['sha256'],governance.CONTEXT,expected),
  encoded({'schema':'ouf.unissued-policy-remainder-preparation.v1'}),digest(closure))
 files={name:sources[module]for name,module in TOKEN_STAGE_SOURCE.items()}
 args=(prepared['owner'],files,closure['declaration']['sourceCommit'],review,records,first,review_binding,prepared['engine'],journal)
 planned=GovernedSemanticOwnerContinuation(unissued,*args,transport=transport)
 require(planned.worker_scope==worker_scope,'EXACT_COMPILED_REMAINDER_SCOPE_REQUIRED');retained_registry(planned)
 selection=prepared['authorization']['plan']['selection'];previous_directory=Path(resources['previousHumanDirectory'])
 previous=HumanSession(selection,previous_directory,previous_directory/'human-access.jwt',resources['previousHumanExpiry'])
 login_review=session.expired_login_review(previous,{'workerReviewHash':digest(review),
  'mcpReviewHash':resources['mcpReviewBinding']['sha256'],'sourceClosureHash':digest(closure),
  'executionContextHash':digest(str(context))})
 require(login_review['priorOAuthAttempts']==49 and login_review['predecessorExpiredAt']==1792172784,
  'EXACT_OBSERVED_OAUTH49_HISTORY_REQUIRED')
 publish_json(context,'login-review.json',login_review)
 consent=authority.terminal_consent(login_review,
  'Fasi tecniche 8/8; funzionali 0/6. Riapertura della sola finestra HUMAN.\n'
  'OAuth:49 consumati, massimo79 ulteriori, cumulativo128; durata7200 secondi.\n'
  'Seguono il browser e una revisione autenticata separata per il solo worker policy.\n'
  'Questa scelta locale non autorizza grant, aggiornamento MCP o proposta semantica.',login=True)
 human=session.open_approved_login(previous,login_review,consent)
 publish_json(context,'login-window-receipt.json',{'reviewHash':digest(login_review),'decision':consent,
  'directory':str(human.directory),'expiresAt':human.expires_at,'budgetReset':False})
 emit('OUF_MCP_UPDATE_PHASE=HUMAN_LOGIN technical=8/8 functional=0/6')
 hb=human.login(emit=emit);retained_registry(planned)
 final=authority.compile_action_review('POLICY_TOKEN_REMAINDER',closure,planned.scopes(),hb,context,
  {'predecessorHistoryHash':digest(review['predecessorRecordHashes']),
   'predecessorIncidentRef':worker_scope['logicalOwnerScopeHash']},3600)
 final['privateMcpReviewBinding']=copy.deepcopy(resources['mcpReviewBinding'])
 final['workerReviewBinding']=review_binding
 publish_json(context,'review.json',final)
 decision=authority.terminal_consent(final,
  'Revisione autenticata del solo worker policy; fasi tecniche8/8, funzionali0/6.\n'
  'Journal precedente conservato:128 tentativi controllati. Massimo69 ulteriori, cumulativo197.\n'
  'Passaggio atomico del fence dopo verifica del worker cancellato; massimo3600 secondi.\n'
  'Riutilizzo della credenziale esistente, nessuna rotazione o modifica grant.\n'
  'Nessun stop container, migrazione DB o dispatch semantico.\n'
  'Dopo APPROVO lascia aperto questo terminale; Ctrl-C cancella la sessione.\n'
  'Revisione privata: '+str(context/'review.json'))
 action=authority.issue_action(final,decision,human)
 stop=threading.Event();remaining=decision['expiresAt']-time.time();require(0<remaining<=3600,'CURRENT_POLICY_REMAINDER_AUTHORITY_REQUIRED')
 previous_handlers={}
 for sig in(signal.SIGINT,signal.SIGTERM,signal.SIGHUP):previous_handlers[sig]=signal.signal(sig,lambda *_:stop.set())
 timer=threading.Timer(remaining,stop.set);timer.daemon=True;timer.start()
 def current_time():require(not stop.is_set(),'POLICY_REMAINDER_CANCELLED_OR_EXPIRED');return time.time()
 action.authority.clock=current_time
 try:
  installed=GovernedSemanticOwnerContinuation(action,*args,transport=transport);worker=installed.install()
  emit('OUF_POLICY_REMAINDER_STARTED='+encoded({'contextPath':str(context),'authorityHash':action.authority_hash,
   'workerJournal':str(journal),'humanDirectory':str(human.directory),'humanExpiry':human.expires_at,
   'mcpReviewBinding':resources['mcpReviewBinding'],'priorControlledGrantAttempts':128,
   'maximumNewTokenGrantAttempts':69,'maximumCumulativeGrantAttempts':197,'expiresAt':decision['expiresAt'],
   'humanOAuthAttempts':human._read()['attempts'],'budgetReset':False,'acceptanceGranted':False}).decode())
  serve(worker,stop,OwnerReporter(worker.r.journal,emit))
 finally:
  stop.set();timer.cancel()
  for sig,handler in previous_handlers.items():signal.signal(sig,handler)
 emit('OUF_POLICY_REMAINDER_ENDED=NO_AUTOMATIC_RESTART_OR_RESET')


def existing_token_action(context,closure,read):
 review=read(context/'review.json',8388608);raw=encoded(read(context/'authority.json',131072))
 require(review.get('schema')=='ouf.semantic-scoped-infrastructure-review.v1'and review.get('kind')=='POLICY_TOKEN_REMAINDER',
  'SAME_SCOPED_POLICY_SESSION_REQUIRED')
 authority.scopes_valid(review['kind'],review['scopes'],review['sourceClosureHash'])
 expected={k:review[k]for k in('sourceClosureHash','creationRequestHash','predecessorHistoryHash','predecessorIncidentRef')};expected['intakeHash']=digest(review)
 mandate=encoded(read(context/'human.json',131072));mh=hashlib.sha256(mandate).hexdigest()
 verifier=DetachedAuthenticator(governance.POLICY,str(context),closure['executables']['openssl'])
 gate=CutoverAuthority(verifier,{'path':str(context/'human.json'),'sha256':mh},mh,governance.CONTEXT,expected)
 action=AggregateAction(gate,raw,review['sourceClosureHash']);action.guard('policyTokenFiniteWorkerSession',review['scopes']['policyTokenFiniteWorkerSession'])
 return action,review


def live_policy_session(context,closure,read):
 action,review=existing_token_action(context,closure,read);worker=review['scopes']['policyTokenFiniteWorkerSession']
 journal=Path(worker['fenceBinding']['value']['journalPath']);row=read(journal/'recovery.json',65536)
 require(row.get('state')=='ACTIVE'and row.get('workerSessionHash')==digest(worker)
  and row.get('controlledPredecessorGrantAttempts')==128 and type(row.get('attempts'))is int
  and 1<=row['attempts']<=69 and row.get('controlledCumulativeGrantAttempts')==128+row['attempts']<=197
  and row.get('publicationCount',0)>=1 and row.get('tokenExpiresWall',0)>time.time()+5,'CURRENT_PUBLISHED_POLICY_SESSION_REQUIRED')
 fence=worker['fenceBinding'];require(read(fence['path'],16384)==fence['value'],'CURRENT_POLICY_FENCE_REQUIRED')
 return action,review


def secret_bytes(fd,restat,uid,gid,modes):
 before=os.fstat(fd)
 require(stat.S_ISREG(before.st_mode)and before.st_uid==uid and(gid is None or before.st_gid==gid)
  and before.st_nlink==1 and stat.S_IMODE(before.st_mode)in modes and 0<before.st_size<=16384,
  'PRIVATE_BOUNDED_ADMIN_SECRET_REQUIRED')
 raw=bytearray()
 while len(raw)<=16384:
  part=os.read(fd,min(4096,16385-len(raw)))
  if not part:break
  raw.extend(part)
 identity=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
 require(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(restat()),
  'ADMIN_SECRET_CHANGED_DURING_READ')
 return bytes(raw)


def namespace_secret(actual,selected,destination,custody):
 require(type(custody)is dict and set(custody)=={'schema','route','uid','gid','mode','singleLink','mountType','mountReadOnly'}
  and custody['schema']=='ouf.postgres-mounted-secret-custody.v1'and custody['route']=='PINNED_POSTGRES_ROOT_FD'
  and all(type(custody[k])is int and 0<=custody[k]<2**31 for k in('uid','gid'))
  and type(custody['mode'])is int and custody['mode']in(0o400,0o440,0o600,0o640)
  and custody['singleLink']is True and custody['mountType']=='bind'and custody['mountReadOnly']is True,
  'EXACT_OBSERVED_ADMIN_SECRET_CUSTODY_REQUIRED')
 pid=actual['State']['Pid'];require(type(pid)is int and pid>1,'CURRENT_POSTGRES_PROCESS_REQUIRED')
 proc=Path('/proc')/str(pid)
 def generation():
  raw=(proc/'stat').read_bytes();require(0<len(raw)<=8192 and raw.startswith((str(pid)+' (').encode()),'BOUNDED_POSTGRES_PROCESS_STAT_REQUIRED')
  rest=raw[raw.rfind(b')')+2:].split();require(len(rest)>=20,'POSTGRES_START_TICKS_REQUIRED')
  ns=(proc/'ns'/'mnt').stat();return(rest[19],ns.st_dev,ns.st_ino)
 before=generation();fds=[]
 try:
  # /proc/<pinned PID>/root is a kernel link to the running workload's actual root.
  cursor=os.open(proc/'root',os.O_PATH|os.O_DIRECTORY|os.O_CLOEXEC);fds.append(cursor)
  parts=Path(selected).parts[1:];require(bool(parts),'CONFIGURED_SECRET_LEAF_REQUIRED')
  for part in parts[:-1]:
   cursor=os.open(part,os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=cursor);fds.append(cursor)
  fd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=cursor);fds.append(fd)
  fdinfo=Path('/proc/self/fdinfo')/str(fd);info=fdinfo.read_bytes();require(len(info)<=8192,'BOUNDED_SECRET_FDINFO_REQUIRED')
  mount_ids=[line.split(b':',1)[1].strip()for line in info.splitlines()if line.startswith(b'mnt_id:')]
  require(len(mount_ids)==1 and mount_ids[0].isdigit(),'EXACT_OPENED_SECRET_MOUNT_ID_REQUIRED')
  mountinfo=(proc/'mountinfo').read_bytes();require(len(mountinfo)<=1048576,'BOUNDED_POSTGRES_MOUNTINFO_REQUIRED')
  rows=[line.split(b' - ',1)[0].split()for line in mountinfo.splitlines()if line.split(b' ',1)[0]==mount_ids[0]]
  require(len(rows)==1 and len(rows[0])>=6,'OPENED_SECRET_MOUNT_REQUIRED')
  unescape=lambda value:re.sub(rb'\\([0-7]{3})',lambda match:bytes([int(match[1],8)]),value).decode('utf-8')
  require(unescape(rows[0][4])==str(destination)and b'ro'in rows[0][5].split(b','),
   'OPENED_SECRET_MUST_BE_SELECTED_READ_ONLY_MOUNT')
  raw=secret_bytes(fd,lambda:os.stat(parts[-1],dir_fd=cursor,follow_symlinks=False),custody['uid'],custody['gid'],(custody['mode'],))
  following=(proc/'mountinfo').read_bytes();require(len(following)<=1048576,'BOUNDED_POSTGRES_MOUNTINFO_REQUIRED')
  same=[line.split(b' - ',1)[0].split()for line in following.splitlines()if line.split(b' ',1)[0]==mount_ids[0]]
  require(same==rows,'POSTGRES_SECRET_MOUNT_CHANGED_DURING_READ')
  require(generation()==before,'POSTGRES_PROCESS_CHANGED_DURING_SECRET_READ')
  return raw
 finally:
  for fd in reversed(fds):os.close(fd)


def configured_admin_password(actual,values,*,custody=None):
 direct=values.get('POSTGRES_PASSWORD');selected=values.get('POSTGRES_PASSWORD_FILE')
 require(not(direct and selected),'AMBIGUOUS_ADMIN_CREDENTIAL_CHANNEL')
 if not selected:
  require(custody is None,'SELECTED_FILE_CUSTODY_REQUIRES_CONFIGURED_FILE')
  require(type(direct)is str and 0<len(direct.encode())<=16384 and '\0'not in direct,
   'EXISTING_EXPLICIT_ADMIN_CREDENTIAL_CHANNEL_REQUIRED')
  return direct
 # Only the exact existing read-only bind mount of the pinned PostgreSQL is eligible.
 require(type(selected)is str and Path(selected).is_absolute()and str(Path(selected))==selected
  and '..'not in Path(selected).parts and not any(c in selected for c in('\0','\n','\r')),
  'EXACT_CONFIGURED_ADMIN_SECRET_PATH_REQUIRED')
 candidates=[]
 for mount in actual['Mounts']:
  destination=mount.get('Destination')
  if type(destination)is str and(selected==destination or selected.startswith(destination.rstrip('/')+'/')):
   candidates.append(mount)
 require(bool(candidates),'CONFIGURED_ADMIN_SECRET_MOUNT_REQUIRED')
 longest=max(len(m['Destination'])for m in candidates);candidates=[m for m in candidates if len(m['Destination'])==longest]
 require(len(candidates)==1,'UNIQUE_ADMIN_SECRET_MOUNT_REQUIRED');mount=candidates[0]
 require(mount.get('Type')=='bind'and mount.get('RW')is False,'READ_ONLY_ADMIN_SECRET_BIND_REQUIRED')
 destination=Path(mount['Destination']);source=mount.get('Source')
 require(type(source)is str and Path(source).is_absolute()and str(Path(source))==source
  and '..'not in Path(source).parts,'EXACT_ADMIN_SECRET_HOST_SOURCE_REQUIRED')
 if custody is not None:
  raw=namespace_secret(actual,selected,destination,custody)
 else:
  path=Path(source)/Path(selected).relative_to(destination)
  for parent in path.parents:
   info=parent.lstat()
   require(stat.S_ISDIR(info.st_mode)and info.st_uid==0 and not info.st_mode&0o022,
    'ROOT_CONTROLLED_ADMIN_SECRET_ANCESTRY_REQUIRED')
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  try:raw=secret_bytes(fd,path.lstat,0,None,(0o400,0o440,0o600,0o640))
  finally:os.close(fd)
 # Match the official PostgreSQL entrypoint's shell command substitution semantics.
 try:password=bytes(raw).rstrip(b'\n').decode('utf-8')
 except UnicodeError:raise UpdateDenied('ADMIN_SECRET_UTF8_REQUIRED')from None
 require(bool(password)and '\0'not in password,'NONEMPTY_ADMIN_SECRET_REQUIRED')
 return password


def admin_database_url(private_review,engine,*,include_observation=False,custody=None):
 pin=private_review['database']['postgresRuntimeBinding'];status,actual=engine.request('GET','/v1.44/containers/'+pin['containerId']+'/json')
 actual_pin=Engine.runtime_binding(actual)if status==200 else{}
 if status==200:actual_pin['mountsHash']=digest(sorted(actual['Mounts'],key=lambda m:m['Destination']))
 require(status==200 and actual_pin==pin and actual['State']['Running']is True,'CURRENT_SELECTED_POSTGRES_REQUIRED')
 values=env(actual['Config']['Env']);admin=private_review['database']['backupReader']
 require(values.get('POSTGRES_USER')==admin,'EXACT_REVIEWED_ADMINISTRATOR_REQUIRED')
 password=configured_admin_password(actual,values,custody=custody)
 status,after=engine.request('GET','/v1.44/containers/'+pin['containerId']+'/json')
 after_pin=Engine.runtime_binding(after)if status==200 else{}
 if status==200:
  require(digest(sorted(after['Mounts'],key=lambda m:m['Destination']))==digest(sorted(actual['Mounts'],key=lambda m:m['Destination'])),
   'POSTGRES_MOUNTS_CHANGED_DURING_CREDENTIAL_READ')
  after_pin['mountsHash']=pin['mountsHash']
 require(status==200 and after_pin==pin and after['State']['Running']is True,
  'POSTGRES_CHANGED_DURING_CREDENTIAL_READ')
 app=urlsplit(env(private_review['oldNativeConfig']['Env'])['MCP_DATABASE_URL'])
 require(app.hostname and app.port and app.path=='/'+private_review['database']['binding']['database'],
  'EXISTING_EXPLICIT_DATABASE_ENDPOINT_REQUIRED')
 netloc=quote(admin,safe='')+':'+quote(password,safe='')+'@'+('['+app.hostname+']'if ':'in app.hostname else app.hostname)+':'+str(app.port)
 result=urlunsplit((app.scheme,netloc,app.path,app.query,''))
 return(result,actual)if include_observation else result


def update_main(prepared,closure,resources,context,read,emit=print):
 authority.closure_valid(closure);private_review=resources['mcpReview'];binding=resources['mcpReviewBinding']
 token_context=Path(resources['tokenContext']);_,token_review=live_policy_session(token_context,closure,read)
 require(token_review['privateMcpReviewBinding']==binding,'SAME_MCP_REVIEW_AS_APPROVED_POLICY_SESSION_REQUIRED')
 receipt=read(token_context/'login-window-receipt.json',131072);directory=Path(receipt['directory'])
 human=HumanSession(prepared['authorization']['plan']['selection'],directory,directory/'human-access.jwt',receipt['expiresAt'])
 human.refresh_if_due();hb=human.current()
 proof=resources['ownerReceiptAbsence'];permit.owner_absence_valid(proof,private_review,time.time(),resources['ownerConnectionRef'])
 # Resolve from the retained installation selection; no new URL or default host.
 engine=Engine(prepared['engine']['socketPath'],tuple(prepared['engine']['socketBinding']))
 admin_url,postgres_observation=admin_database_url(private_review,engine,include_observation=True,
  custody=resources['executionSelection'].get('adminSecretCustody'))
 selection={'schema':'ouf.mcp-single-update-execution-selection.v1',
  'oldContainerName':next(row['name']for row in prepared['cohortPlan']['replacements']if row['module']=='mcp'),
  'metadataMountTarget':resources['executionSelection']['metadataMountTarget'],
  'readinessPort':resources['executionSelection']['readinessPort']}
 pr=permit.compile_review(private_review,binding,closure,hb,context,proof,int(time.time()),resources['ownerConnectionRef'])
 publish_json(context,'permit-review.json',pr)
 pd=authority.terminal_consent(pr,
  'Decisione separata sul reprocessing MCP: massimo una chiamata aggiuntiva, cumulativo2.\n'
  'Stesso commandKey Teatri, stesso HUMAN, tenant, workload e richiesta del claim fallito.\n'
  'Receipt owner assente osservata; validita massima900 secondi.\n'
  'Questa decisione firma il permesso privato; nessuna proposta o approvazione semantica viene inviata.\n'
  'Segue una revisione separata prima di aggiornare MCP e migrare il suo database.')
 files=permit.issue(pr,pd,human,private_review)
 plan=compiler.compile_plan(private_review,binding,context,selection,files,admin_url,postgres_mounts=postgres_observation['Mounts'])
 publish_json(context,'execution-plan.json',plan)
 remaining=pr['absoluteExpiresAt']-int(time.time());require(remaining>=210,'PERMIT_WINDOW_TOO_SHORT_BEFORE_INFRASTRUCTURE_REVIEW')
 final=authority.compile_action_review('MCP_SINGLE_UPDATE',closure,{'mcpSingleUpdate':scope(plan)},hb,context,
  {'predecessorHistoryHash':digest(private_review['retainedClaim']),'predecessorIncidentRef':plan['logicalUpdateRef']},min(900,remaining))
 final['absoluteExpiresAt']=pr['absoluteExpiresAt'];final['permitReviewHash']=digest(pr)
 publish_json(context,'review.json',final)
 decision=authority.terminal_consent(final,
  'Aggiornamento di un solo MCP e migrazione12->13. Fasi tecniche8/8; funzionali0/6.\n'
  'Un backup nuovo verificato, vecchio MCP fermato e conservato, stessa rete/IP/MAC.\n'
  'GRANT temporaneo/DDL/checksum/REVOKE nella stessa transazione; membership committata vietata.\n'
  'Metadati pubblici root0440 montati in sola lettura; credenziale amministrativa solo al migratore.\n'
  'Un tentativo per effetto; esiti ambigui richiedono riconciliazione. Nessun restore automatico.\n'
  'Nessuna operazione su altri servizi, Gateway, grant IAM o proposta semantica.\n'
  'Revisione privata: '+str(context/'review.json'))
 live_policy_session(token_context,closure,read)
 action=authority.issue_action(final,decision,human);cancelled=threading.Event();handlers={}
 for sig in(signal.SIGINT,signal.SIGTERM,signal.SIGHUP):handlers[sig]=signal.signal(sig,lambda *_:cancelled.set())
 def current_time():require(not cancelled.is_set(),'MCP_UPDATE_CANCELLED');return time.time()
 action.authority.clock=current_time
 journal=Journal(context);ports=NativePorts(action,engine,plan);update=SingleMcpUpdate(action,journal,plan,ports)
 try:
  update.initialize()
  while True:
   try:
    result=update.run();emit('OUF_SINGLE_MCP_UPDATE_RESULT='+encoded(result).decode());break
   except UpdatePaused as paused:
    require(str(paused)=='READINESS_RETRY_WAIT','MCP_UPDATE_RECONCILIATION_REQUIRED')
    row=journal.read();emit('OUF_SINGLE_MCP_UPDATE_WAIT='+encoded({'phase':'READINESS','attempts':row['readinessAttempts'],
     'nextReadAt':row['nextReadAt'],'expiresAt':row['expiresAt'],'acceptanceGranted':False}).decode())
    cancelled.wait(min(5,max(0,row['nextReadAt']-time.time())))
 finally:
  for sig,handler in handlers.items():signal.signal(sig,handler)
