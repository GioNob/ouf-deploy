"""Existing installation IAM session: metadata GET, then one native terminal login if expired."""
import hashlib,json,os,re,resource,signal,stat,subprocess,sys,tempfile
from pathlib import Path
from tools.source_revision_update.owner import require,encoded
def digest(raw):return hashlib.sha256(raw).hexdigest()

def reserve(directory,claim):
 directory=Path(directory)
 require(directory.parent.resolve()==directory.parent,'EXACT_FENCE_PARENT_REQUIRED')
 for parent in (directory.parent,*directory.parent.parents):
  info=parent.lstat();require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,'ROOT_FENCE_ANCESTRY_REQUIRED')
 # Exclusive directory is the durable one-use fence, including crash before claim.
 directory.mkdir(mode=0o700)
 fd=os.open(directory.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(directory/'attempt.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  raw=encoded(claim);require(os.write(fd,raw)==len(raw),'DURABLE_CLAIM_WRITE_REQUIRED');os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)

def output_limit():resource.setrlimit(resource.RLIMIT_FSIZE,(262145,262145))
def bounded_read(argv,env):
 with tempfile.TemporaryFile()as out,tempfile.TemporaryFile()as err:
  reply=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=25,env=env,preexec_fn=output_limit)
  out.seek(0);err.seek(0);raw=out.read(262145);diagnostic=err.read(262145)
 require(reply.returncode==0 and 0<len(raw)<=262144 and len(diagnostic)<=262144,'IAM_READ_NOT_RECONCILED')
 return json.loads(raw)

def admin_login(original,profile,iam):
 selection=original['authorization']['plan']['selection'];binding=selection['docker'];binary=Path(binding['path'])
 container=selection['keycloakContainer'];realm=selection['realm'];engine=original['engine']
 require(re.fullmatch('[0-9a-f]{64}',container) and re.fullmatch('[A-Za-z0-9._:-]{1,128}',realm),'EXACT_IAM_SELECTION_REQUIRED')
 socket=Path(engine['socketPath']);require(socket.is_absolute() and socket.resolve()==socket,'EXACT_ENGINE_PATH_REQUIRED')
 def guard_binary_socket():
  require(binary.is_absolute() and binary.resolve()==binary,'EXACT_DOCKER_PATH_REQUIRED')
  for parent in binary.parents:
   info=parent.lstat();require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,'DOCKER_ANCESTRY_REQUIRED')
  info=binary.lstat();require(stat.S_ISREG(info.st_mode)and info.st_uid==0 and not info.st_mode&0o022
    and 0<info.st_size<=134217728 and digest(binary.read_bytes())==binding['sha256'],'DOCKER_EXECUTABLE_CHANGED')
  st=socket.lstat();require(stat.S_ISSOCK(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)in(0o600,0o660)
    and [st.st_dev,st.st_ino,st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode)]==list(engine['socketBinding']),'ENGINE_SOCKET_CHANGED')
 env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','TERM':'xterm-256color',
      'DOCKER_CONFIG':iam['fenceDirectory']}
 base=[str(binary),'--host','unix://'+str(socket)]
 def generation():
  guard_binary_socket()
  state=bounded_read(base+['inspect','--format','{{json .State}}',container],env)
  require(state.get('Running')is True and type(state.get('Pid'))is int and state['Pid']>0
   and type(state.get('StartedAt'))is str and state['StartedAt'],'KEYCLOAK_GENERATION_REQUIRED')
  return {k:state[k]for k in('Pid','StartedAt')}
 before=generation()
 terminal=os.open('/dev/tty',os.O_RDWR|os.O_NOCTTY)
 try:
  require(os.isatty(terminal),'CURRENT_OPERATOR_TERMINAL_REQUIRED')
  reserve(iam['fenceDirectory'],{'schema':iam['schema'],'maximumLoginAttempts':1,'automaticReplayAllowed':False,
   'stoppedClosureSha256':iam['stoppedClosureSha256'],'preparedReceiptSha256':profile['preparationResultSha256'],
   'containerId':container,'generation':before,'passwordReadByDelivery':False,'budgetReset':False})
  require(generation()==before,'KEYCLOAK_GENERATION_CHANGED')
  print('Accesso IAM amministrativo: inserire la password nel prompt Keycloak del terminale; non nella chat.',flush=True)
  argv=base+['exec','-it',container,'/opt/keycloak/bin/kcadm.sh','config','credentials',
   '--server',iam['adminServer'],'--realm',iam['adminRealm'],'--user',iam['adminUser']]
  signal.alarm(0)
  try:subprocess.run(argv,stdin=terminal,stdout=terminal,stderr=terminal,timeout=iam['maximumLoginSeconds'],env=env)
  except subprocess.TimeoutExpired:pass  # One GET resolves an ambiguous completion; never repeat login.
 finally:os.close(terminal)
 signal.alarm(300)
 require(generation()==before,'KEYCLOAK_GENERATION_CHANGED')
 scopes=bounded_read(base+['exec','-i',container,'/opt/keycloak/bin/kcadm.sh','get','client-scopes','-r',realm,'--fields','id,name'],env)
 require(type(scopes)is list and scopes and all(type(row)is dict and set(row)=={'id','name'}
  and type(row['id'])is str and type(row['name'])is str for row in scopes),'IAM_GET_UNPROVEN')
 require(generation()==before,'KEYCLOAK_GENERATION_CHANGED')
 # Match native OwnerTransport's implicit Docker transport to the retained engine.
 os.environ.pop('DOCKER_CONTEXT',None);os.environ['DOCKER_HOST']='unix://'+str(socket)
 print(json.dumps({'schema':iam['schema'],'check':'IAM_GET_RECONCILED','maximumLoginAttempts':1,
  'passwordReadByDelivery':False,'runtimeAuthorityIssued':False,'automaticRetry':False,'budgetReset':False}),flush=True)

def ensure(original,case,context,closure,transport):
 from engine_creation import Engine
 from tools.ingestion_read_authorization.authorization import AuthorizationPaused
 engine=Engine(original['engine']['socketPath'],tuple(original['engine']['socketBinding']))
 engine.check_socket();os.environ.pop('DOCKER_CONTEXT',None)
 os.environ['DOCKER_HOST']='unix://'+original['engine']['socketPath']
 try:transport.oauth()
 except AuthorizationPaused as error:
  require(error.reason=='EXISTING_IAM_SESSION_EXPIRED','IAM_METADATA_UNPROVEN_NO_LOGIN')
  profile=dict(case['iamProfile']);profile['fenceDirectory']=str(context/'iam-login')
  profile['stoppedClosureSha256']=hashlib.sha256(encoded(closure)).hexdigest()
  admin_login(original,{'preparationResultSha256':case['preparationReceiptHash']},profile)
  signal.alarm(0);engine.check_socket();transport.oauth()
