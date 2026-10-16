"""Native adapters for one reviewed MCP update; not an authority issuer.

The entrypoint binds every path, executable, request, credential reference and
endpoint in the signed plan. SQL here is read-only; only the packaged migrator
performs the atomic 12->13 transaction. No semantic/THS/token operation exists.
"""
import copy,hashlib,http.client,ipaddress,json,os,re,selectors,stat,subprocess,tempfile,time
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import quote
from engine_creation import Engine,requested_host_config_matches
from image_custody import loaded,runtime_image_id
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_mcp_update.owner import UpdateDenied,require,digest,STAGES

def env(values):
 require(type(values)is list,'EXACT_ENVIRONMENT_REQUIRED');result={}
 for value in values:
  require(type(value)is str and '='in value,'EXACT_ENVIRONMENT_ENTRY_REQUIRED');key,item=value.split('=',1)
  require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]*',key)and key not in result,'UNIQUE_ENVIRONMENT_REQUIRED');result[key]=item
 return result

def literal(value):
 require(type(value)is str and re.fullmatch('[A-Za-z0-9_.:-]{1,128}',value),'CLOSED_SQL_BINDING_REQUIRED');return "'"+value+"'"

def private_file(path,expected,maximum):
 path=Path(path);require(path.is_absolute()and path.resolve()==path,'EXACT_PRIVATE_PATH_REQUIRED')
 for parent in path.parents:
  s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'ROOT_CONTROLLED_ANCESTRY_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and 0<s.st_size<=maximum,'PRIVATE_FILE_CUSTODY_REQUIRED')
  h=hashlib.sha256();count=0
  while block:=os.read(fd,min(1048576,maximum-count+1)):
   count+=len(block);require(count<=maximum,'PRIVATE_FILE_BOUND_EXHAUSTED');h.update(block)
  def pin(v):return tuple(getattr(v,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  require(count==s.st_size and pin(s)==pin(os.fstat(fd))==pin(path.lstat())and h.hexdigest()==expected,'PRIVATE_FILE_BYTES_CHANGED')
  return {'sha256':h.hexdigest(),'bytes':count}
 finally:os.close(fd)

def command(binding):
 path=Path(binding['path']);s=path.stat()
 require(path.is_absolute()and stat.S_ISREG(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022 and hashlib.sha256(path.read_bytes()).hexdigest()==binding['sha256'],'NATIVE_EXECUTABLE_CHANGED')
 return str(path)

def bounded(argv,seconds,maximum,*,input_stream=None,output_stream=None):
 process=subprocess.Popen(argv,stdin=input_stream if input_stream is not None else subprocess.DEVNULL,
  stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
 output=bytearray();errors=bytearray();count=0;h=hashlib.sha256();header=b'';end=time.monotonic()+seconds
 try:
  with selectors.DefaultSelector()as selector:
   selector.register(process.stdout,selectors.EVENT_READ,'out');selector.register(process.stderr,selectors.EVENT_READ,'err')
   while selector.get_map():
    require(time.monotonic()<end,'NATIVE_OPERATION_TIME_BOUND_EXHAUSTED')
    for key,_ in selector.select(min(.2,max(0,end-time.monotonic()))):
     raw=os.read(key.fd,65536)
     if not raw:selector.unregister(key.fileobj);continue
     if key.data=='out':
      count+=len(raw);require(count<=maximum,'NATIVE_OUTPUT_BOUND_EXHAUSTED');h.update(raw)
      if len(header)<5:header=(header+raw)[:5]
      if output_stream is None:output.extend(raw)
      else:output_stream.write(raw)
     else:errors.extend(raw);require(len(errors)<=65536,'NATIVE_ERROR_BOUND_EXHAUSTED')
   code=process.wait(timeout=max(.01,end-time.monotonic()))
  require(code==0,'NATIVE_OPERATION_OUTCOME_UNPROVEN')
  return bytes(output),{'bytes':count,'sha256':h.hexdigest(),'customFormatHeader':header==b'PGDMP'}
 finally:
  if process.poll()is None:process.kill()
  process.wait(timeout=5);process.stdout.close();process.stderr.close()

class NativePorts:
 def __init__(self,action,engine,plan):
  require(type(action)is AggregateAction and type(engine)is Engine,'REAL_AUTHORITY_AND_ENGINE_REQUIRED')
  self.action,self.engine,self.plan=action,engine,copy.deepcopy(plan)
 def claim_logical_scope(self):
  p=self.plan;parent=Path(p['predecessorReviewPath']).parent.parent
  for ancestor in(parent,*parent.parents):
   s=ancestor.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_LOGICAL_FENCE_PARENT_REQUIRED')
  path=parent/('mcp-single-update-'+p['logicalUpdateRef']+'.claim.json')
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  try:
   raw=json.dumps({'schema':'ouf.mcp-single-update-logical-claim.v1','logicalUpdateRef':p['logicalUpdateRef'],
    'planHash':digest(p),'authorityHash':self.action.authority_hash,'authorityDirectory':p['authorityDirectory'],
    'automaticReplayAllowed':False,'budgetReset':False},sort_keys=True).encode()
   with os.fdopen(os.dup(fd),'wb')as out:out.write(raw);out.flush();os.fsync(out.fileno())
  finally:os.close(fd)
  fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:os.fsync(fd)
  finally:os.close(fd)
 def boot(self):return Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 def request(self,method,path,body=None):
  self.engine.check_socket();return self.engine.request(method,path,body)
 def inspect(self,kind,reference):
  require(kind in('containers','images','networks')and re.fullmatch('[A-Za-z0-9_.:-]{1,128}',reference),'EXACT_ENGINE_REFERENCE_REQUIRED')
  status,value=self.request('GET','/v1.44/'+kind+'/'+quote(reference,safe='')+(''if kind=='networks'else'/json'))
  if status==404:return None
  require(status==200 and type(value)is dict,'NATIVE_OBSERVATION_FAILED');return value
 def runtime(self,actual):
  return {'containerId':actual['Id'],'imageId':actual['Image'],'pid':actual['State']['Pid'],'startedAt':actual['State']['StartedAt'],
   **{n+'Hash':digest(actual[k])for n,k in(('config','Config'),('hostConfig','HostConfig'),('mounts','Mounts'),('networkSettings','NetworkSettings'))}}
 def guard_current(self,stage):
  from tools.semantic_mcp_update.owner import scope
  self.action.guard('mcpSingleUpdate',scope(self.plan));self.engine.check_socket()
  private_file(self.plan['predecessorReviewPath'],self.plan['predecessorReviewHash'],8388608)
  pg=self.inspect('containers',self.plan['postgresRuntimeBinding']['containerId'])
  require(pg is not None and self.runtime(pg)==self.plan['postgresRuntimeBinding']and pg['State']['Running']is True and pg['State']['Paused']is False,'POSTGRES_RUNTIME_CHANGED')
  old=self.inspect('containers',self.plan['oldRuntimeBinding']['containerId']);require(old is not None,'RETAINED_MCP_ABSENT')
  require(old['Image']==self.plan['oldRuntimeBinding']['imageId']and digest(old['Config'])==self.plan['oldRuntimeBinding']['configHash']and digest(old['Mounts'])==self.plan['oldRuntimeBinding']['mountsHash'],'OLD_MCP_CONFIG_CHANGED')
  n=STAGES.index(stage)
  require(old['State']['StartedAt']==self.plan['oldRuntimeBinding']['startedAt'],'OLD_MCP_PROCESS_REPLACED')
  if old['State']['Running']:
   require(digest(old['NetworkSettings'])==self.plan['oldRuntimeBinding']['networkSettingsHash'],'OLD_ENDPOINT_CHANGED')
  else:
   networks=old['NetworkSettings']['Networks'];require(set(networks)<={self.plan['network']['name']},'OLD_NETWORK_PROFILE_CHANGED')
   if networks:
    endpoint=networks[self.plan['network']['name']]
    require(endpoint['NetworkID']==self.plan['network']['id']and endpoint.get('IPAddress','')in('',self.plan['network']['ip'])
     and endpoint.get('MacAddress','').lower()in('',self.plan['network']['mac'].lower()),'STOPPED_ENDPOINT_PROFILE_CHANGED')
  if n>STAGES.index('DETACH_OLD_ENDPOINT'):
   live=self.inspect('networks',self.plan['network']['id'])
   require(live is not None and old['Id']not in(live.get('Containers')or{}),'OLD_ENDPOINT_REINTRODUCED')
  if n<STAGES.index('RENAME_OLD'):require(old['Name']=='/'+self.plan['replacement']['name'],'OLD_NAME_CHANGED')
  elif n>STAGES.index('RENAME_OLD'):require(old['Name']=='/'+self.plan['replacement']['retiredName'],'RETIRED_NAME_CHANGED')
  host=copy.deepcopy(self.plan['oldHostConfig'])
  if n>STAGES.index('DISABLE_OLD_RESTART'):host['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
  # During readback of the claimed restart-policy operation either exact state
  # may be inspected; observe() establishes which effect actually happened.
  if stage=='DISABLE_OLD_RESTART':
   alternate=copy.deepcopy(host);alternate['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
   require(old['HostConfig']in(host,alternate),'OLD_HOST_CONFIGURATION_CHANGED')
  else:require(old['HostConfig']==host,'OLD_HOST_CONFIGURATION_CHANGED')
  if n>STAGES.index('STOP_OLD'):require(old['State']['Running']is False and old['State']['Pid']==0 and old['State']['StartedAt']==self.plan['oldRuntimeBinding']['startedAt'],'OLD_MCP_MUST_REMAIN_STOPPED')
  elif n<STAGES.index('STOP_OLD'):require(old['State']['Running']is True and old['State']['Pid']==self.plan['oldRuntimeBinding']['pid']and old['State']['StartedAt']==self.plan['oldRuntimeBinding']['startedAt'],'OLD_MCP_GENERATION_CHANGED')
 def cli(self,*args):
  return [command(self.plan['programs']['docker']),'--host','unix://'+self.plan['engine']['socketPath'],'--config',self._config,*args]
 def sql(self,expression):
  database=self.plan['database'];admin=database['admin'];name=database['name']
  require(all(re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}',v)for v in(admin,name)),'SELECTED_SQL_CHANNEL_REQUIRED')
  with tempfile.TemporaryDirectory(prefix='ouf-mcp-update-sql-')as directory:
   self._config=directory
   raw,_=bounded(self.cli('exec',self.plan['postgresRuntimeBinding']['containerId'],'env','LC_ALL=C',
    'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000 -c lock_timeout=3000',
    'timeout','-s','KILL','15','psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U',admin,'-d',name,'-c',
    "BEGIN READ ONLY; SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s'; SELECT "+expression+"; ROLLBACK;"),20,65536)
  value=json.loads(raw);require(type(value)is dict,'CLOSED_DATABASE_METADATA_REQUIRED');return value
 def migration_state(self):
  p=self.plan;claim=p['retainedClaim'];where="attempt_id="+literal(claim['attemptId'])+"::uuid"
  state=self.sql("json_build_object('oid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),"
   "'adminSuperuser',(SELECT rolsuper FROM pg_roles WHERE rolname=current_user),"
   "'members',(SELECT count(*) FROM pg_auth_members WHERE roleid=(SELECT oid FROM pg_roles WHERE rolname='ouf_mcp_retention_owner')),"
   "'migrations',(SELECT COALESCE(json_agg(x),'[]'::json)FROM(SELECT version,checksum FROM ouf_mcp.schema_migration ORDER BY version LIMIT 14)x),"
   "'claim',(SELECT json_build_object('state',state,'dispatchState',dispatch_state,'lockVersion',lock_version,'requestHash',request_hash)FROM ouf_mcp.tool_attempt WHERE "+where+"))")
  require(state['oid']==p['database']['oid']and state['adminSuperuser']is True and state['members']==0,'EXACT_DATABASE_AND_ZERO_MEMBERSHIP_REQUIRED')
  require(state['claim']=={k:claim[k]for k in('state','dispatchState','lockVersion','requestHash')},'ORIGINAL_CLAIM_CHANGED')
  return state
 def retained_generation(self,stage,actual,*,running=False):
  require(hasattr(self,'journal'),'SAME_CUSTODIED_HISTORY_REQUIRED')
  effects={e['stage']:e['evidence']for e in self.journal.read()['effects']if e['state']=='APPLIED'}
  creation=effects.get(stage)
  if creation is not None:require(actual['Id']==creation['containerId'],'CREATED_CONTAINER_ID_CHANGED')
  if running:
   started=effects.get('START_REPLACEMENT')
   if started is not None:require(actual['State']['Pid']==started['pid']and actual['State']['StartedAt']==started['startedAt'],'NEW_MCP_PROCESS_GENERATION_CHANGED')
 def candidate(self):
  p=self.plan;actual=self.inspect('containers',p['replacement']['name'])
  if actual is None:return None
  self.retained_generation('CREATE_REPLACEMENT',actual,running=True)
  request=p['replacement']['request'];audit=p['imageAudit']
  require(actual['Id']!=p['oldRuntimeBinding']['containerId']and actual['Image']==runtime_image_id(audit),'EXACT_NEW_MCP_IMAGE_REQUIRED')
  for key,value in request.items():
   if key in('HostConfig','NetworkingConfig')or key=='Hostname'and not value:continue
   if key=='Env':require(env(actual['Config']['Env'])=={**env(audit['imageConfig'].get('Env')or[]),**env(value)},'NEW_MCP_ENVIRONMENT_CHANGED')
   elif key=='Labels':require(actual['Config'].get(key)=={**audit['imageConfig'].get('Labels',{}),**value},'NEW_MCP_LABELS_CHANGED')
   else:require(actual['Config'].get(key)==value,'NEW_MCP_PROCESS_CONFIG_CHANGED')
  host=copy.deepcopy(request['HostConfig']);alternate=copy.deepcopy(host);alternate['RestartPolicy']=p['replacement']['restoreRestartPolicy']
  require(requested_host_config_matches(host,actual['HostConfig'],started=actual['State']['Running'])or requested_host_config_matches(alternate,actual['HostConfig'],started=actual['State']['Running']),'NEW_MCP_HOST_CONFIG_CHANGED')
  network=p['network'];networks=actual['NetworkSettings']['Networks']
  require(set(networks)=={network['name']}and networks[network['name']]['NetworkID']==network['id']
   and networks[network['name']]['IPAddress']==network['ip']and networks[network['name']]['MacAddress'].lower()==network['mac'].lower(),'NEW_MCP_ENDPOINT_CHANGED')
  expected={(m['Type'],m['Source'],m['Destination'],m['RW'])for m in p['oldMounts']}
  expected.add(('bind',p['metadata']['directory'],p['metadata']['target'],False))
  require({(m['Type'],m['Source'],m['Destination'],m['RW'])for m in actual['Mounts']}==expected,'NEW_MCP_MOUNT_CHANGED')
  return actual
 def apply(self,stage):
  p=self.plan;old=p['oldRuntimeBinding']['containerId'];name=p['replacement']['name'];migration=p['migration']
  if stage=='VERIFY_INPUTS':
   private_file(p['imageImport']['path'],p['imageAudit']['archiveSha256'],2147483648)
   require(self.migration_state()['migrations']==p['database']['before'],'PRE_MIGRATION_PREFIX_CHANGED')
   require(self.inspect('containers',p['replacement']['retiredName'])is None and self.inspect('containers',migration['name'])is None,'UPDATE_NAMES_ALREADY_CLAIMED')
  elif stage=='IMPORT_IMAGE':
   if self.inspect('images',runtime_image_id(p['imageAudit']))is None:
    with tempfile.TemporaryDirectory(prefix='ouf-mcp-update-load-')as directory:
     self._config=directory;bounded(self.cli('load','--input',p['imageImport']['path']),180,65536)
  elif stage in('DISABLE_OLD_RESTART','RESTORE_RESTART_POLICY'):
   cid=old if stage=='DISABLE_OLD_RESTART'else self.candidate()['Id']
   policy={'Name':'no','MaximumRetryCount':0}if stage=='DISABLE_OLD_RESTART'else p['replacement']['restoreRestartPolicy']
   status,_=self.request('POST','/v1.44/containers/'+cid+'/update',{'RestartPolicy':policy});require(status==200,'RESTART_POLICY_OUTCOME_UNPROVEN')
  elif stage=='STOP_OLD':
   status,_=self.request('POST','/v1.44/containers/'+old+'/stop?t=20');require(status==204,'STOP_OUTCOME_UNPROVEN')
  elif stage=='BACKUP_DATABASE':
   path=Path(p['database']['backupPath']);fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   try:
    with os.fdopen(os.dup(fd),'wb')as out,tempfile.TemporaryDirectory(prefix='ouf-mcp-update-dump-')as directory:
     self._config=directory;_,proof=bounded(self.cli('exec',p['postgresRuntimeBinding']['containerId'],'env','LC_ALL=C',
      'PGOPTIONS=-c statement_timeout=90000 -c lock_timeout=3000','timeout','-s','KILL','100','pg_dump','--format=custom','--no-owner','--no-acl','-U',p['database']['admin'],'-d',p['database']['name']),110,p['database']['maximumBackupBytes'],output_stream=out)
     out.flush();os.fsync(out.fileno());require(proof['customFormatHeader']and proof['bytes']>5,'CUSTOM_FORMAT_BACKUP_REQUIRED')
     marker=path.with_name(path.name+'.complete.json');marker_fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
     try:os.write(marker_fd,json.dumps(proof,sort_keys=True).encode());os.fsync(marker_fd)
     finally:os.close(marker_fd)
   finally:os.close(fd)
  elif stage=='CREATE_MIGRATOR':
   require(self.inspect('containers',migration['name'])is None,'MIGRATOR_ALREADY_EXISTS')
   status,value=self.request('POST','/v1.44/containers/create?name='+quote(migration['name'],safe=''),migration['request']);require(status==201 and re.fullmatch('[0-9a-f]{64}',value.get('Id','')),'MIGRATOR_CREATION_UNPROVEN')
  elif stage=='START_MIGRATOR':
   actual=self._migrator();require(actual['State']['Status']=='created'and actual['State']['Pid']==0,'NEVER_STARTED_MIGRATOR_REQUIRED')
   status,_=self.request('POST','/v1.44/containers/'+actual['Id']+'/start');require(status==204,'MIGRATOR_START_UNPROVEN')
  elif stage=='VERIFY_MIGRATION':
   end=time.monotonic()+35
   while self._migrator()['State']['Running']:
    require(time.monotonic()<end,'MIGRATOR_EXIT_UNPROVEN');self.guard_current(stage);time.sleep(.2)
   require(self.migration_state()['migrations']==p['database']['after'],'MIGRATION_13_NOT_PROVEN')
  elif stage=='DETACH_OLD_ENDPOINT':
   live=self.inspect('networks',p['network']['id']);require(live is not None,'EXACT_NETWORK_REQUIRED')
   if old in(live.get('Containers')or{}):
    status,_=self.request('POST','/v1.44/networks/'+p['network']['id']+'/disconnect',{'Container':old,'Force':False});require(status==200,'ENDPOINT_RELEASE_UNPROVEN')
  elif stage=='RENAME_OLD':
   status,_=self.request('POST','/v1.44/containers/'+old+'/rename?name='+quote(p['replacement']['retiredName'],safe=''));require(status==204,'OLD_RENAME_UNPROVEN')
  elif stage=='PUBLISH_PUBLIC_METADATA':
   directory=Path(p['metadata']['directory']);require(directory.parent==Path(p['authorityDirectory']),'PUBLIC_METADATA_PARENT_REQUIRED')
   directory.mkdir(mode=0o750);os.chown(directory,0,p['metadata']['gid']);os.chmod(directory,0o750)
   for name,text in p['metadata']['files'].items():
    require(name in('profile.json','policy.json','permit.json'),'CLOSED_PUBLIC_METADATA_MEMBER_REQUIRED')
    fd=os.open(directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o440)
    try:os.fchown(fd,0,p['metadata']['gid']);os.fchmod(fd,0o440);os.write(fd,text.encode());os.fsync(fd)
    finally:os.close(fd)
   fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
   try:os.fsync(fd)
   finally:os.close(fd)
  elif stage=='CREATE_REPLACEMENT':
   require(self.inspect('containers',name)is None,'MCP_NAME_ALREADY_EXISTS')
   status,value=self.request('POST','/v1.44/containers/create?name='+quote(name,safe=''),p['replacement']['request']);require(status==201 and re.fullmatch('[0-9a-f]{64}',value.get('Id','')),'NEW_MCP_CREATION_UNPROVEN')
  elif stage=='START_REPLACEMENT':
   actual=self.candidate();require(actual is not None and actual['State']['Status']=='created'and actual['State']['Pid']==0,'NEVER_STARTED_NEW_MCP_REQUIRED')
   status,_=self.request('POST','/v1.44/containers/'+actual['Id']+'/start');require(status==204,'NEW_MCP_START_UNPROVEN')
  elif stage=='VERIFY_FINAL':
   require(self.migration_state()['migrations']==p['database']['after'],'FINAL_DATABASE_STATE_CHANGED')
   require(self.observe('READINESS')[0]=='APPLIED','CURRENT_READINESS_REQUIRED')
  else:require(stage=='READINESS','UNKNOWN_UPDATE_STAGE')
 def _migrator(self):
  p=self.plan;actual=self.inspect('containers',p['migration']['name']);require(actual is not None,'EXACT_MIGRATOR_REQUIRED');request=p['migration']['request']
  require(actual['Image']==request['Image']and actual['Config']['User']==request['User']and actual['Config']['Entrypoint']==request['Entrypoint']and actual['Config']['Cmd']==['migrate-semantic-reprocessing']
   and env(actual['Config']['Env'])=={**env(p['imageAudit']['imageConfig'].get('Env')or[]),**env(request['Env'])}
   and actual['Mounts']==[]and requested_host_config_matches(request['HostConfig'],actual['HostConfig'],started=actual['State']['Running']),'MIGRATOR_PROCESS_CONFIG_CHANGED')
  networks=actual['NetworkSettings']['Networks'];require(set(networks)=={p['network']['name']}and networks[p['network']['name']]['NetworkID']==p['network']['id'],'MIGRATOR_NETWORK_CHANGED')
  self.retained_generation('CREATE_MIGRATOR',actual)
  return actual
 def observe(self,stage):
  p=self.plan;old=self.inspect('containers',p['oldRuntimeBinding']['containerId'])
  if stage=='VERIFY_INPUTS':return 'APPLIED',{'inputHash':p['predecessorReviewHash']}
  if stage=='IMPORT_IMAGE':
   actual=self.inspect('images',runtime_image_id(p['imageAudit']));return ('UNKNOWN',{})if actual is None else('APPLIED',loaded(p['imageAudit'],actual))
  if stage=='DISABLE_OLD_RESTART':return ('APPLIED',{'restartDisabled':True})if old['HostConfig']['RestartPolicy']=={'Name':'no','MaximumRetryCount':0}else('UNKNOWN',{})
  if stage=='STOP_OLD':return ('APPLIED',{'stoppedContainerId':old['Id']})if old['State']['Running']is False and old['State']['Pid']==0 else('UNKNOWN',{})
  if stage=='BACKUP_DATABASE':
   path=Path(p['database']['backupPath']);require(path.is_file()and not path.is_symlink(),'PRIVATE_BACKUP_REQUIRED')
   s=path.lstat();require(s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and 5<s.st_size<=p['database']['maximumBackupBytes'],'BACKUP_CUSTODY_REQUIRED')
   marker=path.with_name(path.name+'.complete.json');ms=marker.lstat()
   require(stat.S_ISREG(ms.st_mode)and ms.st_uid==ms.st_gid==0 and ms.st_nlink==1 and stat.S_IMODE(ms.st_mode)==0o600 and 0<ms.st_size<=1024,'DURABLE_DUMP_COMPLETION_REQUIRED')
   completed=json.loads(marker.read_bytes());require(completed['customFormatHeader']is True and completed['bytes']==s.st_size and re.fullmatch('[0-9a-f]{64}',completed['sha256']),'SUCCESSFUL_DUMP_COMPLETION_REQUIRED')
   custody=private_file(path,completed['sha256'],p['database']['maximumBackupBytes'])
   with path.open('rb')as raw,tempfile.TemporaryDirectory(prefix='ouf-mcp-update-backup-list-')as directory:
    self._config=directory;_,proof=bounded(self.cli('exec','-i',p['postgresRuntimeBinding']['containerId'],'env','LC_ALL=C','timeout','-s','KILL','15','pg_restore','--list'),20,2097152,input_stream=raw)
   return 'APPLIED',{'archiveSha256':custody['sha256'],'archiveBytes':s.st_size,'nativeRestoreListSha256':proof['sha256']}
  if stage in('CREATE_MIGRATOR','START_MIGRATOR'):
   actual=self._migrator()
   if stage=='START_MIGRATOR'and actual['State']['StartedAt']=='0001-01-01T00:00:00Z':return 'UNKNOWN',{}
   return 'APPLIED',{'containerId':actual['Id'],'configHash':digest(actual['Config']),'startedAt':actual['State']['StartedAt']}
  if stage=='VERIFY_MIGRATION':
   state=self.migration_state();return ('APPLIED',{'databaseStateHash':digest(state),'committedMemberships':0})if state['migrations']==p['database']['after']else('UNKNOWN',{})
  if stage=='DETACH_OLD_ENDPOINT':
   live=self.inspect('networks',p['network']['id']);return ('APPLIED',{'oldEndpointReleased':True})if live is not None and old['Id']not in(live.get('Containers')or{})else('UNKNOWN',{})
  if stage=='RENAME_OLD':return ('APPLIED',{'retiredContainerId':old['Id']})if old['Name']=='/'+p['replacement']['retiredName']else('UNKNOWN',{})
  if stage=='PUBLISH_PUBLIC_METADATA':
   directory=Path(p['metadata']['directory']);s=directory.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and s.st_gid==p['metadata']['gid']and stat.S_IMODE(s.st_mode)==0o750,'PUBLIC_DIRECTORY_CUSTODY_REQUIRED')
   require(set(x.name for x in directory.iterdir())==set(p['metadata']['files']),'PUBLIC_METADATA_MEMBER_DRIFT')
   for name,text in p['metadata']['files'].items():
    path=directory/name;s=path.lstat();require(stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_gid==p['metadata']['gid']and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o440 and path.read_bytes()==text.encode(),'PUBLIC_METADATA_BYTES_DRIFT')
   return 'APPLIED',{'publicMetadataHash':digest(p['metadata']['files'])}
  if stage in('CREATE_REPLACEMENT','START_REPLACEMENT','RESTORE_RESTART_POLICY','READINESS','VERIFY_FINAL'):
   actual=self.candidate()
   if actual is None:return 'UNKNOWN',{}
   if stage in('START_REPLACEMENT','READINESS','RESTORE_RESTART_POLICY','VERIFY_FINAL'):
    require(actual['State']['Running']is True and actual['State']['Pid']>0,'NEW_MCP_NOT_RUNNING')
   proof={'containerId':actual['Id'],'runtimeHash':digest(self.runtime(actual)),'pid':actual['State']['Pid'],'startedAt':actual['State']['StartedAt']}
   if stage=='RESTORE_RESTART_POLICY':require(actual['HostConfig']['RestartPolicy']==p['replacement']['restoreRestartPolicy'],'RESTART_POLICY_NOT_RESTORED')
   if stage in('READINESS','VERIFY_FINAL'):
    ip=ipaddress.ip_address(p['network']['ip']);require(ip.is_private and not ip.is_loopback and not ip.is_unspecified,'REVIEWED_PRIVATE_READINESS_ENDPOINT_REQUIRED')
    client=http.client.HTTPConnection(str(ip),p['readiness']['port'],timeout=5)
    try:
     client.request('GET',p['readiness']['path'],headers={'Accept':'application/json','Connection':'close'});reply=client.getresponse();raw=reply.read(65537)
     require(len(raw)<=65536,'READINESS_RESPONSE_BOUND_EXHAUSTED')
     if reply.status in(429,502,503,504):
      delay=reply.getheader('Retry-After')or'0'
      if re.fullmatch('[0-9]{1,6}',delay):seconds=int(delay)
      else:
       try:seconds=max(0,parsedate_to_datetime(delay).timestamp()-time.time())
       except(ValueError,TypeError,OverflowError):raise UpdateDenied('READINESS_RETRY_AFTER_REQUIRES_REVIEW')from None
      require(0<=seconds<float('inf'),'READINESS_RETRY_AFTER_REQUIRES_REVIEW')
      return 'TRANSIENT',{'retryAfterSeconds':seconds}
     require(reply.status==204 and not raw,'READINESS_PERMANENT_FAILURE');proof['httpStatus']=204
    except(OSError,http.client.HTTPException):return 'TRANSIENT',{'retryAfterSeconds':0}
    finally:client.close()
   return 'APPLIED',proof
  raise UpdateDenied('UNKNOWN_UPDATE_OBSERVATION')
