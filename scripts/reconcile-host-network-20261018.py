"""Root host repair bootstrap. Native provider guards are only read, never bypassed."""
import fcntl,hashlib,json,os,re,signal,stat,tempfile,time
from pathlib import Path

CONFIG_SUFFIXES=('.yaml','.yml','.conf','.properties','/Caddyfile')

def atomic(path,value,owner):
 path=Path(path);raw=owner.encoded(value);fd,name=tempfile.mkstemp(prefix='.network-journal-',dir=path.parent)
 try:
  os.fchmod(fd,0o600)
  with os.fdopen(fd,'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
  os.replace(name,path);directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
  try:os.fsync(directory)
  finally:os.close(directory)
 finally:
  if os.path.lexists(name):os.unlink(name)

def reject_literal_dependencies(raw,profile,owner):
 # Preserve DNS-based bindings. A literal address/port to a moving service must
 # be explicitly reconfigured by its owner, never silently adopted here.
 text=raw.decode('utf-8');owner.require(len(raw)<=2097152,'CONFIGURATION_READ_BOUND')
 for move in profile['moves']:
  if move['oldIPv4']==move['newIPv4']:continue
  pattern=r'(?<![0-9.])'+re.escape(move['oldIPv4'])+r'(?::([0-9]{1,5}))?(?![0-9.])'
  for match in re.finditer(pattern,text):
   port=match[1];owner.require(port is not None and int(port)not in move['servicePorts'],'LITERAL_MOVING_SERVICE_DEPENDENCY_REQUIRES_OWNER_REVIEW')

def configuration_bytes(path,profile,owner):
 path=Path(path);owner.require(path.is_absolute()and'..'not in path.parts,'CONFIGURATION_PATH_REQUIRED')
 for parent in path.parents:
  info=parent.lstat();owner.require(stat.S_ISDIR(info.st_mode)and info.st_uid in profile['configurationOwnerUids']and not info.st_mode&0o022,'CONFIGURATION_ANCESTRY_CHANGED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  first=os.fstat(fd);owner.require(stat.S_ISREG(first.st_mode)and first.st_uid in profile['configurationOwnerUids']and first.st_nlink==1 and not first.st_mode&0o022 and 0<first.st_size<=2097152,'CONFIGURATION_CUSTODY_REQUIRED')
  raw=os.read(fd,2097153);last=os.fstat(fd);pin=lambda i:(i.st_dev,i.st_ino,i.st_size,i.st_mtime_ns,i.st_ctime_ns)
  owner.require(len(raw)==first.st_size and pin(first)==pin(last)==pin(path.lstat()),'CONFIGURATION_CHANGED_DURING_READ');return raw
 finally:os.close(fd)

def configuration_scanner(reader,profile,owner):
 bindings={};count=[0]
 def scan(row,_):
  for entry in row['Config'].get('Env')or[]:
   key,sep,value=entry.partition('=');owner.require(sep,'ENVIRONMENT_SCHEMA')
   if not re.search(r'(?:SECRET|PASSWORD|TOKEN|PRIVATE_KEY)$',key):reject_literal_dependencies(value.encode(),profile,owner)
  for mount in row.get('Mounts')or[]:
   destination=mount['Destination']
   if mount['Type']=='bind'and destination.endswith(CONFIG_SUFFIXES):
    owner.require(mount.get('RW')is False,'CONFIGURATION_MOUNT_MUST_BE_READONLY')
    source=Path(mount['Source']);raw=configuration_bytes(source,profile,owner);reject_literal_dependencies(raw,profile,owner)
    bindings[str(source)]=hashlib.sha256(raw).hexdigest();count[0]+=1;owner.require(count[0]<=32,'CONFIGURATION_FILE_COUNT_BOUND')
 return scan,bindings

def prove_empty_provider(reader,report,owner):
 # Read the ORIGINAL sealed empty-only owner's proof. Never call restore,
 # revoke, publish, adopt handles, or create authority to pass this gate.
 binding=report['loadedBinding'];profile=reader.parse(reader.sealed(binding['profile'],binding['sha256']))
 source_root=Path(binding['source']).parents[1]
 for name,expected in profile['sourceHashes'].items():reader.sealed(source_root/name,expected)
 coordinated=reader.parse(reader.sealed(profile['coordinatedConfiguration'],profile['coordinatedConfigurationHash']))
 boot=reader.parse(reader.sealed(profile['bootConfiguration'],profile['bootConfigurationHash']))
 owner.require(boot['kernel']==coordinated['kernel']and boot['nftPath']==coordinated['nftPath']and boot['lockFile']==coordinated['commonLockFile']and boot['journalFile']!=coordinated['journalFile'],'NATIVE_PROFILE_PAIR_CHANGED')
 journal=reader.parse(reader.read(coordinated['journalFile']))
 owner.require(set(journal)=={'schema',*coordinated['binding'],'state','leaseAuthorized','startAuthorized','leaseAddresses'}and journal['schema']=='ouf.semantic-lease-coordination.v1'and all(journal[k]==v for k,v in coordinated['binding'].items()),'NATIVE_OWNER_JOURNAL_BINDING_REQUIRED')
 owner.require(journal['state']in('QUIESCED','BLOCKED')and journal['leaseAuthorized']is False and journal['startAuthorized']is False,'NATIVE_PROVIDER_AUTHORITY_MUST_REMAIN_REVOKED')
 owner.require(type(journal['leaseAddresses'])is list and len(journal['leaseAddresses'])==len(coordinated['kernel']['providerFlows'])and all(type(row)is list and not row for row in journal['leaseAddresses']),'NATIVE_EMPTY_LEASE_RECEIPTS_REQUIRED')
 empty=reader.parse(reader.read(boot['journalFile']))
 owner.require(empty.get('schema')=='ouf.semantic-runtime-transition.v1'and empty.get('state')=='RUNTIME_EMPTY'and empty.get('startAuthorized')is False and empty.get('transactionId')==boot['transactionId']and empty.get('configurationHash')==profile['bootConfigurationHash'],'NATIVE_EMPTY_TRANSITION_BINDING_REQUIRED')
 native=reader.load_known(Path(profile['bootGuardFile']),profile['bootGuardHash'],'verified_empty_provider_read_only')
 native.validate(boot)
 owner.require(native.membership(boot)=={'inet','bridge'},'NATIVE_EMPTY_TABLE_PAIR_REQUIRED')
 tables=native.tables(boot)
 owner.require(native.footprint(tables)==boot['expectedFootprint']and native.sets_empty(tables),'NATIVE_EMPTY_KERNEL_PROOF_REQUIRED')
 owner.require(reader.parse(reader.read(coordinated['journalFile']))==journal and reader.parse(reader.read(boot['journalFile']))==empty,'NATIVE_JOURNAL_CHANGED_DURING_EMPTY_PROOF')
 return {'ownerState':journal['state'],'emptyKernelProven':True,'providerStartAllowed':False,'nativeReconciliationStillRequired':journal['state']=='BLOCKED'}

def provider_guard(reader,selection,owner):
 report=reader.collect(selection)
 owner.require(report.get('readComplete')and report.get('knownBootSource')and report.get('compilerMatchesProfile')and report.get('restorerMatchesProfile')and report.get('nftExecutableMatches'),'NATIVE_BOOT_CLOSURE_REQUIRED')
 owner.require(report['units'][selection['dockerUnit']]['ActiveState']=='active'and report['units'][selection['guardUnit']]['Result']=='success','NATIVE_DOCKER_GUARD_NOT_SUCCESSFUL')
 for name in ('ownerJournal','bootJournal'):owner.require(report[name]['passed'],'NATIVE_JOURNAL_READ_REQUIRED')
 current=report['ownerJournal']['metadata'];empty=report['bootJournal']['metadata']
 owner.require(current.get('leaseAuthorized')is False and current.get('startAuthorized')is False and current.get('state')in('QUIESCED','BLOCKED')and empty.get('startAuthorized')is False and empty.get('state')=='RUNTIME_EMPTY','PROVIDER_MUST_REMAIN_QUIESCED')
 owner.require(all(value.get('passed')and value.get('metadata',{}).get('matches')is True for value in report['ownerSourceHashesMatch'].values())and report['ownerSourceHashesMatch'],'NATIVE_OWNER_SOURCE_CLOSURE_REQUIRED')
 owner.require(all(report[name].get('passed')and report[name].get('metadata')is True for name in ('nativeOwnerReadConfiguration','nativeBootValidation')),'NATIVE_PURE_VALIDATION_REQUIRED')
 report['emptyProviderProof']=prove_empty_provider(reader,report,owner)
 return report

def run(owner,reader,contracts,profile,selection,contract_selection,parent,pointer):
 owner.require(os.geteuid()==os.getegid()==0,'HOST_ADMINISTRATOR_REQUIRED');owner.validate_profile(profile)
 parent=Path(parent);pointer=Path(pointer)
 # Existing metadata reader checks non-writable root ancestry and exact files.
 for directory in (parent,pointer.parent):
  for item in (directory,*directory.parents):
   info=item.lstat();owner.require(stat.S_ISDIR(info.st_mode)and info.st_uid==0 and not info.st_mode&0o022,'ROOT_PRIVATE_PARENT_REQUIRED')
 owner.require(not os.path.lexists(pointer),'INCIDENT_EXISTS_RECONCILE_DO_NOT_RELAUNCH')
 native=provider_guard(reader,selection,owner);owner.require(native['loadedBinding']['profile']==contract_selection['bootProfile']['path']and native['loadedBinding']['sha256']==contract_selection['bootProfile']['sha256'],'PREBOOT_NATIVE_PROFILE_CHANGED');boot=reader.parse(reader.sealed(native['loadedBinding']['profile'],native['loadedBinding']['sha256']))
 coordinated=reader.parse(reader.sealed(boot['coordinatedConfiguration'],boot['coordinatedConfigurationHash']))
 lock=Path(coordinated['commonLockFile']);fd=os.open(lock,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK);case=None;record=None
 try:
  info=os.fstat(fd);owner.require(stat.S_ISREG(info.st_mode)and info.st_uid==info.st_gid==0 and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600,'COMMON_LOCK_CUSTODY_REQUIRED');fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  owner.require(not os.path.lexists(pointer),'INCIDENT_EXISTS_RECONCILE_DO_NOT_RELAUNCH')
  owner.require((lock.lstat().st_dev,lock.lstat().st_ino)==(info.st_dev,info.st_ino),'COMMON_LOCK_REPLACED')
  provider_guard(reader,selection,owner)
  historical=contracts.collect(contract_selection);owner.require(historical['complete'],'SEALED_PREBOOT_INPUTS_REQUIRED')
  private=contracts.read(contract_selection['preparedPlan']);api=owner.Engine(profile['socketPath'],profile['engineVersion'])
  for role,before in private['beforeApplications'].items():
   actual=api.get('/containers/'+before['Id']+'/json');owner.require(owner.immutable(actual)==owner.immutable(before),'PREBOOT_APPLICATION_CONFIGURATION_CHANGED')
  scan,files=configuration_scanner(reader,profile,owner);plan=owner.compile_plan(profile,api,scan)
  # Source profile and route data are untouched. This is a new host-admin plan,
  # with current process/engine/endpoint bindings, not reuse of prior authority.
  plan['configurationFileBindings']=files;plan['prebootPreparedBinding']=contract_selection['preparedPlan'];plan['nativeBootBinding']=native['loadedBinding'];plan['engineSocketBinding']=list(api.pin)
  case=Path(tempfile.mkdtemp(prefix='host-network-reconciliation-',dir=parent));case.chmod(0o700)
  atomic(case/'plan.json',plan,owner);plan_hash=hashlib.sha256((case/'plan.json').read_bytes()).hexdigest()
  record={'schema':'ouf.host-network-reconciliation-journal.v1','state':'PREPARED','planSha256':plan_hash,'createdAt':int(time.time()),'maximumEngineWrites':2*len(profile['moves'])+1,'claims':[],'runtimeAuthorityIssued':False}
  atomic(case/'journal.json',record,owner)
  ref={'schema':'ouf.host-network-reconciliation-incident.v1','contextPath':str(case),'planSha256':plan_hash}
  claim_fd=os.open(pointer,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(claim_fd,'wb')as stream:stream.write(owner.encoded(ref));stream.flush();os.fsync(stream.fileno())
  directory=os.open(pointer.parent,os.O_RDONLY|os.O_DIRECTORY)
  try:os.fsync(directory)
  finally:os.close(directory)
  print(json.dumps({'check':'REVIEWED_HOST_NETWORK_SCOPE','contextPath':str(case),'planSha256':plan_hash,'moves':[{'name':m['name'],'from':m['oldIPv4'],'to':m['newIPv4']}for m in profile['moves']],'retainedApplicationToStart':profile['restart']['name'],'maximumEngineWrites':2*len(profile['moves'])+1,'configurationFilesRead':len(files),'credentialValuesPrinted':False,'existingRequestsMayFailTransiently':True,'providerStartAllowed':False},sort_keys=True),flush=True)
  def claim(name,request):
   owner.require(record['state']not in ('COMPLETE','STOPPED')and len(record['claims'])<record['maximumEngineWrites'],'DURABLE_OPERATION_BUDGET_EXHAUSTED')
   owner.require(name not in[c['name']for c in record['claims']],'WRITE_ALREADY_CLAIMED')
   for path,expected in files.items():owner.require(hashlib.sha256(configuration_bytes(path,profile,owner)).hexdigest()==expected,'CONFIGURATION_FILE_CHANGED')
   record['state']=name+'_INTENT';record['claims'].append({'name':name,'requestSha256':owner.digest(request)});atomic(case/'journal.json',record,owner)
  result=owner.apply(plan,api,claim)
  after=provider_guard(reader,selection,owner);owner.require(after['loadedBinding']==native['loadedBinding'],'NATIVE_BOOT_BINDING_CHANGED')
  record['state']='COMPLETE';atomic(case/'journal.json',record,owner);result.update(contextPath=str(case),planSha256=plan_hash);return result
 except Exception as error:
  if record is not None:
   record.update(failedPhase=record['state'],state='STOPPED',errorClass=type(error).__name__,reconciliationRequired=True);atomic(case/'journal.json',record,owner)
  if record is not None:return {'schema':'ouf.host-network-reconciliation-result.v1','complete':False,'contextPath':str(case),'phase':record['failedPhase'],'writesClaimed':len(record['claims']),'errorClass':type(error).__name__,'exceptionMessagePrinted':False,'reconciliationRequired':True,'automaticRetry':False,'runtimeAuthorityIssued':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
  raise
 finally:os.close(fd)
