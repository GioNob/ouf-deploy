"""Finite protected comparison only; no baseline adoption or repair."""
import collections,copy,fcntl,json,os,stat
from pathlib import Path

SECTIONS=('Id','Image','Name','Config','HostConfig','Mounts')
# Only standard Docker field names are displayed. Labels, paths, environment
# entries and other installation-controlled keys/values are never copied out.
FIELDS=set(('Id Image Name Config HostConfig Mounts Hostname Domainname User AttachStdin AttachStdout AttachStderr ExposedPorts Tty OpenStdin StdinOnce Env Cmd Healthcheck ArgsEscaped Image Volumes WorkingDir Entrypoint OnBuild Labels StopSignal StopTimeout Shell MacAddress NetworkMode RestartPolicy Name MaximumRetryCount AutoRemove Privileged Binds ContainerIDFile LogConfig Type Config PortBindings PublishAllPorts Dns DnsOptions DnsSearch ExtraHosts VolumesFrom GroupAdd IpcMode Cgroup CgroupnsMode PidMode UTSMode UsernsMode ShmSize Runtime Isolation CpuShares Memory NanoCpus CgroupParent BlkioWeight BlkioWeightDevice BlkioDeviceReadBps BlkioDeviceWriteBps BlkioDeviceReadIOps BlkioDeviceWriteIOps CpuPeriod CpuQuota CpuRealtimePeriod CpuRealtimeRuntime CpusetCpus CpusetMems Devices DeviceCgroupRules DeviceRequests MemoryReservation MemorySwap MemorySwappiness OomKillDisable OomScoreAdj Init ReadonlyRootfs CapAdd CapDrop SecurityOpt MaskedPaths ReadonlyPaths Sysctls Ulimits PidsLimit Links ConsoleSize VolumeDriver StorageOpt Tmpfs Annotations Source Destination Driver Mode RW Propagation SubPath').split())

def kind(value):return type(value).__name__
def order_only(left,right,owner):
 return type(left)is list and type(right)is list and collections.Counter(owner.encoded(v)for v in left)==collections.Counter(owner.encoded(v)for v in right)

def compare(before,after,owner,maximum=96):
 out=[];total=0;visited=0
 def emit(path,left,right,present_left=True,present_right=True):
  nonlocal total
  total+=1
  if len(out)<maximum:out.append({'path':path,'beforePresent':present_left,'afterPresent':present_right,'beforeType':kind(left)if present_left else'absent','afterType':kind(right)if present_right else'absent'})
 def walk(left,right,path,depth=0):
  nonlocal visited
  visited+=1;owner.require(visited<=131072 and depth<=24,'COMPARISON_STRUCTURE_BOUND')
  if owner.encoded(left)==owner.encoded(right):return
  if type(left)is dict and type(right)is dict:
   for index,key in enumerate(sorted(set(left)|set(right))):
    name=key if key in FIELDS else'<field-'+str(index)+'>'
    child=path+'.'+name
    if key not in left or key not in right:emit(child,left.get(key),right.get(key),key in left,key in right)
    elif key in ('Env','Labels','Volumes','ExposedPorts','PortBindings','Binds','Cmd','Entrypoint','Healthcheck','Sysctls','Annotations','StorageOpt','Tmpfs','LogConfig'):emit(child,left[key],right[key])if owner.encoded(left[key])!=owner.encoded(right[key])else None
    else:walk(left[key],right[key],child,depth+1)
  elif type(left)is list and type(right)is list:
   if len(left)!=len(right):emit(path+'.length',None,None)
   if order_only(left,right,owner):emit(path+'.order',left,right);return
   for index,(a,b)in enumerate(zip(left,right)):walk(a,b,path+'['+str(index)+']',depth+1)
  else:emit(path,left,right)
 for key in SECTIONS:
  if key not in before or key not in after:emit(key,before.get(key),after.get(key),key in before,key in after)
  else:walk(before[key],after[key],key)
 return {'immutableMatches':owner.immutable(before)==owner.immutable(after),'differenceCount':total,'differences':out,'truncated':total>len(out),'sections':{k:{'equal':owner.encoded(before.get(k))==owner.encoded(after.get(k)),'orderOnly':order_only(before.get(k),after.get(k),owner)}for k in SECTIONS},'valuesPrinted':False,'unknownFieldNamesPrinted':False}

def run(owner,reader,contracts,bootstrap,selection,contract_selection,profile,execution):
 owner.require(os.geteuid()==os.getegid()==0,'HOST_ADMINISTRATOR_REQUIRED');owner.validate_profile(profile)
 owner.require(not os.path.lexists(execution['incidentPointer']),'INCIDENT_EXISTS_RECONCILE_WITHOUT_REPLAY')
 native=bootstrap.provider_guard(reader,selection,owner)
 owner.require(native['loadedBinding']['profile']==contract_selection['bootProfile']['path']and native['loadedBinding']['sha256']==contract_selection['bootProfile']['sha256'],'NATIVE_BOOT_PROFILE_CHANGED')
 boot=reader.parse(reader.sealed(native['loadedBinding']['profile'],native['loadedBinding']['sha256']))
 coordinated=reader.parse(reader.sealed(boot['coordinatedConfiguration'],boot['coordinatedConfigurationHash']))
 lock=Path(coordinated['commonLockFile']);fd=os.open(lock,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  info=os.fstat(fd);owner.require(stat.S_ISREG(info.st_mode)and info.st_uid==info.st_gid==0 and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600,'COMMON_LOCK_CUSTODY_REQUIRED');fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  owner.require((lock.lstat().st_dev,lock.lstat().st_ino)==(info.st_dev,info.st_ino),'COMMON_LOCK_REPLACED')
  owner.require(not os.path.lexists(execution['incidentPointer']),'INCIDENT_EXISTS_RECONCILE_WITHOUT_REPLAY')
  fresh=bootstrap.provider_guard(reader,selection,owner);owner.require(fresh['loadedBinding']==native['loadedBinding'],'NATIVE_BOOT_BINDING_CHANGED')
  contracts.collect(contract_selection);private=contracts.read(contract_selection['preparedPlan'])
  owner.require(set(private['beforeApplications'])=={'udp','mcp','onboarding'},'EXACT_THREE_APPLICATIONS_REQUIRED')
  api=owner.Engine(profile['socketPath'],profile['engineVersion']);report={};seen={}
  for role,before in sorted(private['beforeApplications'].items()):
   owner.require(len(before['Id'])==64 and all(c in'0123456789abcdef'for c in before['Id']),'PINNED_APPLICATION_REQUIRED')
   path='/containers/'+before['Id']+'/json';current=api.get(path);latest=api.request('GET',path,None,False)
   owner.require(all(current[k]==before[k]==latest[k]for k in ('Id','Image','Name')),'APPLICATION_IDENTITY_CHANGED')
   report[role]={'containerId':before['Id'],'legacyApi144':compare(before,current,owner),'currentServerApi':compare(before,latest,owner),'currentRepresentationsMatch':owner.immutable(current)==owner.immutable(latest),'running':current['State']['Running']}
   seen[role]=copy.deepcopy(current)
  for role,before in private['beforeApplications'].items():owner.require(owner.immutable(api.get('/containers/'+before['Id']+'/json'))==owner.immutable(seen[role]),'APPLICATION_CHANGED_DURING_DIAGNOSIS')
  owner.require(not os.path.lexists(execution['incidentPointer']),'INCIDENT_APPEARED_DURING_DIAGNOSIS')
  return {'schema':'ouf.preboot-application-configuration-difference.v1','complete':True,'applications':report,'providerProof':fresh['emptyProviderProof'],'maximumContainerReads':9,'baselineAdopted':False,'incidentPointerPresent':False,'runtimeMutations':0,'engineWrites':0,'runtimeAuthorityIssued':False,'credentialValuesPrinted':False,'configurationValuesPrinted':False,'automaticRetry':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
 finally:os.close(fd)
