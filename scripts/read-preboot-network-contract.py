#!/usr/bin/env python3
"""Read sealed preboot network contracts without authority, imports or mutations."""
import hashlib,ipaddress,json,os,re,stat,sys,traceback
from pathlib import Path

def require(ok,code):
 if not ok:raise ValueError(code)
def unique(pairs):
 value={}
 for key,item in pairs:require(key not in value,'DUPLICATE_KEY');value[key]=item
 return value
def read(pin):
 path=Path(pin['path']);require(path.is_absolute()and'..'not in path.parts and re.fullmatch('[a-f0-9]{64}',pin['sha256']),'EXACT_BINDING_REQUIRED')
 for parent in (path.parent,*path.parent.parents):
  info=parent.lstat();require(stat.S_ISDIR(info.st_mode)and info.st_uid==0 and not info.st_mode&0o022,'PRIVATE_ANCESTRY_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  first=os.fstat(fd);require(stat.S_ISREG(first.st_mode)and first.st_uid==first.st_gid==0 and first.st_nlink==1 and stat.S_IMODE(first.st_mode)==0o600 and 0<first.st_size<=2097152,'PRIVATE_FILE_REQUIRED')
  raw=os.read(fd,2097153);last=os.fstat(fd);fingerprint=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
  require(len(raw)==first.st_size and fingerprint(first)==fingerprint(last)and hashlib.sha256(raw).hexdigest()==pin['sha256'],'SEALED_BYTES_CHANGED')
  return json.loads(raw,object_pairs_hook=unique)
 finally:os.close(fd)
def ipv4_literals(value):
 """Closed address projection: no field names, URLs, messages or other values."""
 output=set();visited=0
 def visit(node,depth):
  nonlocal visited
  visited+=1;require(visited<=131072 and depth<=32,'STRUCTURE_BOUND')
  if type(node)is dict:
   for key,item in node.items():visit(key,depth+1);visit(item,depth+1)
  elif type(node)is list:
   for item in node:visit(item,depth+1)
  elif type(node)is str:
   for token in re.findall(r'(?<![A-Za-z0-9_.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![A-Za-z0-9_.])',node):
    try:output.add(str(ipaddress.IPv4Address(token)))
    except ipaddress.AddressValueError:pass
 visit(value,0);return sorted(output,key=ipaddress.IPv4Address)
def collect(selection):
 require(set(selection)=={'schema','preparedPlan','bootProfile'}and selection['schema']=='ouf.preboot-network-contract-read-selection.v1','CLOSED_SELECTION_REQUIRED')
 prepared=read(selection['preparedPlan']);require(prepared['schema']=='ouf.source-revision-private-inputs.v1'and prepared['runtimeAuthorityIssued']is False,'AUTHORITY_FREE_INPUT_REQUIRED')
 boot=read(selection['bootProfile']);require(boot['schema']=='ouf.semantic-coordinated-boot-profile.v1','NATIVE_BOOT_PROFILE_REQUIRED')
 owner=read({'path':boot['coordinatedConfiguration'],'sha256':boot['coordinatedConfigurationHash']})
 empty=read({'path':boot['bootConfiguration'],'sha256':boot['bootConfigurationHash']})
 apps={}
 for role,value in prepared['beforeApplications'].items():
  require(role in ('udp','mcp','onboarding')and re.fullmatch('[a-f0-9]{64}',value['Id']),'APPLICATION_SCOPE_CHANGED')
  apps[role]={'containerId':value['Id'],'networkIPv4':ipv4_literals(value['NetworkSettings']['Networks'])}
 projection=json.loads(prepared['gateway']['projectionRaw'],object_pairs_hook=unique)
 return {'schema':'ouf.preboot-network-contract-read.v1','complete':True,'preparedPlan':selection['preparedPlan'],
  'applications':apps,'installationProjectionIPv4':ipv4_literals(projection),
  'gatewayRouteIPv4':ipv4_literals(prepared['gateway']['beforeRoutes']),
  'nativeCoordinatedProfileIPv4':ipv4_literals(owner),'nativeEmptyBootProfileIPv4':ipv4_literals(empty),
  'historicalAddressesAreNotCurrentAuthority':True,'currentTransportReadinessProven':False,
  'nonAddressConfigurationValuesPrinted':False,'networkCoordinatesPrinted':True,'credentialValuesPrinted':False,'credentialFilesRead':0,
  'credentialBearingPreparedInputsRead':1,'runtimeMutations':0,'runtimeAuthorityIssued':False,
  'jobsRetried':0,'profilePublications':0,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
if __name__=='__main__':
 try:
  require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_REQUIRED')
  require(len(sys.argv)==3,'ONE_SEALED_SELECTION_REQUIRED');result=collect(read({'path':sys.argv[1],'sha256':sys.argv[2]}))
 except Exception as error:result={'schema':'ouf.preboot-network-contract-read.v1','complete':False,'errorClass':type(error).__name__,'exceptionMessagePrinted':False,'runtimeMutations':0,'runtimeAuthorityIssued':False,'frames':[{'file':Path(f.filename).name,'function':f.name,'line':f.lineno}for f in traceback.extract_tb(error.__traceback__)[-4:]]}
 print(json.dumps(result,sort_keys=True));sys.exit(0 if result['complete']else 2)
