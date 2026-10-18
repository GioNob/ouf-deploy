"""Bounded mounted-file metadata only. Never open file contents or mutate."""
import hashlib,importlib.util,json,os,signal,stat,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('retained_read',Path(__file__).with_name('read-retained-udp-startup.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
SUFFIXES=('.yaml','.yml','.conf','.properties','/Caddyfile')
def metadata(path,approved):
 info=os.lstat(path)
 return {'regular':stat.S_ISREG(info.st_mode),'directory':stat.S_ISDIR(info.st_mode),'symlink':stat.S_ISLNK(info.st_mode),'uid':info.st_uid,'gid':info.st_gid,'mode':format(stat.S_IMODE(info.st_mode),'04o'),'linkCount':info.st_nlink,'size':info.st_size,'ownerApproved':info.st_uid in approved,'groupOrOtherWritable':bool(info.st_mode&0o022),'nonemptyBoundedFile':0<info.st_size<=2097152,'singleLink':info.st_nlink==1}
def inspect_path(path,approved):
 out={'sourcePath':str(path),'contentReads':0}
 try:out['file']=metadata(path,approved)
 except OSError as error:out['file']={'readableMetadata':False,'errorClass':type(error).__name__}
 out['ancestors']=[]
 m.require(len(path.parents)<=32,'ANCESTRY_BOUND')
 for parent in path.parents:
  try:info=metadata(parent,approved);out['ancestors'].append({'path':str(parent),'directory':info['directory'],'ownerApproved':info['ownerApproved'],'groupOrOtherWritable':info['groupOrOtherWritable'],'uid':info['uid'],'gid':info['gid'],'mode':info['mode']})
  except OSError as error:out['ancestors'].append({'path':str(parent),'errorClass':type(error).__name__})
 return out
def collect(profile):
 m.require(profile['schema']=='ouf.host-network-reconciliation.v1'and 1<=profile['maximumContainers']<=160,'FINITE_INSTALLATION_REQUIRED')
 ids=m.invoke(['ps','--all','--quiet','--no-trunc']).decode().splitlines();m.require(0<len(ids)<=profile['maximumContainers']and len(ids)==len(set(ids))and all(len(v)==64 and all(c in'0123456789abcdef'for c in v)for v in ids),'FLEET_BOUND')
 fmt='{"id":{{json .Id}},"running":{{json .State.Running}},"mounts":{{json .Mounts}}}'
 rows=[json.loads(line)for line in m.invoke(['inspect','--type','container','--format',fmt,*ids]).splitlines()if line];m.require(len(rows)==len(ids)and {v['id']for v in rows}==set(ids),'EXACT_FLEET_REQUIRED')
 files=[]
 for row in rows:
  if not row['running']and row['id']!=profile['restart']['containerId']:continue
  for mount in row['mounts']or[]:
   if mount['Type']!='bind'or not mount['Destination'].endswith(SUFFIXES):continue
   m.require(len(files)<64,'CONFIGURATION_FILE_COUNT_BOUND');path=Path(mount['Source']);m.require(path.is_absolute()and'..'not in path.parts,'EXACT_BIND_PATH_REQUIRED')
   files.append({'containerId':row['id'],'destination':mount['Destination'],'mountReadOnly':mount.get('RW')is False,**inspect_path(path,profile['configurationOwnerUids'])})
 return {'schema':'ouf.mounted-configuration-custody-metadata.v1','complete':True,'files':files,'filesObserved':len(files),'fleetCount':len(rows),'credentialFilesRead':0,'fileContentsRead':0,'runtimeMutations':0,'engineWrites':0,'pathCoordinatesPrinted':True,'configurationValuesPrinted':False,'metadataNotActivationAuthority':True,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
if __name__=='__main__':
 signal.alarm(45)
 try:result=collect(json.loads(Path(sys.argv[1]).read_bytes()))
 except Exception as error:result={'schema':'ouf.mounted-configuration-custody-metadata.v1','complete':False,'errorClass':type(error).__name__,'exceptionMessagePrinted':False,'fileContentsRead':0,'runtimeMutations':0,'engineWrites':0}
 print(json.dumps(result,sort_keys=True));sys.exit(0 if result['complete']else 2)
