"""One reviewed local CAS publication. Network guards stay outside the publisher lock."""
import copy,fcntl,hashlib,os,re,stat
from pathlib import Path
from tools.installation_binding_apply.native import OwnerHttp,Ports as ExistingPorts,baseline_runtime
from tools.chatbot_file_cohort.gateway import private_config
from tools.ingestion_read_gateway_custody.owner import metadata_file
from tools.ingestion_profile_publication.owner import require,digest,scope,scope_key,STAGES,KIND

def publish(binding,raw,logical_ref,local_guard):
 path=Path(binding['path']);require(path.is_absolute()and path.resolve()==path and path.name=='active-projection.json'
  and re.fullmatch('[0-9a-f]{64}',logical_ref),'EXACT_PROJECTION_PUBLICATION_TARGET_REQUIRED')
 private_config(path,binding);parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 lock=None;target=None;temporary=path.name+'.ouf-'+logical_ref[:24]+'.tmp'
 try:
  lock=os.open('.ouf-active-projection.publish.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600,dir_fd=parent)
  s=os.fstat(lock);require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1,'ROOT_PUBLISHER_LOCK_REQUIRED')
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);local_guard()
  old,_=private_config(path,binding);require(hashlib.sha256(old).hexdigest()==binding['sha256'],'ACTIVE_PROJECTION_CAS_PRECONDITION_FAILED')
  target=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
  with os.fdopen(os.dup(target),'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
  private_config(path,binding);local_guard()
  os.replace(temporary,path.name,src_dir_fd=parent,dst_dir_fd=parent);os.fsync(parent)
  actual,new_binding=private_config(path)
  require(actual==raw,'APPROVED_CUSTODY_PUBLICATION_READBACK_FAILED')
  return new_binding
 finally:
  if target is not None:os.close(target)
  if lock is not None:os.close(lock)
  os.close(parent)

class Ports(ExistingPorts):
 def guard_current(self,stage,row):
  require(stage in STAGES[KIND],'CLOSED_PROJECTION_STAGE_REQUIRED')
  self.action.guard(scope_key(self.plan['kind']),scope(self.plan));require(self.human.current()==self.plan['humanBinding'],'SAME_CURRENT_VERIFIED_HUMAN_REQUIRED')
  for name,pin in self.plan['currentApplications'].items():
   status,actual=self.engine.request('GET','/v1.44/containers/'+pin['containerId']+'/json')
   require(status==200 and baseline_runtime(actual,name,self.plan)==pin,'INDEPENDENT_RUNTIME_GENERATION_CHANGED')
  for binding in self.plan['retainedMcpMetadata']:metadata_file(binding)
  require(self.http.active()==self.plan['expectedActive'],'OWNER7_ACTIVE_CHANGED')
  applied=self.evidence(row,'PUBLISH_ACTIVE_PROJECTION')
  expected=applied['publishedBinding']if applied else self.plan['projectionBinding']
  raw,_=private_config(expected['path'],expected)
  require(hashlib.sha256(raw).hexdigest()==(self.plan['projectionHash']if applied else expected['sha256']),'EXACT_PUBLICATION_STATE_REQUIRED')
  require(self.gateway.routes()==self.plan['gateway']['beforeRoutes'],'ALL82_ROUTES_MUST_REMAIN_UNCHANGED')
 def apply(self,stage,row):
  require(stage in STAGES[KIND],'CLOSED_PROJECTION_EFFECT_REQUIRED')
  if stage=='PUBLISH_ACTIVE_PROJECTION':
   from tools.installation_binding_apply.baseline import read
   raw=read(self.plan['exportedProjectionBinding']['path'],self.plan['projectionHash'])
   binding=publish(self.plan['projectionBinding'],raw,self.plan['logicalRef'],lambda:self.action.guard(scope_key(KIND),scope(self.plan)))
   return {'publishedBinding':binding,'projectionHash':self.plan['projectionHash']}
  return {'verified':True}
 def verify(self,stage,row,evidence):
  effects=copy.deepcopy(row['effects']);effects[-1].update(state='APPLIED',evidence=evidence)
  self.guard_current(stage,{**row,'effects':effects})
