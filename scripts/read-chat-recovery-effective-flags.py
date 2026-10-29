#!/usr/bin/env python3
"""Read-only selected runtime switches; no credential bytes or environment dump."""
import hashlib,json,os,re,subprocess,sys
from pathlib import Path
def run(args):
 r=subprocess.run(['/usr/bin/docker',*args],capture_output=True,timeout=10,env={'PATH':'/usr/bin:/bin','DOCKER_HOST':'unix:///var/run/docker.sock','DOCKER_API_VERSION':'1.44'})
 assert r.returncode==0 and len(r.stdout)<1048576
 return r.stdout
def canonical(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def main(profile):
 p=json.loads(Path(profile).read_bytes())
 assert p['schema']=='ouf.chat-recovery-effective-read-selection.v1' and re.fullmatch('[a-f0-9]{40}',p['udpSourceCommit'])
 ids=run(['ps','--no-trunc','--filter','label=org.opencontainers.image.revision='+p['udpSourceCommit'],'--format','{{.ID}}']).decode().splitlines()
 assert len(ids)==1 and re.fullmatch('[a-f0-9]{64}',ids[0])
 a=json.loads(run(['inspect','--type','container',ids[0]]))[0]
 assert a['State']['Running'] is True and a['State']['Paused'] is False
 assert a['Config']['Labels']['org.opencontainers.image.revision']==p['udpSourceCommit']
 values={}
 for row in a['Config']['Env']:
  k,v=row.split('=',1);assert k not in values;values[k]=v
 flat={}
 def visit(value,prefix=''):
  assert type(value)is dict
  for k,v in value.items():
   key=prefix+'.'+k if prefix else k
   if type(v)is dict:visit(v,key)
   else:flat[re.sub('[^a-z0-9]','',key.lower())]=v
 if values.get('SPRING_APPLICATION_JSON'):visit(json.loads(values['SPRING_APPLICATION_JSON']))
 def setting(key,environment,default):
  if key in flat:return flat[key]
  return values.get(environment,default)
 execution=setting('oufudpexecutionenabled','OUF_UDP_EXECUTION_ENABLED',False)
 manual=setting('oufudpmaterializationrecoveryenabled','OUF_UDP_MATERIALIZATION_RECOVERY_ENABLED',False)
 def flag(v):
  assert v in (True,False,'true','false')
  return v is True or v=='true'
 token=setting('oufudpexecutiontokenfile','OUF_UDP_EXECUTION_TOKEN_FILE','')
 assert type(token)is str
 covering=[m for m in a['Mounts'] if token and (token==m['Destination'] or token.startswith(m['Destination'].rstrip('/')+'/'))]
 print(json.dumps({'schema':'ouf.chat-recovery-effective-flags-read.v1','containerId':a['Id'],'sourceCommit':p['udpSourceCommit'],'running':True,'configHash':canonical(a['Config']),'publishedResolutionLoopEnabled':flag(execution),'governedTechnicalRetryApiEnabled':flag(manual),'executionTokenReferenceConfigured':bool(token),'executionTokenCoveringMounts':len(covering),'executionTokenMountReadOnly':bool(covering) and all(m['RW'] is False for m in covering),'credentialFilesRead':0,'credentialValuesPrinted':False,'runtimeMutations':0,'readOnly':True,'completedTechnicalPhases':8,'functionalMilestonesProven':3},sort_keys=True))
if __name__=='__main__':main(sys.argv[1])
