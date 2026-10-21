#!/usr/bin/env python3
"""Read bounded host metadata only. No lock, DNS, credentials, lifecycle or apply."""
import hashlib,json,os,pathlib,stat,subprocess

CONTAINERS={
 "semantic":"7ae83be8c1fe9fe25774b7d748e35153652b29b2501886f89daeabb83bd1a147",
 "adapter":"f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67",
 "southbound":"1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916"}
SNAPSHOTS=[
 "/etc/ouf/deploy-snapshots/semantic-discovery-runtime-inputs-682nr5ky",
 "/etc/ouf/deploy-snapshots/semantic-discovery-java-trust-4pgerb71",
 "/etc/ouf/deploy-snapshots/semantic-discovery-protected-bindings-qb3381ho",
 "/etc/ouf/deploy-snapshots/semantic-discovery-runtime-declaration-nfggulwg",
 "/etc/ouf/deploy-snapshots/semantic-dns-recovery-r9-hkv5exgo"]
FMT="{{.Id}}|{{.Image}}|{{.State.Pid}}|{{.State.StartedAt}}|{{.State.Status}}|{{.Config.User}}|{{.HostConfig.RestartPolicy.Name}}"
def native():
 result={}
 for role,cid in CONTAINERS.items():
  p=subprocess.run(["docker","inspect","--type","container","--format",FMT,cid],capture_output=True,text=True,timeout=15)
  if p.returncode:
   result[role]={"present":False,"exitCode":p.returncode}
   continue
  v=p.stdout.strip().split("|")
  if len(v)!=7 or v[0]!=cid:
   raise ValueError("NATIVE_METADATA_SHAPE_DENIED")
  pid=int(v[2]);generation={}
  if pid>0:
   process=pathlib.Path("/proc",str(pid))
   fields=(process/"stat").read_text().rsplit(")",1)[1].split()
   generation={"pid":pid,"startTicks":int(fields[19]),"networkNamespaceInode":(process/"ns/net").stat().st_ino}
  result[role]={"present":True,"containerId":v[0],"imageId":v[1],"status":v[4],
                "user":v[5],"restartPolicy":v[6],"generation":generation,
                "metadataHash":hashlib.sha256(p.stdout.encode()).hexdigest()}
 return result
def main():
 if os.geteuid()!=0:
  raise SystemExit("OPERATOR_SUDO_REQUIRED")
 first=native()
 snapshots=[]
 for name in SNAPSHOTS:
  path=pathlib.Path(name)
  try:
   info=path.lstat()
   valid=stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022
   snapshots.append({"path":name,"present":True,"rootOwnedDirectoryNotGroupWorldWritable":valid,
                     "mode":oct(stat.S_IMODE(info.st_mode))})
  except FileNotFoundError:
   snapshots.append({"path":name,"present":False})
 service=subprocess.run(["systemctl","show","ouf-semantic-provider-lease-dns-r9.service",
        "--property=LoadState,ActiveState,SubState,MainPID,NRestarts,Restart,InvocationID,Result"],
        capture_output=True,text=True,timeout=15)
 properties={}
 for line in service.stdout.splitlines():
  if "=" in line:
   key,value=line.split("=",1);properties[key]=value
 second=native()
 print("OUF_FILE_LOOP_PACKAGE_HOST_READ="+json.dumps({
  "schema":"ouf.file-loop.package-host-metadata-read.v1",
  "status":"HOST_METADATA_CAPTURED_NOT_TRANSITION_AUTHORITY",
  "containerMetadataStable":first==second,"containers":second,
  "historicalSnapshotDirectories":snapshots,"r9ServiceMetadata":properties,
  "r9ServiceReadExit":service.returncode,"r9LeaseOrApplicationHealthProven":False,
  "completeHostOciProven":False,"readConsistencyMode":"STABLE_REREADS_NOT_ATOMIC_AUTHORITY",
  "commonLockAcquired":False,"privateKeysRead":0,"credentialFilesOpened":0,
  "privateSnapshotFilesOpened":0,"privateValuesPrinted":False,"signaturesIssued":0,
  "dnsQueries":0,"providerCalls":0,"containerLifecycleOperations":0,
  "imageImports":0,"existingConfigurationWrites":0,"firewallWrites":0,
  "databaseWrites":0,"r9Touched":False,"applyAuthorized":False,
  "notReleaseAcceptance":True},sort_keys=True))
if __name__=="__main__":
 main()
