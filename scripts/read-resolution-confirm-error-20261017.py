import hashlib,json,os,re,stat,subprocess
from pathlib import Path
context=Path('/etc/ouf/deploy-snapshots/resolution-comparison-execution-fdqv48fp')
def record():
 fd=os.open(context/'recovery.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd)
  assert stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_nlink==1 and 0<before.st_size<=262144
  raw=os.read(fd,262145)
  pin=lambda x:tuple(getattr(x,k)for k in ("st_dev","st_ino","st_mode","st_uid","st_gid","st_nlink","st_size","st_mtime_ns","st_ctime_ns"))
  assert len(raw)==before.st_size and pin(os.fstat(fd))==pin(before)
  row=json.loads(raw)
  assert row['version']==51 and row['incidentState']=='RECOVERED' and row['nextStage']==20
  return row,hashlib.sha256(raw).hexdigest()
 finally:os.close(fd)
row,binding=record()
markers=['HttpMessageNotReadableException','Required request body is missing','Cannot deserialize','Invalid UUID','UDP_REVIEW_PACKAGE_INVALID','UDP_REASON_REQUIRED','UDP_TARGET_NOT_A_CANDIDATE','UDP_NEW_IDENTITY_DECISION_INVALID','UDP_NEW_IDENTITY_EVIDENCE_STALE','UDP_GOVERNED_EVIDENCE_STALE','HttpMediaTypeNotSupportedException','RequestRejectedException','Invalid CSRF','CSRF token','THS session unavailable','invalid_redirect_uri']
for module in ('onboarding','udp'):
 cid=row['effects'][-1]['evidence']['applications'][module]['runtimeBinding']['containerId']
 assert re.fullmatch('[0-9a-f]{64}',cid)
 result=subprocess.run(['/usr/bin/docker','logs','--since','2h','--tail','400',cid],capture_output=True,timeout=12,check=False)
 log=result.stdout+result.stderr
 assert len(log)<=8388608
 text=log.decode('utf-8','replace')
 print(json.dumps({'module':module,'readOnly':True,'logReadSucceeded':result.returncode==0,'markerCounts':{m:text.count(m)for m in markers},'rawLogsPrinted':False,'diagnosisFromMarkerAlone':False},sort_keys=True))
assert record()[1]==binding
print(json.dumps({'complete':True,'readOnly':True,'retainedRecordStable':True,'confirmCalls':0,'serviceMutations':0,'credentialValuesPrinted':False}))
