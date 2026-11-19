#!/usr/bin/env python3
"""Summarize retained before/after-stop evidence and inspect the old container once.
No SQL, start/stop, image load, credentials, payload emission or file mutation.
"""
import hashlib,json,os,re,stat,subprocess,sys
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path('/var/lib/ouf-storage-migration/ingestion-wide-upgrade-20261108')
CID='d69c3f763d75f8c8f8db382fef0159a4dd5a3b99ee62ae8737a24421f4285c14'
IMAGE='sha256:d173aa8beeb9a1ac29c35a163e254a902e95fedad2871e328886a41831c10697'
TABLES=('ing_run','ing_partition','processing_attempt','ing_lineage','handoff_outbox','runtime_configuration_snapshot','ing_schedule')
JOURNAL=('attempt.json','image-load-intent.json','stop-intent.json','stopped.private.json','detach-intent.json','detached.private.json','rename-intent.json','create-intent.json','created.json','gate-start-intent.json','application-start-intent.json','complete.json')
FIELDS=('version','checksum','success','type','installedRank','installedOn')
def need(ok,code):
 if not ok:raise RuntimeError(code)
def read(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as f:
  st=os.fstat(f.fileno());need(stat.S_ISREG(st.st_mode) and st.st_size<=2097152,'BOUNDED_REGULAR_EVIDENCE_REQUIRED');b=f.read(2097153)
 need(len(b)<=2097152,'EVIDENCE_TOO_LARGE');return b

def validate(v):
 need(v.get('readOnly') is True and str(v.get('databaseOid'))=='21554' and v.get('applicationRoleSuperuser') is False,'OBSERVED_DATABASE_REQUIRED')
 rows=v.get('migrations');need(isinstance(rows,list) and len(rows)<=32,'HISTORY_SHAPE')
 for x in rows:
  need(set(x)==set(FIELDS) and (x['version'] is None or re.fullmatch('[0-9]{1,3}',str(x['version']))) and
    (x['checksum'] is None or type(x['checksum'])is int) and type(x['success'])is bool and x['type'] in ('SCHEMA','SQL','BASELINE') and
    type(x['installedRank'])is int and re.fullmatch('[0-9T:.+ -]{10,40}',x['installedOn']),'HISTORY_SHAPE')
 need(len({x['installedRank'] for x in rows})==len(rows),'DUPLICATE_HISTORY_RANK')
 a=v.get('activity');need(isinstance(a,dict) and set(a)=={'runStates','handoffStates','unexpiredPartitionLeases'},'ACTIVITY_SHAPE')
 for name,states in [('runStates',{'READY','PREFLIGHT','RUNNING','DRAINING','SUCCEEDED','FAILED','PAUSED','OTHER'}),('handoffStates',{'READY','DELIVERING','ACKED','FAILED_RETRYABLE','FAILED_TERMINAL','OTHER'})]:
  need(isinstance(a[name],dict) and set(a[name])<=states and all(type(n)is int and n>=0 for n in a[name].values()),'ACTIVITY_SHAPE')
 need(type(a['unexpiredPartitionLeases'])is int and a['unexpiredPartitionLeases']>=0,'ACTIVITY_SHAPE')
 t=v.get('retainedRows');need(isinstance(t,dict) and set(t)==set(TABLES),'TABLE_FINGERPRINT_SHAPE')
 for x in t.values():need(set(x)=={'rows','fingerprint'} and type(x['rows'])is int and x['rows']>=0 and re.fullmatch('[a-f0-9]{32}',x['fingerprint']),'TABLE_FINGERPRINT_SHAPE')
def compare(before,after):
 validate(before);validate(after)
 sections=[k for k in ('migrations','activity','retainedRows') if before[k]!=after[k]]
 b={x['installedRank']:x for x in before['migrations']};a={x['installedRank']:x for x in after['migrations']}
 history=[]
 for rank in sorted(set(b)|set(a)):
  x,y=b.get(rank),a.get(rank)
  if x!=y:history.append({'installedRank':rank,'beforeVersion':None if x is None else x['version'],'afterVersion':None if y is None else y['version'],
   'change':'ADDED' if x is None else 'REMOVED' if y is None else 'CHANGED',
   'changedFields':[k for k in FIELDS if x is None or y is None or x[k]!=y[k]]})
 tables={t:{'rowsBefore':before['retainedRows'][t]['rows'],'rowsAfter':after['retainedRows'][t]['rows'],
  'rowCountChanged':before['retainedRows'][t]['rows']!=after['retainedRows'][t]['rows'],
  'fingerprintChanged':before['retainedRows'][t]['fingerprint']!=after['retainedRows'][t]['fingerprint']} for t in TABLES}
 return {'changedSections':sections,'migrationHistoryUnchanged':before['migrations']==after['migrations'],'migrationChanges':history,
  'activityBefore':before['activity'],'activityAfterStop':after['activity'],'tableComparisons':tables,
  'changedTables':[t for t in TABLES if before['retainedRows'][t]!=after['retainedRows'][t]],
  'rowIdentifiersPayloadsAndCheckpointsRead':False,'rowFingerprintsEmitted':False,
  'scope':'RETAINED_SUMMARIES_ONLY_NOT_NEW_DATABASE_QUERY','causeOfChangesProven':False}
def inspect_old():
 p=subprocess.run(('/usr/bin/docker','--host','unix:///run/docker.sock','--config','/nonexistent','inspect','--type','container',CID),capture_output=True,timeout=12)
 need(p.returncode==0 and len(p.stdout)<=2097152,'CURRENT_CONTAINER_INSPECT_FAILED');v=json.loads(p.stdout);need(isinstance(v,list) and len(v)==1,'INSPECT_SHAPE');return v[0]
def runtime(old,stopped,current):
 need(all(v.get('Id')==CID and v.get('Image')==IMAGE for v in (old,stopped,current)),'EXACT_OLD_CONTAINER_REQUIRED')
 s=current['State']
 need(type(s.get('Running'))is bool and type(s.get('Pid'))is int and type(s.get('ExitCode'))is int and type(s.get('OOMKilled'))is bool,'RUNTIME_STATE_SHAPE')
 return {'read':True,'running':s['Running'],'pidZero':s['Pid']==0,'exitCode':s['ExitCode'],'oomKilled':s['OOMKilled'],
  'sameGenerationAsStoppedRecord':s.get('StartedAt')==stopped['State'].get('StartedAt'),
  'sameNameAsStoppedRecord':current.get('Name')==stopped.get('Name'),
  'configMatchesStoppedRecord':current.get('Config')==stopped.get('Config'),
  'hostConfigMatchesStoppedRecord':current.get('HostConfig')==stopped.get('HostConfig'),
  'mountsMatchStoppedRecord':current.get('Mounts')==stopped.get('Mounts'),
  'launchMatchesStoppedRecord':all(current.get(k)==stopped.get(k) for k in ('Path','Args')),
  'networksMatchStoppedRecord':current['NetworkSettings']['Networks']==stopped['NetworkSettings']['Networks'],
  'networkCount':len(current['NetworkSettings']['Networks']),
  'retainedStoppedRecordConfirmsStop':stopped['State'].get('Running') is False and stopped['State'].get('Pid')==0,
  'configMatchesBeforeStop':current.get('Config')==old.get('Config')}
def collect(report,root=ROOT,inspector=inspect_old):
 names=('before-database.private.json','stopped-database.private.json','old.private.json','stopped.private.json')
 raw={n:read(root/n) for n in names};report['retainedFilesRead']=len(raw)
 report['databaseComparison']=compare(json.loads(raw[names[0]]),json.loads(raw[names[1]]))
 report['journalFilesPresent']={n:(root/n).exists() for n in JOURNAL}
 report['currentReplacementMarkerPresent']=(root.parent/'ingestion-wide-current.json').exists()
 report['dockerInspectAttempts']=1
 try:report['oldContainer']=runtime(json.loads(raw[names[2]]),json.loads(raw[names[3]]),inspector())
 except Exception as e:
  report['oldContainer']={'read':False,'reason':str(e) if type(e)is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}',str(e)) else type(e).__name__}
 need(all(read(root/n)==v for n,v in raw.items()),'EVIDENCE_CHANGED_DURING_READ');report['retainedFilesUnchangedDuringRead']=True
 report['status']='INGESTION_HELD_STATE_READ_COMPLETE' if report['oldContainer']['read'] else 'READ_PARTIAL'
def main():
 r={'schema':'ouf.ingestion-wide-held-state-read.v1','status':'READ_INCOMPLETE','retainedFilesRead':0,'dockerInspectAttempts':0,
  'databaseRequests':0,'credentialFilesRead':0,'credentialValuesEmitted':False,'serviceConfigurationChanged':False,
  'serviceStartDispatched':False,'serviceStops':0,'imageImports':0,'businessRequestsIssued':0,'s3Requests':0,
  'evidenceFilesModified':False,'rawLogsEmitted':False}
 try:
  need(os.geteuid()==0 and sys.flags.isolated,'ISOLATED_ROOT_REQUIRED');collect(r)
 except Exception as e:r['reason']=str(e) if type(e)is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}',str(e)) else type(e).__name__
 r['observedAt']=datetime.now(timezone.utc).isoformat();print(json.dumps(r,sort_keys=True))
if __name__=='__main__':main()
