"""One bounded unprivileged service read. Never reads protected snapshots."""
import hashlib,json,os,pathlib,re,subprocess
UNIT='ouf-semantic-provider-lease-resilient-r12.service'
FIELDS=('LoadState','ActiveState','SubState','MainPID','Restart','NRestarts','Result','ExecMainCode','ExecMainStatus','ExecMainStartTimestampMonotonic','ExecMainExitTimestampMonotonic')
def project(raw):
 if len(raw)>8192:raise ValueError('BOUNDED_SERVICE_READ_REQUIRED')
 rows={}
 for line in raw.decode().splitlines():
  key,sep,value=line.partition('=')
  if sep:
   if key not in FIELDS or key in rows or not re.fullmatch('[A-Za-z0-9_-]{0,64}',value):raise ValueError('SAFE_EXACT_SERVICE_FIELD_REQUIRED')
   rows[key]=value
 if set(rows)!=set(FIELDS):raise ValueError('COMPLETE_SERVICE_PROPERTIES_REQUIRED')
 return rows
def main():
 report={'schema':'ouf.r12-public-service-read.v1','protectedFileReads':0,'protectedFileWrites':0,
  'serviceLifecycleOperations':0,'imageImports':0,'databaseQueries':0,'firewallWrites':0,
  'budgetReset':False,'r12Touched':False,'productionApplyReady':False,'notReleaseAcceptance':True,'privateValuesPrinted':False}
 try:
  p=subprocess.run(['/usr/bin/systemctl','show',UNIT,'--no-pager','--property='+','.join(FIELDS)],stdin=subprocess.DEVNULL,
   stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
  if p.returncode!=0:raise ValueError('SERVICE_READ_UNPROVEN')
  report.update(status='PUBLIC_SERVICE_READ_COMPLETED',service=project(p.stdout))
 except Exception as e:
  reason=str(e);report.update(status='PUBLIC_SERVICE_READ_BLOCKED',reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,120}',reason) else 'PUBLIC_SERVICE_READ_UNPROVEN')
 print('OUF_R12_PUBLIC_SERVICE_READ='+json.dumps(report,sort_keys=True))
 pathlib.Path('r12-public-service-read.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
 return 0 if report['status']=='PUBLIC_SERVICE_READ_COMPLETED' else 1
if __name__=='__main__':raise SystemExit(main())
