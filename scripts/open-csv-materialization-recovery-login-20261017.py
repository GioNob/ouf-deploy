#!/usr/bin/env python3
"""Retained-host bootstrap; configuration is selected by a pinned versioned case."""
import base64,hashlib,json,os,re,signal,stat,sys,tempfile
from pathlib import Path

def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return hashlib.sha256(encoded(value)).hexdigest()
def pin(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def code_bytes(path,expected,maximum=131072):
 path=Path(path);require(path.is_absolute()and path.resolve()==path,'EXACT_PRIVATE_CODE_PATH_REQUIRED')
 for parent in path.parents:
  s=parent.lstat();require(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not s.st_mode&0o022,'CODE_ANCESTRY_CUSTODY_REQUIRED')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and 0<s.st_size<=maximum,'PRIVATE_CODE_CUSTODY_REQUIRED')
  raw=os.read(fd,maximum+1);require(len(raw)==s.st_size and pin(s)==pin(os.fstat(fd))==pin(path.lstat())and hashlib.sha256(raw).hexdigest()==expected,'PRIVATE_CODE_BYTES_CHANGED');return raw
 finally:os.close(fd)
def emit(check,**values):
 print(json.dumps(dict(schema='ouf.csv-recovery-scope-login-bootstrap.v1',check=check,automaticRetry=False,
  automaticSessionRenewal=False,budgetReset=False,completedTechnicalPhases=8,functionalMilestonesProven=2,**values),sort_keys=True),flush=True)
OVERLAYS={
 'iam_binding_candidate':('iam_binding_candidate.py','tools/semantic_policy_token_owner/iam_binding_candidate.py'),
 'migration_root_custody':('migration_root_custody.py','tools/semantic_policy_token_owner/migration_root_custody.py'),
 **{'tools.chatbot_file_cohort.'+n:(n+'.py','tools/chatbot_file_cohort/'+n+'.py')for n in('continued_owner','review','human_session','gateway')},
 **{'tools.semantic_policy_token_owner.'+n:(n+'.py','tools/semantic_policy_token_owner/'+n+'.py')for n in('installed_owner','supervisor')},
 'image_custody':('image_custody.py','tools/semantic_application_cutover/image_custody.py'),
 **{'tools.semantic_mcp_update.'+n:('mcp_'+n+'.py','tools/semantic_mcp_update/'+n+'.py')for n in('entry','authority','permit','plan','session','owner','native')},
 **{'tools.ingestion_readiness_update.'+n:('readiness_'+n+'.py','tools/ingestion_readiness_update/'+n+'.py')for n in('entry','authority','plan','owner','native')}}
OVERLAYS.update({'tools.onboarding_audit_update.'+n:('audit_'+n+'.py','tools/onboarding_audit_update/'+n+'.py')for n in('entry','authority','owner','native','preparation')})
OVERLAYS.update({'tools.resolution_ths_update.'+n:('resolution_'+n+'.py','tools/resolution_ths_update/'+n+'.py')for n in('entry','authority','owner','native','plan')})
OVERLAYS.update({'tools.resolution_ths_configuration.'+n:('config_'+n+'.py','tools/resolution_ths_configuration/'+n+'.py')for n in('entry','authority','owner','native','plan')})
OVERLAYS.update({'tools.teatri_materialization_apply.'+n:('udp_'+n+'.py','tools/teatri_materialization_apply/'+n+'.py')for n in('entry','authority','owner','native','plan','preparation','preflight','permissions','login')})
OVERLAYS['tools.chatbot_file_cohort.human_session']=('human_session.py','tools/csv_materialization_recovery/human_session.py')
OVERLAYS['tools.csv_materialization_recovery.entry']=('recovery_entry.py','tools/csv_materialization_recovery/entry.py')
def main():
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and len(sys.argv)==4,'ISOLATED_ROOT_AUDIT_FIX_BOOTSTRAP_REQUIRED')
 code=Path(sys.argv[1]);commit=sys.argv[2];manifest_sha=sys.argv[3]
 require(re.fullmatch('[0-9a-f]{40}',commit)and re.fullmatch('[0-9a-f]{64}',manifest_sha),'EXACT_AUDIT_FIX_RELEASE_BINDING_REQUIRED')
 signal.alarm(300);emit('BEGIN',preparationMaximumSeconds=300,newPolicyWorkerStarted=False,runtimeAuthorityIssued=False)
 package=json.loads(code_bytes(code/'package.json',manifest_sha))
 require(package['sourceCommit']==commit and set(package['sourceHashes'])==set(OVERLAYS),'EXACT_AUDIT_FIX_SOURCE_PACKAGE_REQUIRED')
 code_bytes(code/'execute.py',package['executorSha256']);case=json.loads(code_bytes(code/'case.json',package['caseSha256']))
 require(case['schema']=='ouf.csv-recovery-scope-login-selection.v1','VERSIONED_AUDIT_FIX_SELECTION_REQUIRED')
 boot=case['retainedBootstrap'];ns={'__name__':'retained_audit_fix_helpers'}
 exec(compile(code_bytes(boot['path'],boot['sha256']),'<verified-retained-audit-fix-helpers>','exec'),ns)
 old=ns['read'](ns['CONTEXT']/'review.json',8388608,ns['REVIEW']);b=old['scopes']['finiteActionProcess']['bundle']
 bundle=ns['read'](b['path'],8388608,b['sha256']);_,sources=ns['decode_sources'](bundle);prepared=bundle['prepared']
 require(digest(prepared)==old['privateInputHashes']['preparedInputs'],'RETAINED_PREPARED_BINDING_CHANGED')
 for module,(name,path)in OVERLAYS.items():sources[module]=code_bytes(code/name,package['sourceHashes'][module],262144)
 loader=code_bytes(code/'runtime.py',package['loaderSha256'],65536);memory={'__name__':'sealed_onboarding_audit_memory'}
 exec(compile(loader,'<verified-onboarding-audit-memory-loader>','exec'),memory)
 pins={**bundle['declaration']['sourcePins'],'ouf-deploy':commit};extra={'executorSha256':package['executorSha256'],'caseSha256':package['caseSha256'],'mode':'CSV_RECOVERY_SCOPE_LOGIN'}
 declaration=memory['declaration'](commit,sources,loader,pins,extra);closure={**old['sourceClosure'],'declaration':declaration}
 entry,_=memory['load_entry'](commit,sources,loader,digest(declaration),pins,extra)
 context=Path(tempfile.mkdtemp(prefix='csv-recovery-login-',dir=ns['CONTEXT'].parent));context.chmod(0o700)
 emit('PREPARED',contextPath=str(context),newPolicyWorkerStarted=False,maximumGatewayWrites=0,runtimeAuthorityIssued=False)
 entry.main(prepared,sources,closure,case,context,ns['read'],ns,emit=lambda value:print(value,flush=True))
if __name__=='__main__':
 try:main()
 except (Exception,KeyboardInterrupt)as error:
  known=type(error).__name__ in ('ValueError','UpdateDenied','UpdatePaused','PlanDenied','HumanSessionPaused','ReadDenied')
  reason=str(error)if known and re.fullmatch('[A-Z_]{1,160}',str(error))else type(error).__name__
  emit('STOP',reason=reason,exceptionMessagePrinted=False,reconciliationRequired=True)
  raise SystemExit(2)
