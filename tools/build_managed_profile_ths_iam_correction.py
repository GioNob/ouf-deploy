"""Reproducible sealed correction; pure/transport definitions only, no old main."""
import ast,hashlib,json,pprint
from pathlib import Path
def defs(path,names):
 raw=Path(path).read_text();tree=ast.parse(raw);out=''
 for name in names:
  n=next(n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef,ast.Assign))and(getattr(n,'name',None)==name or isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id==name for t in n.targets)))
  out+='\n'.join(raw.splitlines()[n.lineno-1:n.end_lineno])+'\n\n'
 return out
base='scripts/read-managed-profile-ths-iam-bindings-20261028.py';tree=ast.parse(Path(base).read_text())
case=ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='CASE'for t in n.targets)))
parent=json.loads(Path('evidence/managed-profile-ths-iam-binding-read-target-20261028.json').read_text())['result']
parent_hash=hashlib.sha256(json.dumps(parent,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
case.update(parentRoot=parent['contextPath'],parentResultHash=parent_hash,
            expectedObservation=parent['bindingObservation'],outputRoot='/etc/ouf/deploy-snapshots/managed-profile-ths-iam-binding-correction-ba556e9f-20261028-v1')
code='''#!/usr/bin/env python3
"""One exact reviewed additive IAM correction, with same-effect reconciliation.
No old authentication/authority reuse and no runtime configuration APPLY.
"""
import base64,copy,hashlib,http.client,ipaddress,json,os,pwd,random,re,resource,select,signal,socket,stat,struct,subprocess,sys,termios,time,types,uuid
from pathlib import Path
from urllib.parse import urlsplit
MAXIMUMS={'engineGets':7,'privateMetadataReads':3,'responseBytes':2097152,'totalBytes':25165824,'seconds':600}
'''+ 'CASE='+pprint.pformat(case,width=120,sort_dicts=True)+'\n\n'
code+=defs(base,['Stop','require','encoded','digest','decode','frame','ancestry','Capture','process_pin','stable_binding','Engine','Logger'])
code+='\n'.join(x for x in Path('tools/managed_profile_ths_scopes/contract.py').read_text().splitlines()if not x.startswith(('import ','from ')))+'\n\n'
code+=defs('tools/managed_profile_ths_scopes/bindings.py',['scope_rows','binding_report','configuration_profile'])
code+=defs('tools/managed_profile_ths_scopes/iam_read.py',['CLIENT_FIELDS','CHILD','executable','dispatch','ReadLedger','terminal','access'])
code+=defs('tools/managed_profile_ths_scopes/iam_correction.py',['MARKER','compile_correction','link_map','validate_created_scope','validate_location','verify_postcondition','CorrectionCapture','CorrectionLedger'])
code+=defs('tools/managed_profile_ths_scopes/iam_correction_transport.py',['EXTRA_CHILD','BASE_OPERATIONS','dispatch_correction'])
code+=defs('tools/managed_profile_ths_scopes/iam_correction_controller.py',['correction_snapshot','execute_correction'])
code+='''def validate_parent_read(parent,case):
 require(parent.get('schema')=='ouf.managed-profile-ths-iam-binding-read-result.v1'and digest(parent)==case['parentResultHash']
         and parent['status']=='THS_IAM_BINDINGS_OBSERVED_CONFIGURATION_PROFILE_BLOCKED'and parent['complete']is True
         and parent['contextPath']==case['parentRoot']and parent['retainedClientInputsHash']==case['inputsHash']
         and parent['bindingObservation']==case['expectedObservation']and parent['configurationProfilePrepared']is False
         and parent['configurationProfileHash']is None and parent['adminIdentityApiVerified']is True
         and parent['counts']['oauthRequestsReserved']==1 and parent['counts']['adminGetsReserved']==14
         and parent['counts']['engineGets']==5 and parent['counts']['privateMetadataReads']==2
         and parent['iamMutations']==parent['engineWrites']==parent['humanBudgetsGranted']==parent['resumes']==0
         and all(parent[k]is False for k in ('runtimeAuthorityIssued','targetApplyAuthorized','automaticReplayAllowed','budgetReset','scopePatchApplied')),
         'EXACT_COMPLETED_CONSUMED_IAM_READ_REQUIRED')

'''
prepare=defs(base,['prepare']);prepare=prepare.replace('def prepare(','def prepare_correction(',1)
start=prepare.index(" old=Path(case['priorRoot'])")
prepare=prepare[:start]+''' parent=c.private(Path(case['parentRoot'])/'result.json',case['parentResultHash']);validate_parent_read(parent,case)
 plan=compile_correction(parent['bindingObservation'],case['expectedObservation'],installation_ref=case['installationRef'],parent_result_hash=case['parentResultHash'],realm=case['realm'])
'''+prepare[start:]
prepare=prepare[:prepare.index(" review={'schema':")]+''' review={'schema':'ouf.ths-iam-binding-correction-review.v1','plan':plan,'retainedInputsHash':case['inputsHash'],
         'currentBindingsHash':digest({r:stable_binding(v)for r,v in observed.items()}),'currentProcessPins':inputs['currentProcessPins'],
         'adminEndpoint':case['adminEndpoint'],'maximumNewAdministrativeAuthenticationRequests':1,'maximumAdminGetAttempts':40,
         'maximumGetRetryReservations':4,'maximumIamWriteDispatches':4,'maximumEngineGets':7,'maximumSecondsAfterConsent':210,
         'maximumSecondsAfterPassword':120,'oldScopesAndBudgetsRemainConsumed':True,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False}
 c.put('review.json',review);review_path=c.root/'review.json'
 c.seals[str(review_path)]={'metadata':list(frame(review_path.lstat())),'sha256':hashlib.sha256(encoded(review)).hexdigest()}
 return inputs,parent,plan,review,ns,program,active_guard,containers

'''
code+=prepare
code+='''def main():
 c=None
 try:
  resource.setrlimit(resource.RLIMIT_CORE,(0,0))
  require(len(sys.argv)==1 and os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
          and os.environ.get('SUDO_UID')==str(pwd.getpwnam('oufadmin').pw_uid),'ISOLATED_OUFADMIN_ROOT_CORRECTION_REQUIRED')
  require(sys.stdin.isatty()and sys.stdout.isatty(),'INTERACTIVE_OPERATOR_TERMINAL_REQUIRED')
  code=Path(__file__).resolve();ancestry(code.parent);st=code.lstat()
  require(stat.S_ISREG(st.st_mode)and st.st_uid==st.st_gid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o400,'PROTECTED_CORRECTION_ROOT400_REQUIRED')
  require(not os.path.lexists(CASE['outputRoot']),'THS_IAM_CORRECTION_SCOPE_CONSUMED_NO_REPLAY')
  sys.stdout=Logger(code.parent/'operator.log');signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_IAM_CORRECTION_TOTAL_WINDOW_EXPIRED'));signal.alarm(600)
  c=CorrectionCapture(CASE['outputRoot'],2)
  result=execute_correction(c,prepare_correction(c),CASE)
 except BaseException as error:
  reason=str(error)if isinstance(error,Stop)and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'PRIVATE_IAM_CORRECTION_FAILURE_RECONCILE'
  counts=dict(c.counts)if c else{}
  result={'schema':'ouf.managed-profile-ths-iam-binding-correction-result.v1','status':'STOP_RECONCILE','complete':False,'reasonCode':reason,'counts':counts,
          'iamMutationsObserved':counts.get('iamWritesObserved',0),'iamMutationsMayHaveOccurred':counts.get('iamWritesReserved',0)>0,
          'automaticRollbackPerformed':False,'engineWrites':0,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
          'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}
  if c is not None and not(c.root/'result.json').exists():c.put('result.json',result)
 finally:signal.alarm(0)
 print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True)
 return 0 if result['complete']else 2
if __name__=='__main__':raise SystemExit(main())
'''
Path('scripts/correct-managed-profile-ths-iam-bindings-20261028.py').write_text(code)
