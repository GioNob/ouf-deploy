"""Reproduce a read-only conditional owner plan from tracked retained helpers."""
import ast,json,pprint
from pathlib import Path

def defs(path,names):
    raw=Path(path).read_text();tree=ast.parse(raw);out=''
    for name in names:
        node=next(n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef,ast.Assign))
            and (getattr(n,'name',None)==name or isinstance(n,ast.Assign)
                 and any(isinstance(t,ast.Name)and t.id==name for t in n.targets)))
        out+='\n'.join(raw.splitlines()[node.lineno-1:node.end_lineno])+'\n\n'
    return out

base='scripts/read-managed-profile-ths-scopes-20261028.py'
tree=ast.parse(Path(base).read_text())
case=ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign)
    and any(isinstance(t,ast.Name)and t.id=='CASE'for t in n.targets)))
result=json.loads(Path('evidence/managed-profile-ths-iam-binding-correction-target-20261028.json').read_text())['result']
import hashlib
case.update(iamRoot=result['contextPath'],iamResultHash=hashlib.sha256(json.dumps(result,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest(),
    configurationProfileHash=result['configurationProfileHash'],clientId=result['bindingObservation']['clientId'],
    outputRoot='/etc/ouf/deploy-snapshots/managed-profile-ths-native-plan-d0dbbd61-20261028-v1')
code='''#!/usr/bin/env python3
"""Fresh read-only cohort plus private conditional same-image Onboarding plan.
No old main/authority, SQL, IAM/OAuth, imports, credentials or lifecycle ports.
"""
import copy,hashlib,http.client,ipaddress,json,os,pwd,re,signal,socket,stat,struct,sys,types
from pathlib import Path
MAXIMUMS={'engineGets':27,'privateMetadataReads':5,'responseBytes':2097152,'totalBytes':25165824,'seconds':120}
'''+ 'CASE='+pprint.pformat(case,width=120,sort_dicts=True)+'\n\n'
code+=defs(base,['Stop','require','encoded','digest','decode','frame','ancestry','Capture','process_pin','stable_binding','Engine','completed_history','Logger'])
contract='tools/managed_profile_ths_scopes/contract.py'
code+='\n'.join(s for s in Path(contract).read_text().splitlines()if not s.startswith(('from ','import ')))+'\n\n'
code+=defs('tools/acquisition_read_native/plan_helper.py',['CREATE_FIELDS','config_copy','valid_mac','network'])
code+='plan_helpers=types.SimpleNamespace(config_copy=config_copy,network=network,stable_binding=stable_binding)\n\n'
code+=defs('tools/managed_csv_recovery/image_plan.py',['retain_allocations'])
mac=defs('tools/acquisition_read_native/retained_mac.py',['valid','detached_config','policy'])
code+=mac+'retained_mac_policy=policy\n\n'
code+=defs('tools/managed_profile_ths_scopes/native_plan.py',['validate_profile','compile_native_plan'])
capture=defs(base,['inspect_current']).replace('def inspect_current(','def capture_current(',1)
capture=capture[:capture.index("    c.put('inputs.json',payload)")]+'''    return payload,review

'''
code+=capture
code+='''class PlanCapture(Capture):
    def __init__(self,root,cohort_size):
        # Reuse the existing protected five-read custody mode; no old STOP is
        # reopened and no previous counters or operation windows are reset.
        super().__init__(root,cohort_size,reconcile=True)

def prepare(c,case=CASE,*,engine_factory=Engine,pin=process_pin,boot_path=Path('/proc/sys/kernel/random/boot_id')):
    captured,review=capture_current(c,case,engine_factory=engine_factory,pin=pin,boot_path=boot_path)
    iam=c.private(Path(case['iamRoot'])/'result.json',case['iamResultHash'])
    profile=c.private(Path(case['iamRoot'])/'configuration-profile.json',case['configurationProfileHash'])
    plan=compile_native_plan(captured,review,iam,profile,case)
    require(all(list(frame(Path(path).lstat()))==seal['metadata'] for path,seal in c.seals.items()),'PLAN_INPUT_SEAL_CHANGED')
    require(captured['currentRootProcessPins']=={'pid1':pin(1),'engine':pin(captured['engineBinding']['peerCredentials'][0])}
        and boot_path.read_text().strip()==captured['bootId']
        and all(pin(v['pid'])==v for v in captured['currentProcessPins'].values()),'PLAN_PROCESS_OR_BOOT_DRIFT')
    c.put('execution-plan.json',plan)
    private={'schema':'ouf.ths-owner-request-private-native-inputs.v1','currentCapture':captured,
        'conditionalNativePlanHash':digest(plan),'configurationProfileHash':case['configurationProfileHash'],
        'retainedSuccessfulControlReview':review,'retainedIamResult':iam,'historySeals':c.seals,
        'executionEntryQualified':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
        'automaticReplayAllowed':False,'budgetReset':False}
    c.put('execution-inputs.json',private)
    output={'schema':'ouf.ths-owner-request-native-plan-result.v1',
        'status':'THS_OWNER_REQUEST_CONDITIONAL_NATIVE_PLAN_PREPARED_NOT_AUTHORIZED',
        'complete':True,'contextPath':str(c.root),'executionInputsHash':digest(private),
        'conditionalNativePlanHash':digest(plan),'configurationProfileHash':case['configurationProfileHash'],
        'iamResultHash':case['iamResultHash'],'retainedIamBindingSnapshotHash':iam['bindingObservation']['bindingSnapshotHash'],
        'targetRoles':['onboarding'],'cohortSize':13,'unchangedPeers':12,'sameNativeImageRequired':True,
        'nativeImageId':case['nativeImageIds']['onboarding'],'sourceCommit':case['sourceCommits']['onboarding'],
        'addedRequestScopes':list(REQUIRED),'preservedRequestedScopeCount':len(profile['preservedRequestedScopes']),
        'counts':dict(c.counts),'databaseMigration':{'from':36,'to':36,'newMigrations':0},
        'databaseAdmissionProven':False,'currentJobOrBudgetStateObserved':False,
        'executionEntryQualified':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
        'iamRequests':0,'oauthRequests':0,'credentialFileReads':0,'configurationFileContentReads':0,'signingKeyReads':0,
        'engineWrites':0,'sqlSessions':0,'imageImports':0,'newGrantsGranted':0,'humanBudgetsGranted':0,'resumes':0,
        'newJobs':0,'uploads':0,'sourceActivations':0,'acquisitionsExecuted':0,'registryWorkerTouched':False,
        'scopePatchApplied':False,'effectiveBrowserTokenScopesProven':False,'historicalAuthorityReused':False,
        'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}
    c.put('result.json',output);return output

def main():
    c=None
    try:
        require(len(sys.argv)==1 and os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site
            and sys.dont_write_bytecode and os.environ.get('SUDO_UID')==str(pwd.getpwnam('oufadmin').pw_uid),
            'ISOLATED_OUFADMIN_ROOT_NATIVE_PLAN_REQUIRED')
        require(sys.stdin.isatty()and sys.stdout.isatty(),'INTERACTIVE_OPERATOR_TERMINAL_REQUIRED')
        code=Path(__file__).resolve();ancestry(code.parent);st=code.lstat()
        require(stat.S_ISREG(st.st_mode)and st.st_uid==st.st_gid==0 and st.st_nlink==1
            and stat.S_IMODE(st.st_mode)==0o400,'PROTECTED_NATIVE_PLANNER_ROOT400_REQUIRED')
        require(not os.path.lexists(CASE['outputRoot']),'THS_NATIVE_PLAN_SCOPE_CONSUMED_NO_REPLAY')
        sys.stdout=Logger(code.parent/'operator.log')
        signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_NATIVE_PLAN_WINDOW_EXPIRED'));signal.alarm(120)
        c=PlanCapture(CASE['outputRoot'],13)
        print('NUOVO piano privato condizionale:5metadata conservati,27GET Engine coorte13. Solo Onboarding stessa immagine;12peer invariati. Zero SQL/IAM/OAuth/config/credenziali/chiavi/import/lifecycle/grant/budget/resume. Nessun login o APPROVO. Max120s;STOP conservare senza rilancio.',flush=True)
        result=prepare(c)
    except BaseException as error:
        reason=str(error)if isinstance(error,Stop)and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'PRIVATE_NATIVE_PLAN_FAILURE_RECONCILE'
        result={'schema':'ouf.ths-owner-request-native-plan-result.v1','status':'STOP_RECONCILE','complete':False,'reasonCode':reason,
            'contextPath':str(c.root)if c else None,'counts':dict(c.counts)if c else{},'engineWrites':0,
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False,
            'applicationE2EProven':False,'releaseAcceptance':False}
        if c is not None and not(c.root/'result.json').exists():c.put('result.json',result)
    finally:signal.alarm(0)
    print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True)
    return 0 if result['complete']else 2
if __name__=='__main__':raise SystemExit(main())
'''
Path('scripts/prepare-managed-profile-ths-native-plan-20261028.py').write_text(code)
