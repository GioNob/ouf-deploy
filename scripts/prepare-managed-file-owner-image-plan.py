#!/usr/bin/env python3
"""Closed preparation only: three retained metadata, one exact ZIP, no runtime ports."""
import importlib.util,json,os,pwd,re,signal,sys
from pathlib import Path
def main():
    folder=Path(__file__).resolve().parent
    spec=importlib.util.spec_from_file_location('owner_image_plan',folder/'image_plan.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    scope=None
    try:
        m.require(len(sys.argv)==2 and os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and os.environ.get('SUDO_UID')==str(pwd.getpwnam('oufadmin').pw_uid),'ISOLATED_OUFADMIN_ROOT_IMAGE_PLAN_REQUIRED')
        m.require(Path(sys.argv[1])==folder/'onboarding.zip','ONE_EXACT_SEALED_ZIP_PATH_REQUIRED')
        m.ancestry(folder)
        for path in folder.iterdir():
            if path.suffix in('.py','.json'):
                st=path.lstat();m.require(st.st_uid==st.st_gid==0 and m.common.stat.S_ISREG(st.st_mode)and st.st_nlink==1 and m.common.stat.S_IMODE(st.st_mode)==0o400,'ROOT400_PLAN_CODE_REQUIRED')
        case=m.decode((folder/'case.json').read_bytes());m.require(case['schema']=='ouf.managed-file-owner-recovery-image-plan-case.v1'and case['targetApplyAuthorized']is False,'CLOSED_CONDITIONAL_OWNER_CASE_REQUIRED')
        signal.signal(signal.SIGALRM,lambda *_:m.require(False,'FINITE_OWNER_IMAGE_PLAN_WINDOW_EXPIRED'));signal.alarm(300)
        scope=m.Scope(case['outputRoot'])
        helpers={name:m.load_module(folder,name+'.py',checksum)for name,checksum in case['helperHashes'].items()}
        receipt=m.decode((folder/'onboarding-custody.json').read_bytes())
        result=m.prepare(scope,case,receipt,Path(sys.argv[1]),helpers['plan_helper'],helpers['retained_mac'],helpers['image_custody'],helpers['stage_image'].unpack)
    except BaseException as error:
        reason=str(error)if isinstance(error,m.Stop)and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'PRIVATE_OWNER_IMAGE_PLAN_UNPROVEN_RECONCILE'
        result={'schema':'ouf.managed-file-owner-recovery-image-plan-result.v1','status':'STOP_RECONCILE','complete':False,'reasonCode':reason,
            'counts':dict(scope.counts)if scope else{},'runtimeAuthorityIssued':False,'targetUpdateAuthorized':False,'automaticReplayAllowed':False,
            'budgetReset':False,'humanOwnershipReceiptsCreated':0,'humanBudgetsGranted':0,'resumes':0,'applicationE2EProven':False,'releaseAcceptance':False}
        if scope is not None and not(scope.root/'result.json').exists():m.put(scope.root/'result.json',result)
    finally:signal.alarm(0)
    print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True)
    return 0 if result['complete']else 2
if __name__=='__main__':raise SystemExit(main())
