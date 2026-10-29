"""Seal a new four-metadata, 27GET capture; no old main or authority is invoked."""
import ast
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def defs(path,names):
    raw=(ROOT/path).read_text();tree=ast.parse(raw);result=[]
    for name in names:
        node=next(n for n in tree.body if getattr(n,'name',None)==name)
        result.append('\n'.join(raw.splitlines()[node.lineno-1:node.end_lineno]))
    return '\n\n'.join(result)+'\n\n'

def build():
    raw=(ROOT/'scripts/read-managed-file-ownership-20261028.py').read_text();tree=ast.parse(raw)
    nodes=[n for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id in('ASSET','JOB','TEATRI','SUBJECT','TENANT','CASE')for t in n.targets)]
    constants='\n\n'.join('\n'.join(raw.splitlines()[n.lineno-1:n.end_lineno])for n in nodes)
    code='''#!/usr/bin/env python3
"""New finite current-owner capture. No SQL, original file, authentication or runtime action."""
import copy,hashlib,http.client,json,os,pwd,re,signal,socket,stat,struct,sys,time
from pathlib import Path
MAXIMUMS={'engineGets':27,'privateMetadataReads':4,'responseBytes':2097152,'totalBytes':25165824,'seconds':90}
'''
    base='scripts/read-managed-profile-ths-scopes-20261028.py'
    code+=defs(base,('Stop','require','encoded','digest','decode','frame','ancestry','Capture','process_pin','stable_binding','Engine','Logger'))
    code=code.replace("'privateMetadataReads': 5 if reconcile else 3","'privateMetadataReads': 5 if reconcile else 4")
    code+=constants+'\n\n'+defs('tools/managed_file_ownership/reader.py',('history',))
    code+=(ROOT/'tools/managed_file_owner_inputs/capture.py').read_text()+'\n'
    code+='''CASE={**CASE,'ownerReadRoot':OWNER_READ_ROOT,'ownerReadHash':OWNER_READ_HASH,'outputRoot':OUTPUT_ROOT}
def main():
    c=None
    try:
        require(len(sys.argv)==1 and os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and os.environ.get('SUDO_UID')==str(pwd.getpwnam('oufadmin').pw_uid),'ISOLATED_OUFADMIN_CAPTURE_REQUIRED')
        require(sys.stdin.isatty()and sys.stdout.isatty(),'INTERACTIVE_OPERATOR_TERMINAL_REQUIRED')
        code=Path(__file__).resolve();ancestry(code.parent);s=code.lstat()
        require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o400,'ROOT400_OWNER_CAPTURE_REQUIRED')
        require(not os.path.lexists(CASE['outputRoot']),'OWNER_INPUT_CAPTURE_CONSUMED_NO_REPLAY')
        sys.stdout=Logger(code.parent/'operator.log')
        signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_OWNER_CAPTURE_WINDOW_EXPIRED'));signal.alarm(90)
        c=Capture(CASE['outputRoot'],13)
        print('NUOVA sola lettura4metadata conservati:3successoTHS e1letturaownership riuscita;27GET Engine sulla stessa coorte13,solo Onboarding candidato futuro/12peer invariati.90s/24MiB. Zero SQL/fileconfig/credenziali/chiavi/IAM/OAuth/import/lifecycle/grant/budget/resume/acquisizioni. Nessuna authority o piano eseguibile;STOP conserva e consuma,nonrilanciare.',flush=True)
        result=capture_inputs(c)
    except BaseException as error:
        reason=str(error)if isinstance(error,Stop)and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'PRIVATE_OWNER_CAPTURE_FAILURE_RECONCILE'
        result={'schema':'ouf.managed-file-owner-recovery-input-capture-result.v1','status':'STOP_RECONCILE','complete':False,'reasonCode':reason,
            'counts':dict(c.counts)if c else{},'engineWrites':0,'sqlSessions':0,'humanBudgetsGranted':0,'resumes':0,
            'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}
        if c is not None and not(c.root/'result.json').exists():c.put('result.json',result)
    finally:signal.alarm(0)
    print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True)
    return 0 if result['complete']else 2
if __name__=='__main__':raise SystemExit(main())
'''
    return code

if __name__=='__main__':(ROOT/'scripts/capture-managed-file-owner-inputs-20261028.py').write_text(build())
