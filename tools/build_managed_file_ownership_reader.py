"""Reproducibly seal the existing custody/Engine reader and one closed SQL contract."""
import ast
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def selected(path,names):
    raw=(ROOT/path).read_text();tree=ast.parse(raw);out=[]
    for name in names:
        node=next(n for n in tree.body if getattr(n,'name',None)==name)
        out.append('\n'.join(raw.splitlines()[node.lineno-1:node.end_lineno]))
    return '\n\n'.join(out)+'\n\n'

def build():
    code='''#!/usr/bin/env python3
"""New one-use exact Farmacie/Teatri ownership observation. No domain writes or authority."""
import copy,hashlib,http.client,json,os,pwd,re,signal,socket,stat,struct,subprocess,sys,time,uuid
from pathlib import Path
MAXIMUMS={'engineGets':5,'privateMetadataReads':3,'responseBytes':2097152,'totalBytes':25165824,'seconds':90}
'''
    base='scripts/read-managed-profile-ths-scopes-20261028.py'
    code+=selected(base,('Stop','require','encoded','digest','decode','frame','ancestry','Capture','process_pin','stable_binding','Engine','Logger'))
    for source in ('contract','reader'):
        code+='\n'.join(l for l in(ROOT/'tools/managed_file_ownership'/f'{source}.py').read_text().splitlines()if not l.startswith(('import ','from ')))+'\n\n'
    code+='''def main():
    c=None
    try:
        require(len(sys.argv)==1 and os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and os.environ.get('SUDO_UID')==str(pwd.getpwnam('oufadmin').pw_uid),'ISOLATED_OUFADMIN_READ_SCOPE_REQUIRED')
        require(sys.stdin.isatty()and sys.stdout.isatty(),'INTERACTIVE_OPERATOR_TERMINAL_REQUIRED')
        code=Path(__file__).resolve();ancestry(code.parent);s=code.lstat()
        require(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o400,'ROOT400_OWNERSHIP_READER_REQUIRED')
        require(not os.path.lexists(CASE['outputRoot']),'OWNERSHIP_READ_SCOPE_CONSUMED_NO_REPLAY')
        sys.stdout=Logger(code.parent/'operator.log')
        signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_OWNERSHIP_READ_WINDOW_EXPIRED'));signal.alarm(90)
        c=Capture(CASE['outputRoot'],2)
        print('NUOVA lettura3metadata del successo conservato,5GET Engine solo Onboarding/Postgres e UNA SQL REPEATABLE READ READ ONLY,2asset esatti Farmacie/Teatri. Solo metadati/prove booleane ownership e stato stesso job. Zero letture fileconfig/credenziali/chiavi/OAuth/IAM/import/lifecycle/grant/budget/resume/acquisizioni. 90s/24MiB;STOP conserva e consuma,nonrilanciare.',flush=True)
        result=inspect_ownership(c)
    except BaseException as error:
        reason=str(error)if isinstance(error,Stop)and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'PRIVATE_OWNERSHIP_READ_FAILURE_RECONCILE'
        result={'schema':'ouf.managed-file-ownership-read-result.v1','status':'STOP_RECONCILE','complete':False,'reasonCode':reason,
            'counts':dict(c.counts)if c else{},'databaseWrites':0,'engineWrites':0,'humanBudgetsGranted':0,'resumes':0,
            'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}
        if c is not None and not(c.root/'result.json').exists():c.put('result.json',result)
    finally:signal.alarm(0)
    print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True)
    return 0 if result['complete']else 2
if __name__=='__main__':raise SystemExit(main())
'''
    return code

if __name__=='__main__':
    (ROOT/'scripts/read-managed-file-ownership-20261028.py').write_text(build())
