"""Reproducible standalone reader using qualified read-only capture primitives."""
import ast
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]


def definitions(path, names):
    raw = (ROOT/path).read_text()
    tree = ast.parse(raw)
    lines = raw.splitlines()
    out = []
    for name in names:
        node = next(n for n in tree.body if getattr(n, 'name', None) == name)
        out.append('\n'.join(lines[node.lineno-1:node.end_lineno]))
    return '\n\n'.join(out)+'\n\n'


def build():
    code = '''#!/usr/bin/env python3
"""New finite M2 installation metadata read. No provider, SQL, IAM or runtime effects."""
import copy,hashlib,http.client,json,os,pwd,re,signal,socket,stat,struct,sys,time
from pathlib import Path
MAXIMUMS={'engineGets':27,'privateMetadataReads':3,'responseBytes':2097152,'totalBytes':25165824,'seconds':90}
'''
    code += definitions('tools/managed_csv_recovery/retained_inputs.py',
                        ('Stop','require','encoded','digest','decode','frame','ancestry',
                         'Capture','process_pin','stable_binding','Engine'))
    code += definitions('scripts/read-managed-profile-ths-scopes-20261028.py', ('Logger',))
    code += (ROOT/'tools/m2_discovery_bindings/capture.py').read_text()+'\n'
    code += '''
def main():
    c=None
    try:
        require(len(sys.argv)==1 and os.geteuid()==os.getegid()==0 and sys.flags.isolated
            and sys.flags.no_site and sys.dont_write_bytecode
            and os.environ.get('SUDO_UID')==str(pwd.getpwnam('oufadmin').pw_uid),
            'ISOLATED_OUFADMIN_BINDING_CAPTURE_REQUIRED')
        require(sys.stdin.isatty() and sys.stdout.isatty(),'INTERACTIVE_OPERATOR_TERMINAL_REQUIRED')
        code=Path(__file__).resolve(); ancestry(code.parent); info=code.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0
            and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o400,'ROOT400_BINDING_CAPTURE_REQUIRED')
        require(not os.path.lexists(CASE['outputRoot']),'M2_BINDING_CAPTURE_CONSUMED_NO_REPLAY')
        sys.stdout=Logger(code.parent/'operator.log')
        signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_BINDING_CAPTURE_WINDOW_EXPIRED'))
        signal.alarm(90)
        c=Capture(CASE['outputRoot'],13)
        print('Nuova sola lettura: 3 metadata della manutenzione V38 consumata; 27 GET Engine sulla stessa coorte di13. Pin processi, socket e boot.90s/24MiB. Nessun SQL, fileconfig, credenziale, chiave, OAuth/IAM, import, lifecycle, grant, budget, resume o acquisizione. Le risposte Engine possono contenere Env preesistenti: restano private root0600. Nessuna authority o attivazione; STOP conserva e consuma, non rilanciare.',flush=True)
        result=capture_bindings(c)
    except BaseException as error:
        reason=str(error) if isinstance(error,Stop) and re.fullmatch('[A-Z0-9_]{1,120}',str(error)) else 'PRIVATE_M2_BINDING_CAPTURE_FAILURE_RECONCILE'
        result={'schema':'ouf.m2-discovery-current-bindings-result.v1','status':'STOP_RECONCILE',
            'complete':False,'reasonCode':reason,'contextPath':str(c.root) if c else None,
            'counts':dict(c.counts) if c else {},'engineWrites':0,'sqlSessions':0,'iamRequests':0,
            'oauthRequests':0,'humanBudgetsGranted':0,'resumes':0,'runtimeAuthorityIssued':False,
            'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}
        if c is not None and not (c.root/'result.json').exists(): c.put('result.json',result)
    finally:
        signal.alarm(0)
    print(json.dumps(result,sort_keys=True,separators=(',',':')),flush=True)
    return 0 if result['complete'] else 2


if __name__=='__main__':
    raise SystemExit(main())
'''
    return code


if __name__=='__main__':
    (ROOT/'scripts/read-m2-discovery-bindings-20261029.py').write_text(build())

