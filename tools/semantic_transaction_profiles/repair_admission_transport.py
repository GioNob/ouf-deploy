"""Pure pinned repair after R5: shared producer deadline and durable denials.

No target mutation, authority, signing, retry or deadline extension. The parent
continues to enforce its existing monotonic budget and bounded output limit.
"""
import hashlib

from repair_broker_sources import replace_once

PRODUCER = 'tools/semantic_provider_deployment_producer.py'
NODE = 'scripts/semantic_provider_node_attestor.py'
APPROVAL = 'scripts/semantic_provider_installer_approval.py'
PREPARER = 'scripts/semantic_provider_admission_preparer.py'
DRIVER = 'scripts/semantic_provider_preexec_hook.py'
ORIGINAL = {'tools/semantic_provider_deployment_producer.py': '582371358c769f7724fb76bb17fd5e11530a09ab06c19a3a66351fc77d984776', 'scripts/semantic_provider_node_attestor.py': 'd0aa3bf56ebe6f69a324ab3260da60a737ab1508cec8adb644801999b29af191', 'scripts/semantic_provider_installer_approval.py': '13e6d8cbec328d678f8f190bb2706606a22625329c1740f2b9c96fa4526d13e0', 'scripts/semantic_provider_admission_preparer.py': '67b40905ab00ab397b67c5de9a0f5256ca2e69163b92880bc66462b6d2ec973b', 'scripts/semantic_provider_preexec_hook.py': '3489f894c45f182f0a2179bf431a8cc5bde6fe94bc4d9bfda67e134a23fde143'}

DIAGNOSIS = '''
def retain_phase_denial(error, configuration, phase):
    """Best-effort private evidence; never print exception values or overwrite."""
    import re
    import traceback
    fd = None
    directory = None
    try:
        path = Path(configuration)
        allowed = {'attestation-producer.json': {'attestation'},
                   'approval-producer.json': {'approval'},
                   'preparer.json': {'prepare', 'template', 'cleanup'},
                   'driver.json': {'plan', 'apply', 'verify', 'reconcile', 'rollback', 'hook', 'start'}}
        if path.name not in allowed or phase not in allowed[path.name]: return
        if not path.is_absolute() or '..' in path.parts: return
        for parent in (path.parent, *path.parent.parents):
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022: return
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != info.st_gid or info.st_uid != 0 \\
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1: return
        if stat.S_IMODE(path.parent.lstat().st_mode) != 0o700: return
        reason = str(error)
        if not re.fullmatch('[A-Z][A-Z0-9_]{0,95}', reason): reason = 'CHILD_PHASE_UNPROVEN'
        report = {'schema':'ouf.semantic-child-phase-denial.v1', 'phase':phase,
            'reason':reason, 'errorType':type(error).__name__, 'secretValuesPrinted':False,
            'notReleaseAcceptance':True, 'automaticRetryPerformed':False,
            'exceptionPoints':[{'file':Path(t.filename).name, 'function':t.name, 'line':t.lineno}
                for t in traceback.extract_tb(error.__traceback__)[-4:]]}
        if isinstance(error, OSError): report['errno'] = error.errno
        raw = json.dumps(report,sort_keys=True,separators=(',',':')).encode()
        if len(raw) > 8192: return
        directory = os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        current = os.fstat(directory)
        if (current.st_dev,current.st_ino) != (path.parent.lstat().st_dev,path.parent.lstat().st_ino): return
        name = path.stem+'-denial-'+phase+'.json'
        fd = os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb',closefd=False) as stream:
            stream.write(raw);stream.flush();os.fsync(fd)
        os.fsync(directory)
    except Exception:
        pass
    finally:
        if fd is not None: os.close(fd)
        if directory is not None: os.close(directory)

'''


def repair(sources):
    result = dict(sources)
    if set(ORIGINAL) != {PRODUCER,NODE,APPROVAL,PREPARER,DRIVER}:
        raise ValueError('COMPLETE_REVIEWED_ADMISSION_REPAIR_REQUIRED')
    for name,expected in ORIGINAL.items():
        if hashlib.sha256(sources[name]).hexdigest() != expected:
            raise ValueError('ORIGINAL_ADMISSION_SOURCE_HASH_DRIFT')
    code = sources[PRODUCER].decode()
    code = replace_once(code,'selector.select(self.budget.remaining(5))',
                        'selector.select(self.budget.remaining(18))')
    code = replace_once(code,'child.wait(timeout=self.budget.remaining(5))',
                        'child.wait(timeout=self.budget.remaining(18))')
    result[PRODUCER] = code.encode()
    for name,phase in ((NODE,'attestation'),(APPROVAL,'approval'),(PREPARER,None),(DRIVER,None)):
        code = sources[name].decode()
        code = replace_once(code,'def main():\n',DIAGNOSIS+'def main():\n')
        if phase is not None:
            code = replace_once(code,'    except Exception:\n        print(',
                "    except Exception as error:\n        retain_phase_denial(error,args.configuration,'"+phase+"')\n        print(")
        elif name == PREPARER:
            code = replace_once(code,'    except Exception as e:\n        reason = str(e)',
                '    except Exception as e:\n        retain_phase_denial(e,args.configuration,args.mode)\n        reason = str(e)')
        else:
            code = replace_once(code,'    except Exception as error:\n        # The bootstrap',
                '    except Exception as error:\n        retain_phase_denial(error,args.configuration,args.mode)\n        # The bootstrap')
        result[name] = code.encode()
    for name in ORIGINAL: compile(result[name],name,'exec')
    return result
