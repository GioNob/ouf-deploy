"""Compile the expected native transport footprint in a disposable network namespace.

The source-approved profile/links are inputs. Never derive an expected policy
from host nft readback. No host rule write, runtime start, lease or authority.
"""
import copy,ctypes,hashlib,json,os,select,signal,subprocess,tempfile,time
from pathlib import Path
from tools.semantic_provider_deployment_admission import isolated_template,validate_mirrors
from tools.semantic_provider_deployment_producer import program
from .custody_capture import decode,digest,require


class Budget:
    def __init__(self,seconds):self.until=time.monotonic()+seconds
    def check(self):require(time.monotonic()<self.until,'ISOLATED_TRANSPORT_TEMPLATE_DEADLINE')
    def remaining(self):self.check();return self.until-time.monotonic()


def isolated_footprint(profile,links,commands,*,seconds):
    require(os.geteuid()==0 and type(profile) is dict and type(links) is list
        and type(commands) is dict and set(commands)=={'ip','nft'}
        and type(seconds) is int and 1<=seconds<=30,
        'EXACT_BOUNDED_ROOT_TRANSPORT_TEMPLATE_INPUTS_REQUIRED')
    selected,mirrors,bindings=copy.deepcopy((profile,links,commands))
    validate_mirrors(selected,mirrors)
    budget=Budget(seconds);paths={key:program(value,budget) for key,value in bindings.items()}
    parent=(Path('/proc/self/ns/net')).stat().st_ino
    profile_hash=digest(selected);read_fd,write_fd=os.pipe();child=os.fork();waited=False
    if child==0:
        os.close(read_fd);code=1
        try:
            libc=ctypes.CDLL(None,use_errno=True)
            require(libc.unshare(0x40000000)==0,'ISOLATED_TRANSPORT_NAMESPACE_CREATION_UNPROVEN')
            current=Path('/proc/self/ns/net').stat().st_ino
            require(current!=parent,'HOST_TRANSPORT_TEMPLATE_FORBIDDEN')
            def run(name,args,raw=None):
                require(name in paths and type(args) is list
                    and Path('/proc/self/ns/net').stat().st_ino==current!=parent,
                    'CURRENT_ISOLATED_TRANSPORT_NAMESPACE_REQUIRED')
                require(program(bindings[name],budget)==paths[name],'TRANSPORT_TEMPLATE_COMMAND_DRIFT')
                with tempfile.TemporaryFile() as output:
                    reply=subprocess.run([paths[name],*args],input=raw,text=True,stdout=output,
                        stderr=subprocess.DEVNULL,timeout=budget.remaining(),
                        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
                    require(reply.returncode==0,'ISOLATED_TRANSPORT_TEMPLATE_COMMAND_UNPROVEN')
                    output.seek(0);value=output.read(2097153)
                    require(len(value)<=2097152,'ISOLATED_TRANSPORT_TEMPLATE_OUTPUT_UNBOUNDED')
                    return value.decode()
            value=isolated_template(selected,mirrors,parent,current,run)
            budget.check();require(value['profileHash']==profile_hash,'ISOLATED_TRANSPORT_PROFILE_DRIFT')
            result={'ok':True,'template':value,'parentNamespaceInode':parent,'templateNamespaceInode':current}
            code=0
        except Exception:
            result={'ok':False,'reason':'ISOLATED_TRANSPORT_TEMPLATE_UNPROVEN'}
        try:
            raw=json.dumps(result,sort_keys=True,separators=(',',':')).encode()
            if len(raw)<=4096:os.write(write_fd,raw)
        finally:os.close(write_fd)
        os._exit(code)
    os.close(write_fd)
    try:
        require(select.select([read_fd],[],[],budget.remaining())[0],
            'ISOLATED_TRANSPORT_TEMPLATE_DEADLINE')
        raw=os.read(read_fd,4097)
        require(0<len(raw)<=4096,'ISOLATED_TRANSPORT_TEMPLATE_RECEIPT_UNPROVEN')
        while True:
            observed,status=os.waitpid(child,os.WNOHANG)
            if observed==child:waited=True;break
            budget.check();time.sleep(min(.01,budget.remaining()))
        value=decode(raw)
        require(os.WIFEXITED(status) and os.WEXITSTATUS(status)==0 and value.get('ok') is True,
            'ISOLATED_TRANSPORT_TEMPLATE_UNPROVEN')
        require(Path('/proc/self/ns/net').stat().st_ino==parent
            and value['parentNamespaceInode']==parent and value['templateNamespaceInode']!=parent
            and digest(profile)==profile_hash and selected==profile and mirrors==links and bindings==commands,
            'TRANSPORT_TEMPLATE_PARENT_OR_INPUT_CHANGED')
        result=value['template']
        require(result.get('schema')=='ouf.semantic-shared-native-template.v1'
            and result.get('profileHash')==profile_hash and result.get('isolated') is True
            and result.get('hostRulesChanged') is False and result.get('startAuthorized') is False,
            'EXACT_ISOLATED_TRANSPORT_TEMPLATE_RECEIPT_REQUIRED')
        return result
    finally:
        os.close(read_fd)
        if not waited:
            try:os.kill(child,signal.SIGKILL)
            except ProcessLookupError:pass
            os.waitpid(child,0)
