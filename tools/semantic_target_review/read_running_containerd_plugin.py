"""Read Docker endpoint and running containerd task-plugin exports; no start."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import traceback

REPORT={'schema':'ouf.semantic-running-containerd-plugin-read-only.v1','privateKeysRead':0,
    'containerLifecycleOperations':0,'existingConfigurationWrites':0,'signaturesIssued':0,
    'privateValuesPrinted':False,'startAuthorized':False,'notReleaseAcceptance':True,
    'historicalRuntimeBundleArgvCaptured':False}
PHASE='READ_APPROVED_R3_CONTEXT'

def option(args,name):
    for i,value in enumerate(args):
        if value==name and i+1<len(args):return args[i+1]
        if value.startswith(name+'='):return value[len(name)+1:]
    return None

def call(args,limit=131072):
    with tempfile.TemporaryFile() as output:
        result=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.DEVNULL,
            timeout=8,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        output.seek(0);raw=output.read(limit+1)
    assert result.returncode==0 and len(raw)<=limit
    return raw

try:
    assert os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode
    package=Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-transaction-source-ff13uh3n')
    path=package/'provider_transaction_intake.py'
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:raw=os.read(fd,131073)
    finally:os.close(fd)
    assert hashlib.sha256(raw).hexdigest()=='edc3c97d54a9d241c93ea9791f4dffce9984565763c2236ad1644e8b90c4c4b5'
    entry={'__name__':'running_plugin_reader','__file__':str(path)}
    exec(compile(raw,str(path),'exec'),entry)
    context=Path('/etc/ouf/deploy-snapshots/semantic-provider-v2-approved-context-rsj9dtwr')
    approval=entry['parse'](entry['read'](context/'human-approval-binding.json'))
    cfg=entry['parse'](entry['bound']({'path':str(context/'execution-configuration.json'),'sha256':approval['configurationHash']}))
    parents={r:entry['parse'](entry['bound'](b['context']))['bundleParent'] for r,b in cfg['recordsByRole'].items()}
    REPORT['approvedBundleParents']=parents
    assert len(set(parents.values()))==1
    namespace=Path(next(iter(parents.values()))).name
    assert namespace=='moby'
    PHASE='READ_LIVE_DOCKER_CONTAINERD_ENDPOINT'
    daemons=[]
    for item in Path('/proc').iterdir():
        if not item.name.isdigit():continue
        try:
            if (item/'comm').read_text().strip()!='dockerd':continue
            assert (item/'exe').resolve(strict=True)==Path('/usr/bin/dockerd') and item.stat().st_uid==0
            with (item/'cmdline').open('rb') as stream:raw=stream.read(16385)
            assert len(raw)<=16384
            args=raw.decode().rstrip('\0').split('\0')
            socket=option(args,'--containerd')
            daemons.append({'pid':int(item.name),'containerdSocketArgument':socket,
                'containerdNamespaceArgument':option(args,'--containerd-namespace')})
        except (FileNotFoundError,ProcessLookupError):continue
    REPORT['dockerDaemons']=daemons
    assert len(daemons)==1 and daemons[0]['containerdSocketArgument']
    socket=daemons[0]['containerdSocketArgument'].removeprefix('unix://')
    sock=Path(socket);assert sock.is_absolute() and '..' not in sock.parts
    info=sock.stat();assert stat.S_ISSOCK(info.st_mode) and info.st_uid==0 and not info.st_mode&0o002
    PHASE='READ_CTR_METADATA_COMMAND_CONTRACT'
    ctr=Path('/usr/bin/ctr');info=ctr.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022 and info.st_mode&0o111
    REPORT['ctrSha256']=hashlib.sha256(ctr.read_bytes()).hexdigest()
    help_text=call([str(ctr),'plugins','info','--help']).decode()
    PHASE='READ_LIVE_TASK_PLUGIN_EXPORTS'
    base=[str(ctr),'--address',socket,'plugins','info']
    args=base+(['--type','io.containerd.runtime.v2','--id','task'] if '--type' in help_text and '--id' in help_text
        else ['io.containerd.runtime.v2','task'])
    value=json.loads(call(args));plugin=value.get('plugin',value)
    assert plugin.get('type',plugin.get('Type'))=='io.containerd.runtime.v2'
    assert plugin.get('id',plugin.get('ID'))=='task'
    exports=plugin.get('exports',plugin.get('Exports',{}))
    REPORT['liveTaskPluginExports']={k:exports[k] for k in ('root','state') if k in exports}
    REPORT['containerdSocketQueried']=socket
    state=exports.get('state');assert type(state) is str
    p=Path(state);assert p.is_absolute() and '..' not in p.parts and p.name=='io.containerd.runtime.v2.task'
    parent=p/namespace
    REPORT['liveTaskBundleParent']=str(parent)
    REPORT['matchesApprovedBundleParent']={r:str(parent)==v for r,v in parents.items()}
    REPORT['bundleParentPresent']=parent.is_dir()
    REPORT.update(status='LIVE_CONTAINERD_TASK_METADATA_CAPTURED',phase=PHASE)
except Exception as error:
    REPORT.update(status='READ_ONLY_PLUGIN_DIAGNOSIS_BLOCKED',phase=PHASE,errorType=type(error).__name__)
    if isinstance(error,OSError):REPORT['errno']=error.errno
    REPORT['exceptionPoints']=[{'file':Path(t.filename).name,'function':t.name,'line':t.lineno}
        for t in traceback.extract_tb(error.__traceback__)[-4:]]
print('OUF_LIVE_CONTAINERD_PLUGIN_DIAGNOSIS='+json.dumps(REPORT,sort_keys=True))
if REPORT['status']!='LIVE_CONTAINERD_TASK_METADATA_CAPTURED':raise SystemExit(1)
