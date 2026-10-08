"""Register the sealed OUF runtime with an empty allowlist; SIGHUP only."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

NAME='ouf-semantic-admitted-v2'
DAEMON=Path('/etc/docker/daemon.json')
WRAPPER=Path('/usr/local/sbin/ouf-semantic-admitted-v2')
SOCKET='unix:///var/run/docker.sock'
GUARD=Path('/etc/ouf/deploy-snapshots/semantic-runtime-transition-stage-20261003-160211/prepared/runtime-configuration.json')
GUARD_HASH='24968cf990a32b87f3169b9226fe63d224c93a403540afec197011fbd670b0bb'
HELPER=Path('/usr/local/sbin/ouf-discovery-preflight')
HELPER_HASH='65c8caa661005a7bf4bfe7eb1c5f45932a32c3e024095db861882f6c52998618'
BINDS={'python':('/usr/bin/python3.13','889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9'),
'runc':('/usr/bin/runc','3c2ed035be881749630c18eb693dc373a518e938924c1b4c345db72d36a6a256'),
'docker':('/usr/bin/docker','7f5b38163f9c5367f4b42d905c0505877eafa4c20abe49430c85a770aefacf40')}
SELF='register-provider-v2-runtime.py'

class Denied(RuntimeError):pass

def require(ok,why):
    if not ok:raise Denied(why)

def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()+b'\n'
def sha(raw):return hashlib.sha256(raw).hexdigest()

def parse(raw):
    def unique(pairs):
        d={}
        for k,v in pairs:
            require(k not in d,'DUPLICATE_JSON_KEY');d[k]=v
        return d
    return json.loads(raw,object_pairs_hook=unique)

def parents(p):
    require(p.is_absolute() and '..' not in p.parts,'ABSOLUTE_PATH_REQUIRED')
    for parent in (p.parent,*p.parent.parents):
        s=parent.lstat();require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'ROOT_ANCESTOR_REQUIRED')

def read(p,executable=False):
    p=Path(p);parents(p);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        a=os.fstat(fd);limit=64000000 if executable else 262144
        require(stat.S_ISREG(a.st_mode) and a.st_uid==0 and a.st_nlink==1 and a.st_size<=limit
            and (bool(a.st_mode&0o111) and not a.st_mode&0o022 if executable else stat.S_IMODE(a.st_mode)==0o600),'ROOT_FILE_REQUIRED')
        raw=os.read(fd,limit+1);b=os.fstat(fd)
        require(len(raw)==a.st_size and all(getattr(a,k)==getattr(b,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_size','st_mtime_ns','st_ctime_ns')),'ROOT_FILE_DRIFT')
        return raw
    finally:os.close(fd)

def publish(p,raw,mode=0o600):
    parents(p);fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    try:
        os.fchmod(fd,mode)
        with os.fdopen(fd,'wb',closefd=False) as f:f.write(raw);f.flush();os.fsync(f.fileno())
    finally:os.close(fd)
    fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)

def capture(argv,timeout=15):
    with __import__('tempfile').TemporaryFile() as out:
        p=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.DEVNULL,
            timeout=timeout,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        out.seek(0);raw=out.read(1048577)
    require(p.returncode==0 and len(raw)<=1048576,'BOUNDED_COMMAND_FAILED')
    return raw

def docker(*argv):return capture([BINDS['docker'][0],'-H',SOCKET,*argv])
def daemon_pid():
    p=int(capture(['/usr/bin/systemctl','show','docker.service','--property=MainPID','--value']).strip())
    require(p>1,'LIVE_DAEMON_REQUIRED');return p

def identity(pid):
    exe=Path('/proc')/str(pid)/'exe';target=exe.resolve(strict=True)
    require(target.name=='dockerd','DOCKER_PROCESS_REQUIRED');raw=read(target,True)
    proc=Path('/proc')/str(pid)
    st=(proc/'stat').read_text();birth=st.split(') ',1)[1].split()[19]
    args=(proc/'cmdline').read_bytes();require(len(args)<16384,'DAEMON_ARGUMENTS_UNBOUNDED')
    values=args.split(b'\0');configured=None
    for i,item in enumerate(values):
        require(not item.startswith(b'--add-runtime') and not item.startswith(b'--default-runtime'),'DAEMON_RUNTIME_FLAG_CONFLICT')
        if item.startswith(b'--config-file='):configured=item.split(b'=',1)[1].decode()
        elif item==b'--config-file':configured=values[i+1].decode()
    require(configured in (None,str(DAEMON)),'DAEMON_CONFIGURATION_PATH_DRIFT')
    return {'pid':pid,'birth':birth,'path':str(target),'sha256':sha(raw)}

def inventory():
    ids=docker('ps','-aq').decode().splitlines();require(len(ids)<=256 and all(re.fullmatch('[0-9a-f]{64}',v) for v in ids),'CONTAINER_INVENTORY_UNBOUNDED')
    if not ids:return []
    fmt='{{json .Id}} {{json .State.Pid}} {{json .State.StartedAt}} {{json .State.Status}} {{json .State.Running}}'
    return sorted(docker('inspect','--type','container','--format',fmt,*ids).decode().splitlines())

def runtimes():return parse(docker('info','--format','{"runtimes":{{json .Runtimes}},"default":{{json .DefaultRuntime}}}'))
def preflight():
    require(sha(read(HELPER,True))==HELPER_HASH,'READ_HELPER_DRIFT')
    raw=capture([str(HELPER)],90);prefix=b'OUF_DISCOVERY_PRIVILEGED_PREFLIGHT='
    require(raw.startswith(prefix),'NATIVE_GUARD_REPORT_REQUIRED');report=parse(raw[len(prefix):])
    r=report['runtimeReadiness']
    require(r['runtimeCustodyVerified'] is True and r['stableAcrossReads'] is True and r['candidatesNeverStarted'] is True
        and r['providerSetsEmpty'] is True and r['startAuthorized'] is False and report['releaseApplied'] is False
        and r['configurationHash']==GUARD_HASH,'NATIVE_GUARD_CUSTODY_REQUIRED')
    return r

def config(root,manifest):
    paths=manifest['sourceHashes']
    return {'schema':'ouf.semantic-docker-runtime-adapter.v4','sourceHash':paths['scripts/semantic_provider_docker_runtime.py'],
        'runtimePath':BINDS['runc'][0],'runtimeSha256':BINDS['runc'][1],
        'pythonPath':BINDS['python'][0],'pythonSha256':BINDS['python'][1],
        'driverPath':str(root/'source/scripts/semantic_provider_preexec_hook.py'),
        'driverSha256':paths['scripts/semantic_provider_preexec_hook.py'],
        'admissionPath':str(root/'source/scripts/semantic_provider_deployment_broker.py'),
        'admissionSha256':paths['scripts/semantic_provider_deployment_broker.py'],
        'registryRoot':str(root/'registry'),'runtimeStateRoot':'/run/docker','candidates':{}}

def operate(root,manifest_hash):
    require(os.geteuid()==0,'ROOT_REQUIRED');root=Path(root);parents(root/'placeholder')
    require(stat.S_IMODE(root.stat().st_mode)==0o700 and root.stat().st_uid==root.stat().st_gid==0,'PRIVATE_ROOT_REQUIRED')
    require(not os.path.lexists(DAEMON) and not os.path.lexists(WRAPPER),'FOREIGN_CONFIGURATION_PRESERVED')
    for path,expected in BINDS.values():require(sha(read(Path(path),True))==expected,'COMMAND_BINDING_DRIFT')
    raw=read(root/'sources.json');require(sha(raw)==manifest_hash,'SOURCE_MANIFEST_DRIFT');manifest=parse(raw)
    require(set(manifest)=={'sourceCommit','sourceHashes'} and manifest['sourceCommit']=='ace683b1019f79adaace86796b67e463b93ec12e','EXACT_SOURCE_REVISION_REQUIRED')
    sources={name:read(root/'source'/name) for name in manifest['sourceHashes']}
    require(len(sources)==19 and all(sha(v)==manifest['sourceHashes'][n] for n,v in sources.items()),'SOURCE_CLOSURE_DRIFT')
    self_raw=read(root/SELF);guard=read(GUARD);require(sha(guard)==GUARD_HASH,'GUARD_CONFIGURATION_DRIFT')
    before_guard=preflight();pid=daemon_pid();process=identity(pid);containers=inventory();catalogue=runtimes()
    require(catalogue['default']=='runc' and set(catalogue['runtimes'])=={'runc','io.containerd.runc.v2'},'EXISTING_RUNTIME_CATALOGUE_DRIFT')
    pidfd=os.pidfd_open(pid)
    lock=Path(parse(guard)['lockFile']);read(lock);fd=os.open(lock,os.O_RDWR|os.O_NOFOLLOW)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        require(not os.path.lexists(DAEMON) and not os.path.lexists(WRAPPER),'FOREIGN_CONFIGURATION_PRESERVED')
        require(identity(pid)==process and daemon_pid()==pid and inventory()==containers,'LIVE_STATE_CHANGED_BEFORE_PUBLICATION')
        (root/'registry').mkdir(mode=0o700)
        cfg=encoded(config(root,manifest));publish(root/'adapter-configuration.json',cfg)
        shell=('#!/bin/sh\nexec '+BINDS['python'][0]+' -I -B '+str(root/'source/scripts/semantic_provider_docker_runtime.py')+' --configuration '+str(root/'adapter-configuration.json')+' "$@"\n').encode()
        planned=encoded({'runtimes':{NAME:{'path':str(WRAPPER)}}})
        publish(root/'daemon-planned.json',planned)
        capture([process['path'],'--validate','--config-file',str(root/'daemon-planned.json')])
        version=capture([BINDS['python'][0],'-I','-B',str(root/'source/scripts/semantic_provider_docker_runtime.py'),
            '--configuration',str(root/'adapter-configuration.json'),'--version'])
        require(b'runc version' in version,'REAL_ADAPTER_VERSION_FAILED')
        def stable():
            require(read(root/SELF)==self_raw and read(root/'sources.json')==raw and read(GUARD)==guard,'INSTALLATION_INPUT_DRIFT')
            require(all(read(root/'source'/n)==v for n,v in sources.items()),'SOURCE_CLOSURE_DRIFT')
            require(all(sha(read(Path(p),True))==h for p,h in BINDS.values()),'COMMAND_BINDING_DRIFT')
            require(identity(pid)==process and daemon_pid()==pid,'DAEMON_PROCESS_CHANGED')
        stable()
        publish(root/'installation-claim.json',encoded({'state':'REGISTERING_EMPTY_RUNTIME','daemonPid':pid,
            'daemonPreviouslyAbsent':True,'runtimeName':NAME,'daemonHash':sha(planned),'wrapperHash':sha(shell),'startAuthorized':False}))
        publish(WRAPPER,shell,0o755);publish(DAEMON,planned)
        stable();signal.pidfd_send_signal(pidfd,signal.SIGHUP)
        deadline=time.monotonic()+20
        while True:
            current=runtimes()
            if NAME in current['runtimes']:break
            require(time.monotonic()<deadline,'RUNTIME_RELOAD_NOT_OBSERVED');time.sleep(0.25)
        require(current['default']==catalogue['default'] and {k:v for k,v in current['runtimes'].items() if k!=NAME}==catalogue['runtimes']
            and current['runtimes'][NAME].get('path')==str(WRAPPER),'RUNTIME_REGISTRATION_READBACK_DRIFT')
        stable();require(inventory()==containers and read(DAEMON)==planned and read(WRAPPER,True)==shell,'LIVE_STATE_OR_OWNED_FILES_CHANGED')
    finally:
        os.close(fd);os.close(pidfd)
    after_guard=preflight();require(before_guard==after_guard,'NATIVE_GUARD_READBACK_DRIFT')
    report={'schema':'ouf.semantic-provider-v2-runtime-registration.v1','status':'EMPTY_RUNTIME_REGISTERED',
        'directory':str(root),'runtimeName':NAME,'runtimeSourceCommit':manifest['sourceCommit'],'sourceHashes':manifest['sourceHashes'],
        'wrapperHash':sha(shell),'daemonConfigurationHash':sha(planned),'adapterConfigurationHash':sha(cfg),
        'daemonPidUnchanged':True,'existingContainerStatesUnchanged':True,'existingContainerCount':len(containers),
        'guardCustodyUnchanged':True,'defaultRuntimeUnchanged':True,'candidateCount':0,'startAuthorized':False,
        'containerLifecycleOperations':0,'imageImportPerformed':False,'firewallWrites':0,'privateKeysRead':0,'providerCalls':0,
        'generalSudoGranted':False,'daemonRestarted':False,'notReleaseAcceptance':True,'acceptanceGranted':False}
    publish(root/'registration-receipt.json',encoded(report));return report

def main():
    p=argparse.ArgumentParser();p.add_argument('--package-root',type=Path,required=True);p.add_argument('--manifest-sha256',required=True)
    a=p.parse_args()
    try:
        require(sys.flags.isolated and sys.dont_write_bytecode and a.package_root.parent==Path('/etc/ouf/deploy-snapshots')
            and re.fullmatch('semantic-v2-runtime-registration-[A-Za-z0-9]+',a.package_root.name),'EXPLICIT_PRIVATE_PACKAGE_REQUIRED')
        print('OUF_PROVIDER_V2_RUNTIME_REGISTRATION='+json.dumps(operate(a.package_root,a.manifest_sha256),sort_keys=True));return 0
    except Exception as error:
        reason=str(error) if isinstance(error,Denied) and re.fullmatch('[A-Z_]{1,80}',str(error)) else 'REGISTRATION_UNPROVEN'
        print('OUF_PROVIDER_V2_RUNTIME_REGISTRATION=BLOCKED REASON='+reason+' EVIDENCE_RETAINED=true DO_NOT_RERUN_APPLY=true NO_RAW_OUTPUT=true');return 1

if __name__=='__main__':raise SystemExit(main())
