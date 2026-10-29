"""Fixed read-only daemon/guard inputs; never open keys, env or credentials."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

CONFIG=Path('/etc/ouf/deploy-snapshots/semantic-runtime-transition-stage-20261003-160211/prepared/runtime-configuration.json')
CONFIG_HASH='24968cf990a32b87f3169b9226fe63d224c93a403540afec197011fbd670b0bb'

def require(ok, reason):
    if not ok: raise RuntimeError(reason)

def read(path, limit=131072):
    for parent in (path.parent,*path.parent.parents):
        s=parent.lstat(); require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'ROOT_ANCESTOR_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        a=os.fstat(fd);require(stat.S_ISREG(a.st_mode) and a.st_uid==0 and a.st_nlink==1 and not a.st_mode&0o022 and a.st_size<=limit,'BOUNDED_ROOT_FILE_REQUIRED')
        raw=os.read(fd,limit+1);b=os.fstat(fd)
        require(len(raw)==a.st_size and all(getattr(a,k)==getattr(b,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_size','st_mtime_ns','st_ctime_ns')),'ROOT_FILE_READ_DRIFT')
        return raw
    finally:os.close(fd)

def json_value(raw):
    def unique(pairs):
        d={}
        for k,v in pairs:
            require(k not in d,'DUPLICATE_JSON_KEY');d[k]=v
        return d
    return json.loads(raw,object_pairs_hook=unique)

def main():
    try:
        require(os.geteuid()==0 and __import__('sys').flags.isolated,'ROOT_ISOLATED_READ_REQUIRED')
        raw=read(CONFIG);require(hashlib.sha256(raw).hexdigest()==CONFIG_HASH,'ORIGINAL_GUARD_CONFIGURATION_DRIFT')
        cfg=json_value(raw);kernel=cfg['kernel']
        p=subprocess.run(['/usr/bin/systemctl','show','docker.service','--property=ExecStart','--value'],capture_output=True,timeout=10)
        require(p.returncode==0 and len(p.stdout)<=16384,'DOCKER_COMMAND_READ_UNAVAILABLE')
        command=p.stdout.decode();explicit=re.search(r'--config-file(?:=|\s+)([^\s;]+)',command)
        daemon=Path(explicit.group(1) if explicit else '/etc/docker/daemon.json')
        require(daemon.is_absolute() and '..' not in daemon.parts,'DAEMON_CONFIGURATION_PATH_UNPROVEN')
        exists=os.path.lexists(daemon)
        if exists:
            daemon_raw=read(daemon);value=json_value(daemon_raw);require(isinstance(value,dict),'DAEMON_JSON_OBJECT_REQUIRED')
            runtime=value.get('runtimes',{});require(isinstance(runtime,dict) and len(runtime)<=16,'RUNTIME_CATALOGUE_UNBOUNDED')
            runtime_names=sorted(runtime);require(all(re.fullmatch('[A-Za-z0-9_.-]{1,128}',n) for n in runtime_names),'RUNTIME_NAME_INVALID')
            daemon_report={'path':str(daemon),'present':True,'sha256':hashlib.sha256(daemon_raw).hexdigest(),
                'configurationKeys':sorted(value),'runtimeNames':runtime_names,'defaultRuntime':value.get('default-runtime')}
            require(read(daemon)==daemon_raw,'DAEMON_CONFIGURATION_READ_DRIFT')
        else:daemon_report={'path':str(daemon),'present':False,'runtimeNames':[]}
        tools={}
        for name,path in {'python':'/usr/bin/python3','runc':'/usr/bin/runc','docker':'/usr/bin/docker','nft':'/usr/sbin/nft','ip':'/usr/sbin/ip','nsenter':'/usr/bin/nsenter','unshare':'/usr/bin/unshare','mount':'/usr/bin/mount','umount':'/usr/bin/umount','openssl':'/usr/bin/openssl'}.items():
            if not Path(path).exists():
                tools[name]={'present':False};continue
            target=Path(path).resolve(strict=True);binary=read(target,64000000)
            require(target.stat().st_mode&0o111,'COMMAND_NOT_EXECUTABLE')
            tools[name]={'path':str(target),'sha256':hashlib.sha256(binary).hexdigest()}
        require(read(CONFIG)==raw,'ORIGINAL_GUARD_CONFIGURATION_READ_DRIFT')
        report={'schema':'ouf.semantic-provider-v2-runtime-host-inputs.v1','status':'READ_ONLY_HOST_INPUTS',
            'daemon':daemon_report,'commands':tools,'guardConfigurationHash':CONFIG_HASH,
            'guardConfigurationFields':sorted(cfg),'guardTable':kernel['tableName'],
            'guardedInterfaces':kernel['guardedInterfaces'],'excludedSharedInterfaces':kernel['existingInterfaces'],
            'staticFlows':[{k:f[k] for k in ('purpose','source','destination','protocol','port')} for f in kernel['staticFlows']],
            'providerFlowBindings':[{k:f[k] for k in ('endpointRef','source','leaseSeconds','resolutionEvidenceRef')} for f in kernel['providerFlows']],
            'commonLockFile':cfg.get('lockFile'),'configurationWrites':0,'containerLifecycleOperations':0,
            'privateKeysRead':0,'environmentFilesRead':0,'providerCalls':0,'secretValuesPrinted':False,'startAuthorized':False}
        print('OUF_PROVIDER_V2_RUNTIME_HOST='+json.dumps(report,sort_keys=True));return 0
    except Exception as error:
        reason=str(error)
        if not re.fullmatch('[A-Z_]{1,80}',reason):reason='HOST_INPUTS_UNPROVEN'
        print('OUF_PROVIDER_V2_RUNTIME_HOST=BLOCKED REASON='+reason+' NO_RAW_OUTPUT=true');return 1

if __name__=='__main__':raise SystemExit(main())
