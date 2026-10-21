"""Read only public engine build identity through the runner's existing socket."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

DOCKER=Path('/usr/bin/docker')
EXPECTED='7f5b38163f9c5367f4b42d905c0505877eafa4c20abe49430c85a770aefacf40'
def verify():
    for parent in DOCKER.parents:
        s=parent.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise ValueError('DOCKER_ANCESTOR_DRIFT')
    fd=os.open(DOCKER,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        s=os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022 or not s.st_mode&0o111 or s.st_size>64000000:raise ValueError('DOCKER_BINARY_UNPROVEN')
        if hashlib.file_digest(stream,'sha256').hexdigest()!=EXPECTED:raise ValueError('DOCKER_BINARY_DRIFT')
def main():
    try:
        verify()
        with tempfile.TemporaryDirectory(prefix='ouf-engine-source-') as cfg,tempfile.TemporaryFile() as output:
            p=subprocess.run([str(DOCKER),'--config',cfg,'--host','unix:///var/run/docker.sock','version','--format','{{json .Server}}'],
                stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.DEVNULL,timeout=10,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
            output.seek(0);raw=output.read(16385)
            if p.returncode or not 0<len(raw)<=16384:raise ValueError('BOUNDED_ENGINE_READ_FAILED')
        verify();server=json.loads(raw);version=server['Version'];commit=server['GitCommit']
        if not re.fullmatch('[0-9]+[.][0-9]+[.][0-9]+(?:[-+][A-Za-z0-9.-]+)?',version) or not re.fullmatch('[0-9a-f]{7,40}',commit):raise ValueError('EXACT_ENGINE_SOURCE_BINDING_REQUIRED')
        if server['Os']!='linux' or server['Arch']!='amd64':raise ValueError('TARGET_ENGINE_PLATFORM_DRIFT')
        report={'schema':'ouf.semantic-provider-engine-source-read.v1','serverVersion':version,'gitCommit':commit,
            'os':server['Os'],'architecture':server['Arch'],'containerLifecycleOperations':0,'configurationWrites':0,
            'privateKeysRead':0,'privateEnvironmentRead':False,'providerCalls':0,'startAuthorized':False}
        print('OUF_PROVIDER_ENGINE_SOURCE='+json.dumps(report,sort_keys=True));return 0
    except Exception as error:
        reason=str(error) if isinstance(error,ValueError) and re.fullmatch('[A-Z0-9_]{1,80}',str(error)) else 'ENGINE_SOURCE_UNPROVEN'
        print('OUF_PROVIDER_ENGINE_SOURCE=BLOCKED REASON='+reason+' NO_RAW_OUTPUT=true');return 1
if __name__=='__main__':raise SystemExit(main())
