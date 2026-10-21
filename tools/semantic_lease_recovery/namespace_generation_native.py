"""Actual Docker UID10001 process and nsfs under NET_ADMIN only."""
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import namespace_generation as m

def run(args):return subprocess.check_output(args,text=True,timeout=60).strip()

def proc_generation(pid):
    return {'pid':pid,'startTicks':m.ticks(pid),'namespaceInode':(Path('/proc')/str(pid)/'ns/net').stat().st_ino}

def main():
    spec=importlib.util.spec_from_file_location('diag',HERE.parents[1]/'scripts/read-r11-guard-diagnosis.py')
    diag=importlib.util.module_from_spec(spec);spec.loader.exec_module(diag)
    name='ouf-nsfs-ci-'+uuid.uuid4().hex[:8]
    cid=run(['/usr/bin/docker','run','-d','--name',name,'--user','10001:10001','busybox:1.37','sleep','600'])
    try:
        raw=json.loads(run(['/usr/bin/docker','inspect',cid]))[0]
        data={'sandboxKey':raw['NetworkSettings']['SandboxKey'],'state':raw['State']}
        expected=proc_generation(data['state']['Pid']);binding=m.capture(data,expected,proc_generation)
        readfd,writefd=os.pipe();child=os.fork()
        if child==0:
            os.close(readfd)
            try:
                diag.net_admin_only()
                try:proc_generation(expected['pid']);old_denied=False
                except PermissionError:old_denied=True
                fresh=json.loads(run(['/usr/bin/docker','inspect',cid]))[0]
                m.verify_metadata({'sandboxKey':fresh['NetworkSettings']['SandboxKey'],'state':fresh['State']},binding)
                result=m.generation(binding,expected['pid'])
                os.write(writefd,json.dumps({'oldDenied':old_denied,'generation':result}).encode())
            except Exception as error:
                os.write(writefd,json.dumps({'error':type(error).__name__,'reason':str(error)}).encode())
            finally:os._exit(0)
        os.close(writefd);result=json.loads(os.read(readfd,65536));os.close(readfd)
        _,status=os.waitpid(child,0);assert status==0
        assert result=={'oldDenied':True,'generation':expected},result
        drift=dict(binding);drift['inode']+=1
        try:m.generation(drift,expected['pid'])
        except ValueError:pass
        else:raise AssertionError('NSFS_DRIFT_NOT_DENIED')
        print('CI_NAMESPACE_GENERATION=REAL_DOCKER_UID10001_NET_ADMIN_ONLY_NSFS_PASS OLD_PROC_DENIED=true DRIFT_DENIED=true TARGET_ACTIONS=0')
    finally:run(['/usr/bin/docker','rm','-f',cid])

if __name__=='__main__':main()
