"""Real /proc privilege regression with distinct UID; no target access."""
import importlib.util
import json
import os
from pathlib import Path
import signal

path=Path(__file__).with_name('read-r11-guard-diagnosis.py')
spec=importlib.util.spec_from_file_location('guard_diag',path)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def main():
    readfd,writefd=os.pipe()
    target=os.fork()
    if target==0:
        os.close(readfd)
        os.setgid(10001);os.setuid(10001)
        os.write(writefd,b'1');os.close(writefd)
        signal.pause();os._exit(0)
    os.close(writefd);assert os.read(readfd,1)==b'1';os.close(readfd)
    try:
        inode=(Path('/proc')/str(target)/'ns/net').stat().st_ino
        readfd,writefd=os.pipe();child=os.fork()
        if child==0:
            os.close(readfd)
            try:
                m.net_admin_only()
                try:(Path('/proc')/str(target)/'ns/net').stat();result={'denied':False}
                except PermissionError as error:result={'denied':True,'errno':error.errno}
                os.write(writefd,json.dumps(result).encode())
            finally:os._exit(0)
        os.close(writefd);result=json.loads(os.read(readfd,65536));os.close(readfd)
        _,status=os.waitpid(child,0);assert status==0
        assert result=={'denied':True,'errno':13},result
        assert (Path('/proc')/str(target)/'ns/net').stat().st_ino==inode
        print('CI_R11_GUARD_CAPABILITY=ROOT_PASS_NET_ADMIN_ONLY_PROC_NAMESPACE_DENIED DISTINCT_UID=true TARGET_ACTIONS=0')
    finally:
        os.kill(target,signal.SIGTERM);os.waitpid(target,0)

if __name__=='__main__':main()
