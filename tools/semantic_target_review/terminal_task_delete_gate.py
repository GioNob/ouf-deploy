"""Terminal maintenance gate: only acknowledge delete of proven absent tasks.

No kill/start/create/exec or native lifecycle delegation is implemented. The
root maintenance executor supplies a short-lived, exact two-CID configuration.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

class Denied(RuntimeError):pass

def require(ok,reason):
    if not ok:raise Denied(reason)

def private(path,executable=False):
    path=Path(path);require(path.is_absolute() and '..' not in path.parts,'ABSOLUTE_GATE_PATH_REQUIRED')
    for parent in path.parents:
        info=parent.lstat();require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,'ROOT_GATE_ANCESTOR_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd);limit=64000000 if executable else 131072
        require(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0 and info.st_nlink==1 and info.st_size<=limit
            and (info.st_mode&0o111 and not info.st_mode&0o022 if executable else stat.S_IMODE(info.st_mode)==0o600),'ROOT_GATE_FILE_REQUIRED')
        chunks=[];size=0
        while True:
            raw=os.read(fd,65536)
            if not raw:break
            size+=len(raw);require(size<=limit,'GATE_FILE_UNBOUNDED');chunks.append(raw)
        fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        expected=tuple(getattr(info,k) for k in fields)
        require(size==info.st_size and tuple(getattr(os.fstat(fd),k) for k in fields)==expected
            and tuple(getattr(path.lstat(),k) for k in fields)==expected,'GATE_FILE_CHANGED')
        return b''.join(chunks)
    finally:os.close(fd)

def parse_delete(argv,cids,runtime_root):
    require(0<len(argv)<=12 and all(type(s) is str and len(s)<=4096 for s in argv),'BOUNDED_DELETE_ARGV_REQUIRED')
    options={};i=0
    while i<len(argv):
        arg=argv[i]
        if arg in ('--debug','--systemd-cgroup'):
            require(arg not in options,'DUPLICATE_RUNTIME_OPTION');options[arg]=True;i+=1;continue
        if arg in ('--root','--log','--log-format'):
            require(arg not in options and i+1<len(argv),'EXACT_RUNTIME_OPTION_REQUIRED')
            options[arg]=argv[i+1];i+=2;continue
        break
    require(argv[i:][0:1]==['delete'] and len(argv[i:])==2,'DELETE_ONLY_NO_FORCE_REQUIRED')
    cid=argv[i+1];require(cid in cids and re.fullmatch('[0-9a-f]{64}',cid),'EXACT_TERMINAL_CID_REQUIRED')
    require(options.get('--root')==runtime_root,'EXACT_RETAINED_RUNTIME_ROOT_REQUIRED')
    if '--log-format' in options:require(options['--log-format']=='json','RUNC_JSON_LOG_FORMAT_REQUIRED')
    return cid

def absent(config,list_rows,pid_present=os.path.lexists):
    cids=config['tasks']
    # runc serializes a genuinely empty inventory as JSON null.
    if list_rows is None:list_rows=[]
    require(type(list_rows) is list and len(list_rows)<=1024,'BOUNDED_RUNC_INVENTORY_REQUIRED')
    require(not any(row.get('id') in cids for row in list_rows),'TERMINAL_RUNC_ABSENCE_REQUIRED')
    for cid,record in cids.items():
        require(type(record['pid']) is int and record['pid']>1,'EXACT_RECORDED_TASK_PID_REQUIRED')
        require(not pid_present('/proc/'+str(record['pid'])),'TERMINAL_TASK_PID_ABSENCE_REQUIRED')
        require(not pid_present(str(Path(config['runtimeRoot'])/cid)),'TERMINAL_RUNC_DIRECTORY_ABSENCE_REQUIRED')

def acknowledge(configuration_path,argv):
    require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode,'ISOLATED_ROOT_GATE_REQUIRED')
    raw=private(configuration_path);cfg=json.loads(raw)
    require(cfg['schema']=='ouf.semantic-terminal-task-delete-window.v1' and len(cfg['tasks'])==2,'EXACT_TWO_TASK_WINDOW_REQUIRED')
    require(type(cfg['issuedAt']) is int and type(cfg['expiresAt']) is int and cfg['issuedAt']<=time.time()<cfg['expiresAt']
        and cfg['expiresAt']-cfg['issuedAt']<=120,'LIVE_TERMINAL_MAINTENANCE_WINDOW_REQUIRED')
    require(re.fullmatch('[A-Z][A-Z0-9_]{1,100}',cfg['approvalRef']) is not None,'EXPLICIT_MAINTENANCE_APPROVAL_REFERENCE_REQUIRED')
    parse_delete(argv,cfg['tasks'],cfg['runtimeRoot'])
    binding=cfg['runcBinding'];binary=private(binding['path'],True)
    require(hashlib.sha256(binary).hexdigest()==binding['sha256'],'MAINTENANCE_RUNC_EXECUTABLE_DRIFT')
    result=subprocess.run([binding['path'],'--root',cfg['runtimeRoot'],'list','--format','json'],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    require(result.returncode==0 and len(result.stdout)<=131072,'TERMINAL_RUNC_READ_FAILED')
    absent(cfg,json.loads(result.stdout))
    require(private(configuration_path)==raw and private(binding['path'],True)==binary,'MAINTENANCE_GATE_CUSTODY_DRIFT')
    require(time.time()<cfg['expiresAt'],'MAINTENANCE_WINDOW_EXPIRED')
    # Nothing exists in runc and no recorded task PID exists. Only containerd's
    # subsequent terminal metadata/IO/rootfs teardown remains; no syscall kill
    # or runtime delete/create/start is issued by this gate.
    return 0

if __name__=='__main__':
    try:
        require(len(sys.argv)>=4 and sys.argv[1]=='--configuration','EXACT_MAINTENANCE_GATE_CLI_REQUIRED')
        sys.exit(acknowledge(sys.argv[2],sys.argv[3:]))
    except Exception as error:
        reason=str(error) if isinstance(error,Denied) else 'TERMINAL_DELETE_UNPROVEN'
        print('OUF_TERMINAL_DELETE_GATE=DENIED REASON='+reason,file=sys.stderr)
        sys.exit(1)
