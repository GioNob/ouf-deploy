"""Disposable actual containerd/runc terminal metadata teardown; CI only."""
import hashlib,io,json,os,shutil,subprocess,tarfile,tempfile,time,uuid
from pathlib import Path
REPO=Path.cwd();ENGINE=Path(os.environ['OUF_PLUGIN_ENGINE_DIRECTORY']).resolve()
def require(ok,reason):
    if not ok:raise RuntimeError(reason)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
def private(path,raw):path.write_bytes(raw);path.chmod(0o600)
def run(*argv,check=True):
    p=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=35)
    require(len(p.stdout)<1048576 and len(p.stderr)<1048576,'CI_OUTPUT_UNBOUNDED')
    if check:require(p.returncode==0,'CI_COMMAND_FAILED '+Path(argv[0]).name+' '+p.stderr.decode()[:1500])
    return p
with tempfile.TemporaryDirectory(prefix='ouf-terminal-ci-',dir='/root') as temporary:
    root=Path(temporary);engine=root/'engine';engine.mkdir(mode=0o700)
    for p in ENGINE.iterdir():
        if p.is_file():q=engine/p.name;shutil.copyfile(p,q);q.chmod(0o755)
    config=root/'containerd.toml';private(config,b'version = 2\n')
    socket=root/'containerd.sock';state=root/'state';wrapper=root/'runtime';capture=root/'captured';capture.mkdir(mode=0o700)
    proxy='''#!/usr/bin/python3
import json,os,sys
from pathlib import Path
args=sys.argv[1:]
if 'delete' in args:sys.exit(1)
if 'create' in args:
 cid=args[args.index('create')+1]
 # go-runc create may place operation flags before its final CID.
 cid=args[-1]
 Path(CAPTURE+'/'+cid).write_text(json.dumps({'root':args[args.index('--root')+1]}))
os.execv(RUNC,[RUNC,*args])
'''.replace('CAPTURE',repr(str(capture))).replace('RUNC',repr(str(engine/'runc')))
    wrapper.write_text(proxy);wrapper.chmod(0o755)
    # Offline OCI image with a static busybox; no registry/provider requests.
    data=io.BytesIO()
    with tarfile.open(fileobj=data,mode='w') as tar:
        for directory in ('bin','dev','proc','sys','tmp'):
            item=tarfile.TarInfo(directory);item.type=tarfile.DIRTYPE;item.mode=0o755;tar.addfile(item)
        raw=Path('/usr/bin/busybox').read_bytes();item=tarfile.TarInfo('bin/busybox');item.size=len(raw);item.mode=0o755;tar.addfile(item,io.BytesIO(raw))
    layer=data.getvalue();cfg=encoded({'architecture':'amd64','os':'linux','config':{'Entrypoint':['/bin/busybox','sleep','300']},'rootfs':{'type':'layers','diff_ids':['sha256:'+sha(layer)]}})
    def descriptor(kind,raw):return {'mediaType':kind,'digest':'sha256:'+sha(raw),'size':len(raw)}
    manifest=encoded({'schemaVersion':2,'mediaType':'application/vnd.oci.image.manifest.v1+json','config':descriptor('application/vnd.oci.image.config.v1+json',cfg),'layers':[descriptor('application/vnd.oci.image.layer.v1.tar',layer)]})
    image='docker.io/library/ouf-terminal-ci:latest';d=descriptor('application/vnd.oci.image.manifest.v1+json',manifest);d['annotations']={'org.opencontainers.image.ref.name':image};d['platform']={'os':'linux','architecture':'amd64'}
    index=encoded({'schemaVersion':2,'manifests':[d]});archive=root/'image.tar'
    with tarfile.open(archive,'w') as tar:
        for name,raw in [('oci-layout',encoded({'imageLayoutVersion':'1.0.0'})),('index.json',index),*[(('blobs/sha256/'+sha(raw)),raw) for raw in (cfg,layer,manifest)]]:
            item=tarfile.TarInfo(name);item.size=len(raw);item.mode=0o600;tar.addfile(item,io.BytesIO(raw))
    with (root/'daemon.log').open('wb') as log:
        daemon=subprocess.Popen([str(engine/'containerd'),'--config',str(config),'--root',str(root/'storage'),'--state',str(state),'--address',str(socket)],stdout=log,stderr=log,env={**os.environ,'PATH':str(engine)+':/usr/bin:/bin'})
        cids=[uuid.uuid4().hex+uuid.uuid4().hex for _ in range(2)]
        def ctr(*args,check=True):return run(str(engine/'ctr'),'--address',str(socket),'--namespace','ouf-terminal-ci',*args,check=check)
        try:
            deadline=time.monotonic()+15
            while not socket.exists():require(daemon.poll() is None and time.monotonic()<deadline,'CI_CONTAINERD_READINESS');time.sleep(.1)
            ctr('images','import','--local','--platform','linux/amd64','--snapshotter','native',str(archive))
            pids={};roots=set()
            for cid in cids:
                ctr('run','--detach','--snapshotter','native','--runc-binary',str(wrapper),image,cid)
                rows=ctr('tasks','list').stdout.decode().splitlines()[1:]
                pids[cid]=int(next(row.split()[1] for row in rows if row.split()[0]==cid))
                roots.add(json.loads((capture/cid).read_text())['root'])
            require(len(roots)==1,'CI_SHARED_EXPLICIT_RUNC_ROOT');runtime_root=roots.pop()
            for cid in cids:run(str(engine/'runc'),'--root',runtime_root,'kill',cid,'KILL')
            deadline=time.monotonic()+10
            while any(Path('/proc',str(pid)).exists() for pid in pids.values()):require(time.monotonic()<deadline,'CI_TASK_PID_REAP');time.sleep(.1)
            for cid in cids:run(str(engine/'runc'),'--root',runtime_root,'delete',cid)
            rows=ctr('tasks','list').stdout.decode().splitlines()[1:]
            require(all(any(row.split()[0]==cid and row.split()[2]=='STOPPED' for row in rows) for cid in cids),'CI_TWO_STOPPED_RESIDUAL_TASKS')
            require(ctr('tasks','delete',cids[0],check=False).returncode!=0,'CI_ORIGINAL_WRAPPER_MUST_DENY_DELETE')
            before={cid:ctr('containers','info',cid).stdout for cid in cids}
            gate=root/'gate.py';private(gate,(REPO/'tools/semantic_target_review/terminal_task_delete_gate.py').read_bytes())
            gate_cfg=root/'gate.json';now=int(time.time());private(gate_cfg,encoded({'schema':'ouf.semantic-terminal-task-delete-window.v1','approvalRef':'DISPOSABLE_CI_NO_TARGET_AUTHORITY','issuedAt':now,'expiresAt':now+120,'tasks':{cid:{'pid':pid} for cid,pid in pids.items()},'runtimeRoot':runtime_root,'runcBinding':{'path':str(engine/'runc'),'sha256':sha((engine/'runc').read_bytes())}}))
            wrapper.write_text('#!/bin/sh\nexec /usr/bin/python3 -I -B '+str(gate)+' --configuration '+str(gate_cfg)+' "$@"\n');wrapper.chmod(0o755)
            for cid in cids:ctr('tasks','delete',cid)
            rows=ctr('tasks','list').stdout.decode().splitlines()[1:]
            require(not any(row.split()[0] in cids for row in rows),'CI_TWO_TASKS_REMOVED')
            require(all(ctr('containers','info',cid).stdout==before[cid] for cid in cids),'CI_CONTAINER_METADATA_PRESERVED')
            require(not any(v.get('id') in cids for v in (json.loads(run(str(engine/'runc'),'--root',runtime_root,'list','--format','json').stdout) or [])),'CI_NO_RUNTIME_ENTRY_CREATED')
            print('TERMINAL_TASK_CLEANUP_NATIVE=PASS TWO_STOPPED_TASKS_REMOVED=true CONTAINER_METADATA_PRESERVED=true ORIGINAL_DELETE_DENIAL_REPRODUCED=true NO_FORCE_OR_KILL_BY_GATE=true TARGET_AUTHORITY=false')
        finally:
            # CI-only disposal must also release a failed test's shim mounts.
            wrapper.write_text('#!/bin/sh\nexec '+str(engine/'runc')+' \"$@\"\n');wrapper.chmod(0o755)
            for cid in cids:
                ctr('tasks','kill','--signal','SIGKILL',cid,check=False)
                ctr('tasks','delete',cid,check=False)
            daemon.terminate()
            try:daemon.wait(timeout=10)
            except subprocess.TimeoutExpired:daemon.kill();daemon.wait()
