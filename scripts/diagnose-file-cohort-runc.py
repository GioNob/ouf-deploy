#!/usr/bin/python3
"""Read exact retained Registry/adapter references and redacted native state.

No container operation except inspect, and only runc state. No IAM, grant,
restart, unpause, token read, migration, signing or automatic retry.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

BASE=Path('/etc/ouf/deploy-snapshots')
REVIEW='92b3276992b3b3ec459e734196671728b8a49a99a02185e2c6f7c1da87ce82a1'
INTAKE='395c92d7bcb8dadfa3bb248a3e94b37bd36a396cc07c16ee5d1d57a646e00239'
BUNDLE_PARENT='/run/docker/containerd/daemon/io.containerd.runtime.v2.task/moby'
RUNTIME_ROOT='/run/docker/runtime-runc/moby'


def need(ok,reason):
    if not ok:raise ValueError(reason)


def attributes(info):
    return tuple(getattr(info,k) for k in ('st_dev','st_ino','st_uid','st_gid',
                 'st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))


def read_bound(binding, executable=False):
    need(type(binding) is dict and set(binding)=={'path','sha256'} and
         re.fullmatch('[0-9a-f]{64}',binding['sha256']), 'EXACT_SELECTED_BINDING_REQUIRED')
    path=Path(binding['path']);need(path.is_absolute() and '..' not in path.parts,'ABSOLUTE_SELECTED_PATH_REQUIRED')
    for parent in (path.parent,*path.parent.parents):
        info=parent.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,
             'ROOT_ANCESTOR_CUSTODY_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd);limit=64000000 if executable else 2000000
        need(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and before.st_nlink==1
             and 0<before.st_size<=limit and not before.st_mode&0o022
             and (bool(before.st_mode&0o111) if executable else stat.S_IMODE(before.st_mode)==0o600),
             'ROOT_SELECTED_FILE_CUSTODY_REQUIRED')
        with os.fdopen(os.dup(fd),'rb') as stream:raw=stream.read(limit+1)
        need(len(raw)==before.st_size and attributes(before)==attributes(os.fstat(fd))==attributes(path.lstat())
             and hashlib.sha256(raw).hexdigest()==binding['sha256'],'SELECTED_FILE_HASH_OR_GENERATION_DRIFT')
        return raw
    finally:os.close(fd)


def generation(row):
    return {k:row['State'][k] for k in ('Pid','StartedAt','Running','Paused','Status')}


def facts(current, recorded, state):
    cid=current['Id'];bundle=state.get('bundle');expected=BUNDLE_PARENT+'/'+cid
    status=state.get('status');status=status if status in ('created','running','paused','stopped') else 'UNKNOWN'
    docker_status=current['State'].get('Status');docker_status=docker_status if docker_status in ('created','running','paused','exited','dead','restarting') else 'UNKNOWN'
    return {'retainedEngineGenerationMatched':all(current.get(k)==recorded.get(v) for k,v in
                (('Id','id'),('Image','image'))) and current['State']['Pid']==recorded.get('pid')
                and current['State']['StartedAt']==recorded.get('startedAt'),
            'engineRunning':current['State'].get('Running') is True,
            'enginePaused':current['State'].get('Paused') is True,'engineStatus':docker_status,
            'runcStatus':status,'runcContainerIdMatched':state.get('id')==cid,
            'runcPidMatched':type(state.get('pid')) is int and state['pid']==current['State']['Pid'],
            'bundleExactExpected':bundle==expected,
            'bundleUsesVarRunAlias':bundle=='/var'+expected,
            'bundleUsesSystemContainerd':bundle=='/run/containerd/io.containerd.runtime.v2.task/moby/'+cid,
            'bundleHasExactContainerSuffix':type(bundle) is str and Path(bundle).name==cid,
            'oldCollectorConditionPassed':state.get('id')==cid and status=='running'
                and state.get('pid')==current['State']['Pid'] and bundle==expected}


def main():
    need(os.geteuid()==os.getegid()==0 and os.sys.flags.isolated,'ISOLATED_ROOT_READ_REQUIRED')
    review_binding={'path':str(BASE/('semantic-candidate-installation-input-review-'+REVIEW+'.private.json')),'sha256':REVIEW}
    intake_binding={'path':str(BASE/('semantic-native-v11-intake-'+INTAKE)/'intake.json'),'sha256':INTAKE}
    review_raw=read_bound(review_binding);intake_raw=read_bound(intake_binding)
    review=json.loads(review_raw);intake=json.loads(intake_raw)
    execution_binding={'path':str(Path(intake_binding['path']).parent/'retained-execution-configuration.json'),
                       'sha256':intake['fileHashes']['retained-execution-configuration.json']}
    execution_raw=read_bound(execution_binding);execution=json.loads(execution_raw)
    adapter_binding=execution['runtimeAdapterBinding'];adapter_raw=read_bound(adapter_binding);adapter=json.loads(adapter_raw)
    need(adapter['runtimeStateRoot']=='/run/docker','RETAINED_RUNTIME_ROOT_PROFILE_REQUIRED')
    runtime={'path':adapter['runtimePath'],'sha256':adapter['runtimeSha256']}
    read_bound(runtime,True)
    docker=Path(shutil.which('docker') or '/usr/bin/docker').resolve();docker_info=docker.stat()
    need(stat.S_ISREG(docker_info.st_mode) and docker_info.st_uid==docker_info.st_gid==0
         and not docker_info.st_mode&0o022,'ROOT_DOCKER_EXECUTABLE_REQUIRED')
    docker_hash=hashlib.sha256(docker.read_bytes()).hexdigest()
    cid=review['currentRegistry']['id'];need(re.fullmatch('[0-9a-f]{64}',cid),'EXACT_RETAINED_CONTAINER_REQUIRED')
    socket=Path('/var/run/docker.sock').resolve();socket_info=socket.stat()
    need(stat.S_ISSOCK(socket_info.st_mode) and socket_info.st_uid==0,'ROOT_LOCAL_ENGINE_REQUIRED')
    with tempfile.TemporaryDirectory(prefix='ouf-runc-read-') as config:
        def run(argv,limit):
            with tempfile.TemporaryFile() as out:
                result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.DEVNULL,
                    env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},timeout=10)
                need(result.returncode==0 and out.tell()<=limit,'NATIVE_READ_FAILED_OR_UNBOUNDED')
                out.seek(0);return json.loads(out.read(limit+1))
        def inspect():
            row=run([str(docker),'--host','unix://'+str(socket),'--config',config,'inspect','--type=container',cid],8388608)
            need(type(row) is list and len(row)==1 and row[0]['Id']==cid,'EXACT_ENGINE_INSPECTION_REQUIRED')
            return row[0]
        current=inspect()
        state=run([runtime['path'],'--root',RUNTIME_ROOT,'state',cid],16384)
        second=run([runtime['path'],'--root',RUNTIME_ROOT,'state',cid],16384)
        fresh=inspect();result=facts(current,review['currentRegistry'],state)
        result['stableEngineGeneration']=current['Id']==fresh['Id'] and current['Image']==fresh['Image'] and generation(current)==generation(fresh)
        result['stableRuncState']=state==second
        need(read_bound(review_binding)==review_raw and read_bound(intake_binding)==intake_raw
             and read_bound(execution_binding)==execution_raw and read_bound(adapter_binding)==adapter_raw,
             'RETAINED_DIAGNOSIS_INPUT_DRIFT')
        read_bound(runtime,True)
        need(hashlib.sha256(docker.read_bytes()).hexdigest()==docker_hash and
             (socket.stat().st_dev,socket.stat().st_ino)==(socket_info.st_dev,socket_info.st_ino),
             'NATIVE_COMMAND_OR_ENGINE_DRIFT')
        print(json.dumps({'schema':'ouf.chatbot-cohort-runc-diagnosis.v1','readOnly':True,
            'runtimeAuthorityIssued':False,'serviceMutations':0,'containerLifecycleOperations':0,
            'databaseMutations':0,'automaticRetry':False,'budgetReset':False,'notReleaseAcceptance':True,
            'facts':result},sort_keys=True),flush=True)


if __name__=='__main__':
    try:main()
    except Exception as error:
        reason=str(error) if type(error) is ValueError and re.fullmatch('[A-Z][A-Z0-9_]{1,159}',str(error)) else type(error).__name__
        print(json.dumps({'schema':'ouf.chatbot-cohort-runc-diagnosis.v1','status':'BLOCKED','reason':reason,
            'readOnly':True,'runtimeAuthorityIssued':False,'automaticRetry':False}),flush=True)
        raise SystemExit(1)
