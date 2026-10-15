#!/usr/bin/env python3
"""Pinned failed attempt: bounded read-only journals and Engine GETs only."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess

CONTEXT = Path('/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-dd03d434361deb62e1caeaf7958a71c39c095f065e776312779d59dd6a7f4a77')
AUTHORITY = '48c75739575b7d618484ed78184834d2d1961da97fa2870d80d14ce26fe978f4'
SOURCE = 'b64645982655f58a2907bf1425dd86fd6ab0ed9f'
MODULES = ('semantic', 'udp', 'onboarding', 'ingestion', 'mcp')
FIELDS = ('User','Entrypoint','Cmd','Env','WorkingDir','Labels','Volumes','ExposedPorts','StopSignal','Healthcheck','Shell')

def require(ok, code):
    if not ok: raise ValueError(code)

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()

def emit(check, **data):
    print(json.dumps(dict(schema='ouf.chatbot-image-import-readback.v1',check=check,
        readOnly=True,automaticRetry=False,budgetReset=False,**data),sort_keys=True),flush=True)

def read(path, maximum, expected=None):
    path = Path(path)
    require(path.is_absolute() and path.resolve()==path, 'EXACT_READ_PATH_REQUIRED')
    fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_nlink==1
            and not before.st_mode & 0o077 and 0<before.st_size<=maximum,'PRIVATE_BOUNDED_JSON_REQUIRED')
        raw=bytearray()
        while len(raw)<=maximum:
            part=os.read(fd,min(65536,maximum+1-len(raw)))
            if not part:break
            raw.extend(part)
        after=os.fstat(fd)
        require(len(raw)==before.st_size and (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)
            ==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),'JSON_CHANGED_DURING_READ')
        require(expected is None or hashlib.sha256(raw).hexdigest()==expected,'READ_BINDING_DRIFT')
        return json.loads(raw)
    finally:os.close(fd)

def safe_reason(error):
    text=str(error)
    return text if type(error)is ValueError and re.fullmatch('[A-Z][A-Z0-9_]{0,159}',text) else type(error).__name__

def inspect(engine, image):
    require(re.fullmatch('sha256:[0-9a-f]{64}',image),'EXACT_IMAGE_ID_REQUIRED')
    path=engine['socketPath']
    def guard():
        info=os.stat(path,follow_symlinks=False)
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid==0
            and (info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))
            ==tuple(engine['socketBinding']),'ENGINE_SOCKET_BINDING_CHANGED')
    guard()
    class Local(http.client.HTTPConnection):
        def connect(self):
            self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout);self.sock.connect(path)
    connection=Local('localhost',timeout=15)
    try:
        connection.request('GET','/v1.44/images/'+image+'/json')
        response=connection.getresponse();raw=response.read(2097153)
        require(len(raw)<=2097152 and response.status in (200,404),'BOUNDED_IMAGE_GET_REQUIRED')
        guard()
        return response.status,json.loads(raw) if response.status==200 else None
    finally:connection.close()

def comparisons(audit,native):
    if native is None:return dict(imagePresent=False)
    config=native.get('Config')
    mismatch=[name for name in FIELDS if type(config)is not dict or config.get(name)!=audit['imageConfig'].get(name)]
    return dict(imagePresent=True,
        identityPass=native.get('Id')==audit['imageId'] and native.get('Os')=='linux' and native.get('Architecture')=='amd64',
        rootfsPass=native.get('RootFS')=={'Type':'layers','Layers':[r['diffId'] for r in audit['layers']]},
        executionConfigPass=not mismatch,executionConfigMismatchFields=mismatch,
        mismatchTypes={name:{'archive':type(audit['imageConfig'].get(name)).__name__,
            'native':type(config.get(name)).__name__ if type(config)is dict else 'missing'} for name in mismatch})

def main():
    require(os.geteuid()==0,'ROOT_READ_ACCESS_REQUIRED')
    emit('BEGIN',serviceMutations=0,databaseMutations=0,imageImportRequests=0)
    review=read(CONTEXT/'review.json',262144)
    require(review['sourceClosure']['declaration']['sourceCommit']==SOURCE,'EXACT_FAILED_SOURCE_REQUIRED')
    authority=read(CONTEXT/'authority.json',131072,AUTHORITY)
    process=review['scopes']['finiteActionProcess']
    require(authority['finiteActionProcess']==process and process['authorityDirectory']==str(CONTEXT),'PROCESS_BINDING_DRIFT')
    bundle=read(process['bundle']['path'],8388608,process['bundle']['sha256'])
    prepared=bundle['prepared']
    require(digest(prepared)==review['privateInputHashes']['preparedInputs'],'PREPARED_INPUT_BINDING_DRIFT')
    rows=prepared['imagePlan']['images']
    require([r['module'] for r in rows]==list(MODULES),'EXACT_FIVE_IMAGE_PLAN_REQUIRED')
    unit=process['unit']
    require(re.fullmatch(r'ouf-file-cohort-[0-9a-f]{32}\.service',unit),'EXACT_UNIT_REQUIRED')
    result=subprocess.run(['/usr/bin/systemctl','show',unit,'--property=ActiveState,SubState,MainPID,Result,ExecMainStatus'],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=20,check=False)
    require(len(result.stdout)<=8192,'BOUNDED_SYSTEMD_READ_REQUIRED')
    properties=dict(line.split('=',1) for line in result.stdout.decode().splitlines() if '=' in line)
    emit('PROCESS',exitCode=result.returncode,properties=properties)
    status=read(CONTEXT/'delivery-status.json',8192)
    emit('STATUS',phase=status.get('phase'),reason=status.get('reason'),
        authorityMatches=status.get('authorityHash')==AUTHORITY)
    for row in rows:
        module=row['module']
        try:
            directory=Path(process['directoryPlan']['image'+module.capitalize()])
            require(directory==CONTEXT/('image'+module.capitalize()),'EXACT_IMAGE_JOURNAL_PATH_REQUIRED')
            journal=read(directory/'recovery.json',65536)
            intent={k:row['audit'][k] for k in ('imageId','sourceCommit','archiveSha256')}
            require(journal.get('schema')=='ouf.image-import-journal.v1'
                and journal.get('authorityHash')==AUTHORITY and journal.get('intent')==intent
                and journal.get('contextHash')==digest({'intent':intent,'authorityHash':AUTHORITY}), 'IMAGE_JOURNAL_BINDING_DRIFT')
            require(journal.get('state') in ('READY','IN_FLIGHT','VERIFIED')
                and type(journal.get('effectAttemptCount'))is int and journal['effectAttemptCount'] in (0,1)
                and type(journal.get('version'))is int and journal['version'] in (0,1,2)
                and type(journal.get('imageCustodyProven'))is bool,'IMAGE_JOURNAL_STATE_INVALID')
            code,native=inspect(prepared['engine'],row['audit']['imageId'])
            emit('IMAGE',module=module,httpStatus=code,
                journal={k:journal[k] for k in ('state','version','effectAttemptCount','imageCustodyProven')},
                **comparisons(row['audit'],native))
        except Exception as error:emit('IMAGE_READ_ERROR',module=module,reason=safe_reason(error))
    for name in ('containers','databases','gateway','gatewayRuntime'):
        directory=Path(process['directoryPlan'][name])
        require(directory.is_relative_to(CONTEXT),'EXACT_STAGE_PATH_REQUIRED')
        emit('LATER_STAGE_RECORD',stage=name,journalPresent=os.path.lexists(directory/'recovery.json'))
    emit('END',serviceMutations=0,databaseMutations=0,imageImportRequests=0,
        authorityRenewed=False,rawEnvironmentPrinted=False,rawConfigPrinted=False,chatbotEndToEndProven=False)

if __name__=='__main__':
    try:main()
    except Exception as error:
        emit('READ_BLOCKED',reason=safe_reason(error));raise SystemExit(1)
