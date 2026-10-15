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
import urllib.parse

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
    return get(engine,'/v1.44/images/'+image+'/json')

def get(engine, request_path):
    require(request_path.startswith('/v1.44/images/'),'READ_ONLY_IMAGE_ENDPOINT_REQUIRED')
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
        connection.request('GET',request_path)
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
    emit('BEGIN_NATIVE_IDENTITIES',serviceMutations=0,databaseMutations=0,imageImportRequests=0)
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
    total=0
    for row in rows:
        module=row['module'];audit=row['audit']
        try:
            filters=json.dumps({'label':['org.opencontainers.image.revision='+audit['sourceCommit']]},separators=(',',':'))
            path='/v1.44/images/json?all=1&filters='+urllib.parse.quote(filters,safe='')
            code,candidates=get(prepared['engine'],path)
            require(code==200 and type(candidates)is list and len(candidates)<=4,'BOUNDED_IMAGE_LABEL_READ_REQUIRED')
            emit('SOURCE_IMAGE_CANDIDATES',module=module,count=len(candidates),
                approvedArchiveSha256=audit['archiveSha256'])
            for candidate in candidates:
                total+=1;require(total<=12,'BOUNDED_NATIVE_CANDIDATE_COUNT_REQUIRED')
                identity=candidate['Id'];code,native=inspect(prepared['engine'],identity)
                require(code==200 and type(native)is dict,'STABLE_NATIVE_IMAGE_REQUIRED')
                require(inspect(prepared['engine'],identity)==(code,native),'NATIVE_IMAGE_CHANGED_DURING_READ')
                config=native.get('Config') or {};labels=config.get('Labels') or {}
                descriptor=native.get('Descriptor') or {}
                emit('NATIVE_IDENTITY',module=module,nativeImageId=identity,
                    approvedConfigurationImageId=audit['imageId'],
                    sourceLabelMatches=labels.get('org.opencontainers.image.revision')==audit['sourceCommit'],
                    repositoryTagCount=len(native.get('RepoTags') or []),
                    nativeDescriptorDigest=descriptor.get('digest'),
                    nativeDescriptorMediaType=descriptor.get('mediaType'),
                    **comparisons(audit,native))
        except Exception as error:emit('NATIVE_IDENTITY_READ_ERROR',module=module,reason=safe_reason(error))
    emit('END',serviceMutations=0,databaseMutations=0,imageImportRequests=0,
        authorityRenewed=False,rawEnvironmentPrinted=False,rawConfigPrinted=False,chatbotEndToEndProven=False)

if __name__=='__main__':
    try:main()
    except Exception as error:
        emit('READ_BLOCKED',reason=safe_reason(error));raise SystemExit(1)
