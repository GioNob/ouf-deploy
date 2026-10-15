#!/usr/bin/env python3
"""Exact stopped pregrant attempt: private ledgers and image GETs only.

No issuer request, credential/token read, journal initialization, locking,
systemctl mutation, Docker load/start or execution of retained source bodies.
"""
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess

CONTEXT = Path('/etc/ouf/deploy-snapshots/chatbot-file-cohort-signed-3f1e74ca1de7962018be8e1d6dd023f685ea208a70aa5e2e2078f92961d7fd4c')
AUTHORITY = '83d70a33518b7bf7c1ca2904d715623294bb8132d5db1373381ab7ea001f2072'
SOURCE = '95749a8ef316856e16c44c1d7aa3b6791b408993'
MODULES = ('semantic', 'udp', 'onboarding', 'ingestion', 'mcp')
FIELDS = ('User','Entrypoint','Cmd','Env','WorkingDir','Labels','Volumes','ExposedPorts','StopSignal','Healthcheck','Shell')

def require(ok, code):
    if not ok: raise ValueError(code)

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()

def emit(check, **data):
    print(json.dumps(dict(schema='ouf.chatbot-pregrant-retirement-readback.v1',check=check,
        readOnly=True,automaticRetry=False,budgetReset=False,**data),sort_keys=True),flush=True)

def read(path, maximum, expected=None, *, json_data=True):
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
        return json.loads(raw) if json_data else bytes(raw)
    finally:os.close(fd)

def safe_reason(error):
    text=str(error)
    return text if type(error)is ValueError and re.fullmatch('[A-Z][A-Z0-9_]{0,159}',text) else type(error).__name__

def inspect(engine, image, kind='images'):
    require(kind in ('images','containers') and type(image)is str and
        re.fullmatch('sha256:[0-9a-f]{64}' if kind=='images' else '[0-9a-f]{64}',image),
        'EXACT_NATIVE_ID_REQUIRED')
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
        connection.request('GET','/v1.44/'+kind+'/'+image+'/json')
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

PARENT=Path('/etc/ouf/deploy-snapshots')
UNITS=('ouf-policy-token@semantic.timer','ouf-policy-token@semantic.service')

def hex64(value):
    require(type(value)is str and re.fullmatch('[0-9a-f]{64}',value),'EXACT_RECORD_ID_REQUIRED')
    return value

def owner_names(scopes):
    logical=hex64(scopes['policyTokenLegacyRetirement']['logicalOwnerScopeHash'])
    op=digest({'logicalOwnerScopeHash':logical,'operation':'FIRST_COMPLETE_TOKEN_OWNER_INSTALLATION'})
    retire=digest({'logicalOwnerScopeHash':logical,'units':list(UNITS),
        'operation':'FIRST_GOVERNED_LEGACY_RETIREMENT'})
    credential=hex64(scopes['policyTokenFirstControlledGrant']['credentialOperation'])
    session=hex64(scopes['policyTokenFirstControlledGrant']['sessionOperation'])
    out=scopes['policyTokenOutputCustody']
    output=digest({'logicalOwnerScopeHash':logical,'operation':'FIRST_GOVERNED_TOKEN_OUTPUT_CHILD','path':out['path']})
    return {
        'installation':'policy-token-owner-installation-'+op+'.private.json',
        'installationCompleted':'policy-token-owner-installation-'+op+'.private.json.completed',
        'retirement':'policy-token-legacy-retirement-'+retire+'.private.json',
        'output':'policy-token-output-custody-'+output+'.private.json',
        'credentialTransaction':'policy-token-credential-transaction-'+credential+'.private.json',
        'firstGapSession':'policy-token-first-gap-session-'+session+'.private.json',
        'firstGrant':'policy-token-first-controlled-grant-'+session+'.private.json'}

def record_projection(row):
    """Never print scope, secret hashes, paths, payloads or arbitrary strings."""
    require(type(row)is dict,'RECORD_OBJECT_REQUIRED')
    result={}
    for key in ('schema','state'):
        if key in row:
            value=row[key]
            require(type(value)is str and re.fullmatch('[A-Za-z0-9_.-]{1,100}',value),
                'SAFE_RECORD_STATE_REQUIRED')
            result['recordSchema' if key=='schema' else key]=value
    for key in ('version','attemptSlotsConsumed'):
        if key in row:
            require(type(row[key])is int and 0<=row[key]<=100000,'SAFE_RECORD_COUNTER_REQUIRED')
            result[key]=row[key]
    for key in ('commandAttemptConsumed','iamMutationAttemptConsumed','credentialPublished',
                'mkdirAttemptConsumed','automaticReplayAllowed'):
        if key in row:
            require(type(row[key])is bool,'SAFE_RECORD_FLAG_REQUIRED')
            result[key]=row[key]
    return result

def ledger(label,path):
    try:
        row=read(path,262144)
        emit('RECORD',record=label,present=True,recordHash=digest(row),**record_projection(row))
        return row
    except FileNotFoundError:
        emit('RECORD',record=label,present=False)
        return None

def directory(label,path):
    path=Path(path)
    require(path.is_absolute() and path.resolve()==path,'EXACT_DIRECTORY_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,
            'OWNED_DIRECTORY_REQUIRED')
        names=os.listdir(fd)
        require(len(names)<=128,'BOUNDED_DIRECTORY_REQUIRED')
        emit('DIRECTORY',directory=label,device=info.st_dev,inode=info.st_ino,
            modeOctal=format(stat.S_IMODE(info.st_mode),'04o'),uid=info.st_uid,gid=info.st_gid,
            entryCount=len(names),empty=not names)
    finally:os.close(fd)

def source_stage(scope):
    closure=hex64(scope['stageManifestHash'])
    root=Path('/usr/local/libexec/ouf-policy-token')
    stage=root/('semantic-native-v11-intake-'+closure)
    ledger('sourceStageIntent',root/('policy-token-source-stage-'+closure+'.intent'))
    manifest=ledger('sourceStageIntake',stage/'intake.json')
    if manifest is None:return
    require(digest(manifest)==closure,'SOURCE_STAGE_REVIEW_BINDING_DRIFT')
    fields=manifest.get('fileHashes')
    allowed={'bounded-recovery.py','recovery-journal.py','producer.py','supervisor.py',
        'mount-observation.py','source-stage.py','installed-owner.py','worker-entry.py','reporter.py','iam-admission.py'}
    require(type(fields)is dict and 1<=len(fields)<=10 and set(fields)<=allowed,
        'CLOSED_SOURCE_STAGE_REQUIRED')
    passed=all(hashlib.sha256(read(stage/name,131072,json_data=False)).hexdigest()==hex64(expected)
        for name,expected in fields.items())
    emit('SOURCE_STAGE',manifestMatchesReviewed=True,fileCount=len(fields),allFileHashesMatch=passed,
        sourceExecuted=False)

def gateway_generation(engine,row):
    effects=row.get('effects',[])
    if row.get('nextStep')!=8 or len(effects)!=8:return
    expected=effects[-1]['evidence']['runtimeBinding']
    identity=hex64(expected['containerId'])
    code,native=inspect(engine,identity,'containers')
    require(inspect(engine,identity,'containers')==(code,native),'GATEWAY_CHANGED_DURING_READ')
    if native is None:
        emit('GATEWAY_GENERATION',present=False)
        return
    actual={'containerId':native['Id'],'imageId':native['Image'],
        'pid':native['State']['Pid'],'startedAt':native['State']['StartedAt'],
        **{label:digest(native[field]) for label,field in (
            ('configHash','Config'),('hostConfigHash','HostConfig'),
            ('mountsHash','Mounts'),('networkSettingsHash','NetworkSettings'))}}
    emit('GATEWAY_GENERATION',present=True,matchesFinalJournal=actual==expected,
        running=native['State']['Running'],paused=native['State']['Paused'])

def main():
    require(os.geteuid()==0,'ROOT_READ_ACCESS_REQUIRED')
    emit('BEGIN',serviceMutations=0,databaseMutations=0,imageImportRequests=0)
    review=read(CONTEXT/'review.json',262144)
    require(review['sourceClosure']['declaration']['sourceCommit']==SOURCE,'EXACT_FAILED_SOURCE_REQUIRED')
    authority=read(CONTEXT/'authority.json',131072,AUTHORITY)
    process=review['scopes']['finiteActionProcess']
    require(authority['finiteActionProcess']==process and process['authorityDirectory']==str(CONTEXT),
        'PROCESS_BINDING_DRIFT')
    bundle=read(process['bundle']['path'],8388608,process['bundle']['sha256'])
    prepared=bundle['prepared']
    require(digest(prepared)==review['privateInputHashes']['preparedInputs'],'PREPARED_INPUT_BINDING_DRIFT')
    require(all(authority[k]==v for k,v in review['scopes'].items()),'SIGNED_SCOPE_DRIFT')
    unit=process['unit']
    require(unit=='ouf-file-cohort-3f1e74ca1de7962018be8e1d6dd023f6.service','EXACT_DELIVERY_UNIT_REQUIRED')
    props='Id,LoadState,ActiveState,SubState,UnitFileState,MainPID,Result,Job'
    result=subprocess.run(['/usr/bin/systemctl','show',*UNITS,unit,'--no-pager','--property='+props],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=20,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    require(len(result.stdout)<=8192,'BOUNDED_SYSTEMD_READ_REQUIRED')
    for block in result.stdout.decode('ascii').strip().split('\n\n'):
        values={}
        for line in block.splitlines():
            key,sep,value=line.partition('=')
            require(sep and key in props.split(',') and key not in values and
                re.fullmatch('[A-Za-z0-9_@.:-]{0,160}',value),'SAFE_SYSTEMD_METADATA_REQUIRED')
            values[key]=value
        require(values.get('Id') in (*UNITS,unit),'EXACT_SYSTEMD_UNIT_REQUIRED')
        emit('UNIT',exitCode=result.returncode,properties=values)
    status=read(CONTEXT/'delivery-status.json',8192)
    require(status.get('authorityHash')==AUTHORITY,'STATUS_AUTHORITY_DRIFT')
    emit('STATUS',phase=status.get('phase'),reason=status.get('reason'))
    names=owner_names(review['scopes'])
    for label,name in names.items():
        ledger(label,PARENT/name)
    scope=review['scopes']['policyTokenOwnerInstallation']
    source_stage(scope)
    root=Path(scope['journalPath'])
    require(str(root)=='/var/lib/ouf/policy-token/semantic','EXACT_OWNER_RECOVERY_DIRECTORY_REQUIRED')
    for label,name in (('ownerRecovery','recovery.json'),('ownerFirstGrant','owner-first-grant.json'),
                       ('ownerSession','owner-session.json'),('ownerAdmission','owner-admission.json')):
        ledger(label,root/name)
    directory('ownerRecovery',root)
    directory('tokenOutput',review['scopes']['policyTokenOutputCustody']['path'])
    destination=review['scopes']['policyTokenCredentialReestablishment']['destination']
    require(destination=='/etc/ouf/policy-token/credentials/semantic','EXACT_CREDENTIAL_DIRECTORY_REQUIRED')
    directory('credentialRootMetadataOnly',destination)
    rows=prepared['imagePlan']['images']
    require([r['module'] for r in rows]==list(MODULES),'EXACT_FIVE_IMAGE_PLAN_REQUIRED')
    for row in rows:
        module=row['module'];audit=row['audit']
        journal_path=Path(process['directoryPlan']['image'+module.capitalize()])/'recovery.json'
        require(journal_path.is_relative_to(CONTEXT),'EXACT_STAGE_PATH_REQUIRED')
        journal=read(journal_path,8192)
        native_id=audit.get('nativeIdentity',{}).get('nativeImageId',audit['imageId'])
        intent={'imageId':native_id,**{k:audit[k] for k in ('sourceCommit','archiveSha256')}}
        require(journal.get('authorityHash')==AUTHORITY and journal.get('intent')==intent
            and journal.get('contextHash')==digest({'intent':intent,'authorityHash':AUTHORITY}),
            'IMAGE_JOURNAL_BINDING_DRIFT')
        code,native=inspect(prepared['engine'],native_id)
        require(inspect(prepared['engine'],native_id)==(code,native),'IMAGE_CHANGED_DURING_READ')
        expected={**audit,'imageId':native_id}
        emit('IMAGE',module=module,httpStatus=code,
            journal={k:journal.get(k) for k in ('state','version','effectAttemptCount','imageCustodyProven')},
            **comparisons(expected,native))
    for stage in ('authorization','containers','databases','gateway','gatewayRuntime'):
        path=Path(process['directoryPlan'][stage])/'recovery.json'
        require(path.is_relative_to(CONTEXT),'EXACT_STAGE_PATH_REQUIRED')
        row=ledger(stage,path)
        if row is not None and stage=='gatewayRuntime':
            effects=row.get('effects',[])
            require(type(effects)is list and len(effects)<=8,'BOUNDED_GATEWAY_STAGES_REQUIRED')
            require(all(type(e)is dict and e.get('step') in ('disable_restart','stop','rename','create',
                'connect','start','ready','restore_restart') and e.get('state') in ('CLAIMED','APPLIED')
                for e in effects),'EXACT_GATEWAY_STAGES_REQUIRED')
            emit('GATEWAY_PROGRESS',nextStep=row.get('nextStep'),effects=[
                {'step':e['step'],'state':e['state']} for e in effects])
            gateway_generation(prepared['engine'],row)
    emit('END',serviceMutations=0,databaseMutations=0,imageImportRequests=0,
        authorityRenewed=False,credentialOrTokenFilesRead=False,
        rawEnvironmentPrinted=False,rawConfigPrinted=False,chatbotEndToEndProven=False)

if __name__=='__main__':
    try:main()
    except Exception as error:
        emit('READ_BLOCKED',reason=safe_reason(error));raise SystemExit(1)

