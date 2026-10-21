"""Compile current private creation intent; no import/start/fence/firewall/signing.

Target-private values stay in a new root0700 snapshot. This is review evidence,
not transition authority. All source modules are hash-verified in memory.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import types


DECLARATION = Path('/etc/ouf/deploy-snapshots/semantic-r12-cutover-inputs-dxzne_0r/private-runtime-declaration.json')
DECLARATION_HASH = '096a9bb877da54de35d41725064ebb14a0c456c42cf8b83af409bc1f253172d6'
SOURCE_HASHES = {'prepare':'693ec0196a60d3a9f6adee96571947306df4a0cffb449905c3dcf8c09a34da1b',
    'custody':'cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf',
    'creation':'e018567bbd67504ec00d5cbd830c65adbb2670dd7a627b63b9ae20ffa420d665'}


def require(ok, reason):
    if not ok: raise ValueError(reason)


def load_sources(sources):
    require(type(sources) is dict and set(sources) == set(SOURCE_HASHES), 'EXACT_SEALED_PLANNER_MODULE_SET_REQUIRED')
    # Check the COMPLETE closure before executing any module.
    for name,expected in SOURCE_HASHES.items():
        raw=sources[name]
        require(type(raw) is bytes and len(raw)<=131072 and hashlib.sha256(raw).hexdigest()==expected,
                'SEALED_PLANNER_MODULE_HASH_MISMATCH')
    modules={}
    for name,raw in sources.items():
        module=types.ModuleType('sealed_'+name)
        exec(compile(raw,'sealed-'+name,'exec'),module.__dict__)
        modules[name]=module
    return modules


def verify_secret_custody(custody, declaration, current):
    mounts=declaration['roleOwnedReadOnlyMounts']
    require(len(mounts)==3, 'THREE_CURRENT_ROLE_INPUTS_REQUIRED')
    for row in mounts:
        require(row.get('readOnly') is True and row.get('uid')==row.get('gid')==10001
                and row.get('mode')==0o400, 'EXACT_CURRENT_ROLE_METADATA_REQUIRED')
        custody.file_bytes(row['source'],10001,{0o400},expected=row['sha256'])
        require(Path(row['source']).lstat().st_gid==10001, 'CURRENT_ROLE_GROUP_DRIFT')
    projection=declaration['databaseSecretProjection']
    root=Path(projection['sourceDirectory'])
    info=root.lstat()
    require(root.is_dir() and not root.is_symlink() and info.st_uid==info.st_gid==10001
            and info.st_mode & 0o777==0o500, 'CURRENT_DATABASE_SECRET_DIRECTORY_DRIFT')
    row=projection['file']
    require(row['name']=='OUF_SEM_DB_PASSWORD' and row['uid']==row['gid']==10001 and row['mode']==0o400,
            'EXACT_CURRENT_DATABASE_SECRET_METADATA_REQUIRED')
    credential=custody.file_bytes(root/row['name'],10001,{0o400},expected=row['sha256'])
    require((root/row['name']).lstat().st_gid==10001, 'CURRENT_DATABASE_SECRET_GROUP_DRIFT')
    env={}
    for raw in current['Config']['Env']:
        key,value=raw.split('=',1)
        require(key not in env, 'DUPLICATE_CURRENT_APPLICATION_ENV')
        env[key]=value
    require(env.get('OUF_SEM_DB_PASSWORD','').encode()==credential, 'CURRENT_DATABASE_CREDENTIAL_BINDING_DRIFT')


def native_lease_ready(lease):
    require(lease.get('journalState')=='LEASE_READY' and lease.get('leaseAuthorized') is True
            and lease.get('nativeStructureVerified') is True
            and lease.get('journalAndMembershipConsistent') is True
            and lease.get('providerSetsEmpty') is False and lease.get('flowCount')==2
            and len(lease.get('flows',[]))==2
            and all(type(f.get('inetAddressCount')) is int and f['inetAddressCount']>0
                    and f['inetAddressCount']==f.get('bridgeAddressCount')==f.get('approvedAddressCount')
                    and type(f.get('minRemainingTtlSeconds')) is int
                    and 0<f['minRemainingTtlSeconds']<=f['leaseSeconds'] for f in lease['flows']),
            'CURRENT_NATIVE_TWO_FLOW_LEASE_REQUIRED')


def current_host(creation,current):
    memory={}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key,_,value=line.partition(':')
        if key in ('MemAvailable','MemTotal'):memory[key+'Bytes']=int(value.split()[0])*1024
    return {'status':'CURRENT_CUTOVER_HOST_METADATA_CAPTURED','semantic':{
        'containerId':current['Id'],'imageId':current['Image'],
        'generation':{k:current['State'][k] for k in ('Pid','StartedAt','Running')},
        'installedConfigHash':creation.digest(current['Config']),
        'installedHostConfigHash':creation.digest(current['HostConfig']),
        'installedMountsHash':creation.digest(current['Mounts']),
        'networkSettingsHash':creation.digest(current['NetworkSettings'])},
        'resources':{**memory,'rootFilesystemFreeBytes':shutil.disk_usage('/').free}}


def main():
    os.umask(0o077)
    report={'schema':'ouf.semantic-current-creation-intent.v1','containerLifecycleOperations':0,
        'imageImports':0,'databaseWrites':0,'databaseQueries':0,'firewallWrites':0,
        'commonLockAcquired':False,'providerCalls':0,'dnsQueries':0,'signaturesIssued':0,
        'privateValuesPrinted':False,'r12Touched':False,'recoveryBudgetReset':False,
        'applicationHealthProven':False,'notReleaseAcceptance':True}
    phase='VERIFY_SEALED_SOURCE_CLOSURE_AND_CURRENT_PRIVATE_DECLARATION'
    try:
        require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode and len(sys.argv)==1,
                'ISOLATED_ROOT_CURRENT_PLANNER_REQUIRED')
        modules=load_sources(globals().get('__planner_sources__'))
        prepare,custody,creation=(modules[n] for n in ('prepare','custody','creation'))
        raw=custody.file_bytes(DECLARATION,0,{0o600},expected=DECLARATION_HASH)
        declaration=json.loads(raw)
        reader_raw=custody.file_bytes(prepare.R10/'reader.py',0,{0o600},expected=prepare.PROGRAMS['reader.py'])
        reader=types.ModuleType('sealed_reader')
        reader.__file__=str(prepare.R10/'reader.py')
        exec(compile(reader_raw,'sealed-inventory-reader','exec'),reader.__dict__)
        human=reader.parse(reader.private(reader.CONTEXT/'human-approval-binding.json'))
        cfg=reader.parse(reader.private(reader.CONTEXT/'execution-configuration.json',human['configurationHash']))
        phase='READ_CURRENT_R12_LEASE_PEER_AND_APPLICATION'
        before=prepare.r12_state(reader,cfg['commandBindings'])
        args=['inspect','--type','container',reader.SEMANTIC_ID]
        current=reader.parse(prepare.native(reader,cfg['commandBindings']['docker'],args,True))[0]
        observations=reader.collect_cutover();native_lease_ready(observations['lease'])
        require(observations['currentSemanticPeer']['generation']['pid']==current['State']['Pid'],
                'CURRENT_SEMANTIC_PEER_GENERATION_DRIFT')
        phase='REVERIFY_CURRENT_INPUT_CUSTODY_AND_COMPILE_PRIVATE_CREATION_INTENT'
        verify_secret_custody(custody,declaration,current)
        host=current_host(creation,current)
        request,public=creation.compile_creation(declaration,DECLARATION_HASH,host)
        phase='STABLE_RECHECK_BEFORE_PRIVATE_PLAN_PUBLICATION'
        after=reader.parse(prepare.native(reader,cfg['commandBindings']['docker'],args,True))[0]
        last=prepare.r12_state(reader,cfg['commandBindings'])
        require(prepare.frame(after)==prepare.frame(current)
                and last['workerGeneration']==before['workerGeneration']
                and last['authorizationHash']==before['authorizationHash']
                and last['refreshCount']>=before['refreshCount'], 'CURRENT_GENERATION_CHANGED_DURING_PLAN')
        require(custody.file_bytes(DECLARATION,0,{0o600},expected=DECLARATION_HASH)==raw,
                'CURRENT_PRIVATE_DECLARATION_CHANGED')
        verify_secret_custody(custody,declaration,after)
        latest_host=current_host(creation,after)
        require(creation.compile_creation(declaration,DECLARATION_HASH,latest_host)[0]==request,
                'CURRENT_CREATION_INTENT_CHANGED')
        phase='PUBLISH_NEW_PRIVATE_PLAN_NOT_AUTHORITY'
        root=Path(tempfile.mkdtemp(prefix='semantic-current-creation-plan-',dir=prepare.BASE));root.chmod(0o700)
        custody.create(root/'creation-request.private.json',creation.encoded(request))
        custody.create(root/'observation.private.json',creation.encoded({'r12':last,'host':latest_host,'scope':observations}))
        report.update(public,status='CURRENT_CREATION_INTENT_COMPILED_NOT_APPLY_READY',
            evidenceDirectory=str(root),currentR12=last,existingInputFilesReverified=4,
            creationPlanHash=creation.digest(public),replacementContainerCreated=False)
        custody.create(root/'receipt.json',creation.encoded(report))
        code=0
    except Exception as error:
        reason=str(error)
        report.update(status='CURRENT_CREATION_INTENT_BLOCKED',phase=phase,errorType=type(error).__name__,
            reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,120}',reason) else 'CURRENT_CREATION_CUSTODY_UNPROVEN')
        code=1
    print('OUF_CURRENT_CREATION_INTENT='+json.dumps(report,sort_keys=True))
    return code


if __name__=='__main__':raise SystemExit(main())
