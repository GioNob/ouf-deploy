#!/usr/bin/env python3
"""Stop only the exact retained R4a smoke; preserve it and primary Semantic.
Authorized operational preparation under the 10 October09:12:30 CEST delegation.
No removal/restart, DB/configuration writes, keys, signatures or R9 operations.
"""
import hashlib, importlib.util, json, os, tempfile, time
from pathlib import Path

spec=importlib.util.spec_from_file_location('backup',Path(__file__).with_name('backup-semantic-target.py'))
backup=importlib.util.module_from_spec(spec);spec.loader.exec_module(backup)
SMOKE='f1313f339ed65586c35ef8be8e20e89630fd57345d921d1f6226124ee0acc724'
PRIMARY='7ae83be8c1fe9fe25774b7d748e35153652b29b2501886f89daeabb83bd1a147'
IMAGE='sha256:34339477b5c3ec9f4472523c607b524acbf4fa2141685d1c1b8082f5ae25405b'
CONFIG_HASH='9f80e175ca45b3f4c7d6dd6704afd21c75ae6ec262a518f5e33f4b433998ced9'

def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def config(value):return {k:value[k] for k in ('Config','HostConfig','Mounts','NetworkSettings')}
def stable(value):return config(value)|{'Id':value['Id'],'Image':value['Image'],'generation':{k:value['State'][k] for k in ('Pid','StartedAt','Running')}}
def save(path,value):
    with path.open('xb') as stream:stream.write(encoded(value)+b'\n');stream.flush();os.fsync(stream.fileno())
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)

def main():
    os.umask(0o077);directory=None;attempted=False
    report={'schema':'ouf.discovery.retained-smoke-quiescence.v1','decisionRef':'CHAT_OPERATOR_TECHNICAL_DELEGATION_20261010T091230_CEST',
        'containerId':SMOKE,'containersRemoved':0,'containersStarted':0,'databaseWrites':0,'privateKeysRead':0,'privateValuesPrinted':False,
        'signaturesIssued':0,'R9Touched':False,'notReleaseAcceptance':True}
    try:
        smoke,primary,postgres=backup.inspect('ouf-semantic-r4a-smoke'),backup.inspect('ouf-semantic'),backup.inspect('ouf-postgres')
        if smoke['Id']!=SMOKE or smoke['Image']!=IMAGE or primary['Id']!=PRIMARY or not smoke['State']['Running'] or not primary['State']['Running']:
            raise RuntimeError('EXACT_RUNNING_CONTAINERS_REQUIRED')
        if hashlib.sha256(encoded(config(smoke))).hexdigest()!=CONFIG_HASH or smoke['State']['StartedAt']!='2026-09-25T09:42:05.385167291Z' or smoke['HostConfig']['RestartPolicy']['Name']!='no' or smoke['HostConfig']['Runtime'] not in ('','runc'):
            raise RuntimeError('RETAINED_SMOKE_SCOPE_CHANGED')
        database,user,credential=backup.binding(primary,postgres)
        addresses=[n['IPAddress'] for n in smoke['NetworkSettings']['Networks'].values() if n.get('IPAddress')]
        if len(addresses)!=1:raise RuntimeError('ONE_SMOKE_DATABASE_PEER_REQUIRED')
        directory=Path(tempfile.mkdtemp(prefix='ouf-semantic-smoke-quiescence-',dir=Path.home()))
        save(directory/'container-before.json',smoke)
        save(directory/'claim.json',{'state':'QUIESCING_ONCE','containerId':SMOKE,'imageId':IMAGE,'configurationHash':CONFIG_HASH,'removeAuthorized':False,'restartAuthorized':False})
        attempted=True
        backup.call(['docker','stop','--time','30',SMOKE],timeout=45)
        after=backup.inspect('ouf-semantic-r4a-smoke')
        if after['Id']!=SMOKE or after['Image']!=IMAGE or after['State']['Running'] or after['HostConfig']['RestartPolicy']['Name']!='no':raise RuntimeError('SMOKE_STOP_UNPROVEN')
        if stable(primary)!=stable(backup.inspect('ouf-semantic')):raise RuntimeError('PRIMARY_BINDING_CHANGED_DURING_SMOKE_STOP')
        query="SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND client_addr=inet '"+addresses[0]+"';"
        args=['--host=127.0.0.1','--port=5432','--username='+user,'--dbname='+database,'-X','-qAt','-v','ON_ERROR_STOP=1','-c',query]
        for _ in range(10):
            remaining=int(backup.pg(postgres['Id'],'psql',args,credential))
            if remaining==0:break
            time.sleep(1)
        else:raise RuntimeError('SMOKE_DATABASE_SESSIONS_REMAIN')
        report.update(status='SMOKE_RETAINED_STOPPED_PRIMARY_UNCHANGED',containerLifecycleOperations=1,imageId=IMAGE,
            primaryContainerId=PRIMARY,primaryGenerationUnchanged=True,smokeDatabaseSessions=0,smokeExitCode=after['State']['ExitCode'],evidenceDirectory=str(directory),doNotRestartBeforeSchemaCompatibilityReview=True)
        save(directory/'quiescence-receipt.json',report)
    except Exception as error:
        report.update(status='QUIESCENCE_BLOCKED',reason=str(error) if isinstance(error,RuntimeError) else type(error).__name__,containerLifecycleOperationAttempted=attempted,
            evidenceDirectory=str(directory) if directory else None,doNotRerunApply=attempted)
        if directory:
            try:save(directory/'quiescence-denial.json',report)
            except OSError:pass
    print('OUF_RETAINED_SEMANTIC_SMOKE_QUIESCENCE='+json.dumps(report,sort_keys=True))
    return 0 if report['status']=='SMOKE_RETAINED_STOPPED_PRIMARY_UNCHANGED' else 1

if __name__=='__main__':raise SystemExit(main())
