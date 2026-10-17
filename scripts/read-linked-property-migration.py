#!/usr/bin/env python3
"""Installation-specific migration metadata via the retained, hash-bound DB channel."""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys

BOOT=Path('/etc/ouf/deploy-snapshots/semantic-mcp-update-executor-code-yrvtskkt/execute.py')
BOOT_HASH='b02d9737af6d143903910654d34e91a1a82a52b6082d2429d5dbfd070d160af2'

def require(ok,code):
    if not ok: raise ValueError(code)

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()

def main():
    require(os.geteuid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_READ_REQUIRED')
    signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('READ_DEADLINE')))
    signal.alarm(60)
    for path in (BOOT.parent,*BOOT.parent.parents):
        s=path.lstat();require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'RETAINED_HELPER_ANCESTRY_REQUIRED')
    fd=os.open(BOOT,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<=131072,'RETAINED_HELPER_CUSTODY_REQUIRED')
        raw=os.read(fd,131073);require(len(raw)==s.st_size and hashlib.sha256(raw).hexdigest()==BOOT_HASH,'RETAINED_HELPER_HASH_CHANGED')
    finally: os.close(fd)
    ns={'__name__':'linked_property_migration_read_helpers'}
    exec(compile(raw,'<verified-retained-read-helpers>','exec'),ns)
    old=ns['read'](ns['CONTEXT']/'review.json',8388608,ns['REVIEW'])
    link=old['scopes']['finiteActionProcess']['bundle']
    prepared=ns['read'](link['path'],8388608,link['sha256'])['prepared']
    require(digest(prepared)==old['privateInputHashes']['preparedInputs'],'PREPARED_INPUT_BINDING_CHANGED')
    db=prepared['databasePlan'];admin=db['mcpAuditRoleAdministration']['admin']
    pg=ns['engine_get'](prepared['engine'],'containers',db['postgresRuntimeBinding']['containerId'])
    def runtime(a):
        return {'containerId':a['Id'],'imageId':a['Image'],'pid':a['State']['Pid'],'startedAt':a['State']['StartedAt'],**{name+'Hash':digest(a[key]) for name,key in (('config','Config'),('hostConfig','HostConfig'),('mounts','Mounts'),('networkSettings','NetworkSettings'))}}
    require(pg and pg['State']['Running'] and not pg['State']['Paused'] and runtime(pg)==db['postgresRuntimeBinding'],'EXACT_POSTGRES_GENERATION_REQUIRED')
    require([v.split('=',1)[1] for v in pg['Config'].get('Env',[]) if v.startswith('POSTGRES_USER=')]==[admin],'EXISTING_ADMINISTRATOR_BINDING_REQUIRED')
    binding=next(r for r in db['modules'] if r['module']=='udp')
    require(all(isinstance(v,str) and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}',v) for v in (admin,binding['database'])),'EXACT_DATABASE_ROLE_REQUIRED')
    docker=old['sourceClosure']['executables']['docker'];p=Path(docker['path']);s=p.stat()
    require(p.is_absolute() and stat.S_ISREG(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022 and hashlib.sha256(p.read_bytes()).hexdigest()==docker['sha256'],'NATIVE_EXECUTABLE_BINDING_DRIFT')
    sql="""BEGIN READ ONLY; SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s';
    SELECT jsonb_build_object('database',current_database(),'databaseOid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),'role',current_user,'transactionReadOnly',current_setting('transaction_read_only')='on',
      'migrations',(SELECT jsonb_agg(x ORDER BY installed_rank) FROM (SELECT installed_rank,version,script,checksum,success FROM ouf_udp.flyway_schema_history ORDER BY installed_rank LIMIT 100)x),
      'propertyValueOwner',(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='ouf_udp.property_value'::regclass),
      'profileTablePresent',to_regclass('ouf_udp.handoff_property_profile') IS NOT NULL,
      'evidenceColumnPresent',EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='ouf_udp' AND table_name='property_value' AND column_name='reconciliation_evidence'));
    ROLLBACK;"""
    args=[str(p),'--host','unix://'+prepared['engine']['socketPath'],'exec',pg['Id'],'env','LC_ALL=C','PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000 -c lock_timeout=3000','timeout','-s','KILL','15','psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U',admin,'-d',binding['database'],'-c',sql]
    result=subprocess.run(args,capture_output=True,timeout=20,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    require(result.returncode==0 and 0<len(result.stdout)<=65536,'READ_ONLY_MIGRATION_SQL_FAILED')
    facts=json.loads(result.stdout)
    require(facts['database']==binding['database'] and facts['databaseOid']==binding['databaseOid'] and facts['role']==admin and facts['transactionReadOnly'] is True,'EXACT_DATABASE_REQUIRED')
    require(runtime(ns['engine_get'](prepared['engine'],'containers',pg['Id']))==db['postgresRuntimeBinding'],'POSTGRES_GENERATION_CHANGED_DURING_READ')
    return facts

if __name__=='__main__':
    report={'schema':'ouf.linked-property-migration-read.v1','readOnly':True,'databaseMutations':0,'serviceMutations':0,'credentialFilesRead':0,'credentialValuesPrinted':False,'maximumSqlSessions':1,'completedTechnicalPhases':8,'functionalMilestonesProven':2}
    try: report.update(complete=True,facts=main())
    except Exception as error:
        reason=str(error) if type(error) is ValueError and re.fullmatch('[A-Z_]+',str(error)) else type(error).__name__
        report.update(complete=False,reason=reason,exceptionMessagePrinted=False)
    print('OUF_LINKED_PROPERTY_MIGRATION_READ='+json.dumps(report,sort_keys=True))
