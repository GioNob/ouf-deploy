"""Quiesced custom-format backup and readback; only application Flyway runs DDL."""
import copy,json,os,re
from pathlib import Path
from tools.linked_property_rollout import preparation
from tools.source_revision_update.owner import require,digest,MIGRATION
from tools.semantic_mcp_update.native import bounded,command,private_file

def sql(module, app):
 require(module in('onboarding','udp','mcp') and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}',app),'EXACT_DATABASE_MODULE_AND_ROLE_REQUIRED')
 schema='ouf_'+module
 common="'database',current_database(),'role',current_user,'transactionReadOnly',current_setting('transaction_read_only')='on','databaseOid',(select oid::bigint from pg_database where datname=current_database()),'databaseBytes',pg_database_size(current_database())"
 if module in('onboarding','udp'):
  fields=f"""'migrations',(select jsonb_agg(x order by installed_rank) from
   (select installed_rank,version,script,checksum,success from {schema}.flyway_schema_history order by installed_rank limit 100)x)"""
 else:fields=f"'migrations',(select jsonb_agg(x order by version) from (select version,checksum::text from {schema}.schema_migration order by version limit 100)x)"
 if module=='onboarding':
  fields+=f""",'revisionTablePresent',to_regclass('{schema}.source_property_revision')is not null,
   'revisionTableOwned',(select pg_get_userbyid(relowner)='{app}' from pg_class where oid=to_regclass('{schema}.source_property_revision')),
   'revisionAppendOnly',exists(select 1 from pg_trigger where tgrelid=to_regclass('{schema}.source_property_revision')
    and tgname='source_property_revision_append_only' and not tgisinternal and tgenabled='O' and tgtype=27
    and tgfoid=to_regprocedure('{schema}.reject_audit_change()'))"""
 return "BEGIN READ ONLY; SET LOCAL statement_timeout='10s'; SET LOCAL lock_timeout='3s'; SELECT jsonb_build_object("+common+","+fields+"); ROLLBACK;"

def raw_runtime(actual):
    return {'containerId':actual['Id'],'imageId':actual['Image'],
        'pid':actual['State']['Pid'],'startedAt':actual['State']['StartedAt'],
        **{name+'Hash':digest(actual[key])for name,key in
           (('config','Config'),('hostConfig','HostConfig'),('mounts','Mounts'),('networkSettings','NetworkSettings'))}}

class Database:
    def __init__(self,plan,prepared,ns):
        self.plan=copy.deepcopy(plan);self.prepared=prepared;self.ns=ns;self.ports=None
    def guard(self):
        self.ports.action.guard('sourceRevisionUpdate',self.ports.plan_scope())
        pin=self.plan['database']['postgresRuntimeBinding']
        actual=self.ns['engine_get'](self.plan['engine'],'containers',pin['containerId'])
        require(actual and raw_runtime(actual)==pin and actual['State']['Running']is True,
                'POSTGRES_GENERATION_CHANGED')
        command(self.plan['programs']['docker'])
    def facts(self,module):
        self.guard()
        require(module in ('onboarding','udp','mcp'),'EXACT_DATABASE_MODULE_REQUIRED')
        db=self.prepared['databasePlan']
        binding=next(v for v in db['modules'] if v['module']==module)
        admin=db['mcpAuditRoleAdministration']['admin']
        require(all(re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,62}',v) for v in (admin,binding['database'])),'EXACT_DATABASE_IDENTIFIERS_REQUIRED')
        args=[command(self.plan['programs']['docker']),'--host','unix://'+self.plan['engine']['socketPath'],
            '--config',self.plan['authorityDirectory'],'exec',self.plan['database']['postgresRuntimeBinding']['containerId'],
            'env','LC_ALL=C','PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000 -c lock_timeout=3000',
            'timeout','-s','KILL','15','psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U',admin,
            '-d',binding['database'],'-c',sql(module,binding['user'])]
        raw,_=bounded(args,20,131072)
        fact=json.loads(raw)
        require(fact['transactionReadOnly'] is True and fact['database']==binding['database']
            and fact['databaseOid']==binding['databaseOid'] and fact['role']==admin,'DATABASE_IDENTITY_CHANGED')
        return fact
    def verify_before(self):
        observed={m:self.facts(m) for m in ('onboarding','udp','mcp')}
        for module,facts in observed.items():
            expected=self.plan['database']['before'][module]
            require(all(facts[k]==expected[k]for k in('database','databaseOid','role','migrations')),
                    'DATABASE_CHANGED_SINCE_PRIVATE_PREPARATION')
        require(observed['onboarding']['revisionTablePresent'] is False,'V34_ALREADY_PRESENT_OR_PARTIAL')
        return observed
    def quiescent(self):
        for row in self.plan['replacements'].values():
            actual=self.ports.inspect('containers',row['oldRuntimeBinding']['containerId'])
            require(actual is not None and actual['State']['Running']is False and actual['State']['Pid']==0
                    and actual['HostConfig']['RestartPolicy']['Name']=='no','BOTH_APPLICATIONS_MUST_BE_STOPPED_FOR_BACKUP')
    def backup(self):
        self.quiescent();before=self.verify_before()
        root=Path(self.plan['authorityDirectory']);path=root/'onboarding.dump'
        pg=self.plan['database']['postgresRuntimeBinding']['containerId']
        database=before['onboarding']['database'];user=before['onboarding']['role']
        args=[command(self.plan['programs']['docker']),'--host','unix://'+self.plan['engine']['socketPath'],'--config',str(root),'exec',pg]
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb')as stream:
            _,evidence=bounded(args+['pg_dump','-U',user,'-d',database,'--format=custom','--no-owner','--no-acl','--lock-wait-timeout=10s'],90,1073741824,output_stream=stream)
            stream.flush();os.fsync(stream.fileno())
        require(evidence['customFormatHeader']and evidence['bytes']>100,'CUSTOM_FORMAT_BACKUP_REQUIRED')
        self.guard();self.quiescent()
        with path.open('rb')as stream:
            bounded(args[:args.index('exec')]+['exec','-i',pg,'pg_restore','--file=/dev/null'],90,65536,input_stream=stream)
        after=self.verify_before()
        require(all(after[m]['migrations']==before[m]['migrations'] for m in before),'HISTORY_CHANGED_DURING_BACKUP')
        proof={'path':str(path),'sha256':evidence['sha256'],'bytes':evidence['bytes'],
               'payloadParsed':True,'databaseOid':before['onboarding']['databaseOid'],'historyHash':digest(before['onboarding']['migrations']),
               'restorePerformed':False}
        preparation.write_new(root/'backup.json',preparation.encoded(proof))
        directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(directory)
        finally:os.close(directory)
        return proof
    def verify_backup(self):
        root=Path(self.plan['authorityDirectory']);proof=self.ns['read'](root/'backup.json',65536)
        require(proof['path']==str(root/'onboarding.dump')and proof['payloadParsed']is True and proof['restorePerformed']is False
                and proof['databaseOid']==self.plan['database']['before']['onboarding']['databaseOid']
                and proof['historyHash']==digest(self.plan['database']['before']['onboarding']['migrations']), 'EXACT_VERIFIED_QUIESCED_BACKUP_REQUIRED')
        found=private_file(proof['path'],proof['sha256'],1073741824)
        require(found['bytes']==proof['bytes'],'BACKUP_SIZE_CHANGED')
        return proof
    def verify_migrated(self):
        self.verify_backup()
        observed={m:self.facts(m) for m in ('onboarding','udp','mcp')}
        for module,facts in observed.items():
            expected=self.plan['database']['before'][module]
            require(all(facts[k]==expected[k]for k in ('database','databaseOid','role')),
                    'DATABASE_IDENTITY_CHANGED')
            expected_history=copy.deepcopy(expected['migrations'])
            if module=='onboarding':
                expected_history.append({'installed_rank':34,'version':'34',
                    'script':MIGRATION['script'],'checksum':MIGRATION['checksum'],'success':True})
                require(facts['revisionTablePresent'] is True and facts['revisionTableOwned'] is True
                        and facts['revisionAppendOnly'] is True,'V34_SCHEMA_OBJECTS_UNPROVEN')
            require(facts['migrations']==expected_history,'EXACT_POST_MIGRATION_HISTORY_REQUIRED')
        return {'onboardingVersion':34,'udpVersion':36,'checksum':MIGRATION['checksum'],
                'mcpMigrationsUnchanged':True,'nativeFlywayHistoryVerified':True}
