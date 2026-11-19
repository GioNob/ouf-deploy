"""Quiesced custom-format backup and readback; only application Flyway runs DDL."""
import copy,os
from pathlib import Path
from tools.linked_property_rollout import preparation
from tools.linked_property_rollout.owner import require,digest,MIGRATION
from tools.semantic_mcp_update.native import bounded,command,private_file

class Database:
    def __init__(self,plan,prepared,ns):
        self.plan=copy.deepcopy(plan);self.prepared=prepared;self.ns=ns;self.ports=None
    def guard(self):
        self.ports.action.guard('linkedPropertyUpdate',self.ports.plan_scope())
        pin=self.plan['database']['postgresRuntimeBinding']
        actual=self.ns['engine_get'](self.plan['engine'],'containers',pin['containerId'])
        require(actual and preparation.runtime(actual)==pin and actual['State']['Running']is True,
                'POSTGRES_GENERATION_CHANGED')
        command(self.plan['programs']['docker'])
    def facts(self,module):
        self.guard()
        return preparation.database_facts(self.ns,self.prepared,self.plan['programs']['docker']['path'],module,Path(self.plan['authorityDirectory']))
    def verify_before(self):
        observed={m:self.facts(m) for m in ('udp','onboarding')}
        for module,facts in observed.items():
            expected=self.plan['database']['before'][module]
            require(all(facts[k]==expected[k]for k in('database','databaseOid','applicationRole','migrations')),
                    'DATABASE_CHANGED_SINCE_PRIVATE_PREPARATION')
        require(not observed['udp']['profileTablePresent']and not observed['udp']['evidenceColumnPresent'],
                'V35_ALREADY_PRESENT_OR_PARTIAL')
        require(observed['udp']['rolePreflight']==self.plan['database']['before']['udp']['rolePreflight'],
                'MIGRATION_ROLE_CHANGED')
        return observed
    def quiescent(self):
        for row in self.plan['replacements'].values():
            actual=self.ports.inspect('containers',row['oldRuntimeBinding']['containerId'])
            require(actual is not None and actual['State']['Running']is False and actual['State']['Pid']==0
                    and actual['HostConfig']['RestartPolicy']['Name']=='no','BOTH_APPLICATIONS_MUST_BE_STOPPED_FOR_BACKUP')
    def backup(self):
        self.quiescent();before=self.verify_before()
        root=Path(self.plan['authorityDirectory']);path=root/'udp.dump'
        pg=self.plan['database']['postgresRuntimeBinding']['containerId']
        database=before['udp']['database'];user=before['udp']['role']
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
               'payloadParsed':True,'databaseOid':before['udp']['databaseOid'],'historyHash':digest(before['udp']['migrations']),
               'restorePerformed':False}
        preparation.write_new(root/'backup.json',preparation.encoded(proof))
        directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(directory)
        finally:os.close(directory)
        return proof
    def verify_backup(self):
        root=Path(self.plan['authorityDirectory']);proof=self.ns['read'](root/'backup.json',65536)
        require(proof['path']==str(root/'udp.dump')and proof['payloadParsed']is True and proof['restorePerformed']is False
                and proof['databaseOid']==self.plan['database']['before']['udp']['databaseOid']
                and proof['historyHash']==digest(self.plan['database']['before']['udp']['migrations']), 'EXACT_VERIFIED_QUIESCED_BACKUP_REQUIRED')
        found=private_file(proof['path'],proof['sha256'],1073741824)
        require(found['bytes']==proof['bytes'],'BACKUP_SIZE_CHANGED')
        return proof
    def verify_migrated(self):
        self.verify_backup()
        for module in('udp','onboarding'):
            facts=self.facts(module)
            preparation.verify_history(facts['migrations'],self.plan['database']['expected'][module], 'ouf_'+module,allow_existing_schema=True)
            if module=='udp':
                require(facts['profileTablePresent']and facts['evidenceColumnPresent'],'V35_SCHEMA_OBJECTS_UNPROVEN')
        return {'udpVersion':35,'checksum':MIGRATION['checksum'],'onboardingMigrationsUnchanged':True,'nativeFlywayHistoryVerified':True}
