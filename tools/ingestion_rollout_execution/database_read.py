"""Finite native SQL snapshot channel, explicit per-Ente local Engine profile.

No migration, credentials, environment inheritance, runtime effect or admission.
One attempt is durably counted before each native dispatch. A caller must still
compose current Owner/HUMAN, application generation and startup-policy guards.
"""
import copy
import json
import os
from pathlib import PurePosixPath
import re
import selectors
import signal
import stat
import subprocess
import time
import iam_governance_intake as governance
from engine_creation import Engine
from tools.ingestion_rollout_execution.contract import AUTHORITY_KEY,require,scope,digest,path,hashed
from tools.ingestion_rollout_execution.replacement import EngineReader
from tools.ingestion_rollout_execution import database_policy as policy,runtime_bindings
from tools.ingestion_rollout_execution.engine_channel import after_reads
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.human_session import HumanSession

MAX_SESSIONS=128

def runtime_binding(binding):
    require(type(binding)is dict and set(binding)=={'containerId','imageId','pid','startedAt','configHash',
            'hostConfigHash','mountsHash','networkSettingsHash'}and hashed(binding['containerId'])
            and type(binding['imageId'])is str and re.fullmatch('sha256:[0-9a-f]{64}',binding['imageId'])
            and type(binding['pid'])is int and binding['pid']>0 and type(binding['startedAt'])is str
            and binding['startedAt']and all(hashed(binding[k])for k in('configHash','hostConfigHash','mountsHash','networkSettingsHash')),
            'FULL_POSTGRES_RUNTIME_BINDING_REQUIRED')

def validate_profile(p):
    require(type(p)is dict and set(p)=={'schema','engineBinding','postgresRuntimeBinding','postgresRestartCount',
            'identity','dockerExecutable','dockerConfigDirectory','dockerConfigIdentity','containerPrograms','unixSocketDirectory','runtimeBindingProfile'},
            'EXACT_DATABASE_CONTROL_PROFILE_REQUIRED')
    require(p['schema']=='ouf.ingestion-rollout-native-database-read.v1','QUALIFIED_LOCAL_DATABASE_CHANNEL_REQUIRED')
    require(p['runtimeBindingProfile']in runtime_bindings.PROFILES,'EXPLICIT_DATABASE_RUNTIME_BINDING_PROFILE_REQUIRED')
    runtime_binding(p['postgresRuntimeBinding'])
    require(type(p['postgresRestartCount'])is int and p['postgresRestartCount']>=0,'EXPLICIT_POSTGRES_RESTART_COUNT_REQUIRED')
    engine=p['engineBinding']
    require(type(engine)is dict and set(engine)=={'socketPath','socketBinding'}and path(engine['socketPath'])
            and type(engine['socketBinding'])is list and len(engine['socketBinding'])==5
            and all(type(v)is int and v>=0 for v in engine['socketBinding'])
            and engine['socketBinding'][2]==0 and engine['socketBinding'][4]in(0o600,0o660),
            'EXACT_CUSTODIED_DATABASE_ENGINE_BINDING_REQUIRED')
    identity=p['identity']
    require(type(identity)is dict and set(identity)=={'database','user','databaseOid','postgresPort'},
            'EXPLICIT_DATABASE_IDENTITY_REQUIRED')
    policy.identifier(identity['database']);policy.identifier(identity['user'])
    require(type(identity['databaseOid'])is int and identity['databaseOid']>0
            and type(identity['postgresPort'])is int and 1<=identity['postgresPort']<=65535,
            'EXPLICIT_DATABASE_OID_AND_PORT_REQUIRED')
    program=p['dockerExecutable']
    require(type(program)is dict and set(program)=={'path','sha256'}and path(program['path'])and hashed(program['sha256']),
            'EXACT_DATABASE_DOCKER_PROGRAM_REQUIRED')
    path(p['dockerConfigDirectory']);path(p['unixSocketDirectory'])
    identity=p['dockerConfigIdentity']
    require(type(identity)is list and len(identity)==5 and all(type(v)is int and v>=0 for v in identity)
            and identity[2]==identity[3]==0 and stat.S_ISDIR(identity[4])and not identity[4]&0o022,
            'EXACT_EMPTY_DOCKER_CONFIG_DIRECTORY_IDENTITY_REQUIRED')
    require(type(p['containerPrograms'])is dict and set(p['containerPrograms'])=={'env','timeout','psql'},
            'EXPLICIT_NATIVE_CONTAINER_PROGRAMS_REQUIRED')
    for value in p['containerPrograms'].values():path(value)
    return p

def empty_config_directory(selected):
    # All ancestors root-custodied; no symlink or credential-bearing config.
    fds=[]
    try:
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(fd)
        for name in PurePosixPath(selected).parts[1:]:
            fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);fds.append(fd)
            s=os.fstat(fd);require(s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'ROOT_CUSTODIED_EMPTY_DOCKER_CONFIG_REQUIRED')
        require(not os.listdir(fd),'EMPTY_CREDENTIAL_FREE_DOCKER_CONFIG_REQUIRED')
        s=os.fstat(fd);return [s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode]
    finally:
        for fd in reversed(fds):os.close(fd)

def arguments(profile):
    p=validate_profile(profile);identity=p['identity'];program=p['containerPrograms']
    return [p['dockerExecutable']['path'],'--host','unix://'+p['engineBinding']['socketPath'],
        '--config',p['dockerConfigDirectory'],'exec',p['postgresRuntimeBinding']['containerId'],program['env'],'-i','LC_ALL=C',
        'PGPASSFILE=/dev/null','PGSERVICEFILE=/dev/null','PGSYSCONFDIR=/nonexistent',
        'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=5000 -c lock_timeout=1000 -c idle_in_transaction_session_timeout=5000',
        program['timeout'],'-s','KILL','15',program['psql'],'-X','-w','-q','-A','-t','-v','ON_ERROR_STOP=1',
        '-v','VERBOSITY=sqlstate','-h',p['unixSocketDirectory'],'-p',str(identity['postgresPort']),
        '-U',identity['user'],'-d',identity['database'],'-c',policy.SQL]

def bounded_read(arguments):
    proc=subprocess.Popen(arguments,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        env={'LC_ALL':'C'},start_new_session=True)
    output,errors=bytearray(),bytearray();deadline=time.monotonic()+20
    try:
        with selectors.DefaultSelector()as watch:
            watch.register(proc.stdout,selectors.EVENT_READ,'out');watch.register(proc.stderr,selectors.EVENT_READ,'err')
            while watch.get_map():
                require(time.monotonic()<deadline,'FINITE_DATABASE_NATIVE_READ_TIMEOUT')
                for key,_ in watch.select(min(.2,max(0,deadline-time.monotonic()))):
                    raw=os.read(key.fd,65536)
                    if not raw:watch.unregister(key.fileobj);continue
                    target,limit=(output,524288)if key.data=='out'else(errors,65536)
                    require(len(target)+len(raw)<=limit,'BOUNDED_DATABASE_NATIVE_OUTPUT_REQUIRED');target.extend(raw)
            status=proc.wait(timeout=max(.01,deadline-time.monotonic()))
        return status,bytes(output),bytes(errors)
    finally:
        if proc.poll()is None:os.killpg(proc.pid,signal.SIGKILL)
        proc.wait(timeout=5);proc.stdout.close();proc.stderr.close()

class NativeDatabaseRead:
    def __init__(self,action,journal,review,human,reader):
        require(type(action)is AggregateAction and type(journal)is Journal and type(human)is HumanSession
                and type(reader)is EngineReader,'CONCRETE_SIGNED_DATABASE_READ_COMPONENTS_REQUIRED')
        self.action,self.journal,self.human,self.reader=action,journal,human,reader
        self.review=copy.deepcopy(review);self.scope=scope(self.review)
        self.profile=copy.deepcopy(review.get('databaseControlProfile'));validate_profile(self.profile)
        self.last_report=None
        require(review.get('maximumDatabaseReadSessions')==MAX_SESSIONS
                and str(journal.root)==review['executionContext'],'SAME_SIGNED_FINITE_DATABASE_READ_PROFILE_REQUIRED')
        self.config_identity=copy.deepcopy(self.profile['dockerConfigIdentity']);self.check()
    def check(self):
        require(scope(self.review)==self.scope and self.profile==self.review['databaseControlProfile'],'DATABASE_CONTROL_REVIEW_DRIFT')
        self.action.guard(AUTHORITY_KEY,self.scope)
        require(self.human.current()==self.scope['humanBinding'],'SAME_CURRENT_AUTHENTICATED_HUMAN_REQUIRED')
        row=self.journal.read();count=row.get('nativeDatabaseReadSessions',0)
        require(row.get('scopeHash')==digest(self.scope)and row.get('authorityHash')==self.action.authority_hash
                and row.get('budgetReset')is False and type(count)is int and 0<=count<=MAX_SESSIONS,
                'SAME_PERSISTENT_DATABASE_SESSION_BUDGET_REQUIRED')
        engine=self.profile['engineBinding'];self.reader.engine.check_socket()
        require(self.reader.engine.path==engine['socketPath']and list(self.reader.engine.binding)==engine['socketBinding'],
                'SAME_CUSTODIED_DATABASE_ENGINE_REQUIRED')
        program=self.profile['dockerExecutable']
        require(program==governance.executable(program['path']),'DATABASE_DOCKER_PROGRAM_CHANGED')
        require(empty_config_directory(self.profile['dockerConfigDirectory'])==self.config_identity,
                'DATABASE_DOCKER_CONFIG_DIRECTORY_CHANGED')
        pg=self.reader.container(self.profile['postgresRuntimeBinding']['containerId']);state=pg['State']
        require(runtime_bindings.observed(pg,self.profile['runtimeBindingProfile'])==self.profile['postgresRuntimeBinding']and state['Running']is True
                and state['Paused']is False and state['Restarting']is False
                and pg['RestartCount']==self.profile['postgresRestartCount'],'CURRENT_POSTGRES_GENERATION_CHANGED')
        return after_reads(self.journal,row)
    def reserve(self):
        row=self.check();count=row.get('nativeDatabaseReadSessions',0)
        require(count<MAX_SESSIONS,'CUMULATIVE_DATABASE_READ_BUDGET_EXHAUSTED')
        require(min(row['expiresAt']-time.time(),row['expiresMonotonic']-time.monotonic())>25,
                'CURRENT_NATIVE_DATABASE_STAGE_WINDOW_REQUIRED')
        self.journal.compare_and_save(row,{**row,'nativeDatabaseReadSessions':count+1,'version':row['version']+1})
        self.check()
    def snapshot(self):
        self.check();self.reserve()
        status,raw,unused_errors=bounded_read(arguments(self.profile))
        self.check();require(status==0 and 0<len(raw)<=524288,'NATIVE_FIXED_READ_ONLY_DATABASE_QUERY_UNPROVEN')
        def unique(pairs):
            result={}
            for key,value in pairs:
                require(key not in result,'DUPLICATE_NATIVE_DATABASE_JSON_FIELD');result[key]=value
            return result
        try:facts=json.loads(raw,object_pairs_hook=unique)
        except(ValueError,UnicodeError):require(False,'EXACT_NATIVE_DATABASE_JSON_REQUIRED')
        report=policy.qualify_snapshot(facts,self.profile['identity'],now=time.time())
        # Fixed non-secret admission diagnostics only. Never retain SQL rows,
        # connection strings, credentials or application payloads for logging.
        self.last_report={k:report[k]for k in('sqlHistoryMatchesCandidate','runtimeCatalogMatchesQualifiedCandidate',
            'requiredRuntimePrivilegesAvailable','runtimeRoleBroadFlagsAbsent','postgres17Utf8',
            'pressureAndControlHeadroomWithinReadProfile','runtimeWorkDrainedAtSnapshot',
            'observedConnectionHeadroom','storedPressureState','workCountsLowerBounds')}
        self.last_report['connectionControlCounts']=copy.deepcopy(facts['connections'])
        self.check();require(report['databaseReadPrerequisitesProven']is True,'CURRENT_DATABASE_READ_PREREQUISITES_NOT_PROVEN')
        return report
