"""Read-only audit availability, never accounting initialization or token admission.

A bounded sample of CLIENT_LOGIN events is not an all-time grant counter. Empty,
disabled, filtered or truncated event storage never means zero historical usage.
"""
import re
import subprocess
import tempfile
import resource
import time
import iam_binding_candidate as binding

CONFIG_FIELDS='eventsEnabled,eventsExpiration,enabledEventTypes'
EVENT_FIELDS='time,type,clientId'
EVENT_TYPES=('CLIENT_LOGIN','CLIENT_LOGIN_ERROR')
SAMPLE_LIMIT=100

def categories(raw):
    text=raw.decode('utf-8','replace').lower()
    patterns=((r'session (?:has )?expired|failed to refresh access token|invalid_grant|not logged in|no token specified','SESSION_AUTH_FAILURE_TEXT_OBSERVED'),
        (r'unauthorized|\b401\b','UNAUTHORIZED_TEXT_OBSERVED'),(r'forbidden|\b403\b','FORBIDDEN_TEXT_OBSERVED'),
        (r'connection refused|connectexception','CONNECTION_REFUSED_TEXT_OBSERVED'),
        (r'timed out|timeout','CONNECTION_TIMEOUT_TEXT_OBSERVED'),
        (r'no such container|is not running','CONTAINER_UNAVAILABLE_TEXT_OBSERVED'),
        (r'permission denied','LOCAL_PERMISSION_FAILURE_TEXT_OBSERVED'))
    return [label for pattern,label in patterns if re.search(pattern,text)] or ['UNCLASSIFIED_CLI_FAILURE']

class AuditReader:
    def __init__(self,client,report,clock=time.monotonic):
        binding.require(type(client)is str and re.fullmatch('[A-Za-z0-9_.:-]{1,128}',client),'EXACT_ACCOUNTING_CLIENT_REFERENCE_REQUIRED')
        self.client,self.report,self.clock=client,report,clock;self.deadline=clock()+70
    def get(self,path,fields,queries=()):
        allowed=path=='events/config' and fields==CONFIG_FIELDS and not queries
        allowed=allowed or (path=='events' and fields==EVENT_FIELDS and len(queries)==4
            and queries[:3]==('client='+self.client,'first=0','max=101')
            and queries[3] in tuple('type='+kind for kind in EVENT_TYPES))
        binding.require(allowed,'EXACT_READ_ONLY_ACCOUNTING_RESOURCE_REQUIRED')
        timeout=min(15,self.deadline-self.clock());binding.require(timeout>0,'FINITE_ACCOUNTING_OBSERVATION_DEADLINE')
        argv=['/usr/bin/docker','exec','ouf-keycloak','/opt/keycloak/bin/kcadm.sh','get',path,
            '--server','http://localhost:8080','-r','ouf','--fields',fields]
        for query in queries:argv+=['-q',query]
        def child_cap():resource.setrlimit(resource.RLIMIT_FSIZE,(1048576,1048576))
        self.report['iamMetadataGetAttempts']+=1
        with tempfile.TemporaryFile()as stdout,tempfile.TemporaryFile()as stderr:
            try:result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,timeout=timeout,preexec_fn=child_cap)
            except subprocess.TimeoutExpired:
                self.report['diagnosticCategories']=['CLI_TIMEOUT_OBSERVED'];raise binding.CandidateDenied('ACCOUNTING_GET_TIMEOUT') from None
            stdout.seek(0);stderr.seek(0);raw=stdout.read(262145);err=stderr.read(65537)
        self.report.update(lastIamGetExitCode=result.returncode,diagnosticTextTruncated=len(err)>65536)
        if result.returncode:
            self.report['diagnosticCategories']=categories(err[:65536])
            binding.require(False,'EXISTING_IAM_AUDIT_GET_UNAVAILABLE')
        binding.require(0<len(raw)<=262144,'ACCOUNTING_RESPONSE_UNBOUNDED')
        return binding.decode(raw)

def config_shape(value):
    binding.require(type(value)is dict and set(value)<=set(CONFIG_FIELDS.split(','))
        and type(value.get('eventsEnabled'))is bool,'COMPLETE_AUDIT_ENABLEMENT_SCHEMA_REQUIRED')
    if 'eventsExpiration'in value:binding.require(type(value['eventsExpiration'])is int and value['eventsExpiration']>=0,'AUDIT_RETENTION_SCHEMA_REQUIRED')
    if 'enabledEventTypes'in value:
        binding.require(type(value['enabledEventTypes'])is list and len(value['enabledEventTypes'])<=256
            and all(type(t)is str and re.fullmatch('[A-Z][A-Z0-9_]{0,95}',t)for t in value['enabledEventTypes'])
            and len(set(value['enabledEventTypes']))==len(value['enabledEventTypes']),'AUDIT_EVENT_TYPE_SCHEMA_REQUIRED')
    return value

def evaluate(reader,report):
    report['phase']='EXISTING_IAM_AUDIT_CONFIGURATION_READ'
    config=config_shape(reader.get('events/config',CONFIG_FIELDS))
    samples={};enabled=config.get('enabledEventTypes')
    selected=[kind for kind in EVENT_TYPES if config['eventsEnabled'] and type(enabled)is list and kind in enabled]
    for kind in selected:
        report['phase']='BOUNDED_SELECTED_CLIENT_EVENT_SAMPLE'
        rows=reader.get('events',EVENT_FIELDS,('client='+reader.client,'first=0','max=101','type='+kind))
        binding.require(type(rows)is list and len(rows)<=SAMPLE_LIMIT+1,'BOUNDED_AUDIT_EVENT_SAMPLE_REQUIRED')
        for row in rows:
            binding.require(type(row)is dict and set(row)==set(EVENT_FIELDS.split(','))
                and row['type']==kind and row['clientId']==reader.client
                and type(row['time'])is int and row['time']>=0,'EXACT_SELECTED_AUDIT_EVENT_REQUIRED')
        times=[row['time']for row in rows[:SAMPLE_LIMIT]]
        samples[kind]={'sampleEventCount':len(times),'sampleTruncated':len(rows)>SAMPLE_LIMIT,
            'oldestSampleTimeMillis':min(times)if times else None,'newestSampleTimeMillis':max(times)if times else None}
    if selected:
        report['phase']='AUDIT_CONFIGURATION_STABILITY_READ'
        binding.require(config_shape(reader.get('events/config',CONFIG_FIELDS))==config,'AUDIT_CONFIGURATION_CHANGED')
    report.update(auditStorageEnabled=config['eventsEnabled'],requiredClientLoginEventTypesEnabled=set(EVENT_TYPES)<=set(enabled or []),
        auditRetentionSeconds=config.get('eventsExpiration'),auditRetentionValueObserved='eventsExpiration'in config,
        sampledEventTypes=list(samples),eventSampleCounts={kind:value['sampleEventCount']for kind,value in samples.items()},
        eventSampleTruncated=any(v['sampleTruncated']for v in samples.values()),
        emptyEventSampleIsNotZeroHistoricalUsage=True,historicalAccountingReconciled=False,
        historicalGrantAttemptCount=None,actualTokenIntrospectionProven=False,
        reason='AUDIT_STORAGE_DISABLED_HISTORY_UNPROVEN'if not config['eventsEnabled']else
            'REQUIRED_AUDIT_EVENT_TYPES_UNPROVEN'if set(selected)!=set(EVENT_TYPES)else
            'BOUNDED_AUDIT_SAMPLE_NOT_COMPLETE_GRANT_HISTORY',status='ACCOUNTING_SOURCE_OBSERVED_NOT_RECONCILED')
    return {'schema':'ouf.policy-token-accounting-source-observation.v1','auditConfiguration':config,'samples':samples,
        'sampleLimitPerEventType':SAMPLE_LIMIT,'completeHistoryCoverageProven':False,
        'clientLoginEventIsNotIndependentlyProvenGrantAttempt':True,'historicalGrantAttemptCount':None,
        'historicalAccountingReconciled':False,'automaticAccountingInitializationAllowed':False,
        'runtimeAuthorityIssued':False,'productionApplyReady':False,'budgetReset':False,'r12Touched':False,'notReleaseAcceptance':True}
