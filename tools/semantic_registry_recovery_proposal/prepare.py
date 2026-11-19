"""Private blocked proposal only; no runtime execution or authority issuance."""
import datetime

import hashlib

import ipaddress

import http.client

import json

import os

from pathlib import Path

import re

import signal

import socket

import stat

import struct

import sys

import subprocess

from urllib.parse import urlencode, urlsplit
import tempfile

SCHEMA='ouf.semantic-registry-recovery-proposal-result.v1'
CASE_SCHEMA='ouf.semantic-registry-recovery-proposal-case.v1'
MAX_GETS=4
MAX_BYTES=2_097_152
STATE_FIELDS=('Status','Running','Paused','Restarting','Dead','OOMKilled','Pid','ExitCode','Error','StartedAt','FinishedAt')
# Exact gate contract from tools/semantic_application_cutover/gated_creation_plan.py.
GATE='OUF_APPLICATION_GATE=0; trap "OUF_APPLICATION_GATE=1" USR1; while [ "$OUF_APPLICATION_GATE" = 0 ]; do sleep 1 & wait "$!"; done; exec "$@"'
ENTRY=['/bin/sh','-c',GATE,'ouf-gated-application']
JAVA=['java','-XX:MaxRAMPercentage=75','-jar','/app/application.jar']

def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()

def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()

class Stop(Exception):
    pass

def require(ok, code):
    if not ok:
        raise Stop(code)

def unique(items):
    result = {}
    for key, value in items:
        require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result

def decode(raw):
    return json.loads(raw, object_pairs_hook=unique)

def private_json(path):
    p = Path(path)
    require(p.is_absolute() and '..' not in p.parts and str(p.resolve()) == str(p),
            'EXACT_PRIVATE_PATH_REQUIRED')
    for parent in p.parents:
        info=parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,
                'ROOT_CONTROLLED_METADATA_ANCESTRY_REQUIRED')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0
                and not before.st_mode & 0o022 and 0 < before.st_size <= 8_388_608,
                'ROOT_OWNED_BOUNDED_METADATA_REQUIRED')
        raw = bytearray()
        while len(raw) <= before.st_size:
            block = os.read(fd, min(65_536, before.st_size + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode,
                              s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(len(raw) == before.st_size
                and identity(before) == identity(os.fstat(fd)) == identity(p.lstat()),
                'PRIVATE_METADATA_CHANGED')
        return decode(raw), bytes(raw)
    finally:
        os.close(fd)

class BaseEngine:
    def check(self):
        p = Path(self.binding['socketPath'])
        require(p.is_absolute() and '..' not in p.parts and str(p.resolve()) == str(p),
                'EXACT_ENGINE_PATH_REQUIRED')
        s = p.lstat()
        require(stat.S_ISSOCK(s.st_mode) and s.st_uid == 0
                and stat.S_IMODE(s.st_mode) in (0o600, 0o660)
                and [s.st_dev, s.st_ino, s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)]
                == self.binding['socketBinding'], 'ENGINE_BINDING_CHANGED')

    def get(self, path):
        require(path in self.paths and self.calls < MAX_GETS, 'CLOSED_FOUR_GET_BUDGET')
        self.check()
        selected = self.binding['socketPath']

        class Connection(http.client.HTTPConnection):
            def connect(connection):
                connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.sock.settimeout(connection.timeout)
                connection.sock.connect(selected)

        connection = Connection('retained-engine', timeout=4)
        try:
            self.calls += 1
            connection.request('GET', path, headers={'Connection': 'close'})
            response = connection.getresponse()
            raw = response.read(MAX_BYTES + 1)
            require(len(raw) <= MAX_BYTES, 'LOG_OR_METADATA_LIMIT_REACHED')
            self.check()
            require(response.status == 200, 'ENGINE_GET_STATUS_' + str(response.status))
            return raw
        finally:
            connection.close()

    def inspect(self, cid):
        path = '/v1.44/containers/' + cid + '/json'
        require(path in self.inspects, 'EXACT_INSPECT_ID_REQUIRED')
        value = decode(self.get(path))
        require(value['Id'] == cid, 'EXACT_INSPECT_ID_REQUIRED')
        return value

def generation(actual, pin):
    s = actual['State']
    require(actual['Id'] == pin['containerId'] and s['Pid'] == pin['pid']
            and s['StartedAt'] == pin['startedAt'] and s['Running'] is True
            and not s.get('Paused') and not s.get('Restarting') and not s.get('Dead'),
            'GATEWAY_GENERATION_CHANGED')
    require(actual['Image'] == pin['imageId'] and all(digest(actual[field]) == pin[key]
            for field,key in [('Config','configHash'),('HostConfig','hostConfigHash'),
                              ('NetworkSettings','networkSettingsHash')]), 'GATEWAY_BINDING_CHANGED')

def stable_fields(actual):
    # Omit continuously changing health-check history; bind lifecycle/config/network.
    return {'Id': actual['Id'], 'Image': actual['Image'], 'Config': actual['Config'],
            'HostConfig':actual['HostConfig'], 'Mounts':actual['Mounts'],
            'NetworkSettings': actual['NetworkSettings'], 'RestartCount': actual['RestartCount'],
            'State': {key: actual['State'].get(key) for key in STATE_FIELDS}}

def stopped(error):
    reason = str(error) if type(error) is Stop else 'DIAGNOSTIC_UNCONFIRMED_' + type(error).__name__
    if re.fullmatch('[A-Z][A-Z0-9_]{0,127}', reason) is None:
        reason = 'DIAGNOSTIC_UNCONFIRMED'
    return {'schema': SCHEMA, 'status': 'STOP_RECONCILE', 'reasonCode': reason,
            'readOnlyRuntime': True, 'runtimeEffectsDispatched': 0, 'activationResubmitted': False,
            'automaticReplayAllowed': False, 'budgetReset': False, 'rootCauseEstablished': False}


class Engine(BaseEngine):
    def __init__(self,binding,ids):
        require(len(ids)==len(set(ids))==2 and all(type(cid) is str and re.fullmatch('[a-f0-9]{64}',cid) for cid in ids),
                'TWO_EXACT_CONTAINERS_REQUIRED')
        self.binding,self.calls=binding,0
        self.inspects={'/v1.44/containers/'+cid+'/json' for cid in ids}
        self.paths=self.inspects


def compile_proposal(case,review,journal,registry):
    cfg,host,state=registry['Config'],registry['HostConfig'],registry['State']
    require(registry['Id']==case['historicalRegistryId'] and state['Status']=='exited'
            and state['Running'] is False and state['Pid']==0
            and state.get('Paused') is not True and state.get('Restarting') is not True
            and state.get('Dead') is not True,'EXACT_STOPPED_REGISTRY_REQUIRED')
    require(cfg.get('Entrypoint')==ENTRY and cfg.get('Cmd')==JAVA and cfg.get('User')=='10001:10001',
            'EXACT_RETAINED_GATED_LAUNCH_REQUIRED')
    rows=cfg.get('Env')
    require(type(rows) is list and len(rows)<=256,'BOUNDED_ENVIRONMENT_REQUIRED')
    env={}
    for row in rows:
        require(type(row) is str and '=' in row and len(row)<=16384,'VALID_ENVIRONMENT_REQUIRED')
        key,value=row.split('=',1)
        require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]*',key) and key not in env,'UNIQUE_ENVIRONMENT_REQUIRED')
        env[key]=value
    require(env.get('OUF_SCHEMA_GOV_ENABLED')=='false' and env.get('OUF_DISCOVERY_WORKER_ENABLED')=='false',
            'OBSERVED_FILE_ONLY_FLAGS_REQUIRED')
    require(not set(env)&{'JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS'}
            and not any(key.startswith('SPRING_') and key!='SPRING_CONFIG_IMPORT' for key in env),
            'NO_HIGH_PRIORITY_FEATURE_OVERRIDE_REQUIRED')
    require(not any(key.lower().replace('_','') in {'oufsemanticprovidersschemagovenabled','oufsemanticdiscoveryworkerenabled'} for key in env),
            'NO_FILE_ONLY_FEATURE_ALIAS_REQUIRED')
    require(host.get('RestartPolicy')=={'Name':'no','MaximumRetryCount':0}
            and host.get('Privileged',False) is False and not host.get('CapAdd')
            and host.get('CapDrop')==['ALL'] and 'no-new-privileges:true' in host.get('SecurityOpt',[])
            and all(host.get(key)!='host' and not str(host.get(key,'')).startswith('container:')
                    for key in ('NetworkMode','PidMode','IpcMode','UTSMode')),
            'RETAINED_BOUNDED_GATED_HOST_REQUIRED')
    require(type(registry['Image']) is str and re.fullmatch('sha256:[a-f0-9]{64}',registry['Image']),
            'EXACT_HISTORICAL_IMAGE_REQUIRED')
    native=review['executionReview']
    return {'schema':'ouf.semantic-registry-blocked-recovery-proposal.v1',
        'kind':'REVIEW_INPUTS_ONLY_NOT_EXECUTABLE_AUTHORITY',
        'caseHash':digest(case),'retainedPatchReviewHash':digest(review),'retainedPatchJournalHash':digest(journal),
        'priorObservationLog':case['priorObservationLog'],
        'registry':{'containerId':registry['Id'],'imageId':registry['Image'],
            'stableMetadataHash':digest(stable_fields(registry)),
            'configHash':digest(cfg),'hostConfigHash':digest(host),
            'mountsHash':digest(sorted(registry['Mounts'],key=lambda m:m['Destination'])),
            'networkSettingsHash':digest(registry['NetworkSettings']),
            'fileOnlyFlagsObserved':True,'gatedLaunchObserved':True},
        'gatewayBinding':native['runtimeGuardProfile']['unchangedApplications']['gateway']['binding'],
        'engineBinding':native['engineBinding'],
        'proposedScope':'NEW_GATED_GENERATION_OF_EXACT_STOPPED_REGISTRY',
        'proposedEffectClasses':['START_PREAPPLICATION_GATE','PAUSE_VERIFIED_NEW_GATE',
            'ATTEST_FRESH_GENERATION','UNPAUSE_ATTESTED_GATE','RELEASE_SAME_GENERATION_ONCE'],
        'requiredGates':['EXACT_HISTORICAL_OWNER_AND_CLAIM_CHAIN','COMPLETE_CURRENT_OCI_ROOTFS_AND_MOUNT_CUSTODY',
            'NEW_PROCESS_GENERATION_AND_ATTESTATION','CURRENT_DATABASE_OWNER_AND_STARTUP_ADMISSION',
            'CURRENT_TOKEN_OWNER_WITHOUT_UNREVIEWED_GRANTS','CURRENT_GATEWAY_ROUTE_MAP_AND_TARGET_BINDING',
            'QUALIFIED_GOVERNED_RECOVERY_EXECUTOR','FRESH_EXACT_HUMAN_RUNTIME_AUTHORITY'],
        'unresolvedGateCount':8,'providerRecoveryProposed':False,'newProviderLeaseProposed':False,
        'oldStartOrSignalClaimReusable':False,'oldAttestationReusableForNewPid':False,
        'rawContainerConfigurationStored':False,'credentialsRead':False,
        'oauthRequests':0,'newOAuthBudgetProposed':False,'newHumanWindowProposed':False,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'nativeExecutorQualified':False,
        'automaticReplayAllowed':False,'budgetReset':False,'rootCauseEstablished':False,
        'currentRegistryIdentityEstablished':False,'releaseAcceptance':False,
        'completedTechnicalPhases':8,'functionalMilestonesProven':4}


def capture(case):
    require(type(case) is dict and set(case)=={'schema','contextPath','historicalRegistryId','privateParent','priorObservationLog'}
            and case['schema']==CASE_SCHEMA and case['privateParent']=='/etc/ouf/deploy-snapshots', 'EXACT_PROPOSAL_CASE_REQUIRED')
    root=case['contextPath'];review,rraw=private_json(root+'/review.json');journal,jraw=private_json(root+'/recovery.json')
    native=review['executionReview']
    require(journal['nextStage']==len(native['stages'])==len(journal['effects'])==12
            and all(row['state']=='APPLIED' for row in journal['effects']), 'COMPLETED_PATCH_REQUIRED')
    pin=native['runtimeGuardProfile']['unchangedApplications']['gateway']['binding'];gid=pin['containerId'];rid=case['historicalRegistryId']
    engine=Engine(native['engineBinding'],[gid,rid]);gateway=engine.inspect(gid);generation(gateway,pin)
    registry=engine.inspect(rid);proposal=compile_proposal(case,review,journal,registry)
    registry_after=engine.inspect(rid);gateway_after=engine.inspect(gid);generation(gateway_after,pin)
    require(stable_fields(registry)==stable_fields(registry_after) and stable_fields(gateway)==stable_fields(gateway_after),
            'PROPOSAL_RESOURCE_DRIFT')
    require(private_json(root+'/review.json')[1]==rraw and private_json(root+'/recovery.json')[1]==jraw,
            'RETAINED_CONTEXT_CHANGED')
    return proposal,engine.calls


def publish(case,proposal):
    parent=Path(case['privateParent'])
    for path in [parent,*parent.parents]:
        info=path.lstat()
        require(path.resolve()==path and stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,
                'ROOT_CONTROLLED_PROPOSAL_PARENT_REQUIRED')
    # Only a new private proposal directory/file; no journal/claim/runtime mutation.
    root=Path(tempfile.mkdtemp(prefix='semantic-registry-recovery-proposal-',dir=parent))
    os.chmod(root,0o700)
    parent_fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(parent_fd)
    finally:os.close(parent_fd)
    path=root/'proposal.json';raw=encoded(proposal)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        remaining=memoryview(raw)
        while remaining:
            count=os.write(fd,remaining);require(count>0,'PROPOSAL_WRITE_INCOMPLETE');remaining=remaining[count:]
        os.fsync(fd);os.fchmod(fd,0o400);os.fsync(fd)
    finally:os.close(fd)
    require(private_json(str(path))[1]==raw,'PRIVATE_PROPOSAL_READBACK_FAILED')
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
    return str(path),digest(proposal)


if __name__=='__main__':
    try:
        require(os.geteuid()==0 and sys.flags.isolated,'ROOT_ISOLATED_PREPARER_REQUIRED')
        signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(Stop('PROPOSAL_DEADLINE')));signal.alarm(35)
        require(len(sys.argv)==2,'ONE_CASE_FILE_REQUIRED')
        with open(sys.argv[1],'rb') as source:raw=source.read(8193)
        require(len(raw)<=8192,'BOUNDED_CASE_REQUIRED');case=decode(raw)
        proposal,gets=capture(case);path,sha=publish(case,proposal)
        print(json.dumps({'schema':SCHEMA,'status':'BLOCKED_RECOVERY_PROPOSAL_RETAINED','complete':True,
            'privateProposalPath':path,'proposalHash':sha,'unresolvedGateCount':proposal['unresolvedGateCount'],
            'gatedFileOnlyLaunchObserved':True,'engineGets':gets,'maximumEngineGets':MAX_GETS,
            'runtimeEffectsDispatched':0,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
            'nativeExecutorQualified':False,'oauthRequests':0,'credentialFilesOpened':0,'providerRecoveryProposed':False,
            'activationResubmitted':False,'automaticReplayAllowed':False,'budgetReset':False,
            'completedTechnicalPhases':8,'functionalMilestonesProven':4,'releaseAcceptance':False},sort_keys=True),flush=True)
    except Exception as error:
        print(json.dumps(stopped(error),sort_keys=True),flush=True);sys.exit(1)
