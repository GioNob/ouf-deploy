"""One bounded private preparation; no application, IAM, SQL or image apply.

Read the three exact consumed provenance records without reopening their scopes,
reobserve their current thirteen peers, and prepare two separate immutable copies.
Historical files remain untouched. The result is an input to native review, never
a mandate, a valid credential claim, a TLS admission, or an executable cutover.
"""
import hashlib
import hmac
import http.client
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import struct
import time

from .audit import KEY_REFERENCE_NAMES, env
from .custody_capture import (Capture, Stop, attrs, decode, digest, encoded,
    process_pin, require, INPUT_ROOT, INPUT_HASH)
from .projections import compile_projections

COHORT_ROOT=Path('/etc/ouf/deploy-snapshots/m2-discovery-current-bindings-0601fdfa-20261029-v1')
COHORT_HASH='14e42ac96293d342cd71b7386360b976882ac7ec75a18838d3960999430f3a13'
CANDIDATE_ROOT=Path('/etc/ouf/deploy-snapshots/m2-discovery-custody-f759d397-20261029-v1')
CANDIDATE_HASH='eed64887cfcf18dc4be6de32c954b67649adf72ff384c3296d4bfe21ba1188c5'
SCOPE=Path('/etc/ouf/deploy-snapshots/m2-discovery-material-preparation-eed64887-20261029-v1')
KEY_SLOT='OUF_SEMANTIC_DISCOVERY_OWNER_KEY'
MAX_BYTES=16777216


def stable_binding(value):
    return {k:value[k] for k in ('Id','Image','Config','HostConfig','Mounts','NetworkSettings')} | {
        'generation':{k:value['State'][k] for k in ('Pid','StartedAt','Running','Paused','Restarting')}}


class Preparation(Capture):
    def __init__(self,scope):
        super().__init__(scope)
        self.until=time.monotonic()+90
        self.counts.update(engineGets=0,privateCopiesPrepared=0,publicCertificateCopiesPrepared=0,preparedCopyReads=0)
        self.directory_identity=attrs(self.scope.lstat())[:6]

    def guarded(self):
        self.check();self.ancestors(self.scope/'placeholder')
        require(attrs(self.scope.lstat())[:6]==self.directory_identity,
                'MATERIAL_PREPARATION_DIRECTORY_CHANGED')

    def read(self,path,uid,gid,mode,maximum,kind):
        self.guarded();path=Path(path);self.ancestors(path)
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            info=os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid==uid and info.st_gid==gid
                    and stat.S_IMODE(info.st_mode)==mode and info.st_nlink==1
                    and 0<info.st_size<=maximum,'PREPARATION_FILE_CUSTODY_UNPROVEN')
            raw=os.read(fd,maximum+1)
            require(len(raw)==info.st_size and attrs(info)==attrs(os.fstat(fd))==attrs(path.lstat()),
                    'PREPARATION_FILE_CHANGED_DURING_READ')
        finally:os.close(fd)
        self.counts[kind]+=1;self.counts['bytes']+=len(raw)
        require(self.counts['bytes']<=MAX_BYTES,'MATERIAL_PREPARATION_BYTE_LIMIT')
        self.seals[str(path)]=attrs(info);self.guarded();return raw

    def copy_once(self,name,raw,*,gid,mode,private):
        self.guarded()
        require(name in ('schema-gov-client-secret','semantic-discovery-owner.key','provider-public-ca.crt')
                and type(raw) is bytes and 0<len(raw)<=1048576,
                'CLOSED_BOUNDED_MATERIAL_PROJECTION_REQUIRED')
        self.put('copy-'+name+'-claim.json',{'name':name,'sha256':hashlib.sha256(raw).hexdigest(),
                'uid':0,'gid':gid,'mode':mode,'attemptNotCompletion':True})
        directory=os.open(self.scope,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
            try:
                os.fchown(fd,0,gid);os.fchmod(fd,mode)
                with os.fdopen(os.dup(fd),'wb') as out:
                    out.write(raw);out.flush();os.fsync(out.fileno())
                info=os.fstat(fd)
                require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_gid==gid
                        and stat.S_IMODE(info.st_mode)==mode and info.st_nlink==1 and info.st_size==len(raw),
                        'PREPARED_PROJECTION_CUSTODY_UNPROVEN')
            finally:os.close(fd)
            os.fsync(directory)
        finally:os.close(directory)
        self.counts['privateCopiesPrepared' if private else 'publicCertificateCopiesPrepared']+=1
        require(self.read(self.scope/name,0,gid,mode,1048576,'preparedCopyReads')==raw,
                'PREPARED_PROJECTION_READBACK_UNPROVEN')
        self.guarded()
        return {'path':str(self.scope/name),'sha256':hashlib.sha256(raw).hexdigest(),
                'uid':0,'gid':gid,'mode':mode,'metadata':attrs(info)}


class ReadOnlyEngine:
    def __init__(self,capture,binding,ids):
        require(type(binding) is dict and set(binding)=={'socketPath','socketBinding','peerCredentials'}
                and len(ids)==13 and len(set(ids))==13
                and all(re.fullmatch('[0-9a-f]{64}',cid) for cid in ids),
                'EXACT_THIRTEEN_PEER_READ_ONLY_ENGINE_REQUIRED')
        self.c,self.binding=capture,binding
        self.allowed={'/v1.44/info'}|{'/v1.44/containers/'+cid+'/json' for cid in ids}

    def get(self,path):
        c=self.c;c.guarded()
        require(path in self.allowed and c.counts['engineGets']<27,
                'CLOSED_MATERIAL_PREPARATION_ENGINE_GET_SCOPE_REQUIRED')
        selected=Path(self.binding['socketPath']);c.ancestors(selected)
        info=selected.lstat()
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid==0
                and [info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)]==self.binding['socketBinding'],
                'MATERIAL_PREPARATION_ENGINE_SOCKET_CHANGED')
        c.counts['engineGets']+=1;number=c.counts['engineGets']
        c.put('engine-get-'+str(number)+'-claim.json',{'method':'GET','path':path,'attemptNotCompletion':True})
        binding=self.binding
        class Local(http.client.HTTPConnection):
            def connect(conn):
                conn.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                conn.sock.settimeout(min(4,c.until-time.monotonic()));conn.sock.connect(str(selected))
                peer=list(struct.unpack('3i',conn.sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)))
                require(peer==binding['peerCredentials'] and peer[1]==0,'MATERIAL_PREPARATION_ENGINE_PEER_CHANGED')
        connection=Local('root-local-engine',timeout=min(4,c.until-time.monotonic()))
        try:
            connection.request('GET',path,headers={'Connection':'close'})
            response=connection.getresponse();raw=response.read(2097153)
            c.counts['bytes']+=len(raw)
            require(response.status==200 and 0<len(raw)<=2097152 and c.counts['bytes']<=MAX_BYTES,
                    'BOUNDED_SUCCESSFUL_MATERIAL_PREPARATION_ENGINE_GET_REQUIRED')
            value=decode(raw);c.put('engine-get-'+str(number)+'-response.json',value)
            return value
        finally:connection.close()


def public_certificate_only(raw):
    require(type(raw) is bytes and re.fullmatch(
        rb'-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\r?\n?',raw),
        'ONE_PUBLIC_CERTIFICATE_WITHOUT_PRIVATE_MATERIAL_REQUIRED')
    der=ssl.PEM_cert_to_DER_cert(raw.decode('ascii'))
    require(128<=len(der)<=1048576,'BOUNDED_PUBLIC_CERTIFICATE_REQUIRED')
    # Parsing/CA constraints, current validity, issuer trust, TLS and PKCS12
    # production remain explicit native preparation/admission requirements.
    return raw


def prepare(c,*,input_root=INPUT_ROOT,input_hash=INPUT_HASH,cohort_root=COHORT_ROOT,
            cohort_hash=COHORT_HASH,candidate_root=CANDIDATE_ROOT,candidate_hash=CANDIDATE_HASH,
            pin=process_pin,boot_path=Path('/proc/sys/kernel/random/boot_id'),engine_factory=ReadOnlyEngine):
    def metadata(path,expected):
        value=decode(c.read(path,0,0,0o600,2097152,'metadataReads'))
        require(digest(value)==expected,'EXACT_CONSUMED_PREPARATION_PROVENANCE_REQUIRED');return value
    inputs=metadata(input_root/'inputs.json',input_hash)
    cohort=metadata(cohort_root/'inputs.json',cohort_hash)
    candidates=metadata(candidate_root/'material-candidates.private.json',candidate_hash)
    require(inputs.get('schema')=='ouf.m2-discovery-private-installation-inputs.v1'
            and cohort.get('schema')=='ouf.m2-discovery-current-private-bindings.v1'
            and len(cohort['observations'])==13 and set(cohort['observations'])==set(cohort['processPins'])
            and set(inputs['observations'])==set(candidates['processPins'])=={'semantic','mcp','apisix','gateway-owner'}
            and candidates['installationInputsHash']==input_hash,
            'COMPLETE_BOUND_COHORT_AND_CUSTODY_PROVENANCE_REQUIRED')
    require(all(value.get(k) is False for value in (inputs,cohort)
                for k in ('historicalAuthorityReused','runtimeAuthorityIssued','automaticReplayAllowed','budgetReset')),
            'PROVENANCE_CANNOT_REOPEN_HISTORICAL_AUTHORITY')
    plan=compile_projections(candidates,{'path':str(candidate_root/'material-candidates.private.json'),
        'sha256':candidate_hash},str(c.scope),KEY_SLOT)
    boot=boot_path.read_text().strip()
    require(boot==inputs['bootId']==cohort['bootId'],'PREPARATION_CURRENT_BOOT_REQUIRED')
    roots=cohort['rootProcessPins']
    require(set(roots)=={'pid1','engine'} and roots['pid1']==pin(1)
            and roots['engine']==pin(cohort['engineBinding']['peerCredentials'][0]),
            'PREPARATION_ROOT_PROCESS_GENERATION_CHANGED')
    require(set(inputs['observations'])<=set(cohort['observations']), 'INSTALLATION_ROLES_OUTSIDE_REVIEWED_COHORT')
    for role in inputs['observations']:
        require(stable_binding(inputs['observations'][role])==stable_binding(cohort['observations'][role])
                and inputs['processPins'][role]==candidates['processPins'][role]==cohort['processPins'][role],
                'INSTALLATION_AND_CUSTODY_GENERATION_DISAGREE')
    engine=engine_factory(c,cohort['engineBinding'],[v['Id'] for v in cohort['observations'].values()])
    require(engine.get('/v1.44/info').get('ServerVersion')=='29.8.1','QUALIFIED_PREPARATION_ENGINE_REQUIRED')
    current={}
    for role,prior in sorted(cohort['observations'].items()):
        actual=engine.get('/v1.44/containers/'+prior['Id']+'/json')
        require(stable_binding(actual)==stable_binding(prior) and actual['State']['Running'] is True
                and actual['State']['Paused'] is False and actual['State']['Restarting'] is False
                and pin(actual['State']['Pid'])==cohort['processPins'][role],
                'CURRENT_FULL_PREPARATION_COHORT_CHANGED')
        current[role]=actual
    values={}
    kinds={'providerCredential':'credentialFileReads','registryDiscoveryKey':'applicationMacKeyReads',
           'gatewayDiscoveryKey':'applicationMacKeyReads','publicProviderCa':'publicCertificateReads'}
    for role,row in candidates['candidates'].items():
        raw=c.read(row['path'],row['uid'],row['gid'],row['mode'],1048576 if role=='publicProviderCa' else 4096,kinds[role])
        require(attrs(Path(row['path']).lstat())==row['metadata']
                and hmac.compare_digest(hashlib.sha256(raw).hexdigest(),row['sha256']),
                'CANDIDATE_CONTENT_OR_METADATA_CHANGED_SINCE_CUSTODY')
        if role.endswith('Key'):
            require(re.fullmatch(rb'[0-9a-f]{64}',raw),'EXACT_MATCHED_DISCOVERY_MAC_KEY_BYTES_REQUIRED')
        values[role]=raw
    require(hmac.compare_digest(values['registryDiscoveryKey'],values['gatewayDiscoveryKey']),
            'MATCHED_DISCOVERY_CONSUMER_PAIR_REQUIRED')
    public_certificate_only(values['publicProviderCa'])
    gateway=env(current['apisix']);discovery=values['gatewayDiscoveryKey'].decode('ascii')
    require(KEY_SLOT not in gateway or hmac.compare_digest(gateway[KEY_SLOT],discovery),
            'EXISTING_DISCOVERY_KEY_SLOT_HAS_DIFFERENT_MATERIAL')
    required={'OUF_GATEWAY_DELEGATION_KEY','OUF_SEMANTIC_READ_OWNER_KEY','OUF_SEMANTIC_PROPOSAL_OWNER_KEY'}
    require(required<=set(gateway) and all(gateway[k] and not hmac.compare_digest(gateway[k],discovery)
            for k in KEY_REFERENCE_NAMES if k in gateway), 'EXISTING_APPLICATION_KEY_PURPOSE_COLLISION')
    def unchanged():
        c.guarded()
        require(boot_path.read_text().strip()==boot and pin(1)==roots['pid1']
                and pin(roots['engine']['pid'])==roots['engine']
                and all(pin(p['pid'])==p for p in cohort['processPins'].values())
                and all(attrs(Path(p).lstat())==s for p,s in c.seals.items()),
                'MATERIAL_PREPARATION_SOURCE_OR_GENERATION_CHANGED')
    unchanged()
    copies={}
    for row in plan['projections']:
        copies[row['role']]=c.copy_once(Path(row['destination']).name,values[row['role']],
                                      gid=row['gid'],mode=row['mode'],private=True)
    copies['publicProviderCa']=c.copy_once('provider-public-ca.crt',values['publicProviderCa'],
                                         gid=0,mode=0o600,private=False)
    for role,first in sorted(current.items()):
        again=engine.get('/v1.44/containers/'+first['Id']+'/json')
        require(stable_binding(again)==stable_binding(first),'COHORT_CHANGED_DURING_MATERIAL_PREPARATION')
    unchanged()
    private={'schema':'ouf.m2-discovery-private-material-preparation.v1',
        'installationInputsHash':input_hash,'cohortInputsHash':cohort_hash,'candidateBindingHash':candidate_hash,
        'bootId':boot,'currentObservations':current,'processPins':cohort['processPins'],
        'rootProcessPins':roots,'engineBinding':cohort['engineBinding'],'projectionPlan':plan,'preparedCopies':copies,
        'sourceSeals':c.seals,'counts':dict(c.counts),'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
        'historicalAuthorityReused':False,'automaticReplayAllowed':False,'budgetReset':False}
    c.put('prepared-inputs.private.json',private)
    return {'schema':'ouf.m2-discovery-material-preparation-result.v1',
        'status':'PRIVATE_MATERIAL_COPIES_PREPARED_NOT_ADMITTED','complete':True,'scope':str(c.scope),
        'preparedInputsHash':digest(private),'candidateBindingHash':candidate_hash,'currentPeerCount':13,
        'counts':dict(c.counts),'historicalSourceFilesPreserved':True,'matchedDiscoveryPairObserved':True,
        'publicCertificateEnvelopeOnlyChecked':True,'currentCertificateCaValidityAndTrustProven':False,
        'iamAndProviderCombinedTrustStorePrepared':False,'rawPrivateValuesPrinted':False,
        'newKeysGenerated':0,'deploymentSigningKeyReads':0,'signaturesIssued':0,
        'engineWrites':0,'sqlSessions':0,'iamRequests':0,'oauthRequests':0,'containerLifecycleOperations':0,
        'imageImports':0,'newGrantsGranted':0,'budgetsGranted':0,'uploads':0,'newJobs':0,'resumes':0,
        'sourceActivations':0,'acquisitionsExecuted':0,'scopeConsumed':True,'historicalAuthorityReused':False,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'stableCapabilitiesOperationalProven':False,
        'applicationE2EProven':False,'releaseAcceptance':False,'automaticReplayAllowed':False,'budgetReset':False}


def main():
    c=None
    try:
        c=Preparation(SCOPE);result=prepare(c);c.put('result.json',result);code=0
    except Exception as error:
        reason=str(error)
        result={'schema':'ouf.m2-discovery-material-preparation-result.v1','status':'STOP_RECONCILE',
            'reasonCode':reason if isinstance(error,(Stop,ValueError)) and re.fullmatch('[A-Z][A-Z0-9_]{0,160}',reason)
                         else 'MATERIAL_PREPARATION_UNPROVEN','complete':False,'scope':str(SCOPE),
            'scopeConsumed':os.path.lexists(SCOPE),'counts':dict(c.counts) if c else {},
            'automaticReplayAllowed':False,'budgetReset':False,'runtimeAuthorityIssued':False,
            'targetApplyAuthorized':False,'applicationE2EProven':False,'releaseAcceptance':False}
        if c:
            try:c.put('result.json',result)
            except Exception:pass
        code=1
    print(__import__('json').dumps(result,sort_keys=True));return code

if __name__=='__main__':raise SystemExit(main())
