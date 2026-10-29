"""Read-only provider representation reconciliation after an exact consumed STOP.

Compare complete identities across the fixed capture API and the current Engine's
negotiated API. No field is dropped, no provider is selected by name, and no match
grants admission/resume/apply. Preserve the previously staged public PKCS12.
"""
import copy,hashlib,http.client,os,re,socket,stat,struct,time
from pathlib import Path
from .audit import path
from .custody_capture import require,attrs,decode,digest,process_pin,encoded,Stop
from .material_preparation import Preparation,stable_binding

STOP_SCOPE=Path('/etc/ouf/deploy-snapshots/m2-discovery-trust-context-68daa9c9-20261029-v1')
STOP_HASH='960507a9df468f100a91338819ec30fb95e098cabefe010c3335ebc60f9cbbfa'
MATERIAL_ROOT=Path('/etc/ouf/deploy-snapshots/m2-discovery-material-roles-2d133870-20261029-v1')
MATERIAL_HASH='68daa9c9af2e3d5b41aceff988405e78a6fd3cb90a8c71f922816dd85964d392'
MANIFEST_ROOT=Path('/etc/ouf/deploy-snapshots/semantic-discovery-runtime-inputs-682nr5ky')
MANIFEST_HASH='732a633e46cb06bb720352aa6a90946281ba6489e94aa35dc04820eae56b4a70'
OWNER_HASH='0b72275fcc2c51be0929ca0ba454de932ae4863af1b2410dd67bef61bf81e91a'
SCOPE=Path('/etc/ouf/deploy-snapshots/m2-provider-reconciliation-960507a9-20261029-v1')
MAX_BYTES=4194304
CAPTURE_API='1.44'


def identity(row):
    return {'containerId':row['Id'],'imageId':row['Image'],
        'configurationHash':digest({k:row[k] for k in ('Config','HostConfig','Mounts')}|
                                  {'networks':row['NetworkSettings']['Networks']})}


def api_version(value):
    require(type(value) is str and re.fullmatch(r'1\.[0-9]{2}',value)
            and 44<=int(value.split('.')[1])<=99,'BOUNDED_EXACT_ENGINE_API_VERSION_REQUIRED')
    return value


def analyze(expected,captured,views,negotiated_api):
    api_version(negotiated_api)
    require(type(expected) is dict and {'containerId','imageId','configurationHash'}<=set(expected)
            and re.fullmatch('[0-9a-f]{64}',expected['containerId'])
            and re.fullmatch('sha256:[0-9a-f]{64}',expected['imageId'])
            and re.fullmatch('[0-9a-f]{64}',expected['configurationHash']),
            'EXACT_HISTORICAL_PROVIDER_IDENTITY_REQUIRED')
    require(type(views) is dict and set(views)=={CAPTURE_API,negotiated_api},
            'ONLY_CAPTURE_AND_NEGOTIATED_PROVIDER_VIEWS_REQUIRED')
    rows={'captured':captured,**views};exact={k:expected[k] for k in ('containerId','imageId','configurationHash')}
    checks={};states={}
    for label,row in rows.items():
        actual=identity(row)
        require(actual['containerId']==expected['containerId'],'PROVIDER_RESPONSE_FOR_OTHER_ID_DENIED')
        state=row['State']
        require(all(type(state[k]) is bool for k in ('Running','Paused','Restarting'))
                and type(state['Pid']) is int and state['Pid']>=0,
                'TYPED_MINIMIZED_PROVIDER_STATE_REQUIRED')
        checks[label]={k:actual[k]==exact[k] for k in exact}
        checks[label]['completeIdentityMatches']=actual==exact
        states[label]={k:state[k] for k in ('Running','Paused','Restarting')}
    matches=[a for a in sorted(views) if checks[a]['completeIdentityMatches']]
    current_state=states[negotiated_api]
    blocked=not current_state['Running'] or current_state['Paused'] or current_state['Restarting']
    if blocked:classification='CURRENT_PROVIDER_STATE_BLOCKS_NATIVE_CONTEXT'
    elif matches and not checks['captured']['completeIdentityMatches']:
        classification='HISTORICAL_IDENTITY_MATCHES_A_CURRENT_API_REPRESENTATION'
    elif matches:classification='HISTORICAL_IDENTITY_MATCHES_CURRENT_VIEW_NO_ADMISSION'
    else:classification='HISTORICAL_PROVIDER_IDENTITY_HAS_NO_CURRENT_VIEW_MATCH'
    return {'schema':'ouf.m2-provider-representation-analysis.v1','classification':classification,
        'captureApi':CAPTURE_API,'negotiatedApi':negotiated_api,'identityChecks':checks,'stateChecks':states,
        'matchingCurrentApis':matches,'capturedIdentityEqualsCurrentCaptureApi':identity(captured)==identity(views[CAPTURE_API]),
        'currentViewBindings':{a:digest(stable_binding(r)) for a,r in sorted(views.items())},
        'currentStateBlocksNativeContext':blocked,'fieldsDroppedForMatching':[],
        'rawConfigurationOrEnvironmentValuesPrinted':False,'historicalAuthorityReused':False,
        'providerAdmissionProven':False,'nativeContextAcceptanceGranted':False,
        'resumeAllowed':False,'targetApplyAuthorized':False,'runtimeAuthorityIssued':False,
        'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False}


def core_pin_observations(pins,pin):
    """Incident facts only; absent/reused old PIDs confer no current admission."""
    require(type(pins) is dict and len(pins)==13,'EXACT_RETAINED_CORE_PIN_DOMAIN_REQUIRED')
    result={}
    for alias,expected in sorted(pins.items()):
        require(type(expected) is dict and type(expected.get('pid')) is int and expected['pid']>=1,
                'EXACT_RETAINED_CORE_PID_REQUIRED')
        try:actual=pin(expected['pid'])
        except (FileNotFoundError,ProcessLookupError):
            result[alias]={'state':'PROCESS_ABSENT','observedHash':None}
        else:
            result[alias]={'state':'MATCHED' if actual==expected else 'GENERATION_CHANGED',
                           'observedHash':digest(actual)}
    return result


def verify_stop(value):
    expected={'applicationMacKeyReads':0,'bytes':906004,'contextEngineGets':3,
        'credentialFileReads':0,'engineGets':27,'metadataReads':5,'nativeConfigurationReads':0,
        'preparedCopyReads':0,'privateCopiesPrepared':0,'publicCertificateCopiesPrepared':0,
        'publicCertificateReads':2,'publicTrustStoreReadbacks':1,'publicTrustStoresPrepared':1}
    require(value.get('schema')=='ouf.m2-discovery-trust-context-preparation-result.v1'
            and value.get('status')=='STOP_RECONCILE'
            and value.get('reasonCode')=='CURRENT_RETAINED_PROVIDER_IDENTITY_CHANGED'
            and value.get('scope')==str(STOP_SCOPE) and value.get('scopeConsumed') is True
            and value.get('complete') is False and value.get('partialPublicStorePreserved') is True
            and value.get('counts')==expected and value.get('rawCredentialOrKeyValuesPrinted') is False
            and all(value.get(k) is False for k in ('runtimeAuthorityIssued','targetApplyAuthorized',
                'applicationE2EProven','releaseAcceptance','automaticReplayAllowed','budgetReset')),
            'EXACT_CONSUMED_PROVIDER_STOP_REQUIRED_NO_REPLAY')


class ReconciliationCapture(Preparation):
    def __init__(self,scope):
        super().__init__(scope);self.until=time.monotonic()+45
        self.counts.update(providerEngineGets=0,recoveredPublicStoreReads=0)
    def read(self,*args):
        raw=super().read(*args)
        require(self.counts['bytes']<=MAX_BYTES,'PROVIDER_RECONCILIATION_BYTE_LIMIT')
        return raw


class ProviderViewsEngine:
    """At most five GET attempts, one provider ID, no caller-selected API."""
    def __init__(self,c,binding,provider):
        require(re.fullmatch('[0-9a-f]{64}',provider)
                and set(binding)=={'socketPath','socketBinding','peerCredentials'},
                'EXACT_PROVIDER_RECONCILIATION_ENGINE_BINDING_REQUIRED')
        self.c,self.binding,self.provider=c,copy.deepcopy(binding),provider
        self.negotiated=None
    def get(self,selected):
        c=self.c;c.guarded()
        base='/v'+CAPTURE_API+'/containers/'+self.provider+'/json'
        allowed={'/version',base}
        if self.negotiated:allowed.add('/v'+self.negotiated+'/containers/'+self.provider+'/json')
        require(selected in allowed and c.counts['providerEngineGets']<5
                and (selected=='/version') is (self.negotiated is None),
                'CLOSED_PROVIDER_RECONCILIATION_GET_SCOPE_REQUIRED')
        binding=self.binding;selected_socket=Path(binding['socketPath']);c.ancestors(selected_socket)
        s=selected_socket.lstat()
        require(stat.S_ISSOCK(s.st_mode) and s.st_uid==0
                and [s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)]==binding['socketBinding'],
                'PROVIDER_RECONCILIATION_ENGINE_SOCKET_CHANGED')
        c.counts['providerEngineGets']+=1;n=c.counts['providerEngineGets']
        c.put('provider-get-'+str(n)+'-claim.json',{'method':'GET','path':selected,'attemptNotCompletion':True})
        class Local(http.client.HTTPConnection):
            def connect(conn):
                conn.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                conn.sock.settimeout(min(4,c.until-time.monotonic()));conn.sock.connect(str(selected_socket))
                peer=list(struct.unpack('3i',conn.sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)))
                require(peer==binding['peerCredentials'] and peer[1]==0,'PROVIDER_RECONCILIATION_ENGINE_PEER_CHANGED')
        conn=Local('root-local-provider-reconciliation')
        try:
            conn.request('GET',selected,headers={'Connection':'close'})
            reply=conn.getresponse();raw=reply.read(2097153);c.counts['bytes']+=len(raw)
            require(reply.status==200 and 0<len(raw)<=2097152 and c.counts['bytes']<=MAX_BYTES,
                    'BOUNDED_SUCCESSFUL_PROVIDER_RECONCILIATION_GET_REQUIRED')
            value=decode(raw);c.put('provider-get-'+str(n)+'-response.json',value)
            if selected=='/version':
                require(value.get('Version')=='29.8.1','QUALIFIED_RECONCILIATION_ENGINE_REQUIRED')
                self.negotiated=api_version(value['ApiVersion'])
            return value
        finally:conn.close()


def reconcile(c,*,stop_scope=STOP_SCOPE,stop_hash=STOP_HASH,material_root=MATERIAL_ROOT,
              material_hash=MATERIAL_HASH,manifest_root=MANIFEST_ROOT,manifest_hash=MANIFEST_HASH,
              owner_hash=OWNER_HASH,pin=process_pin,boot_path=Path('/proc/sys/kernel/random/boot_id'),
              engine_factory=ProviderViewsEngine):
    require(type(c) is ReconciliationCapture,'EXACT_READ_ONLY_RECONCILIATION_CAPTURE_REQUIRED')
    def metadata(p,expected=None):
        v=decode(c.read(p,0,0,0o600,2097152,'metadataReads'))
        require(expected is None or digest(v)==expected,'EXACT_PROVIDER_RECONCILIATION_METADATA_REQUIRED')
        return v
    stop=metadata(stop_scope/'result.json',stop_hash);verify_stop(stop)
    material_path=material_root/'prepared-inputs.private.json';material=metadata(material_path,material_hash)
    require(material.get('schema')=='ouf.m2-discovery-private-material-role-preparation.v1'
            and all(material.get(k) is False for k in ('runtimeAuthorityIssued','targetApplyAuthorized',
                'historicalAuthorityReused','automaticReplayAllowed','budgetReset')),
            'EXACT_UNADMITTED_PROVIDER_MATERIAL_RECORD_REQUIRED')
    trust=metadata(stop_scope/'public-trust-inputs.json')
    require(trust.get('schema')=='ouf.m2-discovery-prepared-public-trust.v1'
            and trust['proposal']['materialBinding']=={'path':str(material_path),'sha256':material_hash}
            and trust['proposal']['iamOwnerConfigurationBinding']['sha256']==owner_hash
            and trust.get('targetApplyAuthorized') is False and trust.get('runtimeAuthorityIssued') is False
            and trust.get('targetTlsAdmissionProven') is False and trust.get('currentOwnerAdmissionProven') is False,
            'EXACT_PRESERVED_UNADMITTED_PUBLIC_TRUST_RECORD_REQUIRED')
    store=trust['publicStore']
    require(store['path']==str(stop_scope/'provider-trust.p12')
            and (store['uid'],store['gid'],store['mode'])==(0,10001,0o440),
            'EXACT_PRESERVED_PUBLIC_STORE_PATH_AND_CUSTODY_REQUIRED')
    public=c.read(Path(store['path']),0,10001,0o440,1048576,'recoveredPublicStoreReads')
    require(hashlib.sha256(public).hexdigest()==store['sha256']==trust['proposal']['sha256']
            and attrs(Path(store['path']).lstat())==store['metadata'],
            'PRESERVED_PUBLIC_STORE_BYTES_OR_CUSTODY_CHANGED')
    raw=c.read(manifest_root/'private-input-manifest.json',0,0,0o600,131072,'metadataReads')
    manifest=decode(raw)
    require(hashlib.sha256(raw).hexdigest()==manifest_hash==material['projectionPlan']['materialManifestHash']
            and manifest.get('schema')=='ouf.discovery.private-runtime-input-manifest.v1'
            and all(manifest.get(k) is False for k in ('mountsInstalled','applicationCutoverAuthorized','leaseAuthorityGranted'))
            and manifest['publicCaHash']==material['preparedCopies']['publicProviderCa']['sha256'],
            'EXACT_ORIGINAL_UNAPPLIED_PROVIDER_MANIFEST_REQUIRED')
    expected=manifest['inputBindings']['southbound'];cid=expected['containerId']
    claim=metadata(stop_scope/'context-engine-get-3-claim.json')
    require(claim=={'method':'GET','path':'/v1.44/containers/'+cid+'/json','attemptNotCompletion':True},
            'EXACT_FAILED_PROVIDER_CAPTURE_ROUTE_REQUIRED')
    captured=metadata(stop_scope/'context-engine-get-3-response.json')
    # Validate the old snapshot as diagnostic input before any new dispatch.
    analyze(expected,captured,{CAPTURE_API:captured},CAPTURE_API)
    boot=boot_path.read_text().strip();roots=material['rootProcessPins'];pins=material['processPins']
    require(len(pins)==len(material['currentObservations'])==13
            and set(pins)==set(material['currentObservations']) and set(roots)=={'pid1','engine'},
            'EXACT_RETAINED_THIRTEEN_CORE_PROCESS_PINS_REQUIRED')
    core_before=core_pin_observations(pins,pin)
    def unchanged():
        c.guarded()
        require(boot_path.read_text().strip()==boot==material['bootId']
                and pin(1)==roots['pid1'] and pin(material['engineBinding']['peerCredentials'][0])==roots['engine']
                and core_pin_observations(pins,pin)==core_before
                and all(attrs(Path(p).lstat())==s for p,s in c.seals.items()),
                'PROVIDER_RECONCILIATION_SOURCE_OR_CORE_GENERATION_CHANGED')
    unchanged();engine=engine_factory(c,material['engineBinding'],cid)
    version=engine.get('/version');negotiated=api_version(version['ApiVersion'])
    require(version.get('Version')=='29.8.1','QUALIFIED_RECONCILIATION_ENGINE_REQUIRED')
    views={a:engine.get('/v'+a+'/containers/'+cid+'/json') for a in sorted({CAPTURE_API,negotiated})}
    analysis=analyze(expected,captured,views,negotiated)
    primary=views[negotiated];pid=primary['State']['Pid']
    provider_pin=pin(pid) if primary['State']['Running'] and pid>1 else None
    require(all(v['State']['Pid']==pid and {k:v['State'][k] for k in ('Running','Paused','Restarting')}
                =={k:primary['State'][k] for k in ('Running','Paused','Restarting')} for v in views.values()),
            'SAME_CURRENT_PROVIDER_PROCESS_ACROSS_API_VIEWS_REQUIRED')
    for a,row in sorted(views.items()):
        again=engine.get('/v'+a+'/containers/'+cid+'/json')
        require(stable_binding(again)==stable_binding(row),'PROVIDER_CHANGED_DURING_RECONCILIATION')
    unchanged()
    require(provider_pin is None or pin(pid)==provider_pin,'PROVIDER_RECONCILIATION_PROCESS_CHANGED')
    record={'schema':'ouf.m2-provider-read-only-reconciliation.v1','analysis':analysis,
        'failedResultBinding':{'path':str(stop_scope/'result.json'),'sha256':stop_hash},
        'materialBinding':{'path':str(material_path),'sha256':material_hash},
        'preservedTrustInputsBinding':{'path':str(stop_scope/'public-trust-inputs.json'),'sha256':digest(trust)},
        'preservedPublicStore':store,'providerManifestBinding':{'path':str(manifest_root/'private-input-manifest.json'),'sha256':manifest_hash},
        'expectedHistoricalProvider':expected,'capturedProvider':captured,'currentViews':views,
        'providerProcessPin':provider_pin,'retainedCorePinObservations':core_before,
        'engineVersion':version,'sourceSeals':dict(c.seals),
        'counts':dict(c.counts),'currentFullCohortConfigurationProven':False,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'automaticReplayAllowed':False,'budgetReset':False}
    c.put('reconciliation.private.json',record)
    return {'schema':'ouf.m2-provider-reconciliation-result.v1','status':'READ_ONLY_PROVIDER_RECONCILIATION_COMPLETE',
        'complete':True,'scope':str(c.scope),'scopeConsumed':True,'reconciliationHash':digest(record),
        'preservedTrustInputsHash':digest(trust),'preservedPublicStoreSha256':store['sha256'],
        'analysis':analysis,'retainedCorePinStates':{state:sum(v['state']==state for v in core_before.values())
            for state in ('MATCHED','PROCESS_ABSENT','GENERATION_CHANGED')},
        'counts':dict(c.counts),'historicalFilesAndPublicStorePreserved':True,
        'rawCredentialOrKeyValuesPrinted':False,'newPublicStoresPrepared':0,
        'iamRequests':0,'oauthRequests':0,'sqlSessions':0,'engineWrites':0,'containerLifecycleOperations':0,
        'nativeConfigurationReads':0,'newKeysGenerated':0,'signaturesIssued':0,'budgetsGranted':0,
        'currentFullCohortConfigurationProven':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
        'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}


def main():
    c=None
    try:
        c=ReconciliationCapture(SCOPE);result=reconcile(c);c.put('result.json',result);code=0
    except Exception as error:
        reason=str(error)
        result={'schema':'ouf.m2-provider-reconciliation-result.v1','status':'STOP_RECONCILE',
            'reasonCode':reason if isinstance(error,(Stop,ValueError)) and re.fullmatch('[A-Z][A-Z0-9_]{0,160}',reason)
                else 'PROVIDER_RECONCILIATION_UNPROVEN','complete':False,'scope':str(SCOPE),
            'scopeConsumed':os.path.lexists(SCOPE),'counts':dict(c.counts) if c else {},
            'historicalFilesAndPublicStorePreserved':True,'rawCredentialOrKeyValuesPrinted':False,
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'automaticReplayAllowed':False,
            'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}
        if c:
            try:c.put('result.json',result)
            except Exception:pass
        code=1
    print(__import__('json').dumps(result,sort_keys=True));return code

if __name__=='__main__':raise SystemExit(main())
