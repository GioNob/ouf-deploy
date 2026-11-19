"""Corrective material preparation bound to an exact failed predecessor.

Published predecessor modules/capsules stay byte-exact. Friendly inventory names
are labels: selection uses one unique container ID plus the entire binding and
process pin. All thirteen current peers are still checked before any copy.
"""
import hashlib,hmac,json,os,re
from pathlib import Path
from .material_preparation import (Preparation,ReadOnlyEngine,stable_binding,
    public_certificate_only,attrs,decode,digest,encoded,process_pin,require,Stop,
    INPUT_ROOT,INPUT_HASH,COHORT_ROOT,COHORT_HASH,CANDIDATE_ROOT,CANDIDATE_HASH,
    KEY_SLOT,compile_projections,env,KEY_REFERENCE_NAMES)

PREDECESSOR_ROOT=Path('/etc/ouf/deploy-snapshots/m2-discovery-material-preparation-eed64887-20261029-v1')
PREDECESSOR_HASH='2d13387053ab8bc824f64183a1efb00d038a117b2a3d28547237be6eca7247ac'
SCOPE=Path('/etc/ouf/deploy-snapshots/m2-discovery-material-roles-2d133870-20261029-v1')
COHORT_RESULT_HASH='a5161311451021f936692274c6ad91cecb7a40ca2e0017da533765905fd0f674'
ROLES={'semantic','mcp','apisix','gateway-owner'}


def verify_predecessor(value,root):
    require(value.get('schema')=='ouf.m2-discovery-material-preparation-result.v1'
            and value.get('status')=='STOP_RECONCILE' and value.get('complete') is False
            and value.get('reasonCode')=='INSTALLATION_ROLES_OUTSIDE_REVIEWED_COHORT'
            and value.get('scope')==str(root) and value.get('scopeConsumed') is True
            and all(value.get(k) is False for k in ('applicationE2EProven','automaticReplayAllowed',
                'budgetReset','releaseAcceptance','runtimeAuthorityIssued','targetApplyAuthorized')),
            'EXACT_FAILED_ROLE_PREDECESSOR_REQUIRED_NO_REPLAY')
    counts=value.get('counts',{})
    require(set(counts)=={'applicationMacKeyReads','bytes','credentialFileReads','engineGets','metadataReads',
                'preparedCopyReads','privateCopiesPrepared','publicCertificateCopiesPrepared','publicCertificateReads'}
            and counts['metadataReads']==3 and type(counts['bytes']) is int and 0<counts['bytes']<=16777216
            and all(type(v) is int and v==0 for k,v in counts.items() if k not in ('bytes','metadataReads')),
            'FAILED_ROLE_PREDECESSOR_MUST_HAVE_NO_ENGINE_SECRET_OR_COPY_EFFECT')


def bind_installation_roles(inputs,cohort,candidates,cohort_root,cohort_hash):
    require(inputs.get('sourceBinding')=={'root':str(cohort_root),'inputsHash':cohort_hash,
                'resultHash':COHORT_RESULT_HASH}
            and inputs.get('engineBinding')==cohort.get('engineBinding')
            and inputs.get('rootProcessPins')==cohort.get('rootProcessPins'),
            'EXACT_INSTALLATION_COHORT_PROVENANCE_CHAIN_REQUIRED')
    observations=cohort['observations'];pins=cohort['processPins']
    require(len(observations)==13 and set(observations)==set(pins)
            and set(inputs['observations'])==set(inputs['processPins'])==set(candidates['processPins'])==ROLES,
            'EXACT_ROLE_AND_COHORT_PIN_DOMAINS_REQUIRED')
    ids=[row.get('Id') for row in observations.values()]
    require(all(type(cid) is str and re.fullmatch('[0-9a-f]{64}',cid) for cid in ids)
            and len(set(ids))==13,'THIRTEEN_UNIQUE_REVIEWED_CONTAINER_IDS_REQUIRED')
    selected=[row.get('Id') for row in inputs['observations'].values()]
    require(len(set(selected))==4 and all(cid in ids for cid in selected),
            'FOUR_UNIQUE_INSTALLATION_IDS_IN_REVIEWED_COHORT_REQUIRED')
    role_map={}
    for role,expected in sorted(inputs['observations'].items()):
        matches=[alias for alias,row in observations.items() if row['Id']==expected['Id']]
        require(len(matches)==1,'ONE_COHORT_CONTAINER_ID_MATCH_REQUIRED')
        alias=matches[0]
        require(stable_binding(expected)==stable_binding(observations[alias])
                and inputs['processPins'][role]==candidates['processPins'][role]==pins[alias]
                and expected['State']['Pid']==pins[alias]['pid'],
                'INSTALLATION_AND_CUSTODY_GENERATION_DISAGREE')
        role_map[role]=alias
    require(len(set(role_map.values()))==4,'ONE_TO_ONE_INSTALLATION_ROLE_MAPPING_REQUIRED')
    return role_map


def prepare(c,*,input_root=INPUT_ROOT,input_hash=INPUT_HASH,cohort_root=COHORT_ROOT,
            cohort_hash=COHORT_HASH,candidate_root=CANDIDATE_ROOT,candidate_hash=CANDIDATE_HASH,
            predecessor_root=PREDECESSOR_ROOT,predecessor_hash=PREDECESSOR_HASH,
            pin=process_pin,boot_path=Path('/proc/sys/kernel/random/boot_id'),engine_factory=ReadOnlyEngine):
    def metadata(path,expected):
        value=decode(c.read(path,0,0,0o600,2097152,'metadataReads'))
        require(digest(value)==expected,'EXACT_CONSUMED_PREPARATION_PROVENANCE_REQUIRED');return value
    predecessor=metadata(predecessor_root/'result.json',predecessor_hash)
    verify_predecessor(predecessor,predecessor_root)
    predecessor_binding={'path':str(predecessor_root/'result.json'),'sha256':predecessor_hash}
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
    role_map=bind_installation_roles(inputs,cohort,candidates,cohort_root,cohort_hash)
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
    gateway=env(current[role_map['apisix']]);discovery=values['gatewayDiscoveryKey'].decode('ascii')
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
    private={'schema':'ouf.m2-discovery-private-material-role-preparation.v1',
        'failedPredecessor':predecessor_binding,'installationRoleMap':role_map,
        'selectedInstallationObservations':{role:current[alias] for role,alias in role_map.items()},
        'installationInputsHash':input_hash,'cohortInputsHash':cohort_hash,'candidateBindingHash':candidate_hash,
        'bootId':boot,'currentObservations':current,'processPins':cohort['processPins'],
        'rootProcessPins':roots,'engineBinding':cohort['engineBinding'],'projectionPlan':plan,'preparedCopies':copies,
        'sourceSeals':c.seals,'counts':dict(c.counts),'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
        'historicalAuthorityReused':False,'automaticReplayAllowed':False,'budgetReset':False}
    c.put('prepared-inputs.private.json',private)
    return {'schema':'ouf.m2-discovery-material-role-preparation-result.v1',
        'status':'PRIVATE_MATERIAL_ROLE_COPIES_PREPARED_NOT_ADMITTED','complete':True,'scope':str(c.scope),
        'preparedInputsHash':digest(private),'predecessorResultHash':predecessor_hash,
        'installationRoleMapHash':digest(role_map),'selectedInstallationRoleCount':4,'candidateBindingHash':candidate_hash,'currentPeerCount':13,
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
        result={'schema':'ouf.m2-discovery-material-role-preparation-result.v1','status':'STOP_RECONCILE',
            'reasonCode':reason if isinstance(error,(Stop,ValueError)) and re.fullmatch('[A-Z][A-Z0-9_]{0,160}',reason)
                         else 'MATERIAL_ROLE_PREPARATION_UNPROVEN','complete':False,'scope':str(SCOPE),
            'scopeConsumed':os.path.lexists(SCOPE),'counts':dict(c.counts) if c else {},
            'automaticReplayAllowed':False,'budgetReset':False,'runtimeAuthorityIssued':False,
            'targetApplyAuthorized':False,'applicationE2EProven':False,'releaseAcceptance':False}
        if c:
            try:c.put('result.json',result)
            except Exception:pass
        code=1
    print(__import__('json').dumps(result,sort_keys=True));return code

if __name__=='__main__':raise SystemExit(main())
