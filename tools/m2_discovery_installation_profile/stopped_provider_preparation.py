"""Prepare exact historical provider inputs and current stopped-dependency context.

This is a new read-only preparation model, not a live peer/admission and not a
restart of the consumed collector. Historical launch/template/driver bytes remain
provenance only. No secret-file read, key issuance, lifecycle or application call.
"""
import copy,hashlib,os,re
from pathlib import Path
from .audit import path
from .custody_capture import attrs,decode,digest,process_pin,require,Stop
from .material_preparation import Preparation,ReadOnlyEngine,stable_binding
from .native_context import ContextEngine,BUNDLE_PARENTS,canonical_sandbox

RECON_ROOT=Path('/etc/ouf/deploy-snapshots/m2-provider-reconciliation-960507a9-20261029-v1')
RESULT_HASH='f6673b37e724f58d11553f98ea5c5efa83e42adb00038e90247a6ef7fe31121f'
RECON_HASH='84184832451fed0828f6e56b7e0d6ffb3c582a4879849d8903eed296666fcb21'
MATERIAL_ROOT=Path('/etc/ouf/deploy-snapshots/m2-discovery-material-roles-2d133870-20261029-v1')
MATERIAL_HASH='68daa9c9af2e3d5b41aceff988405e78a6fd3cb90a8c71f922816dd85964d392'
TRUST_ROOT=Path('/etc/ouf/deploy-snapshots/m2-discovery-trust-context-68daa9c9-20261029-v1')
TRUST_HASH='afbbe4808075fdb4374e74615ec4e13ea89646b06a5787b20c2f2656c7367e4d'
STORE_HASH='33418234a5428623b3f82e4219b1c29e014a14de1a537452366d9e54878c9559'
OWNER_HASH='0b72275fcc2c51be0929ca0ba454de932ae4863af1b2410dd67bef61bf81e91a'
PROVIDER_ID='1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916'
PROVIDER_IMAGE='sha256:c15541037a08276e36715a3c3798c2d07fe6faabf5547d3885a66cd10575e366'
PROFILE_HASH='dadb08b067e1a14dfdfe3fc8360f5544dc30885148a0d5c730913eb7c3d7073f'
DRAFT='/etc/ouf/deploy-snapshots/semantic-provider-v2-transaction-draft-g1yrsazc/southbound/'
CATALOG={
 'driver':{'path':'/etc/ouf/deploy-snapshots/semantic-provider-v2-transaction-mf9x0eqd/registry/'+PROVIDER_ID+'/driver.json','sha256':'66ff61a2a5f5a40279b615c7962796ebde6b0432dae167443a4ae4a3db8a5836'},
 'framePolicy':{'path':DRAFT+'framePolicy.json','sha256':'f49155fa412bb76d529713cb4ac2c253105884e9e72f7d2d74dfc5ccf9c5c822'},
 'launch':{'path':DRAFT+'launch.json','sha256':'cbc1f30c200a6a27e92b8055aa5542df30f7d124d08004d6f3bfe7dfb9ed2a39'},
 'template':{'path':DRAFT+'template.json','sha256':'0ef8aa503bfb6a5c789000cd73de6e987d1a55688894475e555f4d566581ad05'},
 'preparerTemplate':{'path':DRAFT+'preparerTemplate.json','sha256':'7ac15676ff00e38e1ac5bf5bd2356e42c34dbe9b485a5ba38d562380dcb1a894'}}
SCOPE=Path('/etc/ouf/deploy-snapshots/m2-stopped-provider-inputs-84184832-20261029-v1')


def retained_contract(values,*,provider_id,provider_image,profile_hash):
    require(type(values) is dict and set(values)==set(CATALOG),'EXACT_FIVE_HISTORICAL_PROVIDER_RECORDS_REQUIRED')
    driver=values['driver'];profile=driver['profile'];frame=values['framePolicy']
    require(profile['containerId']==provider_id and digest(profile)==profile_hash
            and frame.get('schema')=='ouf.semantic-configured-creation-frame-policy.v1'
            and digest(frame['expectedOci'])==profile['bundleHash'],
            'EXACT_HISTORICAL_PROVIDER_PROFILE_AND_COMPLETE_FRAME_REQUIRED')
    require(all(type(v) is dict for v in values.values()),'HISTORICAL_PROVIDER_JSON_OBJECTS_REQUIRED')
    return {'schema':'ouf.m2-provider-historical-source-inputs.v1',
        'providerId':provider_id,'providerImage':provider_image,'profileHash':profile_hash,
        'applicationHash':profile['bundleHash'],
        'driverSchema':driver['schema'],'authorityReused':False,
        'replacementExpectedPolicyCompiled':False,'currentNativeAdmissionProven':False}


class StoppedProviderPreparation(Preparation):
    def __init__(self,scope):
        super().__init__(scope)
        self.counts.update(recoveredPublicStoreReads=0,nativeConfigurationReads=0)


def prepare(c,*,recon_root=RECON_ROOT,result_hash=RESULT_HASH,recon_hash=RECON_HASH,
            material_root=MATERIAL_ROOT,material_hash=MATERIAL_HASH,trust_root=TRUST_ROOT,
            trust_hash=TRUST_HASH,store_hash=STORE_HASH,owner_hash=OWNER_HASH,
            catalog=CATALOG,provider_id=PROVIDER_ID,provider_image=PROVIDER_IMAGE,
            profile_hash=PROFILE_HASH,pin=process_pin,
            boot_path=Path('/proc/sys/kernel/random/boot_id'),
            engine_factory=ReadOnlyEngine,context_engine_factory=ContextEngine,bundle_parents=BUNDLE_PARENTS):
    require(type(c) is StoppedProviderPreparation,'EXACT_STOPPED_PROVIDER_INPUT_PREPARATION_REQUIRED')
    def metadata(p,expected=None,raw_hash=False):
        raw=c.read(p,0,0,0o600,2097152,'metadataReads');value=decode(raw)
        actual=hashlib.sha256(raw).hexdigest() if raw_hash else digest(value)
        require(expected is None or actual==expected,'EXACT_STOPPED_PROVIDER_INPUT_BINDING_REQUIRED')
        return value
    result=metadata(recon_root/'result.json',result_hash)
    require(result.get('schema')=='ouf.m2-provider-reconciliation-result.v1'
            and result.get('status')=='READ_ONLY_PROVIDER_RECONCILIATION_COMPLETE'
            and result.get('scope')==str(recon_root) and result.get('complete') is True
            and result.get('scopeConsumed') is True and result.get('reconciliationHash')==recon_hash
            and result.get('preservedTrustInputsHash')==trust_hash
            and result.get('preservedPublicStoreSha256')==store_hash
            and result.get('retainedCorePinStates')=={'MATCHED':13,'PROCESS_ABSENT':0,'GENERATION_CHANGED':0}
            and all(result.get(k) is False for k in ('runtimeAuthorityIssued','targetApplyAuthorized',
                'automaticReplayAllowed','budgetReset','applicationE2EProven','releaseAcceptance')),
            'EXACT_SUCCESSFUL_CONSUMED_STOPPED_PROVIDER_DIAGNOSIS_REQUIRED')
    recon=metadata(recon_root/'reconciliation.private.json',recon_hash)
    require(recon.get('schema')=='ouf.m2-provider-read-only-reconciliation.v1'
            and recon['analysis']==result['analysis']
            and recon['materialBinding']=={'path':str(material_root/'prepared-inputs.private.json'),'sha256':material_hash}
            and recon['preservedTrustInputsBinding']=={'path':str(trust_root/'public-trust-inputs.json'),'sha256':trust_hash}
            and all(recon.get(k) is False for k in ('runtimeAuthorityIssued','targetApplyAuthorized','automaticReplayAllowed','budgetReset')),
            'EXACT_READ_ONLY_RECONCILIATION_PROVENANCE_REQUIRED')
    material=metadata(material_root/'prepared-inputs.private.json',material_hash)
    require(material.get('schema')=='ouf.m2-discovery-private-material-role-preparation.v1'
            and all(material.get(k) is False for k in ('runtimeAuthorityIssued','targetApplyAuthorized',
                'historicalAuthorityReused','automaticReplayAllowed','budgetReset')),
            'UNADMITTED_MATERIAL_PROVENANCE_REQUIRED')
    trust=metadata(trust_root/'public-trust-inputs.json',trust_hash)
    require(trust.get('schema')=='ouf.m2-discovery-prepared-public-trust.v1'
            and trust['proposal']['materialBinding']==recon['materialBinding']
            and trust['proposal']['iamOwnerConfigurationBinding']['sha256']==owner_hash
            and trust['publicStore']==recon['preservedPublicStore'],
            'EXACT_PRESERVED_PUBLIC_TRUST_INPUTS_REQUIRED')
    store=trust['publicStore']
    require(store['path']==str(trust_root/'provider-trust.p12')
            and (store['uid'],store['gid'],store['mode'])==(0,10001,0o440),
            'EXACT_EXISTING_PUBLIC_STORE_CUSTODY_REQUIRED')
    raw=c.read(Path(store['path']),0,10001,0o440,1048576,'recoveredPublicStoreReads')
    require(hashlib.sha256(raw).hexdigest()==store_hash==store['sha256']==trust['proposal']['sha256']
            and attrs(Path(store['path']).lstat())==store['metadata'],'PRESERVED_PUBLIC_STORE_CHANGED')
    require(type(catalog) is dict and set(catalog)==set(CATALOG),'EXACT_HISTORICAL_PROVIDER_CATALOG_REQUIRED')
    values={}
    for name,binding in sorted(catalog.items()):
        require(set(binding)=={'path','sha256'},'EXACT_HISTORICAL_PROVIDER_FILE_BINDING_REQUIRED')
        values[name]=metadata(Path(path(binding['path'])),binding['sha256'],raw_hash=True)
    history=retained_contract(values,provider_id=provider_id,provider_image=provider_image,profile_hash=profile_hash)
    owner_binding=trust['proposal']['iamOwnerConfigurationBinding']
    owner=metadata(Path(path(owner_binding['path'])),owner_hash)
    require(owner.get('schema')=='ouf.registry-operational-token-configuration.v1',
            'EXACT_CURRENT_IAM_OWNER_CONFIGURATION_REFERENCE_REQUIRED')
    policy_binding=owner['verification']['trustPolicy']
    require(set(policy_binding)=={'path','sha256'},'EXACT_NATIVE_PUBLIC_TRUST_POLICY_REFERENCE_REQUIRED')
    policy=metadata(Path(path(policy_binding['path'])),policy_binding['sha256'],raw_hash=True)
    require(type(policy) is dict,'NATIVE_PUBLIC_POLICY_JSON_REFERENCE_REQUIRED')
    current=material['currentObservations'];pins=material['processPins'];roots=material['rootProcessPins']
    require(len(current)==13 and set(current)==set(pins) and set(roots)=={'pid1','engine'},
            'EXACT_THIRTEEN_CURRENT_CORE_INPUTS_REQUIRED')
    boot=boot_path.read_text().strip()
    def unchanged():
        c.guarded()
        require(boot_path.read_text().strip()==boot==material['bootId']
                and pin(1)==roots['pid1'] and pin(material['engineBinding']['peerCredentials'][0])==roots['engine']
                and all(pin(v['pid'])==v for v in pins.values())
                and all(attrs(Path(p).lstat())==s for p,s in c.seals.items()),
                'STOPPED_PROVIDER_INPUT_SOURCE_OR_CORE_GENERATION_CHANGED')
    unchanged()
    engine=engine_factory(c,material['engineBinding'],[row['Id'] for row in current.values()])
    require(engine.get('/v1.44/info').get('ServerVersion')=='29.8.1','QUALIFIED_PREPARATION_ENGINE_REQUIRED')
    observed={}
    for alias,prior in sorted(current.items()):
        actual=engine.get('/v1.44/containers/'+prior['Id']+'/json')
        require(stable_binding(actual)==stable_binding(prior) and actual['State']['Running'] is True
                and actual['State']['Paused'] is False and actual['State']['Restarting'] is False
                and pin(actual['State']['Pid'])==pins[alias],'CURRENT_CORE_BINDING_CHANGED')
        observed[alias]=actual
    semantic=observed[material['installationRoleMap']['semantic']]
    attachments=semantic['NetworkSettings']['Networks'];require(len(attachments)==1,'ONE_EXACT_REGISTRY_NETWORK_REQUIRED')
    network_name,attachment=next(iter(attachments.items()));network_id=attachment['NetworkID']
    context_engine=context_engine_factory(c,material['engineBinding'],provider_id,network_id)
    info=context_engine.get('/v1.44/info')
    require(info.get('ServerVersion')=='29.8.1' and info.get('Driver')=='overlayfs'
            and info.get('CgroupDriver')=='systemd','QUALIFIED_CURRENT_ENGINE_CONTEXT_REQUIRED')
    storage=Path(path(info['DockerRootDir']))
    network=context_engine.get('/v1.44/networks/'+network_id)
    require(network.get('Id')==network_id and network.get('Name')==network_name
            and network.get('Driver')=='bridge' and network.get('EnableIPv6') is False,'EXACT_CURRENT_REGISTRY_BRIDGE_REQUIRED')
    provider=context_engine.get('/v1.44/containers/'+provider_id+'/json')
    require(provider['Id']==provider_id and provider['Image']==provider_image
            and provider['State']['Running'] is False and provider['State']['Paused'] is False
            and provider['State']['Restarting'] is False
            and stable_binding(provider)==stable_binding(recon['currentViews']['1.44']),
            'SAME_EXACT_STOPPED_PROVIDER_SNAPSHOT_REQUIRED')
    # Observe ONLY the running Registry. A stopped provider has no admitted live
    # OCI peer or namespace; never manufacture one from its old profile.
    cid=semantic['Id'];selected=[Path(p)/cid/'config.json' for p in bundle_parents
                              if os.path.lexists(Path(p)/cid/'config.json')]
    require(len(selected)==1,'ONE_CURRENT_REGISTRY_CONTAINERD_BUNDLE_REQUIRED')
    selected=selected[0];mode=selected.lstat().st_mode&0o777
    require(mode in (0o600,0o644),'ROOT_REGISTRY_OCI_FILE_MODE_REQUIRED')
    raw=c.read(selected,0,0,mode,2097152,'nativeConfigurationReads');oci=decode(raw)
    rootfs=Path(path(oci['root']['path']))
    require(rootfs.is_absolute() and rootfs!=storage and rootfs.is_relative_to(storage),
            'REGISTRY_ROOTFS_OUTSIDE_ENGINE_STORAGE')
    sandbox,ns_identity=canonical_sandbox(c,semantic['NetworkSettings']['SandboxKey'],pins[material['installationRoleMap']['semantic']])
    registry={'containerId':cid,'configurationPath':str(selected),'configurationSha256':hashlib.sha256(raw).hexdigest(),
        'oci':oci,'bundleParent':str(selected.parent.parent),'bundlePath':str(selected.parent),'rootfsPath':str(rootfs),
        'networkNamespace':str(sandbox),'observedSandboxKey':semantic['NetworkSettings']['SandboxKey'],
        'networkNamespaceIdentity':ns_identity,'runtimeBinding':pins[material['installationRoleMap']['semantic']]}
    require(stable_binding(context_engine.get('/v1.44/containers/'+provider_id+'/json'))==stable_binding(provider)
            and context_engine.get('/v1.44/networks/'+network_id)==network,'STOPPED_PROVIDER_OR_BRIDGE_CHANGED')
    for alias,prior in sorted(current.items()):
        require(stable_binding(engine.get('/v1.44/containers/'+prior['Id']+'/json'))==stable_binding(prior),
                'CORE_CHANGED_DURING_STOPPED_PROVIDER_PREPARATION')
    unchanged()
    require(canonical_sandbox(c,registry['observedSandboxKey'],registry['runtimeBinding'])
            ==(sandbox,ns_identity),'REGISTRY_NAMESPACE_CHANGED_DURING_PREPARATION')
    require(c.counts['metadataReads']==11 and c.counts['engineGets']==27
            and c.counts['contextEngineGets']==5 and c.counts['nativeConfigurationReads']==1
            and c.counts['recoveredPublicStoreReads']==1
            and c.counts['credentialFileReads']==c.counts['applicationMacKeyReads']==0,
            'EXACT_STOPPED_PROVIDER_PREPARATION_READ_COUNTS_REQUIRED')
    proposal={'schema':'ouf.m2-discovery-stopped-provider-installation-inputs.v1',
        'reconciliationBinding':{'path':str(recon_root/'reconciliation.private.json'),'sha256':recon_hash},
        'materialBinding':recon['materialBinding'],'preservedTrustInputsBinding':recon['preservedTrustInputsBinding'],
        'preservedPublicStore':store,'historicalProviderSources':copy.deepcopy(catalog),
        'historicalProviderContract':history,'historicalRecords':values,
        'currentPublicPolicyBinding':policy_binding,'currentPublicPolicyReference':policy,
        'currentOwnerConfigurationBinding':owner_binding,
        'currentCoreObservations':observed,'processPins':pins,'rootProcessPins':roots,
        'engineBinding':material['engineBinding'],'bootId':boot,'currentStoppedProvider':provider,
        'currentRegistryNativeContext':registry,'registryNetwork':network,
        'engineProfile':{k:info[k] for k in ('ServerVersion','Driver','CgroupDriver','DockerRootDir')},
        'sourceSeals':dict(c.seals),'counts':dict(c.counts),
        'requiredProviderWork':'FRESH_COORDINATED_GATED_DEPENDENCY_ADMISSION_AND_DISTINCT_WORKER',
        'requiredBeforeRegistryPhase':'ATTEST_NEW_OCI_PEER',
        'stoppedProviderUsedAsLivePeer':False,'newProviderExpectedPolicyCompiled':False,
        'oldDriverMayExecute':False,'historicalAuthorityReused':False,
        'currentProviderAdmissionProven':False,'providerTlsAdmissionProven':False,
        'currentFullCohortConfigurationProven':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
        'automaticReplayAllowed':False,'budgetReset':False}
    c.put('installation-inputs.private.json',proposal)
    return {'schema':'ouf.m2-stopped-provider-inputs-result.v1',
        'status':'STOPPED_PROVIDER_INSTALLATION_INPUTS_PREPARED_NOT_ADMITTED','complete':True,
        'scope':str(c.scope),'scopeConsumed':True,'installationInputsHash':digest(proposal),
        'reconciliationHash':recon_hash,'preservedTrustInputsHash':trust_hash,'preservedPublicStoreSha256':store_hash,
        'historicalProviderSourceContractVerified':True,'providerStoppedObserved':True,
        'registryNativeContextsObserved':1,'providerNativeContextsObserved':0,'currentCoreCount':13,
        'driverSchema':history['driverSchema'],'counts':dict(c.counts),
        'requiredBeforeRegistryPhase':'ATTEST_NEW_OCI_PEER','stoppedProviderUsedAsLivePeer':False,
        'oldDriverMayExecute':False,'historicalAuthorityReused':False,'newPublicStoresPrepared':0,
        'engineWrites':0,'containerLifecycleOperations':0,'iamRequests':0,'oauthRequests':0,'sqlSessions':0,
        'newKeysGenerated':0,'signaturesIssued':0,'budgetsGranted':0,'uploads':0,'newJobs':0,'resumes':0,
        'rawConfigurationOrEnvironmentValuesPrinted':False,'providerAdmissionProven':False,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'automaticReplayAllowed':False,
        'budgetReset':False,'applicationE2EProven':False,'stableCapabilitiesOperationalProven':False,'releaseAcceptance':False}


def main():
    c=None
    try:
        c=StoppedProviderPreparation(SCOPE);result=prepare(c);c.put('result.json',result);code=0
    except Exception as error:
        reason=str(error)
        result={'schema':'ouf.m2-stopped-provider-inputs-result.v1','status':'STOP_RECONCILE',
            'reasonCode':reason if isinstance(error,(Stop,ValueError)) and re.fullmatch('[A-Z][A-Z0-9_]{0,160}',reason)
                else 'STOPPED_PROVIDER_INPUT_PREPARATION_UNPROVEN','complete':False,'scope':str(SCOPE),
            'scopeConsumed':os.path.lexists(SCOPE),'counts':dict(c.counts) if c else {},
            'existingFilesWritten':0,'rawConfigurationOrEnvironmentValuesPrinted':False,
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'historicalAuthorityReused':False,
            'automaticReplayAllowed':False,'budgetReset':False,'applicationE2EProven':False,'releaseAcceptance':False}
        if c:
            try:c.put('result.json',result)
            except Exception:pass
        code=1
    print(__import__('json').dumps(result,sort_keys=True));return code

if __name__=='__main__':raise SystemExit(main())
