"""Bind seven native core phases with cross-phase scope consistency.

No target entrypoint or default authority. The six owner phases must already be
source-sealed and supplied by the installer; missing phases block construction
before any claim/effect. Authority/native checkpoints remain separately owned.
"""
from transition_journal import PHASES,digest,require
from producer_adapter import ProducerAdapter
from endpoint_adapter import EndpointAdapter
from creation_adapter import CreationAdapter
from runtime_adapters import PausedStageAdapter,ReleasePausedAdapter
from fenced_backup_adapter import FencedBackupAdapter
from migration_admission_adapter import MigrationAdmissionAdapter

CORE={'QUIESCE_PRODUCERS','FENCED_BACKUP','RELEASE_OLD_ENDPOINT','CREATE_REPLACEMENT','STAGE_PAUSED_REPLACEMENT','ADMIT_MIGRATION','START_REPLACEMENT'}
OWNER=set(PHASES)-CORE

def configure_core(engine,transition,request,store,admin,intents,owner_adapters,backup_checkpoint,gated_stage=None,gated_release=None):
    require(type(intents) is dict and set(intents)==set(PHASES) and type(owner_adapters) is dict
            and set(owner_adapters)==OWNER,'COMPLETE_SOURCE_SEALED_OWNER_PHASES_REQUIRED')
    require(all(callable(getattr(a,'apply',None)) and callable(getattr(a,'observe',None)) for a in owner_adapters.values())
            and callable(backup_checkpoint),'COMPLETE_OWNER_EFFECT_AND_RECONCILIATION_INTERFACES_REQUIRED')
    require(intents['CREATE_REPLACEMENT']==request and transition.read()['creationRequestHash']==digest(request),'EXACT_SHARED_CREATION_REQUEST_REQUIRED')
    backup=intents['FENCED_BACKUP'];admission=intents['ADMIT_MIGRATION'];endpoint=intents['RELEASE_OLD_ENDPOINT'];quiesce=intents['QUIESCE_PRODUCERS']
    require(all(backup.get(k)==admission.get(k) for k in ('containerId','database','databaseOid','user')),'BACKUP_AND_MIGRATION_DATABASE_SCOPE_MISMATCH')
    from gated_creation_plan import ENTRY
    from gated_stage_adapter import GatedStageAdapter
    from gated_release_adapter import GatedReleaseAdapter
    gated=request.get('Entrypoint')==ENTRY
    if gated:
        require(type(gated_stage) is GatedStageAdapter and type(gated_release) is GatedReleaseAdapter
                and gated_stage.transition is transition and gated_release.transition is transition
                and digest(gated_stage.request)==digest(request) and gated_release.request_hash==digest(request)
                and gated_stage.store is store and gated_release.store is store,'EXPLICIT_GATED_STAGE_AND_RELEASE_ADAPTERS_REQUIRED')
        release_reference=gated_release.intent
    else:
        require(gated_stage is None and gated_release is None,'GATED_ADAPTER_WITHOUT_EXPLICIT_GATE_REQUEST_DENIED')
        release_reference={'creationRequestHash':digest(request),'priorEvidencePhase':'STAGE_PAUSED_REPLACEMENT'}
    require(intents['STAGE_PAUSED_REPLACEMENT']=={'creationRequestHash':digest(request),'priorEvidencePhase':'CREATE_REPLACEMENT'}
            and intents['START_REPLACEMENT']==release_reference,'CREATION_STAGE_RELEASE_REFERENCES_MISMATCH')
    pins=[p for p in quiesce['producerBindings'] if p['containerId']==endpoint['containerId']]
    require(len(pins)==1,'ENDPOINT_OWNER_NOT_IN_QUIESCED_PRODUCER_SCOPE')
    original=quiesce['initialNetworkSettings'][endpoint['containerId']]
    require(digest(original)==pins[0]['networkSettingsHash'],'QUIESCENCE_ORIGINAL_NETWORK_SCOPE_MISMATCH')
    attachment=original['Networks'].get(endpoint['networkName'])
    require(type(attachment) is dict and attachment.get('NetworkID')==endpoint['networkId']
            and attachment.get('EndpointID')==endpoint['originalEndpointId'] and attachment.get('IPAddress')==endpoint['staticIpv4']
            and attachment.get('MacAddress')==endpoint['macAddress'],'ORIGINAL_AND_RELEASED_ENDPOINT_SCOPE_MISMATCH')
    networks=request.get('NetworkingConfig',{}).get('EndpointsConfig',{})
    require(set(networks)=={endpoint['networkName']} and request.get('HostConfig',{}).get('NetworkMode')==endpoint['networkName'],'REPLACEMENT_BRIDGE_SCOPE_MISMATCH')
    replacement=networks[endpoint['networkName']]
    require(replacement.get('IPAMConfig',{}).get('IPv4Address')==endpoint['staticIpv4'] and replacement.get('MacAddress')==endpoint['macAddress'], 'REPLACEMENT_RETAINED_IP_MAC_SCOPE_MISMATCH')
    require(request['HostConfig'].get('RestartPolicy')=={'Name':'no','MaximumRetryCount':0},'REPLACEMENT_RESTART_MUST_REMAIN_EXPLICIT')
    adapters=dict(owner_adapters)
    adapters.update({'QUIESCE_PRODUCERS':ProducerAdapter(engine,transition,quiesce,store),
                     'FENCED_BACKUP':FencedBackupAdapter(admin,backup,backup_checkpoint,transition.context,store),
                     'RELEASE_OLD_ENDPOINT':EndpointAdapter(engine,transition,endpoint,store),
                     'CREATE_REPLACEMENT':CreationAdapter(engine,transition,request,store),
                     'STAGE_PAUSED_REPLACEMENT':gated_stage if gated else PausedStageAdapter(engine,transition,request,store),
                     'ADMIT_MIGRATION':MigrationAdmissionAdapter(admin,engine,transition,admission,store),
                     'START_REPLACEMENT':gated_release if gated else ReleasePausedAdapter(engine,transition,request,store)})
    return adapters

def configure_owned_core(engine,transition,request,store,admin,intents,remaining_owner_adapters,
                         backup_checkpoint,retirement_channel,retirement_before_store,gated_stage=None,gated_release=None):
    """Eight concrete phases; remaining five owner phases must be sealed separately.

    Constructing this mapping performs no phase effect and grants no authority.
    Missing owner phase or mismatched retained history blocks before any claim.
    """
    from r12_retirement_adapter import R12RetirementAdapter,R12RetirementChannel
    require(type(remaining_owner_adapters) is dict and set(remaining_owner_adapters)==OWNER-{'STOP_REVOKE_OLD_LEASE'},
            'FIVE_COMPLETE_SOURCE_SEALED_OWNER_PHASES_REQUIRED')
    require(type(retirement_channel) is R12RetirementChannel,'TYPED_RETAINED_RETIREMENT_CHANNEL_REQUIRED')
    row=transition.read()
    require(row.get('predecessorHistoryHash')==retirement_channel.capture_history_hash
            and row.get('predecessorIncidentRef')==retirement_channel.capture['r12-authorization.json']['incidentRef'],
            'CORE_RETIREMENT_PREDECESSOR_HISTORY_OR_INCIDENT_DRIFT')
    retirement=R12RetirementAdapter(retirement_channel,transition,intents['STOP_REVOKE_OLD_LEASE'],retirement_before_store,store)
    return configure_core(engine,transition,request,store,admin,intents,
                          {**remaining_owner_adapters,'STOP_REVOKE_OLD_LEASE':retirement},backup_checkpoint,gated_stage,gated_release)
