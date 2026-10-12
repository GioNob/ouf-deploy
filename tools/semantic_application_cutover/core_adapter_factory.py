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

def configure_core(engine,transition,request,store,admin,intents,owner_adapters,backup_checkpoint):
    require(type(intents) is dict and set(intents)==set(PHASES) and type(owner_adapters) is dict
            and set(owner_adapters)==OWNER,'COMPLETE_SOURCE_SEALED_OWNER_PHASES_REQUIRED')
    require(all(callable(getattr(a,'apply',None)) and callable(getattr(a,'observe',None)) for a in owner_adapters.values())
            and callable(backup_checkpoint),'COMPLETE_OWNER_EFFECT_AND_RECONCILIATION_INTERFACES_REQUIRED')
    require(intents['CREATE_REPLACEMENT']==request and transition.read()['creationRequestHash']==digest(request),'EXACT_SHARED_CREATION_REQUEST_REQUIRED')
    backup=intents['FENCED_BACKUP'];admission=intents['ADMIT_MIGRATION'];endpoint=intents['RELEASE_OLD_ENDPOINT'];quiesce=intents['QUIESCE_PRODUCERS']
    require(all(backup.get(k)==admission.get(k) for k in ('containerId','database','databaseOid','user')),'BACKUP_AND_MIGRATION_DATABASE_SCOPE_MISMATCH')
    require(intents['STAGE_PAUSED_REPLACEMENT']=={'creationRequestHash':digest(request),'priorEvidencePhase':'CREATE_REPLACEMENT'}
            and intents['START_REPLACEMENT']=={'creationRequestHash':digest(request),'priorEvidencePhase':'STAGE_PAUSED_REPLACEMENT'},'CREATION_STAGE_RELEASE_REFERENCES_MISMATCH')
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
                     'STAGE_PAUSED_REPLACEMENT':PausedStageAdapter(engine,transition,request,store),
                     'ADMIT_MIGRATION':MigrationAdmissionAdapter(admin,engine,transition,admission,store),
                     'START_REPLACEMENT':ReleasePausedAdapter(engine,transition,request,store)})
    return adapters
