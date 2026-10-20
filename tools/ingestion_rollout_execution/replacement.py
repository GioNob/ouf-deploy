"""Read-only verification of complete, installation-bound Docker replacements.

No discovery, defaults for an Ente, creation, restart, credential read or runtime
authority. A caller must supply the reviewed frame and durable creation/process
identities. This component does not implement the Runner's native effect ports.
"""
import copy
import re
from tools.ingestion_rollout_execution.contract import require
from tools.ingestion_rollout_preparation.frames import environment,NO_RESTART,OWNER_ENV,SECRET_SLOT

ID=re.compile('[0-9a-f]{64}')

def generation(actual):
    state=actual['State']
    require(ID.fullmatch(actual['Id'])and state['Running']is True and state['Status']=='running'
            and state['Paused']is False and state.get('Restarting',False)is False
            and state.get('Dead',False)is False and state.get('OOMKilled',False)is False
            and not state.get('Error')and actual.get('RestartCount')==0
            and type(state['Pid'])is int and state['Pid']>0
            and type(state['StartedAt'])is str and state['StartedAt']
            and not state['StartedAt'].startswith('0001-'),'FIRST_RUNNING_PROCESS_GENERATION_REQUIRED')
    return {'containerId':actual['Id'],'pid':state['Pid'],'startedAt':state['StartedAt']}

def _mounts(frame):
    request=frame['requestTemplate'];expected={}
    for old in frame['oldMounts']:
        destination=old['Destination']
        require(destination not in expected,'DUPLICATE_RETAINED_MOUNT')
        expected[destination]={k:old[k]for k in ('Type','Source','Destination','RW')}
    additions={}
    for bind in request['HostConfig'].get('Binds')or[]:
        require(type(bind)is str and len(bind.split(':'))in(2,3),'EXPLICIT_LOCAL_BIND_SYNTAX_REQUIRED')
        parts=bind.split(':');source,destination=parts[:2];options=parts[2].split(',')if len(parts)==3 else[]
        require(source.startswith('/')and destination.startswith('/')and destination not in additions,
                'DISTINCT_ABSOLUTE_LOCAL_BINDS_REQUIRED')
        additions[destination]={'Type':'bind','Source':source,'Destination':destination,'RW':'ro'not in options}
    for mount in request['HostConfig'].get('Mounts')or[]:
        destination=mount['Target']
        require(destination not in additions and mount['Type']=='bind','DISTINCT_EXPLICIT_LOCAL_MOUNTS_REQUIRED')
        additions[destination]={'Type':'bind','Source':mount['Source'],'Destination':destination,'RW':not mount.get('ReadOnly',False)}
    expected.update(additions)
    return expected

def validate(frame,actual,image_config,old_id,*,created_id,process=None,phase='RUNNING',
             restart_restored=False,resolved_owner_key=None):
    """Compare private values internally; emit only non-secret resource identity.

    Docker injects the new CID alias and a default hostname. Those are the only
    generation substitutions. Empty native OomKillDisable remains None. CREATED
    permits only Docker's still-unallocated endpoint fields, never another IP.
    The resolved Gateway key is supplied in memory by a separately governed port.
    """
    require(frame.get('schema')=='ouf.ingestion-local-docker-frame-template.v1'
            and frame.get('module')in('ingestion','gateway')and phase in('CREATED','RUNNING')
            and frame.get('preserveObservedAddressesAndMacs')is True
            and frame.get('targetApplyAuthorized')is False and frame.get('runtimeAuthorityIssued')is False,
            'EXACT_UNAUTHORIZED_REVIEWED_FRAME_REQUIRED')
    require(type(created_id)is str and ID.fullmatch(created_id)and ID.fullmatch(old_id)
            and actual['Id']==created_id!=old_id and actual['Name']=='/'+frame['name'],
            'DURABLY_CREATED_REPLACEMENT_IDENTITY_REQUIRED')
    request=copy.deepcopy(frame['requestTemplate'])
    expected_env=environment(request.get('Env')or[])
    if frame['module']=='gateway':
        require(expected_env.get(OWNER_ENV)==SECRET_SLOT and type(resolved_owner_key)is str
                and re.fullmatch('[0-9a-f]{64}',resolved_owner_key),'EXACT_PRIVATE_NATIVE_KEY_REQUIRED')
        expected_env[OWNER_ENV]=resolved_owner_key
    else:require(resolved_owner_key is None,'NO_UNRELATED_SECRET_RESOLUTION_ALLOWED')
    config=actual['Config']
    require(actual['Image']==request['Image'],'REPLACEMENT_IMAGE_CHANGED')
    for key,value in request.items():
        if key in('HostConfig','NetworkingConfig'):continue
        if key=='Env':
            require(environment(config.get('Env')or[])=={**environment(image_config.get('Env')or[]),**expected_env},
                    'REPLACEMENT_ENVIRONMENT_CHANGED')
        elif key=='Labels':
            require(config.get(key)=={**(image_config.get(key)or{}),**(value or{})},'REPLACEMENT_LABELS_CHANGED')
        elif key=='Hostname'and value=='':require(config.get(key)==created_id[:12],'NEW_GENERATION_HOSTNAME_REQUIRED')
        else:require(config.get(key)==value,'REPLACEMENT_PROCESS_CONFIG_CHANGED')
    require(config.get('MacAddress')in(None,''),'LEGACY_CONTAINER_MAC_REINTRODUCED')
    # Unknown fields require a reviewed profile change, not silent acceptance.
    require(set(config)<=set(image_config)|set(request)|{'MacAddress'},'UNREVIEWED_CONTAINER_CONFIG_FIELD')
    for key,value in image_config.items():
        if key not in request:require(config.get(key)==value,'UNREVIEWED_IMAGE_CONFIG_INHERITANCE')
    host=copy.deepcopy(request['HostConfig'])
    require(host['RestartPolicy']==NO_RESTART,'RESTART_DISABLED_CREATE_FRAME_REQUIRED')
    if restart_restored:host['RestartPolicy']=frame['restoreRestartPolicy']
    for key,value in host.items():require(actual['HostConfig'].get(key)==value,'REPLACEMENT_HOST_CONFIG_CHANGED')
    expected_mounts=_mounts(frame);observed={}
    for mount in actual['Mounts']:
        destination=mount['Destination'];require(destination not in observed,'DUPLICATE_ACTUAL_MOUNT')
        observed[destination]={k:mount[k]for k in ('Type','Source','Destination','RW')}
    require(observed==expected_mounts,'REPLACEMENT_MOUNTS_CHANGED')
    endpoints=request['NetworkingConfig']['EndpointsConfig'];networks=actual['NetworkSettings']['Networks']
    require(1<=len(endpoints)<=8 and set(networks)==set(endpoints),'REPLACEMENT_NETWORK_SET_CHANGED')
    for name,expected in endpoints.items():
        endpoint=networks[name]
        require(endpoint['NetworkID']==expected['NetworkID'],'REPLACEMENT_NETWORK_ID_CHANGED')
        require(not endpoint.get('Links'),'UNREVIEWED_ENDPOINT_LINKS')
        require(endpoint.get('IPAMConfig')==expected.get('IPAMConfig'),'REPLACEMENT_IPAM_CHANGED')
        for key in ('DriverOpts','GwPriority'):
            if key in expected:require(endpoint.get(key)==expected[key],'REPLACEMENT_ENDPOINT_OPTIONS_CHANGED')
        aliases=endpoint.get('Aliases')or[]
        require(len(aliases)==len(set(aliases))and sorted(v for v in aliases if v not in(created_id,created_id[:12]))
                ==sorted(expected.get('Aliases')or[]),'REPLACEMENT_NETWORK_ALIASES_CHANGED')
        for observed_key,selected_key in (('IPAddress','IPv4Address'),('GlobalIPv6Address','IPv6Address')):
            selected=(expected.get('IPAMConfig')or{}).get(selected_key,'');value=endpoint.get(observed_key,'')
            require(value==selected or phase=='CREATED'and value=='','REPLACEMENT_ENDPOINT_ADDRESS_CHANGED')
        mac=endpoint.get('MacAddress')or''
        require(mac.lower()==expected['MacAddress'].lower()or phase=='CREATED'and mac=='',
                'REPLACEMENT_ENDPOINT_MAC_CHANGED')
    if phase=='CREATED':
        state=actual['State']
        require(process is None and state['Status']=='created'and state['Pid']==0
                and state['Running']is False and state['Paused']is False and actual.get('RestartCount')==0,
                'NEVER_STARTED_REPLACEMENT_REQUIRED')
        return {'containerId':created_id,'neverStarted':True}
    current=generation(actual)
    require(process is None or current==process,'REPLACEMENT_PROCESS_GENERATION_CHANGED')
    return current

class EngineReader:
    """Existing custodied Engine, exact IDs only; GET only, no transport fallback."""
    def __init__(self,engine):
        from engine_creation import Engine
        require(type(engine)is Engine,'CUSTODIED_NATIVE_ENGINE_REQUIRED')
        self.engine=engine
    def container(self,container_id):
        require(type(container_id)is str and ID.fullmatch(container_id),'EXACT_FULL_CONTAINER_ID_REQUIRED')
        self.engine.check_socket()
        status,value=self.engine.request('GET','/v1.44/containers/'+container_id+'/json')
        self.engine.check_socket()
        require(status==200 and type(value)is dict and value.get('Id')==container_id,'EXACT_CONTAINER_READ_REQUIRED')
        return value
