"""Complete local Docker frame templates; no effects, secrets or runtime authority."""
import copy
import ipaddress
import re

NO_RESTART={'Name':'no','MaximumRetryCount':0}
CONFIG_DESTINATION='/usr/local/apisix/conf/config.yaml'
OWNER_ENV='OUF_INGESTION_READ_OWNER_KEY'
SECRET_SLOT='@ouf-secret-reference:ingestionReadOwnerKey'

def require(ok,code):
    if not ok:raise ValueError(code)

def environment(entries):
    require(type(entries)is list and len(entries)<=256,'BOUNDED_ENVIRONMENT_REQUIRED')
    result={}
    for row in entries:
        require(type(row)is str and '='in row and len(row)<=65536,'BOUNDED_ENVIRONMENT_ENTRY_REQUIRED')
        key,value=row.split('=',1)
        require(re.fullmatch('[A-Za-z_][A-Za-z_0-9]*',key)and key not in result and '\0'not in value,'UNIQUE_ENVIRONMENT_REQUIRED')
        result[key]=value
    return result

def expose_owner_environment(raw):
    require(type(raw)is bytes and 0<len(raw)<=1048576,'BOUNDED_GATEWAY_CONFIG_REQUIRED')
    marker='nginx_config:\n  envs:\n';text=raw.decode('utf-8')
    require(text.count(marker)==1,'EXACT_NGINX_ENV_ALLOWLIST_REQUIRED')
    head,tail=text.split(marker,1);names=[]
    for line in tail.splitlines(keepends=True):
        match=re.fullmatch(r'  - ([A-Z][A-Z0-9_]{0,127})\n',line)
        if not match:break
        names.append(match[1])
    require(names and len(names)==len(set(names)),'CLOSED_NGINX_ENV_ALLOWLIST_REQUIRED')
    # Reject another spelling elsewhere: do not mistake an unrelated YAML key
    # or duplicate list for an already exposed worker environment binding.
    require(text.count(OWNER_ENV)==names.count(OWNER_ENV),'UNAMBIGUOUS_OWNER_ENV_ALLOWLIST_REQUIRED')
    return raw if OWNER_ENV in names else (head+marker+'  - '+OWNER_ENV+'\n'+tail).encode()

def replace_config_bind(host,old_source,new_source):
    changed=0
    for i,value in enumerate(host.get('Binds')or[]):
        if value.startswith(old_source+':'+CONFIG_DESTINATION+':'):
            require(value.split(':',2)[2].split(',')[0]=='ro','READ_ONLY_GATEWAY_CONFIG_REQUIRED')
            host['Binds'][i]=new_source+value[len(old_source):];changed+=1
    for row in host.get('Mounts')or[]:
        if row.get('Target')==CONFIG_DESTINATION:
            require(row.get('Type')=='bind'and row.get('Source')==old_source and row.get('ReadOnly')is True,
                    'EXACT_READ_ONLY_GATEWAY_CONFIG_REQUIRED')
            row['Source']=new_source;changed+=1
    require(changed==1,'EXACT_ONE_CONFIG_BIND_REPLACEMENT_REQUIRED')

def endpoints(actual):
    observed=actual['NetworkSettings']['Networks']
    require(type(observed)is dict and 1<=len(observed)<=8,'EXPLICIT_RETAINED_NETWORKS_REQUIRED')
    result={}
    for name,row in observed.items():
        require(re.fullmatch('[A-Za-z0-9_.-]{1,128}',name)and re.fullmatch('[0-9a-f]{64}',row['NetworkID']),
                'EXACT_NETWORK_IDENTITY_REQUIRED')
        require(not row.get('Links'),'LINKED_NETWORK_REQUIRES_DISTINCT_REVIEW')
        aliases=row.get('Aliases')or[]
        require(type(aliases)is list and len(aliases)<=32 and all(type(v)is str and re.fullmatch('[A-Za-z0-9_.-]{1,253}',v)for v in aliases),
                'EXPLICIT_NETWORK_ALIASES_REQUIRED')
        ipam=copy.deepcopy(row.get('IPAMConfig')or{})
        for field,source,version in [('IPv4Address','IPAddress',4),('IPv6Address','GlobalIPv6Address',6)]:
            value=row.get(source)
            if value:
                require(ipaddress.ip_address(value).version==version,'EXACT_OBSERVED_ENDPOINT_ADDRESS_REQUIRED')
                require(not ipam.get(field)or ipam[field]==value,'OBSERVED_AND_REQUESTED_IPAM_DRIFT')
                ipam[field]=value
        mac=row.get('MacAddress')or''
        require(re.fullmatch('[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}',mac),'EXACT_OBSERVED_ENDPOINT_MAC_REQUIRED')
        result[name]={'NetworkID':row['NetworkID'],'Aliases':[v for v in aliases if v not in(actual['Id'],actual['Id'][:12])],
                      'IPAMConfig':ipam,'MacAddress':mac}
        if row.get('DriverOpts')is not None:result[name]['DriverOpts']=copy.deepcopy(row['DriverOpts'])
        if 'GwPriority'in row:result[name]['GwPriority']=row['GwPriority']
    return result

def frame(module,actual,image_id,candidate_config,draft,new_gateway_config_path=None):
    # The caller binds actual to its approved installation/runtime profile.
    # Network IDs, names, addresses and MACs below are parameters, never defaults.
    require(module in('ingestion','gateway')and re.fullmatch('sha256:[0-9a-f]{64}',image_id),'EXACT_TWO_MODULE_FRAME_REQUIRED')
    config=copy.deepcopy(actual['Config']);host=copy.deepcopy(actual['HostConfig'])
    require(host.get('AutoRemove')is not True and host.get('Privileged')is not True
            and not host.get('Links')and not host.get('VolumesFrom')and not host.get('ContainerIDFile')
            and not str(host.get('PidMode','')).startswith('container:')and not str(host.get('IpcMode','')).startswith('container:'),
            'INDEPENDENT_RETAINABLE_CONTAINER_REQUIRED')
    restart=copy.deepcopy(host['RestartPolicy'])
    require(restart in(NO_RESTART,{'Name':'unless-stopped','MaximumRetryCount':0}),'REVIEWED_RESTART_POLICY_REQUIRED')
    if 'OomKillDisable'in host:
        require(host['OomKillDisable']is None or type(host['OomKillDisable'])is bool,'EXACT_OOM_POLICY_REQUIRED')
    host['RestartPolicy']=copy.deepcopy(NO_RESTART)
    values=environment(config.get('Env')or[])
    retained_endpoints=endpoints(actual)
    legacy_mac=config.pop('MacAddress',None)
    require(legacy_mac in(None,'') or type(legacy_mac)is str and re.fullmatch('[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}',legacy_mac)
            and legacy_mac.lower()in{row['MacAddress'].lower()for row in retained_endpoints.values()},
            'LEGACY_CONTAINER_MAC_MUST_MATCH_OBSERVED_ENDPOINT')
    if module=='ingestion':
        require(config.get('User')==candidate_config.get('User')=='10002:10002'
                and config.get('Entrypoint')==candidate_config.get('Entrypoint')==['java','-jar','/app/app.jar']
                and config.get('WorkingDir')==candidate_config.get('WorkingDir'), 'EXACT_RETAINED_JAVA_PROCESS_CONTRACT_REQUIRED')
        proposed=draft['ingestion']
        for key,value in {**proposed['ownerReadEnvironmentAdditions'],**proposed['startupEnvironmentAddition']}.items():
            require(key not in values or values[key]==value,'OWNER_STARTUP_ENVIRONMENT_COLLISION')
            values[key]=value
        require(proposed['bootstrapCmd'][-2:]==['--spring.flyway.enabled=false','--ouf.ingestion.startup.schema-mode=VALIDATE_ONLY'],
                'QUALIFIED_VALIDATE_ONLY_BOOTSTRAP_REQUIRED')
        config['Cmd']=copy.deepcopy(proposed['bootstrapCmd'])
        config['Labels']={**(config.get('Labels')or{}),'org.opencontainers.image.revision':draft['candidate']['sourceCommit']}
        new=proposed['readOnlyBindAddition']
        require(new['Type']=='bind'and new['RW']is False and all(m['Destination']!=new['Destination']for m in actual['Mounts']),
                'ONE_NEW_READ_ONLY_OWNER_BIND_REQUIRED')
        host.setdefault('Binds',[])
        if host['Binds']is None:host['Binds']=[]
        host['Binds'].append(new['Source']+':'+new['Destination']+':ro')
        inherited=environment(candidate_config.get('Env')or[])
        home=inherited.get('JAVA_HOME')
        require(not home or home.rstrip('/')+'/bin'in values.get('PATH',inherited.get('PATH','')).split(':'),
                'PACKAGED_JAVA_SEARCH_PATH_REQUIRES_REVIEW')
        require(set((candidate_config.get('Volumes')or{}))<={m['Destination']for m in actual['Mounts']},
                'NO_NEW_UNREVIEWED_IMAGE_VOLUME_REQUIRED')
    else:
        require(image_id==actual['Image']and OWNER_ENV not in values,'EXACT_UNCHANGED_GATEWAY_IMAGE_REQUIRED')
        values[OWNER_ENV]=SECRET_SLOT
        if new_gateway_config_path:
            selected=[m for m in actual['Mounts']if m['Destination']==CONFIG_DESTINATION]
            require(len(selected)==1 and selected[0]['Type']=='bind'and selected[0]['RW']is False,'EXACT_CONFIG_BIND_REQUIRED')
            replace_config_bind(host,selected[0]['Source'],new_gateway_config_path)
    config['Env']=[key+'='+value for key,value in sorted(values.items())]
    config['Image']=image_id
    if config.get('Hostname')==actual['Id'][:12]:config['Hostname']=''
    require(not config.get('Healthcheck')or module=='gateway'or config['Healthcheck']==candidate_config.get('Healthcheck'),
            'REVIEWED_EXISTING_HEALTHCHECK_REQUIRED')
    return {'schema':'ouf.ingestion-local-docker-frame-template.v1','module':module,'name':actual['Name'].lstrip('/'),
        'requestTemplate':{**config,'HostConfig':host,'NetworkingConfig':{'EndpointsConfig':retained_endpoints}},
        'restoreRestartPolicy':restart,'oldMounts':copy.deepcopy(actual['Mounts']),
        'preserveObservedAddressesAndMacs':True,'resolveGatewaySecretAfterNativeAuthorityRequired':module=='gateway',
        'legacyContainerMacMovedToExplicitEndpoints':bool(legacy_mac),
        'nativeCreationRoundTripQualified':False,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False}
