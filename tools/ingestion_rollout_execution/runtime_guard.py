"""Stage-aware predecessor and unchanged-generation checks, without I/O.

Only owned attempted/APPLIED stages permit their exact old-runtime deltas.
Stopped endpoints may lose allocation fields under the Docker1.44 adapter;
network identity, static options, aliases and every unrelated field remain
bound. No MAC/IP is invented or copied to a different installation.
"""
import copy
from engine_creation import Engine
from tools.ingestion_rollout_execution.contract import require,digest
from tools.ingestion_rollout_execution.database_read import runtime_binding
from tools.ingestion_rollout_execution import runtime_bindings

NO_RESTART={'Name':'no','MaximumRetryCount':0}
RELEASED_STRINGS={'EndpointID','Gateway','IPAddress','IPv6Gateway','GlobalIPv6Address','MacAddress'}
RELEASED_INTS={'IPPrefixLen','GlobalIPv6PrefixLen'}

def validate_profile(profile,packet):
    require(type(profile)is dict and set(profile)=={'schema','beforeContainers','unchangedApplications'},
            'EXACT_NATIVE_RUNTIME_GUARD_PROFILE_REQUIRED')
    require(profile['schema']=='ouf.ingestion-rollout-runtime-guard.v1'
            and type(profile['beforeContainers'])is dict and set(profile['beforeContainers'])=={'ingestion','gateway'}
            and type(profile['unchangedApplications'])is dict and set(profile['unchangedApplications'])=={'onboarding','mcp','udp'},
            'EXACT_TWO_REPLACED_AND_THREE_UNCHANGED_APPLICATIONS_REQUIRED')
    for module,before in profile['beforeContainers'].items():
        runtime_binding(packet['expectedRuntimeBindings'][module])
        require(runtime_bindings.observed(before,runtime_bindings.SORTED)==packet['expectedRuntimeBindings'][module]
                and before['Name']=='/'+packet['frames'][module]['name']
                and before['State']['Running']is True and before['State']['Paused']is False
                and before['State']['Restarting']is False and type(before['RestartCount'])is int and before['RestartCount']>=0,
                'FULL_APPROVED_RUNNING_PREDECESSOR_REQUIRED')
    ids={p['containerId']for p in packet['expectedRuntimeBindings'].values()}
    for pin in profile['unchangedApplications'].values():
        require(type(pin)is dict and set(pin)=={'binding','restartCount','bindingProfile'}and type(pin['restartCount'])is int
                and pin['restartCount']>=0,'EXACT_UNCHANGED_APPLICATION_GENERATION_REQUIRED')
        require(pin['bindingProfile']in runtime_bindings.PROFILES,'EXPLICIT_UNCHANGED_BINDING_PROFILE_REQUIRED')
        runtime_binding(pin['binding']);ids.add(pin['binding']['containerId'])
    require(len(ids)==5,'EXACT_FIVE_DISTINCT_RUNTIME_APPLICATIONS_REQUIRED')
    return profile

def unchanged(actual,pin):
    require(runtime_bindings.observed(actual,pin['bindingProfile'])==pin['binding']and actual['RestartCount']==pin['restartCount']
            and actual['State']['Running']is True and actual['State']['Paused']is False
            and actual['State']['Restarting']is False,'UNCHANGED_APPLICATION_GENERATION_DRIFT')

def permission(review,row,name):
    indices={s['name']:i for i,s in enumerate(review['stages'])};i=indices[name]
    if i>=len(row['effects']):return False,False
    effect=row['effects'][i]
    require(effect['stage']==name and effect['intentHash']==review['stages'][i]['intentHash'],
            'EXACT_RETAINED_STAGE_HISTORY_REQUIRED')
    return effect['state']=='APPLIED',effect['state']=='CLAIMED'and effect.get('nativeRequestAttempted')is True

def predecessor(module,actual,profile,packet,review,row):
    before=profile['beforeContainers'][module];frame=packet['frames'][module]
    require(actual['Id']==before['Id']and actual['Image']==before['Image']
            and actual['Mounts']==before['Mounts']and actual['RestartCount']==before['RestartCount'],
            'RETAINED_PREDECESSOR_ID_IMAGE_MOUNTS_OR_RESTART_CHANGED')
    host=copy.deepcopy(before['HostConfig']);disabled=copy.deepcopy(host);disabled['RestartPolicy']=NO_RESTART
    done,pending=permission(review,row,module+'.DISABLE_OLD_RESTART')
    require(actual['HostConfig']in([disabled]if done else[host,disabled]if pending else[host]),
            'PREDECESSOR_HOST_CONFIG_OR_RESTART_POLICY_DRIFT')
    done,pending=permission(review,row,module+'.STOP_OLD');state=actual['State']
    require(state['Paused']is False and state['Restarting']is False
            and state['StartedAt']==before['State']['StartedAt'],'PREDECESSOR_PROCESS_HISTORY_CHANGED')
    stopped=state['Running']is False and state['Pid']==0
    running=state['Running']is True and state['Pid']==before['State']['Pid']
    require(stopped if done else(stopped or running)if pending else running,'PREDECESSOR_UNOWNED_STOP_OR_NEW_PROCESS')
    expected_config=copy.deepcopy(before['Config']);actual_config=copy.deepcopy(actual['Config'])
    if stopped:
        # API1.44 can cease echoing a released primary endpoint MAC in Config.
        # The sole accepted alternatives are its original observed value or
        # empty/absent metadata; this never changes the reviewed create frame.
        original=expected_config.pop('MacAddress',None);current=actual_config.pop('MacAddress',None)
        require(current in(None,'',original),'PREDECESSOR_LEGACY_MAC_ECHO_DRIFT')
    require(actual_config==expected_config,'PREDECESSOR_IMMUTABLE_CONFIG_CHANGED')
    names=[before['Name']];done,pending=permission(review,row,module+'.RENAME_OLD')
    stage=next(s for s in review['stages']if s['name']==module+'.RENAME_OLD')
    retained='/'+stage['intent']['retainedName']
    require(actual['Name']in([retained]if done else[names[0],retained]if pending else names),
            'PREDECESSOR_NAME_CHANGED_WITHOUT_OWNED_RENAME')
    expected=before['NetworkSettings']['Networks'];observed=actual['NetworkSettings']['Networks']
    require(type(observed)is dict and set(observed)<=set(expected),'UNREVIEWED_PREDECESSOR_NETWORK')
    for name,endpoint in expected.items():
        network=endpoint['NetworkID'];done,pending=permission(review,row,module+'.DETACH_'+network)
        if done:require(name not in observed,'DETACHED_PREDECESSOR_NETWORK_REAPPEARED');continue
        if name not in observed:
            require(pending,'PREDECESSOR_ENDPOINT_REMOVED_WITHOUT_OWNED_DETACH');continue
        value=observed[name]
        if not stopped:require(value==endpoint,'RUNNING_PREDECESSOR_ENDPOINT_DRIFT');continue
        require(type(value)is dict and set(value)==set(endpoint),'CLOSED_STOPPED_ENDPOINT_FIELDS_REQUIRED')
        for key,wanted in endpoint.items():
            got=value[key]
            if key in RELEASED_STRINGS:require(got in(wanted,''),'STOPPED_ENDPOINT_ALLOCATION_CHANGED')
            elif key in RELEASED_INTS:require(type(got)is int and got in(wanted,0),'STOPPED_ENDPOINT_PREFIX_CHANGED')
            else:require(got==wanted,'STOPPED_ENDPOINT_STATIC_OPTIONS_CHANGED')
    # While still running the complete network state stays exact. After the
    # owned stop Docker releases its sandbox/port state; no such state is reused.
    if running:require(actual['NetworkSettings']==before['NetworkSettings'],'RUNNING_PREDECESSOR_NETWORK_STATE_CHANGED')
    else:
        actual_top={k:v for k,v in actual['NetworkSettings'].items()if k!='Networks'}
        before_top={k:v for k,v in before['NetworkSettings'].items()if k!='Networks'}
        require(set(actual_top)==set(before_top),'CLOSED_STOPPED_NETWORK_STATE_FIELDS_REQUIRED')
        for key,wanted in before_top.items():
            got=actual_top[key]
            if key in RELEASED_STRINGS|{'SandboxID','SandboxKey','LinkLocalIPv6Address'}:
                require(got in(wanted,''),'STOPPED_NETWORK_ALLOCATION_CHANGED')
            elif key in RELEASED_INTS|{'LinkLocalIPv6PrefixLen'}:
                require(type(got)is int and got in(wanted,0),'STOPPED_NETWORK_PREFIX_CHANGED')
            elif key=='Ports':require(got in(wanted,{},None),'STOPPED_PUBLISHED_PORT_BINDING_CHANGED')
            elif key in('SecondaryIPAddresses','SecondaryIPv6Addresses'):
                require(got in(wanted,[],None),'STOPPED_SECONDARY_ADDRESS_CHANGED')
            else:require(got==wanted,'STOPPED_NETWORK_STATIC_STATE_CHANGED')
    return {'retainedPredecessorMatched':True,'containerId':actual['Id'],'stopped':stopped,
            'remainingNetworks':len(observed),'observedAddressesAndMacsPreservedOrReleased':True}
