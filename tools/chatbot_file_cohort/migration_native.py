"""Exact MCP create request and image-default reconciliation; grants no authority."""
import copy,re
from tools.chatbot_file_cohort.plan import digest,require


def request_for(installation_plan):
    row=next(r for r in installation_plan['replacements'] if r['module']=='mcp')
    suffix=row['retiredName'].removeprefix('ouf-mcp-before-')
    require(suffix and re.fullmatch('[a-z0-9-]{1,60}',suffix),'EXACT_MCP_MIGRATION_COHORT_REQUIRED')
    c=row['creationRequest'];values=[v for v in c['Env'] if v.startswith('MCP_DATABASE_URL=')]
    require(len(values)==1 and c['User']=='10005:10005' and c['Entrypoint']==['/usr/local/bin/ouf-mcp']
        and re.fullmatch('sha256:[0-9a-f]{64}',c['Image']),'EXACT_PACKAGED_MCP_MIGRATION_ROLE_REQUIRED')
    endpoint=c['NetworkingConfig']['EndpointsConfig']['ouf-backend']
    return 'ouf-mcp-migrate-'+suffix,{'Image':c['Image'],'User':'10005:10005',
        'Entrypoint':['/usr/local/bin/ouf-mcp'],'Cmd':['migrate'],'WorkingDir':'/app','Env':values,
        'Labels':{'it.ouf.file-cohort':suffix,'it.ouf.role':'mcp-migration'},
        'HostConfig':{'NetworkMode':'ouf-backend','RestartPolicy':{'Name':'no','MaximumRetryCount':0},
            'AutoRemove':False,'ReadonlyRootfs':True},
        'NetworkingConfig':{'EndpointsConfig':{'ouf-backend':{'NetworkID':endpoint['NetworkID']}}}}


def env(values):
    require(type(values)is list and len(values)<=512,'MIGRATION_ENVIRONMENT_SHAPE')
    result={}
    for value in values:
        require(type(value)is str and '=' in value,'MIGRATION_ENVIRONMENT_ENTRY')
        key,item=value.split('=',1)
        require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]*',key) and key not in result,'MIGRATION_DUPLICATE_OR_INVALID_ENVIRONMENT')
        result[key]=item
    return result


def native_matches(name,request,image_config,actual):
    require(type(actual)is dict,'MIGRATION_NATIVE_ABSENT')
    c=actual['Config'];h=actual['HostConfig'];net=actual['NetworkSettings']['Networks']
    require(actual['Name']=='/'+name and actual['Image']==request['Image']
        and all(c.get(k)==request[k] for k in ('User','Entrypoint','Cmd','WorkingDir'))
        and env(c.get('Env'))=={**env(image_config.get('Env') or []),**env(request['Env'])}
        and c.get('Labels')=={**(image_config.get('Labels') or {}),**request['Labels']}
        and all(h.get(k)==v for k,v in request['HostConfig'].items())
        and h.get('Privileged') is False and actual.get('Mounts')==[]
        and set(net)=={'ouf-backend'} and net['ouf-backend']['NetworkID']==request['NetworkingConfig']['EndpointsConfig']['ouf-backend']['NetworkID']
        and actual['RestartCount']==0,'MCP_MIGRATION_IMAGE_AND_REQUEST_NATIVE_IDENTITY_DRIFT')
    return actual


def immutable_native(actual):
    # Same narrow OOM default equivalence already qualified by engine_creation.
    host=copy.deepcopy(actual['HostConfig'])
    require('OomKillDisable' in host and (host['OomKillDisable'] is None or type(host['OomKillDisable'])is bool),
        'MIGRATION_OOM_DEFAULT_SHAPE')
    if host['OomKillDisable'] is None:host['OomKillDisable']=False
    return {'containerId':actual['Id'],'imageId':actual['Image'],'configHash':digest(actual['Config']),
        'hostConfigHash':digest(host),'mountsHash':digest(actual['Mounts'])}


def created(actual):
    s=actual['State']
    require(s['Status']=='created' and s['Pid']==0 and s['Running'] is False and s['Paused'] is False
        and s['Restarting'] is False and s['Dead'] is False and actual['RestartCount']==0
        and s['StartedAt']=='0001-01-01T00:00:00Z','MCP_MIGRATION_MUST_BE_NEVER_STARTED')
    return actual
