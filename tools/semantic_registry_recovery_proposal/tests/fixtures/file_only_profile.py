"""Exact native-file deployment profile; no effects, authority or arbitrary skips.

The reviewed image/source closure must retain IAM, consultation and THS. This
compiler only binds a launch that disables external discovery; it never proves
application compatibility or adopts the observed OCI as an expected policy.
"""
import copy
import hashlib
import json
import re

PROFILE = 'ouf.semantic-file-only-native-proposal.v1'
PHASES = ('STOP_REVOKE_OLD_LEASE', 'QUIESCE_PRODUCERS', 'FENCED_BACKUP',
          'RELEASE_OLD_ENDPOINT', 'CREATE_REPLACEMENT', 'STAGE_PAUSED_REPLACEMENT',
          'ATTEST_NEW_OCI_PEER', 'ADMIT_MIGRATION', 'START_REPLACEMENT',
          'VERIFY_APPLICATION', 'RELEASE_PRODUCERS')
FLAGS = {'OUF_SCHEMA_GOV_ENABLED': 'false', 'OUF_DISCOVERY_WORKER_ENABLED': 'false'}

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',', ':'),allow_nan=False).encode()).hexdigest()

def require(ok, reason):
    if not ok: raise ValueError(reason)

def compile_profile(request, configtree):
    from gated_creation_plan import ENTRY
    require(type(request) is dict and len(json.dumps(request)) <= 131072,
            'FILE_ONLY_EXACT_BOUNDED_CREATION_REQUEST_REQUIRED')
    require(type(request.get('Image')) is str and re.fullmatch('sha256:[0-9a-f]{64}', request['Image'])
            and request.get('User') == '10001:10001', 'FILE_ONLY_PINNED_IMAGE_AND_USER_REQUIRED')
    java=['java','-XX:MaxRAMPercentage=75','-jar','/app/application.jar']
    require((request.get('Entrypoint') == java and request.get('Cmd') in (None, []))
            or (request.get('Entrypoint') == ENTRY and request.get('Cmd') == java),
            'FILE_ONLY_EXACT_APPLICATION_ENTRY_REQUIRED')
    rows=request.get('Env'); require(type(rows) is list and len(rows)<=256, 'FILE_ONLY_ENV_REQUIRED')
    env={}
    for row in rows:
        require(type(row) is str and '=' in row and len(row)<=16384 and '\x00' not in row,
                'FILE_ONLY_ENV_REQUIRED')
        name,value=row.split('=',1)
        require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]*',name) and name not in env, 'FILE_ONLY_ENV_DUPLICATE_OR_INVALID')
        env[name]=value
    require(all(env.get(k)==v for k,v in FLAGS.items()), 'FILE_ONLY_DISCOVERY_MUST_BE_EXPLICITLY_DISABLED')
    # Reject higher-priority Spring/JVM channels that could override the two
    # reviewed flags. The sole external config input is the DB-only configtree.
    require(not set(env)&{'JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS'},
            'FILE_ONLY_JVM_PROPERTY_OVERRIDE_DENIED')
    require(not any(k.startswith('SPRING_') and k!='SPRING_CONFIG_IMPORT' for k in env),
            'FILE_ONLY_SPRING_OVERRIDE_DENIED')
    aliases={'oufsemanticprovidersschemagovenabled','oufsemanticdiscoveryworkerenabled'}
    require(not any(k.lower().replace('_','') in aliases for k in env), 'FILE_ONLY_FEATURE_ALIAS_OVERRIDE_DENIED')
    fields={'source','target','readOnly','uid','gid','directoryMode','fileName','fileMode','maxBytes','sha256'}
    require(type(configtree) is dict and set(configtree)==fields
            and configtree['fileName']=='OUF_SEM_DB_PASSWORD' and configtree['readOnly'] is True
            and configtree['uid']==configtree['gid']==10001 and configtree['directoryMode']==0o500
            and configtree['fileMode']==0o400 and type(configtree['maxBytes']) is int and 1<=configtree['maxBytes']<=1048576
            and type(configtree['sha256']) is str and re.fullmatch('[0-9a-f]{64}',configtree['sha256']),
            'FILE_ONLY_DB_ONLY_CONFIGTREE_REQUIRED')
    for k in ('source','target'):
        value=configtree[k]
        require(type(value) is str and value.startswith('/') and value!='/' and not set(value.split('/')[1:])&{'','.', '..'}
                and not any(c in value for c in ('\x00','\n',':',',')) and not value.endswith('/'),
                'FILE_ONLY_CONFIGTREE_PATH_REQUIRED')
    require(env.get('SPRING_CONFIG_IMPORT')=='configtree:'+configtree['target']+'/',
            'FILE_ONLY_EXACT_DB_CONFIGTREE_IMPORT_REQUIRED')
    host=request.get('HostConfig')
    require(type(host) is dict and host.get('RestartPolicy')=={'Name':'no','MaximumRetryCount':0}
            and host.get('Privileged',False) is False and not host.get('CapAdd')
            and host.get('NetworkMode')!='host', 'FILE_ONLY_EXPLICIT_BOUNDED_HOST_REQUIRED')
    # Bind the import to its exact readonly mount; full mount/OCI/custody checks
    # remain mandatory at the native acceptance checkpoint.
    selected=[]
    for mount in host.get('Mounts') or []:
        require(type(mount) is dict,'FILE_ONLY_MOUNT_INVALID')
        if mount.get('Target')==configtree['target']:
            selected.append(mount.get('Type')=='bind' and mount.get('Source')==configtree['source'] and mount.get('ReadOnly') is True)
    for bind in host.get('Binds') or []:
        require(type(bind) is str,'FILE_ONLY_MOUNT_INVALID')
        parts=bind.split(':')
        if len(parts)>=2 and parts[1]==configtree['target']:
            selected.append(len(parts)==3 and parts[0]==configtree['source'] and parts[2]=='ro')
    require(selected==[True], 'FILE_ONLY_EXACT_READONLY_CONFIGTREE_MOUNT_REQUIRED')
    return {'schema':'ouf.semantic-file-only-execution-profile.v1','deploymentProfile':PROFILE,
            'creationRequestHash':digest(request),'databaseConfigtreeHash':digest(configtree),
            'disabledFeatures':dict(FLAGS),'phaseOrder':list(PHASES),
            'externalProviderCallsAllowed':False,'newDistinctLeaseWorkerRequired':False}

class FileOnlyProfile:
    """Typed immutable-by-validation scope, not a caller boolean or approval."""
    def __init__(self, request, configtree):
        self.request=copy.deepcopy(request); self.configtree=copy.deepcopy(configtree)
        self.compiled=compile_profile(self.request,self.configtree)
        self.sha256=digest(self.compiled)
    def verify(self, request):
        require(type(request) is dict and digest(request)==self.compiled['creationRequestHash']
                and compile_profile(request,self.configtree)==self.compiled and digest(self.compiled)==self.sha256,
                'FILE_ONLY_REVIEWED_PROFILE_OR_REQUEST_DRIFT')
        return self.sha256
