"""Read-only two-peer generation probe for a signed operational lease receipt.

This contract allows the attested Registry gate to become Java in the SAME
generation. It does not relax historical live-peer/admission collectors or issue
admission. The installed guard must authenticate the generation receipt first.
"""
import copy,hashlib,http.client,json,os,re,socket,stat,struct,time
from pathlib import Path
from .custody_capture import decode,digest,require
from tools.semantic_provider_deployment_authentication import ancestors
from tools.semantic_registry_operational_owner.guard import protected_file

DOCKER_FIELDS=('Id','Image','Config','HostConfig','Mounts','NetworkSettings')
ROLES={'registry','provider'}


def ticks(pid):
    require(type(pid) is int and 1<pid<2147483647,'EXACT_RUNTIME_PROBE_PROCESS_REQUIRED')
    with (Path('/proc')/str(pid)/'stat').open('rb') as stream:raw=stream.read(16385)
    require(0<len(raw)<=16384 and raw.startswith(str(pid).encode()+b' (') and b') ' in raw,
        'BOUNDED_RUNTIME_PROBE_PROCESS_REQUIRED')
    value=int(raw.rsplit(b') ',1)[1].split()[19])
    require(value>0,'CURRENT_RUNTIME_PROBE_START_TICKS_REQUIRED');return value


def generation_reference(snapshot):
    return digest({'bootId':snapshot['bootId'],'nativeProfileHash':snapshot['nativeProfileHash'],
        'peers':{role:{k:snapshot['peers'][role][k] for k in
            ('containerId','imageId','pid','startedAt','startTicks','namespace')} for role in sorted(ROLES)}})


class NativeLeaseGenerationProbe:
    def __init__(self,observations_root,*,seconds=5):
        self.root=Path(observations_root);ancestors(self.root/'placeholder');s=self.root.lstat()
        require(self.root.is_absolute() and stat.S_ISDIR(s.st_mode) and s.st_uid==s.st_gid==0
            and stat.S_IMODE(s.st_mode)==0o700 and type(seconds) is int and 1<=seconds<=10,
            'PRIVATE_BOUNDED_NATIVE_LEASE_OBSERVATIONS_REQUIRED')
        self.root_identity=(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode);self.seconds=seconds

    def __call__(self,receipt):
        require(type(receipt) is dict and all(type(receipt.get(k)) is str and re.fullmatch('[0-9a-f]{64}',receipt[k])
            for k in ('nativeObservationHash','nativeProfileHash','generationRef','desiredProfileHash')),
            'AUTHENTICATED_RUNTIME_GENERATION_RECEIPT_REFERENCE_REQUIRED')
        s=self.root.lstat()
        require((s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode)==self.root_identity,'NATIVE_LEASE_OBSERVATION_DIRECTORY_CHANGED')
        path=self.root/(receipt['nativeObservationHash']+'.json')
        raw=protected_file(path,1048576,expected=receipt['nativeObservationHash'],modes=(0o400,0o600))
        snapshot=decode(raw)
        fields={'schema','desiredProfileHash','nativeProfileHash','profiles','bootId','generationRef','engineBinding','peers'}
        require(type(snapshot) is dict and set(snapshot)==fields
            and snapshot['schema']=='ouf.discovery-lease-generation-observation.v1'
            and digest(snapshot)==receipt['nativeObservationHash']
            and snapshot['desiredProfileHash']==receipt['desiredProfileHash']
            and snapshot['nativeProfileHash']==receipt['nativeProfileHash']==digest(snapshot['profiles'])
            and snapshot['bootId']==receipt['bootId']
            and snapshot['generationRef']==receipt['generationRef']==generation_reference(snapshot)
            and type(snapshot['profiles']) is dict and set(snapshot['profiles'])==ROLES
            and type(snapshot['peers']) is dict and set(snapshot['peers'])==ROLES,
            'EXACT_SIGNED_NATIVE_LEASE_OBSERVATION_REQUIRED')
        for role,profile in snapshot['profiles'].items():
            require(type(profile) is dict and set(profile)=={'nodeRecipeHash','applicationHash','imageConfigurationHash','rootfsSealHash'}
                and all(type(v) is str and re.fullmatch('[0-9a-f]{64}',v) for v in profile.values()),
                'INDEPENDENT_COMPLETE_NODE_PROFILE_REFERENCES_REQUIRED')
        peers=snapshot['peers']
        require(len({p['containerId'] for p in peers.values()})==2,'TWO_DISTINCT_NATIVE_LEASE_PEERS_REQUIRED')
        for role,p in peers.items():
            require(type(p) is dict and set(p)=={'containerId','imageId','dockerBindingHash','pid','startedAt',
                    'startTicks','namespace','allowedPausedStates'}
                and type(p['containerId']) is str and re.fullmatch('[0-9a-f]{64}',p['containerId'])
                and type(p['imageId']) is str and re.fullmatch('sha256:[0-9a-f]{64}',p['imageId'])
                and type(p['dockerBindingHash']) is str and re.fullmatch('[0-9a-f]{64}',p['dockerBindingHash'])
                and type(p['pid']) is int and p['pid']>1 and type(p['startTicks']) is int and p['startTicks']>0
                and type(p['startedAt']) is str and 1<=len(p['startedAt'])<=128
                and p['allowedPausedStates']==([False,True] if role=='registry' else [False])
                and all(type(v) is bool for v in p['allowedPausedStates'])
                and type(p['namespace']) is dict and set(p['namespace'])=={'path','identity'}
                and type(p['namespace']['identity']) is list and len(p['namespace']['identity'])==2
                and all(type(v) is int and v>0 for v in p['namespace']['identity']),
                'EXACT_ATTESTED_NATIVE_LEASE_PEER_GENERATION_REQUIRED')
        engine=snapshot['engineBinding']
        require(type(engine) is dict and set(engine)=={'socketPath','socketBinding','peerCredentials','startTicks'}
            and engine['socketPath'] in ('/run/docker.sock','/var/run/docker.sock')
            and type(engine['socketBinding']) is list and len(engine['socketBinding'])==5
            and all(type(v) is int for v in engine['socketBinding'])
            and type(engine['peerCredentials']) is list and len(engine['peerCredentials'])==3
            and all(type(v) is int for v in engine['peerCredentials'])
            and engine['peerCredentials'][0]>1 and engine['peerCredentials'][1:]==[0,0]
            and type(engine['startTicks']) is int and engine['startTicks']>0,
            'EXACT_CUSTODIED_NATIVE_LEASE_ENGINE_BINDING_REQUIRED')
        deadline=time.monotonic()+self.seconds;total=0;reads=0
        allowed={'/v1.44/containers/'+p['containerId']+'/json' for p in peers.values()}
        def read(selected):
            nonlocal total,reads
            require(selected in allowed and reads<4 and time.monotonic()<deadline,'CLOSED_FOUR_NATIVE_LEASE_GETS_REQUIRED')
            selected_socket=Path(engine['socketPath']).resolve(strict=True);ancestors(selected_socket)
            info=selected_socket.lstat()
            require(stat.S_ISSOCK(info.st_mode) and info.st_uid==0
                and [info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)]==engine['socketBinding']
                and ticks(engine['peerCredentials'][0])==engine['startTicks'],'NATIVE_LEASE_ENGINE_OR_PROCESS_CHANGED')
            class Local(http.client.HTTPConnection):
                def connect(connection):
                    connection.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                    connection.sock.settimeout(min(2,deadline-time.monotonic()))
                    connection.sock.connect(str(selected_socket))
                    peer=list(struct.unpack('3i',connection.sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)))
                    require(peer==engine['peerCredentials'],'NATIVE_LEASE_ENGINE_PEER_CHANGED')
            client=Local('root-local-lease-generation');reads+=1
            try:
                client.request('GET',selected,headers={'Connection':'close'})
                reply=client.getresponse();body=reply.read(2097153);total+=len(body)
                require(reply.status==200 and 0<len(body)<=2097152 and total<=8388608,
                    'BOUNDED_SUCCESSFUL_NATIVE_LEASE_ENGINE_GET_REQUIRED')
                return decode(body)
            finally:client.close()
        def verify(role):
            p=peers[role];before=ticks(p['pid']);row=read('/v1.44/containers/'+p['containerId']+'/json')
            state=row['State']
            require(row['Id']==p['containerId'] and row['Image']==p['imageId']
                and digest({k:row[k] for k in DOCKER_FIELDS})==p['dockerBindingHash']
                and state['Running'] is True and state['Restarting'] is False
                and type(state['Paused']) is bool and state['Paused'] in p['allowedPausedStates']
                and state['Pid']==p['pid'] and state['StartedAt']==p['startedAt']
                and row['RestartCount']==0 and before==p['startTicks']==ticks(p['pid']),
                'NATIVE_LEASE_PEER_CONFIGURATION_OR_GENERATION_CHANGED')
            observed=Path(row['NetworkSettings']['SandboxKey'])
            require(observed.parent in (Path('/run/docker/netns'),Path('/var/run/docker/netns')),
                'EXACT_DOCKER_RUNTIME_NAMESPACE_PARENT_REQUIRED')
            selected=observed.resolve(strict=True)
            require(selected.parent==Path('/run/docker/netns') and selected.name==observed.name
                and str(selected)==p['namespace']['path'],'EXACT_DOCKER_RUNTIME_NAMESPACE_BINDING_REQUIRED')
            ancestors(selected);info=selected.stat()
            require(info.st_uid==0 and [info.st_dev,info.st_ino]==p['namespace']['identity'],
                'CURRENT_DOCKER_RUNTIME_NAMESPACE_IDENTITY_REQUIRED')
        for _ in range(2):
            for role in sorted(ROLES):verify(role)
        require(reads==4 and time.monotonic()<deadline
            and ticks(engine['peerCredentials'][0])==engine['startTicks']
            and protected_file(path,1048576,expected=receipt['nativeObservationHash'],modes=(0o400,0o600))==raw,
            'NATIVE_LEASE_GENERATION_CHANGED_DURING_PROBE')
        return {k:receipt[k] for k in ('nativeObservationHash','nativeProfileHash','generationRef','bootId')}
