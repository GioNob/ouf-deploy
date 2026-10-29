"""Read-only current Docker/OCI context beside the staged public trust input.

The original material manifest selects one provider by exact ID/image/configuration,
not by a guessed container name. Historical process pins do not authorize a current
process: current boot/root/core/provider pins and namespace identities are observed.
No runc operation, application request, IAM, SQL, firewall or lifecycle mutation.
"""
import copy,hashlib,http.client,os,re,socket,stat,struct
from pathlib import Path
from .custody_capture import require,attrs,decode,digest,process_pin,encoded,MATERIAL_ROOT,MANIFEST_HASH
from .material_preparation import stable_binding,MAX_BYTES
from .audit import path

BUNDLE_PARENTS=('/run/docker/containerd/daemon/io.containerd.runtime.v2.task/moby',
                '/run/containerd/io.containerd.runtime.v2.task/moby')


def provider_identity(row):
    return {'containerId':row['Id'],'imageId':row['Image'],
        'configurationHash':digest({k:row[k] for k in ('Config','HostConfig','Mounts')}|
                                  {'networks':row['NetworkSettings']['Networks']})}


def canonical_sandbox(c,reference,pinned):
    """Accept only Docker's two system aliases to the same protected namespace."""
    observed=Path(path(reference))
    require(observed.parent in (Path('/run/docker/netns'),Path('/var/run/docker/netns')),
            'EXACT_DOCKER_NAMESPACE_PARENT_REQUIRED')
    selected=observed.resolve(strict=True)
    require(selected.parent==Path('/run/docker/netns') and selected.name==observed.name,
            'EXACT_DOCKER_NAMESPACE_ALIAS_TARGET_REQUIRED')
    c.ancestors(selected);s=selected.stat()
    require([s.st_dev,s.st_ino]==pinned['namespaces']['net'],
            'CURRENT_DOCKER_SANDBOX_NAMESPACE_MISMATCH')
    return selected,[s.st_dev,s.st_ino]


class ContextEngine:
    """Five exact local GET attempts; distinct from the frozen 27-GET reader."""
    def __init__(self,c,binding,provider,network):
        require(re.fullmatch('[0-9a-f]{64}',provider)
                and re.fullmatch('[0-9a-f]{64}',network),
                'EXACT_PROVIDER_AND_NETWORK_IDS_REQUIRED')
        self.c,self.binding=c,copy.deepcopy(binding)
        self.allowed={'/v1.44/info','/v1.44/containers/'+provider+'/json','/v1.44/networks/'+network}
        c.counts['contextEngineGets']=0

    def get(self,selected):
        c=self.c;c.guarded()
        require(selected in self.allowed and c.counts['contextEngineGets']<5,
                'CLOSED_FIVE_CONTEXT_GET_ATTEMPTS_REQUIRED')
        binding=self.binding;selected_socket=Path(binding['socketPath']);c.ancestors(selected_socket)
        s=selected_socket.lstat()
        require(stat.S_ISSOCK(s.st_mode) and s.st_uid==0
                and [s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)]==binding['socketBinding'],
                'CONTEXT_ENGINE_SOCKET_CHANGED')
        c.counts['contextEngineGets']+=1;n=c.counts['contextEngineGets']
        c.put('context-engine-get-'+str(n)+'-claim.json',{'method':'GET','path':selected,'attemptNotCompletion':True})
        class Local(http.client.HTTPConnection):
            def connect(conn):
                conn.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                conn.sock.settimeout(min(4,c.until-__import__('time').monotonic()))
                conn.sock.connect(str(selected_socket))
                peer=list(struct.unpack('3i',conn.sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)))
                require(peer==binding['peerCredentials'] and peer[1]==0,'CONTEXT_ENGINE_PEER_CHANGED')
        connection=Local('root-local-context-engine')
        try:
            connection.request('GET',selected,headers={'Connection':'close'})
            response=connection.getresponse();raw=response.read(2097153)
            c.counts['bytes']+=len(raw)
            require(response.status==200 and 0<len(raw)<=2097152 and c.counts['bytes']<=MAX_BYTES,
                    'BOUNDED_SUCCESSFUL_CONTEXT_ENGINE_GET_REQUIRED')
            value=decode(raw);c.put('context-engine-get-'+str(n)+'-response.json',value);return value
        finally:connection.close()


def collect(c,*,material,trust_result,material_root=MATERIAL_ROOT,manifest_hash=MANIFEST_HASH,
            pin=process_pin,boot_path=Path('/proc/sys/kernel/random/boot_id'),
            engine_factory=ContextEngine,bundle_parents=BUNDLE_PARENTS):
    require(trust_result.get('complete') is True
            and trust_result.get('status')=='PUBLIC_JAVA_TRUSTSTORE_PREPARED_NOT_ADMITTED'
            and trust_result.get('scope')==str(c.scope)
            and trust_result.get('targetApplyAuthorized') is False
            and c.counts['engineGets']==27,'COMPLETED_UNADMITTED_TRUST_PREPARATION_REQUIRED')
    c.counts['nativeConfigurationReads']=0
    raw=c.read(material_root/'private-input-manifest.json',0,0,0o600,131072,'metadataReads')
    manifest=decode(raw)
    require(hashlib.sha256(raw).hexdigest()==manifest_hash
            and manifest.get('schema')=='ouf.discovery.private-runtime-input-manifest.v1'
            and all(manifest.get(k) is False for k in
                    ('mountsInstalled','applicationCutoverAuthorized','leaseAuthorityGranted'))
            and manifest_hash==material['projectionPlan']['materialManifestHash']
            and manifest['publicCaHash']==material['preparedCopies']['publicProviderCa']['sha256'],
            'EXACT_UNAPPLIED_PROVIDER_MATERIAL_MANIFEST_REQUIRED')
    provider_binding=manifest['inputBindings']['southbound']
    require({'containerId','imageId','configurationHash'}<=set(provider_binding),
            'EXACT_RETAINED_PROVIDER_IDENTITY_REQUIRED')
    core=material['currentObservations'];roles=material['installationRoleMap']
    semantic=core[roles['semantic']]
    attachments=semantic['NetworkSettings']['Networks']
    require(len(attachments)==1,'ONE_EXACT_CURRENT_REGISTRY_NETWORK_REQUIRED')
    network_name,attachment=next(iter(attachments.items()));network_id=attachment['NetworkID']
    engine=engine_factory(c,material['engineBinding'],provider_binding['containerId'],network_id)
    info=engine.get('/v1.44/info')
    require(info.get('ServerVersion')=='29.8.1' and info.get('Driver')=='overlayfs'
            and info.get('CgroupDriver')=='systemd','QUALIFIED_CONTEXT_ENGINE_PROFILE_REQUIRED')
    storage=Path(path(info['DockerRootDir']))
    network=engine.get('/v1.44/networks/'+network_id)
    require(network.get('Id')==network_id and network.get('Name')==network_name
            and network.get('Driver')=='bridge' and network.get('EnableIPv6') is False,
            'EXACT_CURRENT_REGISTRY_BRIDGE_REQUIRED')
    provider=engine.get('/v1.44/containers/'+provider_binding['containerId']+'/json')
    require(provider_identity(provider)=={k:provider_binding[k] for k in
            ('containerId','imageId','configurationHash')}
            and provider['State']['Running'] is True and provider['State']['Paused'] is False
            and provider['State']['Restarting'] is False,'CURRENT_RETAINED_PROVIDER_IDENTITY_CHANGED')
    provider_pin=pin(provider['State']['Pid']);boot=boot_path.read_text().strip()
    def unchanged():
        c.guarded()
        require(boot_path.read_text().strip()==boot==material['bootId']
                and material['rootProcessPins']['pid1']==pin(1)
                and material['rootProcessPins']['engine']==pin(material['engineBinding']['peerCredentials'][0])
                and all(pin(v['pid'])==v for v in material['processPins'].values())
                and provider_pin==pin(provider['State']['Pid'])
                and all(attrs(Path(p).lstat())==s for p,s in c.seals.items()),
                'NATIVE_CONTEXT_SOURCE_OR_GENERATION_CHANGED')
    unchanged();nodes={}
    require(type(bundle_parents) in (list,tuple) and 1<=len(bundle_parents)<=2
            and all(path(p)==p for p in bundle_parents),'EXACT_NATIVE_BUNDLE_PARENTS_REQUIRED')
    for role,row,pinned in (('semantic',semantic,material['processPins'][roles['semantic']]),
                            ('provider',provider,provider_pin)):
        cid=row['Id'];selected=[Path(p)/cid/'config.json' for p in bundle_parents
                              if os.path.lexists(Path(p)/cid/'config.json')]
        require(len(selected)==1,'ONE_CURRENT_CONTAINERD_BUNDLE_REQUIRED')
        selected=selected[0];s=selected.lstat();mode=stat.S_IMODE(s.st_mode)
        require(mode in (0o600,0o644),'ROOT_CONTAINERD_CONFIGURATION_MODE_REQUIRED')
        oci_raw=c.read(selected,0,0,mode,2097152,'nativeConfigurationReads');oci=decode(oci_raw)
        require(oci.get('ociVersion') and type(oci.get('root')) is dict,
                'CURRENT_COMPLETE_OCI_CONFIGURATION_REQUIRED')
        root=Path(oci['root']['path'])
        require(root.is_absolute() and root!=storage and root.is_relative_to(storage),
                'CURRENT_OCI_ROOTFS_OUTSIDE_ENGINE_STORAGE')
        sandbox,namespace_identity=canonical_sandbox(c,row['NetworkSettings']['SandboxKey'],pinned)
        nodes[role]={'containerId':cid,'runtimeBinding':copy.deepcopy(pinned),
            'engineBindingHash':digest(stable_binding(row)),'bundleParent':str(selected.parent.parent),
            'bundlePath':str(selected.parent),'configurationPath':str(selected),
            'configurationSha256':hashlib.sha256(oci_raw).hexdigest(),
            'oci':oci,'rootfsPath':str(root),'networkNamespace':str(sandbox),
            'networkNamespaceIdentity':namespace_identity,
            'observedSandboxKey':row['NetworkSettings']['SandboxKey']}
    require(stable_binding(engine.get('/v1.44/containers/'+provider['Id']+'/json'))==stable_binding(provider)
            and engine.get('/v1.44/networks/'+network_id)==network,'CONTEXT_PROVIDER_OR_NETWORK_CHANGED')
    unchanged()
    require(all(canonical_sandbox(c,row['observedSandboxKey'],row['runtimeBinding'])
                ==(Path(row['networkNamespace']),row['networkNamespaceIdentity']) for row in nodes.values()),
            'NATIVE_CONTEXT_NAMESPACE_CHANGED_DURING_READ')
    record={'schema':'ouf.m2-discovery-current-native-context.v1',
        'trustPreparationResultHash':digest(trust_result),'materialBindingHash':digest(material),
        'providerManifestBinding':{'path':str(material_root/'private-input-manifest.json'),'sha256':manifest_hash},
        'providerBinding':provider_identity(provider),'providerProcessPin':provider_pin,
        'engineProfile':{k:info[k] for k in ('ServerVersion','Driver','CgroupDriver','DockerRootDir')},
        'registryNetwork':network,'nativeNodes':nodes,'sourceSeals':dict(c.seals),
        'currentPeerCount':len({r['Id'] for r in core.values()}|{provider['Id']}),
        'counts':dict(c.counts),'currentTlsOrIamAdmissionProven':False,'nativeContextIsExpectedPolicy':False,
        'historicalAuthorityReused':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
        'automaticReplayAllowed':False,'budgetReset':False}
    c.put('native-context.private.json',record)
    return {'schema':'ouf.m2-discovery-native-context-result.v1','status':'CURRENT_NATIVE_CONTEXT_CAPTURED_NOT_ADMITTED',
        'nativeContextHash':digest(record),'currentPeerCount':record['currentPeerCount'],'nativeNodesObserved':2,
        'contextEngineGets':c.counts['contextEngineGets'],'nativeConfigurationReads':c.counts['nativeConfigurationReads'],
        'currentTlsOrIamAdmissionProven':False,'nativeContextIsExpectedPolicy':False}
