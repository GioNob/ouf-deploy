"""Review provider expectations before the new Engine identities exist.

Pure compilation only. The installer must bind both later identities to its
owned creation receipts and gate window. No actual OCI is a policy input; the
existing full-frame compiler and v4 broker/node/installer protocols are reused.
"""
import copy,re
from pathlib import PurePosixPath
from .custody_capture import digest,encoded,require
from tools.semantic_frame_compiler.compile_creation_frame_policy import compile_policy,environment,docker_context
from tools.semantic_provider_peer_bindings import declaration,declarations
from tools.semantic_provider_deployment_admission import transport_hash

CID_SLOT='$REGISTRY_CONTAINER_ID'
APP_SLOT='$REGISTRY_APPLICATION_HASH'
FIELDS={'schema','sourceClosureHash','qualifiedPackageHash','imageConfigurationHash','expectedImageId',
    'expectedRootfsSeal','creationRequest','frameTemplate','launch','dockerContext','networkBindings',
    'transportTemplate','tableName','runtimeBinding'}
RECIPE_FIELDS={'schema','sourceClosureHash','qualifiedPackageHash','imageConfigurationHash','expectedImageId',
    'expectedRootfsSeal','creationRequestHash','frameTemplateHash','launchHash','dockerContextHash',
    'transportTemplateHash','runtimeExecutableHash'}
CONTEXT_FIELDS={'schema','bundleParent','metadataParent','networkNamespaceParent','networkNamespaceName',
    'cgroupDriver','storageParent','rootfsLayout'}
FALSE_FACTS={k:False for k in ('inputsAuthenticated','providerAdmissionProven','runtimeAuthorityIssued',
    'targetApplyAuthorized','applicationStartAuthorized','releaseAcceptance')}

def hashed(value):return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None
def absolute(value):
    require(type(value) is str and value.startswith('/') and str(PurePosixPath(value))==value
        and '..' not in PurePosixPath(value).parts and value!='/' and len(value)<=4096,
        'EXACT_PROVIDER_INSTALLATION_PATH_REQUIRED')
    return value

def context_for(value,cid):
    require(type(value) is dict and set(value)==CONTEXT_FIELDS and hashed(cid)
        and value['schema']=='ouf.discovery-provider-docker-context-template.v1'
        and value['rootfsLayout'] in {'docker-containerd-overlayfs-v1','bundle-rootfs-v1'},
        'EXACT_STATIC_PROVIDER_DOCKER_CONTEXT_REQUIRED')
    for key in ('bundleParent','metadataParent','networkNamespaceParent','storageParent'):absolute(value[key])
    # A namespace identity may not be borrowed from the stopped predecessor.
    # This initial profile uses the fresh private namespace created by runc.
    require(value['networkNamespaceName'] is None,'NEW_PROVIDER_PRIVATE_OCI_NAMESPACE_REQUIRED')
    context={k:copy.deepcopy(v) for k,v in value.items() if k not in {'rootfsLayout','schema'}}
    context.update(schema='ouf.semantic-docker-frame-context.v1',containerId=cid,
        rootfsPath=(value['storageParent']+'/rootfs/overlayfs/'+cid
            if value['rootfsLayout']=='docker-containerd-overlayfs-v1' else value['bundleParent']+'/'+cid+'/rootfs'))
    docker_context(context)
    return context

def rendered_transport(flows,registry):
    require(type(registry) is dict and set(registry)=={'containerId','applicationHash'}
        and all(hashed(v) for v in registry.values()),'EXACT_REGISTRY_PEER_IDENTITY_REQUIRED')
    require(type(flows) is list and 1<=len(flows)<=128,'BOUNDED_PROVIDER_TRANSPORT_TEMPLATE_REQUIRED')
    out=copy.deepcopy(flows);count=0
    for flow in out:
        require(type(flow) is dict and set(flow)=={'purpose','authorityRef','source','destination','protocol','port','peerIngress'},
            'EXACT_PROVIDER_TRANSPORT_TEMPLATE_FLOW_REQUIRED')
        peer=flow['peerIngress'];require(type(peer) is dict,'EXACT_PROVIDER_TRANSPORT_PEER_REQUIRED')
        if peer.get('kind')=='CREATED_CANDIDATE':
            require(set(peer)=={'kind','declaration','bindingRef'} and type(peer['declaration']) is dict,
                'EXACT_PROVIDER_REGISTRY_DECLARATION_REQUIRED')
            own=peer['declaration']
            require(own.get('containerId')==CID_SLOT and own.get('applicationHash')==APP_SLOT,
                'ONLY_OWNED_REGISTRY_PEER_SLOTS_ALLOWED')
            own.update(registry);declaration(own)
            require(any(n['bindingRef']==peer['bindingRef'] for n in own['networkBindings']),
                'EXACT_PROVIDER_REGISTRY_NIC_REFERENCE_REQUIRED');count+=1
    require(count>=1,'EXPLICIT_GATE_WINDOW_REGISTRY_DEPENDENCY_REQUIRED')
    # No general interpolation facility: slot text outside those two fields is
    # an error, including environment, paths, argv, addresses and authorities.
    require(b'$REGISTRY_' not in encoded(out),'PROVIDER_LATE_BINDING_OUTSIDE_CLOSED_PEER_FIELDS')
    return out

def launch_matches_request(request,launch,runtime):
    require(type(request) is dict and set(request)<={'Image','User','Entrypoint','Cmd','Env','WorkingDir',
        'HostConfig','NetworkingConfig','Tty','Hostname','Domainname','Volumes','Labels','ExposedPorts'}
        and type(request.get('Image')) is str and re.fullmatch('sha256:[0-9a-f]{64}',request['Image']),
        'EXACT_PINNED_PROVIDER_CREATION_REQUEST_REQUIRED')
    host=request.get('HostConfig');net=request.get('NetworkingConfig');startup=launch.get('startup',{});manifest=launch.get('manifest',{})
    require(type(host) is dict and set(host)<={'Runtime','NetworkMode','RestartPolicy','CapDrop','CapAdd','SecurityOpt',
        'Privileged','ReadonlyRootfs','Memory','MemorySwap','PidsLimit','NanoCpus','Mounts','PidMode','IpcMode',
        'UTSMode','CgroupnsMode','OomKillDisable'},'CLOSED_PROVIDER_HOST_CONFIGURATION_REQUIRED')
    require(type(host) is dict and type(net) is dict and set(net)=={'EndpointsConfig'}
        and type(net['EndpointsConfig']) is dict and len(net['EndpointsConfig'])==1,
        'ONE_EXPLICIT_PROVIDER_PRIVATE_NETWORK_REQUIRED')
    name,endpoint=next(iter(net['EndpointsConfig'].items()))
    require(type(name) is str and name not in {'host','none','default','bridge'} and type(endpoint) is dict
        and host.get('NetworkMode') in (name,endpoint.get('NetworkID')),
        'REVIEWED_PROVIDER_NETWORK_BINDING_REQUIRED')
    require(type(host.get('Runtime')) is str and re.fullmatch('ouf-[A-Za-z0-9_-]+',host['Runtime'])
        and host.get('RestartPolicy')=={'Name':'no','MaximumRetryCount':0}
        and host.get('Privileged',False) is False and host.get('CapDrop')==['ALL'] and not host.get('CapAdd')
        and host.get('SecurityOpt')==['no-new-privileges:true']
        and all(host.get(k) in (None,'') for k in ('PidMode','IpcMode','UTSMode','CgroupnsMode')),
        'EXPLICIT_NAMED_ADMITTED_PROVIDER_RUNTIME_AND_NO_RESTART_REQUIRED')
    require(type(runtime) is dict and set(runtime)=={'path','sha256'} and hashed(runtime['sha256']),
        'EXACT_NATIVE_PROVIDER_RUNTIME_EXECUTABLE_BINDING_REQUIRED');absolute(runtime['path'])
    require(type(startup.get('uid')) is int and type(startup.get('gid')) is int
        and startup['uid']>0 and startup['gid']>0
        and request.get('User')==str(startup['uid'])+':'+str(startup['gid'])
        and startup.get('args')==request.get('Entrypoint',[])+request.get('Cmd',[])
        and startup.get('cwd')==request.get('WorkingDir'), 'PROVIDER_INDEPENDENT_STARTUP_AND_REQUEST_DRIFT')
    env=environment(startup.get('env'));require(env.pop('HOSTNAME',None)=='$OUF_HOSTNAME'
        and env==environment(request.get('Env')),'PROVIDER_INDEPENDENT_ENVIRONMENT_AND_REQUEST_DRIFT')
    require(manifest.get('user')==request['User'] and type(host.get('ReadonlyRootfs')) is bool
        and manifest.get('readOnlyRoot') is host['ReadonlyRootfs']
        and manifest.get('memoryBytes')==host.get('Memory')==host.get('MemorySwap')
        and manifest.get('pidsLimit')==host.get('PidsLimit'), 'PROVIDER_INDEPENDENT_RESOURCE_AND_REQUEST_DRIFT')
    mounts=host.get('Mounts')
    require(type(mounts) is list and len(mounts)==len(manifest.get('mounts',[]))
        and all(type(m) is dict and set(m)=={'Type','Source','Target','ReadOnly'} and m['Type']=='bind'
            and m['ReadOnly'] is True for m in mounts)
        and [{'source':m['Source'],'target':m['Target'],'readOnly':m['ReadOnly']} for m in mounts]==manifest['mounts'],
        'EXACT_PROVIDER_PRIVATE_READONLY_MOUNTS_REQUIRED')

def template(*,source_closure_hash,qualified_package_hash,image_configuration_hash,expected_rootfs_seal,
             request,frame_template,launch,docker_context_template,network_bindings,transport_template,
             table_name,runtime_binding):
    require(all(hashed(v) for v in (source_closure_hash,qualified_package_hash,image_configuration_hash)),
        'INDEPENDENT_PROVIDER_PACKAGE_AND_SOURCE_BINDINGS_REQUIRED')
    seal=expected_rootfs_seal
    require(type(seal) is dict and set(seal)=={'schema','sha256','entries','bytes'}
        and seal['schema']=='ouf.semantic-rootfs-seal.v1' and hashed(seal['sha256'])
        and type(seal['entries']) is int and 1<=seal['entries']<=100000
        and type(seal['bytes']) is int and 0<=seal['bytes']<=8589934592,
        'INDEPENDENT_PROVIDER_RUNTIME_ROOTFS_SEAL_REQUIRED')
    launch_matches_request(request,launch,runtime_binding)
    endpoints=request['NetworkingConfig']['EndpointsConfig'];endpoint=next(iter(endpoints.values()))
    require(type(network_bindings) is list and len(network_bindings)==1
        and endpoint.get('MacAddress')==network_bindings[0].get('mac')
        and type(endpoint.get('IPAMConfig')) is dict
        and endpoint['IPAMConfig']=={'IPv4Address':network_bindings[0].get('ipv4')},
        'EXACT_NEW_PROVIDER_NETWORK_ALLOCATION_REQUIRED')
    require(type(table_name) is str and re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,31}',table_name),
        'EXACT_PROVIDER_TRANSPORT_TABLE_REQUIRED')
    # Validation identities are pure compiler inputs, never runtime defaults or
    # evidence. Actual identities must later come from the owning installer.
    provider='0'*64;registry={'containerId':'1'*64,'applicationHash':'2'*64}
    declaration({'containerId':provider,'applicationHash':'3'*64,'networkBindings':network_bindings})
    concrete=rendered_transport(transport_template,registry);declarations(concrete,provider)
    compile_policy(frame_template,launch,context_for(docker_context_template,provider))
    value={'schema':'ouf.discovery-provider-installation-template.v1','sourceClosureHash':source_closure_hash,
        'qualifiedPackageHash':qualified_package_hash,'imageConfigurationHash':image_configuration_hash,
        'expectedImageId':request['Image'],'expectedRootfsSeal':seal,'creationRequest':request,
        'frameTemplate':frame_template,'launch':launch,'dockerContext':docker_context_template,
        'networkBindings':network_bindings,'transportTemplate':transport_template,'tableName':table_name,
        'runtimeBinding':runtime_binding}
    require(len(encoded(value))<=131072,'BOUNDED_PROVIDER_INSTALLATION_TEMPLATE_REQUIRED')
    return copy.deepcopy(value)

def recompile(value):
    require(type(value) is dict and set(value)==FIELDS and value.get('schema')=='ouf.discovery-provider-installation-template.v1',
        'EXACT_PROVIDER_INSTALLATION_TEMPLATE_REQUIRED')
    result=template(source_closure_hash=value['sourceClosureHash'],qualified_package_hash=value['qualifiedPackageHash'],
        image_configuration_hash=value['imageConfigurationHash'],expected_rootfs_seal=value['expectedRootfsSeal'],
        request=value['creationRequest'],frame_template=value['frameTemplate'],launch=value['launch'],
        docker_context_template=value['dockerContext'],network_bindings=value['networkBindings'],
        transport_template=value['transportTemplate'],table_name=value['tableName'],runtime_binding=value['runtimeBinding'])
    require(result==value,'PROVIDER_INSTALLATION_TEMPLATE_DRIFT');return result

def node_recipe(value):
    t=recompile(value)
    return {'schema':'ouf.discovery-provider-independent-node-recipe.v2',
        **{k:copy.deepcopy(t[k]) for k in ('sourceClosureHash','qualifiedPackageHash','imageConfigurationHash','expectedImageId','expectedRootfsSeal')},
        **{target:digest(t[source]) for target,source in (
            ('creationRequestHash','creationRequest'),('frameTemplateHash','frameTemplate'),('launchHash','launch'),('dockerContextHash','dockerContext'))},
        'transportTemplateHash':digest({k:t[k] for k in ('networkBindings','transportTemplate','tableName')}),
        'runtimeExecutableHash':t['runtimeBinding']['sha256']}

def expected_node_profile(value):
    recipe=node_recipe(value)
    return {'nodeRecipeHash':digest(recipe),'imageConfigurationHash':recipe['imageConfigurationHash'],
        'rootfsSealHash':digest(recipe['expectedRootfsSeal'])}

def materialize(value,container_id,registry):
    t=recompile(value)
    require(hashed(container_id) and container_id!=registry.get('containerId'),
        'DISTINCT_PROVIDER_AND_REGISTRY_IDENTITIES_REQUIRED')
    context=context_for(t['dockerContext'],container_id)
    policy=compile_policy(t['frameTemplate'],t['launch'],context)
    candidate={'networkBindings':copy.deepcopy(t['networkBindings']),
        'transport':rendered_transport(t['transportTemplate'],registry),'tableName':t['tableName']}
    declarations(candidate['transport'],container_id)
    return {'schema':'ouf.discovery-materialized-provider-proposal.v1','templateHash':digest(t),
        'nodeRecipe':node_recipe(t),'independentNodeProfile':expected_node_profile(t),
        'containerId':container_id,'registryIdentity':copy.deepcopy(registry),'dockerContext':context,'framePolicy':policy,
        'applicationHash':digest(policy['expectedOci']),'artifactHash':digest(policy),
        'transportHash':transport_hash(candidate),'candidate':candidate,**FALSE_FACTS}
