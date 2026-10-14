"""Offline target-specific route compilation from the pinned Gateway package.

Not loaded by the isolated effect executor. The prepared complete JSON plan is
bound to both the aggregate HUMAN authority and the gateway publication scope.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
from engine_creation import Engine
from tools.chatbot_file_cohort.gateway import PROFILE, route_map, NamespaceAdmin, private_config
from tools.chatbot_file_cohort.plan import digest, encoded, require, sha, environment, runtime_pin
from tools.semantic_policy_token_owner.producer import protected_directory

def materialize_target(runtime, references):
    """Only target projection + named secret references; never CI fixture input.

    Gateway source is imported from the authenticated package closure. Its own
    materializers validate issuer, audience, workload, owner routes and scopes.
    """
    from tools.materialize_object_search import materialize as objects
    from tools.materialize_managed_file_mcp import materialize as managed
    from tools.materialize_managed_upload import materialize as upload
    from tools.materialize_semantic_read import materialize as semantic_read
    from tools.materialize_semantic_proposals import add_to_existing
    from tools.materialize_onboarding_review import materialize as review
    from tools.materialize_semantic_human_runtime import materialize as semantic_human
    from tools.materialize_trusted_human_onboarding_runtime import materialize as onboarding_human
    require(set(references) == {'oidcSecretRef', 'delegationKeyEnv', 'authorizationKeyEnv',
            'udpKeyEnv', 'semanticReadKeyEnv', 'semanticProposalKeyEnv', 'semanticReadRouteIds'},
            'EXACT_TARGET_GATEWAY_REFERENCES_REQUIRED')
    oidc = references['oidcSecretRef']
    names = [references[k] for k in ('delegationKeyEnv', 'authorizationKeyEnv', 'udpKeyEnv',
                                    'semanticReadKeyEnv', 'semanticProposalKeyEnv')]
    require(type(oidc) is str and oidc.startswith(('$ENV://', '$secret://'))
            and len(set(names)) == 5 and all(type(n) is str and re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', n)
                                           for n in names), 'DISTINCT_NAMED_GATEWAY_KEYS_REQUIRED')
    args = (runtime, oidc, names[0], names[1])
    result = objects(*args, names[2])
    result['routes'].extend(r for r in managed(*args)['routes']
        if r.get('labels', {}).get('ouf-mediation') == 'managed-file-delegation-v1')
    result['routes'].append(upload(*args))
    result = semantic_read(result, runtime['x-ouf-installation'], names[0], names[3],
        {'scheme': 'http', 'nodes': {'ouf-semantic-registry:8080': 1}}, references['semanticReadRouteIds'])
    result = add_to_existing(result, runtime, names[0], names[4])
    result = review(result, runtime, names[0], names[1])
    result['routes'].extend(semantic_human(runtime, oidc)['routes'])
    approvals = {'trusted-human-onboarding-approvals-get', 'trusted-human-onboarding-approvals-post'}
    result['routes'].extend(r for r in onboarding_human(runtime, oidc)['routes'] if r['id'] in approvals)
    rows = route_map(result['routes'])
    # Gateway operational status is outside the file cohort. Its retained
    # routes remain in `previous`; the target has no running control-plane
    # container, so this cohort must not re-publish those two upstreams.
    for rid in ('operational-execute-ouf-gateway-operations-summary',
                'operational-execute-ouf-gateway-operations-incidents'):
        row=rows.get(rid)
        require(row is not None and row.get('labels',{}).get('ouf-mediation')=='operational-execute-v1'
                and row.get('upstream',{}).get('nodes')=={'ouf-gateway-control-plane:8081':1},
                'EXACT_UNRELATED_GATEWAY_OPERATIONAL_ROUTE_REQUIRED')
        del rows[rid]
    # Make APISIX schema defaults explicit in the signed request so full GET
    # equality does not mistake server-added default values for foreign drift.
    for row in rows.values():
        row.setdefault('status',1)
        row.setdefault('priority',0)
    require(approvals <= set(rows), 'ONBOARDING_APPROVAL_NAMESPACE_REQUIRED')
    require(rows['trusted-human-onboarding-approvals-post']['upstream']['timeout']['read'] == 55,
            'QUALIFIED_CONTINUATION_ROUTE_TIMEOUT_REQUIRED')
    return rows


def compile_gateway_plan(previous, runtime, references, package, transport_binding, upstream_bindings=None):
    require(package.get('module') == 'gateway' and package.get('artifactKind') == 'SOURCE_AND_ROUTE_PACKAGE'
            and re.fullmatch(r'[0-9a-f]{40}', package.get('sourceCommit', ''))
            and sha(package.get('cohortSourceLockSha256')), 'QUALIFIED_GATEWAY_SOURCE_PACKAGE_REQUIRED')
    before = route_map(list(previous.values()))
    desired = materialize_target(runtime, references)
    if upstream_bindings is not None:
        # The installation projection may map logical module names to retained
        # Docker DNS aliases. Each mapping is independently observed below.
        for row in desired.values():
            upstream=row.get('upstream',{})
            nodes=upstream.get('nodes')
            if type(nodes) is not dict:continue
            changed={}
            for peer,weight in nodes.items():
                host,separator,port=peer.rpartition(':')
                require(separator and host in upstream_bindings and port==str(upstream_bindings[host]['port']),
                        'UNOBSERVED_GATEWAY_APPLICATION_UPSTREAM')
                changed[upstream_bindings[host]['alias']+':'+port]=weight
            upstream['nodes']=changed
    after = copy.deepcopy(before)
    after.update(desired)
    # No id replacement may silently shadow a different retained endpoint.
    selector = lambda r: encoded([r.get('uri'), r.get('uris'), r.get('methods'), r.get('vars')])
    for rid, row in desired.items():
        require(all(other == rid or selector(old) != selector(row) for other, old in after.items()),
                'RETAINED_ROUTE_SELECTOR_COLLISION_REQUIRES_REVIEW')
    changes = [{'id': rid, 'before': before.get(rid), 'after': desired[rid]}
               for rid in sorted(desired) if before.get(rid) != desired[rid]]
    return {'schema': PROFILE, 'sourceCommit': package['sourceCommit'],
            'gatewayModulePackageHash': digest(package), 'targetRuntimeHash': digest(runtime),
            'targetReferencesHash': digest(references), 'transportBinding': copy.deepcopy(transport_binding),
            'upstreamBindings':copy.deepcopy(upstream_bindings),
            'previousRuntimeHash': digest(before), 'proposedRuntimeHash': digest(after),
            'previousRoutes': before, 'proposedRoutes': after, 'changes': changes,
            'automaticRollbackAllowed': False, 'automaticWriteReplayAllowed': False,
            'runtimeAuthorityIssued': False, 'notReleaseAcceptance': True}


def stage_private(directory, name, raw, mode=0o600, gid=0):
    """One private prepared object; exact reuse, never overwrite or regenerate."""
    require(re.fullmatch(r'[A-Za-z0-9._-]{1,180}',name) and type(raw) is bytes and 0<len(raw)<=1048576,
            'BOUNDED_PREPARED_PRIVATE_OBJECT_REQUIRED')
    with protected_directory(directory) as parent:
        try:
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode,dir_fd=parent)
        except FileExistsError:fd=None
        if fd is not None:
            try:
                os.fchown(fd,0,gid);os.fchmod(fd,mode)
                with os.fdopen(os.dup(fd),'wb') as stream:
                    stream.write(raw);stream.flush();os.fsync(stream.fileno())
                os.fsync(parent)
            finally:os.close(fd)
        check=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        try:
            info=os.fstat(check);value=os.read(check,1048577)
            identity=lambda v:(v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid,v.st_nlink,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==0 and info.st_gid==gid
                    and stat.S_IMODE(info.st_mode)==mode and value==raw and len(value)==info.st_size
                    and identity(info)==identity(os.fstat(check))==identity(os.stat(name,dir_fd=parent,follow_symlinks=False)),
                    'PREPARED_PRIVATE_OBJECT_PARTIAL_OR_CHANGED')
        finally:os.close(check)
    return {'path':str(Path(directory)/name),'sha256':hashlib.sha256(raw).hexdigest(),
            'uid':0,'gid':gid,'modeOctal':format(mode,'04o'),'bytes':len(raw)},fd is not None


def stage_proposal_key(directory, existing_key=None):
    name='semantic-proposal-owner.key'
    with protected_directory(directory) as parent:
        try:fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        except FileNotFoundError:fd=None
        if fd is not None:
            try:value=os.read(fd,65)
            finally:os.close(fd)
        else:value=(existing_key or secrets.token_hex(32)).encode('ascii')
    require(re.fullmatch(rb'[0-9a-f]{64}',value) and (existing_key is None or value==existing_key.encode('ascii')),
            'RETAINED_PROPOSAL_KEY_PARTIAL_OR_CONFLICTING')
    binding,created=stage_private(directory,name,value,0o440,10001)
    return value.decode('ascii'),binding,created


def lua_constant(route,name):
    values=[]
    for plugin in ('serverless-pre-function','serverless-post-function'):
        for source in route.get('plugins',{}).get(plugin,{}).get('functions',[]):
            values.extend(json.loads(x) for x in re.findall(r'^local '+re.escape(name)+r' = ("[^\n]*")$',source,re.M))
    require(values and len(set(values))==1 and type(values[0]) is str,'UNIQUE_RETAINED_LUA_CONSTANT_REQUIRED')
    return values[0]


def proposal_identity(runtime, routes):
    """The exact owner receipt identity already rendered into all four routes."""
    installation=runtime['x-ouf-installation']
    identity={'issuer':installation['issuerUrl'].rstrip('/'),'audience':installation['gatewayAudience'],
              'workload':installation['mcpServiceIdentity']}
    for mode in ('create','validate','review','read'):
        route=routes['semantic-proposal-'+mode]
        for constant,key in (('ISSUER','issuer'),('AUDIENCE','audience'),('MCP_WORKLOAD','workload')):
            require(lua_constant(route,constant)==identity[key],'MATERIALIZED_PROPOSAL_IDENTITY_DRIFT')
    return identity


def observe_references(routes, runtime, values, proposal_env):
    def selected(uri):
        rows=[r for r in routes.values() if r.get('uri')==uri]
        require(len(rows)==1,'EXACT_RETAINED_MEDIATION_ROUTE_REQUIRED');return rows[0]
    base=selected('/internal/capabilities/v1/execute')
    permission=selected('/internal/capabilities/v1/execute/authorization/read')
    udp=selected('/internal/capabilities/v1/execute/urban.object.search')
    search=selected('/internal/capabilities/v1/execute/semantic/search')
    get=selected('/internal/capabilities/v1/execute/semantic/get')
    selected_routes=(base,permission,udp,search,get)
    installation=runtime['x-ouf-installation']
    for route in selected_routes:
        for name,key in (('ISSUER','issuerUrl'),('AUDIENCE','gatewayAudience'),('MCP_WORKLOAD','mcpServiceIdentity')):
            expected=installation[key].rstrip('/') if name=='ISSUER' else installation[key]
            require(lua_constant(route,name)==expected,'RETAINED_GATEWAY_INSTALLATION_IDENTITY_DRIFT')
    delegation=lua_constant(base,'DELEGATION_KEY_ENV')
    require(all(lua_constant(r,'DELEGATION_KEY_ENV')==delegation for r in selected_routes),
            'RETAINED_GATEWAY_DELEGATION_KEY_CONFLICT')
    read=lua_constant(search,'OWNER_KEY_ENV')
    require(read==lua_constant(get,'OWNER_KEY_ENV'),'CONSULTATION_RECEIPT_KEY_CONFLICT')
    refs={'oidcSecretRef':base['plugins']['openid-connect']['client_secret'],
          'delegationKeyEnv':delegation,'authorizationKeyEnv':lua_constant(permission,'OWNER_KEY_ENV'),
          'udpKeyEnv':lua_constant(udp,'OWNER_KEY_ENV'),'semanticReadKeyEnv':read,
          'semanticProposalKeyEnv':proposal_env,'semanticReadRouteIds':{'search':search['id'],'get':get['id']}}
    for name in ('delegationKeyEnv','authorizationKeyEnv','udpKeyEnv','semanticReadKeyEnv'):
        require(refs[name] in values and re.fullmatch(r'[0-9a-f]{64}',values[refs[name]]),
                'RETAINED_GATEWAY_SIGNING_KEY_UNAVAILABLE')
    return refs


def expose_environment(raw,name):
    text=raw.decode('utf-8');marker='nginx_config:\n  envs:\n'
    require(text.count(marker)==1,'EXACT_RETAINED_NGINX_ENV_ALLOWLIST_REQUIRED')
    head,tail=text.split(marker,1);lines=tail.splitlines(keepends=True);names=[]
    for line in lines:
        match=re.fullmatch(r'  - ([A-Z][A-Z0-9_]{0,127})\n',line)
        if not match:break
        names.append(match[1])
    require(names and len(names)==len(set(names)),'CLOSED_NGINX_ENV_ALLOWLIST_REQUIRED')
    if name in names:return raw
    return (head+marker+'  - '+name+'\n'+tail).encode('utf-8')


def prepare_gateway(package_directory, package_record, engine, projection_binding,
                    selected_semantic_container, output_directory, cohort_id,
                    proposal_key_environment='OUF_SEMANTIC_PROPOSAL_OWNER_KEY',
                    selected_control_container='ouf-gateway-control-plane'):
    """Current bounded reads + private staging only; no daemon or IAM effects."""
    from tools.chatbot_file_cohort.images import private_open
    from tools.chatbot_file_cohort.gateway_runtime import compile_runtime, proposed_transport
    from tools.apply_installation_projection import apply_projection
    require(type(engine) is Engine and re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}',proposal_key_environment),
            'CONCRETE_GATEWAY_PREPARATION_INPUTS_REQUIRED')
    record=package_record;require(record.get('module')=='gateway' and type(record.get('files')) is dict,
                                'AUTHENTICATED_GATEWAY_PACKAGE_RECORD_REQUIRED')
    with private_open(Path(package_directory)/'gateway'/'compiled-route-declarations.json',4194304) as stream:
        raw=stream.read();require(hashlib.sha256(raw).hexdigest()==record['files']['compiled-route-declarations.json']
            ==record['compiledRouteDeclarationsSha256'],'GATEWAY_DECLARATION_PACKAGE_HASH_DRIFT')
    projection_raw,current_projection=private_config(projection_binding['path'],projection_binding)
    runtime=apply_projection(json.loads(raw),json.loads(projection_raw))
    status,actual=engine.request('GET','/v1.44/containers/ouf-apisix/json')
    require(status==200 and actual.get('Name')=='/ouf-apisix','SELECTED_CURRENT_APISIX_REQUIRED');runtime_pin(actual)
    mounts=[m for m in actual['Mounts'] if m.get('Destination')=='/usr/local/apisix/conf/config.yaml']
    require(len(mounts)==1,'ONE_SELECTED_APISIX_CONFIG_BIND_REQUIRED')
    binding=NamespaceAdmin.observe(engine,mounts[0]['Source']);transport=NamespaceAdmin(engine,binding)
    previous=transport.routes();values=environment(actual['Config'].get('Env') or [])
    refs=observe_references(previous,runtime,values,proposal_key_environment)
    key,key_binding,new_key=stage_proposal_key(output_directory,values.get(proposal_key_environment))
    require(key not in [values[refs[k]] for k in ('delegationKeyEnv','authorizationKeyEnv','udpKeyEnv','semanticReadKeyEnv')],
            'PROPOSAL_RECEIPT_KEY_MUST_BE_DISTINCT')
    config_raw,_=private_config(binding['configBinding']['path'],binding['configBinding'])
    proposed_raw=expose_environment(config_raw,proposal_key_environment)
    replacement=None;writes=int(new_key)
    if proposal_key_environment not in values or proposed_raw!=config_raw:
        _,created=stage_private(output_directory,'apisix-config-'+hashlib.sha256(proposed_raw).hexdigest()+'.yaml',proposed_raw,0o444)
        new_path=str(Path(output_directory)/('apisix-config-'+hashlib.sha256(proposed_raw).hexdigest()+'.yaml'))
        _,new_config=private_config(new_path);writes+=int(created)
        replacement=compile_runtime(actual,binding['configBinding'],new_config,proposal_key_environment,key,key_binding['sha256'],cohort_id,
                                    admin_key_binding=binding.get('adminKeyBinding'))
    selected={'ouf-udp-object-resolution':'ouf-udp','ouf-onboarding':'ouf-onboarding',
              'ouf-ingestion-runtime':'ouf-ingestion','ouf-mcp-server':'ouf-mcp',
              'ouf-semantic-registry':selected_semantic_container,
              'ouf-gateway-control-plane':selected_control_container}
    services={};projections=runtime['x-ouf-installation'].get('serviceBindings',{})
    required={peer.rpartition(':')[0] for row in materialize_target(runtime,refs).values()
              for peer in row.get('upstream',{}).get('nodes',{})}
    short_names={'ouf-mcp-server':'ouf-mcp','ouf-ingestion-runtime':'ouf-ingestion',
                 'ouf-semantic-registry':'ouf-semantic'}
    for logical,identity in selected.items():
        if logical not in required and short_names.get(logical) not in required:continue
        code,container=engine.request('GET','/v1.44/containers/'+identity+'/json')
        require(code==200,'SELECTED_COHORT_UPSTREAM_UNAVAILABLE');pin=runtime_pin(container)
        network_name='ouf-gateway-control' if logical=='ouf-gateway-control-plane' else 'ouf-backend'
        net=container['NetworkSettings']['Networks'].get(network_name)
        require(type(net) is dict and net['NetworkID']==actual['NetworkSettings']['Networks'][network_name]['NetworkID'],
                'COHORT_UPSTREAM_NETWORK_DRIFT')
        aliases=set(net.get('Aliases') or [])
        # An absent binding leaves the observed, network-advertised Docker
        # name authoritative. An explicit projection remains exact.
        alias=projections.get(logical,container['Name'].lstrip('/'))
        require(alias in aliases,'PROJECTED_APPLICATION_DNS_ALIAS_UNPROVEN')
        services[logical]={'alias':alias,'port':8081 if logical=='ouf-gateway-control-plane' else 8080,
                           'currentRuntimeBinding':pin,'networkId':net['NetworkID']}
        services[alias]=services[logical]
    # Some canonical runtime declarations already use these short owner names.
    for logical,short in (('ouf-mcp-server','ouf-mcp'),('ouf-ingestion-runtime','ouf-ingestion'),
                          ('ouf-semantic-registry','ouf-semantic')):
        if logical in services:services[short]=services[logical]
    package={k:v for k,v in record.items() if k!='files'}
    plan=compile_gateway_plan(previous,runtime,refs,package,proposed_transport(replacement) if replacement else binding,services)
    identity=proposal_identity(runtime,plan['proposedRoutes'])
    plan['proposalIdentity']=identity
    plan['projectionBinding']=current_projection
    plan['proposalKeyBinding']=key_binding
    plan['gatewayRuntimePlanHash']=digest(replacement) if replacement else None
    require(transport.routes()==previous and NamespaceAdmin.observe(engine,mounts[0]['Source'])==binding,
            'GATEWAY_CHANGED_DURING_COMPLETE_PREPARATION')
    return {'gatewayPlan':plan,'gatewayRuntimePlan':replacement,'proposalKeyBinding':key_binding,
            'targetReferences':refs,'proposalIdentity':identity,'privateEvidenceWrites':writes,'runtimeMutations':0,
            'runtimeAuthorityIssued':False,'notReleaseAcceptance':True}


