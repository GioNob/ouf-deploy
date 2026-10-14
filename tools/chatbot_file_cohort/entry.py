"""One complete private intake, one HUMAN review, one finite native action.

The outer delivery authenticates this entire preparation source capsule before
executing it. Preparation observes selected existing resources, stages unused
package/key bytes, and performs the existing interactive logins. Application
effects remain behind the complete review and current signed HUMAN mandate.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import threading
import time
from urllib.parse import urlsplit

from engine_creation import Engine
from tools.chatbot_file_cohort.package_custody import extract_cohort,extract_source,new_directory
from tools.chatbot_file_cohort.plan import digest,encoded,require,environment,runtime_pin
from tools.semantic_policy_token_owner.producer import protected_directory

PRODUCER='f31a653ee1da56b29a6171c159f9c601523735b9'
RUN=38536134146
ARCHIVE='be55c6eda4485a4c90da9872f63e2533abe21c741c4926ecc129626cc01530f9'
ONBOARDING='84828f74ac586bae09a78f0fb197b75b1a3d98d1'
BASELINE='releases/chatbot-existing-cinema-baseline-20261014.json'
BASELINE_HASH='d55ef320243acd4f4f7b932eb57c5771a67ea8bfcbbd7824e25a5995e482acfb'
OWNER_FILES={
 'scripts/r4a_authorization_lifecycle.py':'77e1f33d335f7116556cb73765c1323e001f4f99400f7fd504685b8fbfd9b89f',
 'scripts/r4a_keycloak_client_scope_catalogue.py':'4ca8a16e7c6bb3a48e5834c4cea97709f51cf77a1f59711b947b84a29c2b74a8',
 'catalogue/chatbot-source-review-capabilities.json':'e435034af73920531bb18a4185e08b8622f3ac691a2c9c646f9110150751213e'}
PICKER_HASH='bb24bbc94e60ed9b229bd0a5710822157648f4933f2f23f1b497807680d93e3e'


def report(phase,**safe):
    print(json.dumps({'schema':'ouf.chatbot-file-cohort-intake-status.v1','phase':phase,
        'budgetReset':False,'runtimeAuthorityIssued':False,'chatbotEndToEndProven':False,
        'notReleaseAcceptance':True,**safe},sort_keys=True,separators=(',',':')),flush=True)


def emit_line(message):
    # The operator command tees stdout; interactive login instructions must be
    # visible before the device flow waits for the HUMAN to act.
    print(message,flush=True)


def source_bytes(path,expected=None,maximum=262144):
    path=Path(path)
    with protected_directory(path.parent) as directory:
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
    try:
        info=os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0
            and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1 and 0<info.st_size<=maximum,
            'CUSTODIED_QUALIFIED_PREPARATION_SOURCE_REQUIRED')
        with os.fdopen(os.dup(fd),'rb') as stream:raw=stream.read(maximum+1)
        require(len(raw)==info.st_size and (expected is None or hashlib.sha256(raw).hexdigest()==expected),
                'QUALIFIED_PREPARATION_SOURCE_CHANGED')
        return raw
    finally:os.close(fd)


def qualified_module(name,path,expected):
    require(name not in sys.modules,'QUALIFIED_PREPARATION_MODULE_ALREADY_LOADED')
    raw=source_bytes(path,expected)
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    module.__qualified_source_sha256__=expected
    sys.modules[name]=module
    exec(compile(raw,str(path),'exec'),module.__dict__)
    return module


def verify_preparation_capsule(source,stage,expected):
    manifest=json.loads(source_bytes(Path(stage)/'preparation-manifest.json',expected,2097152))
    require(set(manifest)=={'schema','files'} and manifest['schema']=='ouf.chatbot-file-preparation-capsule.v1'
        and type(manifest['files']) is dict and 1<=len(manifest['files'])<=512,
        'EXACT_AUTHENTICATED_PREPARATION_CAPSULE_REQUIRED')
    for relative,hashed in manifest['files'].items():
        require(type(relative) is str and not Path(relative).is_absolute() and '..' not in Path(relative).parts
            and str(Path(relative))==relative and re.fullmatch('[0-9a-f]{64}',hashed),
            'EXACT_PREPARATION_CAPSULE_MEMBER_REQUIRED')
        source_bytes(Path(source)/relative,hashed,2097152)
    return manifest


def current(engine,name):
    code,row=engine.request('GET','/v1.44/containers/'+name+'/json')
    require(code==200,'SELECTED_CURRENT_CONTAINER_UNAVAILABLE')
    runtime_pin(row)
    return row


def compilation_owner(owner_inputs,sources,closure,stage,context,lineage):
    """Real constructor, deliberately absent mandate, no output-directory effect."""
    import iam_governance_intake as governance
    from cutover_authority import CutoverAuthority
    from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
    from tools.semantic_policy_token_owner.owner_installation import AggregateAction
    from tools.chatbot_file_cohort.delivery import build_owner
    absent=hashlib.sha256(b'UNISSUED_PREPARATION_ONLY').hexdigest()
    verifier=DetachedAuthenticator(governance.POLICY,str(stage),closure['executables']['openssl'])
    gate=CutoverAuthority(verifier,{'path':str(Path(context)/'unissued-mandate.json'),'sha256':absent},
        absent,governance.CONTEXT,{'sourceClosureHash':digest(closure),'creationRequestHash':absent,
        'intakeHash':digest(owner_inputs),**lineage})
    return build_owner(AggregateAction(gate,encoded({'schema':'ouf.preparation-without-authority.v1'}),digest(closure)),
                       {'owner':owner_inputs},sources)


def collect(args):
    source=Path(args.source_directory);stage=Path(args.staging_directory)
    require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode and sys.flags.no_site,
            'ROOT_ISOLATED_NO_SITE_PREPARATION_REQUIRED')
    require(re.fullmatch('[0-9a-f]{40}',args.source_commit)
        and re.fullmatch('[0-9a-f]{64}',args.preparation_source_hash),'EXACT_SOURCE_CAPSULE_IDENTITY_REQUIRED')
    with protected_directory(source):pass
    with protected_directory(stage):pass
    verify_preparation_capsule(source,stage,args.preparation_source_hash)
    report('AUTHENTICATED_PACKAGE_PRIVATE_EXTRACTION')
    package,manifest,provenance=extract_cohort(args.package_archive,ARCHIVE,PRODUCER,RUN,new_directory(stage,'package'))
    records={row['module']:row for row in manifest['modules']}
    require(records['onboarding']['sourceCommit']==ONBOARDING,'EXACT_QUALIFIED_OWNER_SOURCE_REQUIRED')
    owner_root=Path(extract_source(package,records['onboarding'],new_directory(stage,'onboarding-source')))
    gateway_root=Path(extract_source(package,records['gateway'],new_directory(stage,'gateway-source')))
    # These modules are imported only after their package bytes and exact source
    # hashes are authenticated. The executor independently closes the same two.
    lifecycle=qualified_module('qualified_owner_authorization_lifecycle',owner_root/'scripts/r4a_authorization_lifecycle.py',
                               OWNER_FILES['scripts/r4a_authorization_lifecycle.py'])
    scopes=qualified_module('qualified_owner_scope_catalogue',owner_root/'scripts/r4a_keycloak_client_scope_catalogue.py',
                            OWNER_FILES['scripts/r4a_keycloak_client_scope_catalogue.py'])
    picker=qualified_module('qualified_onboarding_picker',owner_root/'scripts/r4a_picker_onboarding_rollout.py',PICKER_HASH)
    import tools
    tools.__path__.append(str(gateway_root/'tools'))
    from tools.chatbot_file_cohort import assemble
    from tools.chatbot_file_cohort.delivery import native_environment
    from tools.chatbot_file_cohort.iam_session import ensure_admin_session
    from tools.chatbot_file_cohort.owner_preparation import prepare_owner
    from tools.chatbot_file_cohort.target_selection import select_target
    from tools.chatbot_file_cohort.gateway_preparation import prepare_gateway
    from tools.chatbot_file_cohort.images import prepare_imports
    from tools.chatbot_file_cohort.preparation import prepare_cohort,database_binding
    from tools.chatbot_file_cohort.databases import observe_database
    from tools.chatbot_file_cohort.authorization import OwnerPrimitives,OwnerTransport,compile_plan
    from tools.chatbot_file_cohort.human_session import HumanSession
    from tools.chatbot_file_cohort.acceptance import compile_acceptance_plan,observe_acceptance_input
    from file_only_preparation import default_selection,retained_inputs,lineage,prepare_file_only_installation
    paths=json.loads(source_bytes(source/'tools/chatbot_file_cohort/source_paths.json'))
    sources={name:source_bytes(owner_root/path.split(':',1)[1] if path.startswith('ouf-onboarding:') else source/path)
             for name,path in paths.items()}
    loader=source_bytes(source/'tools/chatbot_file_cohort/runtime.py')
    closure=assemble.source_closure(source_commit=args.source_commit,
        source_pins={'ouf-deploy':args.source_commit,'ouf-onboarding':ONBOARDING},sources=sources,loader=loader)
    # The fixed local Engine path is resolved once; custody is checked for each
    # request. Ambient Docker context/configuration never selects another daemon.
    socket_path=str(Path('/var/run/docker.sock').resolve())
    socket_info=os.stat(socket_path,follow_symlinks=False)
    socket_binding=(socket_info.st_dev,socket_info.st_ino,socket_info.st_uid,socket_info.st_gid,stat.S_IMODE(socket_info.st_mode))
    engine=Engine(socket_path,socket_binding)
    native_environment(engine,closure['executables']['docker'],new_directory(stage,'docker-cli'))
    report('CURRENT_ADMINISTRATIVE_SESSION')
    ensure_admin_session(engine,closure['executables']['docker'],new_directory(stage,'iam-session'),emit=emit_line)
    cohort_id='chatbot-file-'+str(RUN)
    selected=select_target(engine,closure['executables']['docker'],picker,PICKER_HASH)
    retained_selection=default_selection();retained,_=retained_inputs(retained_selection)
    history=lineage(retained_selection)
    report('CURRENT_OWNER_IAM_TLS_AND_ROOT_CUSTODY')
    owner_input=prepare_owner(source_commit=args.source_commit,source_closure_hash=digest(closure),cohort_id=cohort_id,
        docker_binding=closure['executables']['docker'],engine_path=engine.path)
    report('EXACT_IMAGE_AND_GATEWAY_PREPARATION')
    image_plan=prepare_imports(package,manifest,new_directory(stage,'images'))
    _,context=assemble.authority_directory(cohort_id,digest(closure),digest(manifest))
    owner=compilation_owner(owner_input['owner'],sources,closure,stage,context,history)
    gateway=prepare_gateway(package,records['gateway'],engine,selected['projectionBinding'],
        retained['installationReview']['currentRegistry']['id'],new_directory(stage,'gateway'),cohort_id)
    postgres=current(engine,'ouf-postgres');onboarding=current(engine,'ouf-onboarding')
    db=database_binding('onboarding',onboarding,postgres,selected['thsConfigurationBinding'])
    observed=observe_database(postgres['Id'],db['user'],db['database'],'onboarding')
    db['databaseOid']=observed['identity']['oid']
    asset_id='6609b245-86ed-4315-8ce0-73f2a8555bf3';profile_id='7984c39c-7396-4248-ab0a-f2efc390b49c'
    acceptance_input=observe_acceptance_input(engine,Engine.runtime_binding(postgres),db,
        asset_id=asset_id,profile_id=profile_id,subject=selected['selection']['subject'])
    acceptance=compile_acceptance_plan(asset_id=asset_id,profile_id=profile_id,profile_version=1,
        tenant=selected['selection']['tenant'],subject=selected['selection']['subject'],
        canonical_type='https://schema.org/PerformingArtsTheater',
        ontology_semantic_id='https://api.ouf-lab.it/semantic/teatri#TeatriOntology',
        baseline=json.loads(source_bytes(source/BASELINE,BASELINE_HASH)),asset_observation=acceptance_input)
    # The optional administrative password prompt and all preexec-constrained
    # collectors have completed before a refresh thread can exist.
    human_dir=new_directory(stage,'human-session')
    session=HumanSession(selected['selection'],human_dir,human_dir/'human-access.jwt',int(time.time())+7200)
    stop=threading.Event();session.login(emit=emit_line,stop=stop);session.start_refresh(stop,emit=emit_line)
    try:
        catalogue=source_bytes(owner_root/'catalogue/chatbot-source-review-capabilities.json',
                              OWNER_FILES['catalogue/chatbot-source-review-capabilities.json'])
        primitives=OwnerPrimitives.from_qualified_modules(lifecycle,scopes,catalogue,OWNER_FILES)
        transport=OwnerTransport(selected['selection'],str(session.token_path),str(session.token_path),
                                 wait=lambda seconds:preparation_wait(session,stop,seconds),human_session=session)
        report('CURRENT_HUMAN_OWNER_AUTHORIZATION_REVIEW')
        auth_plan=compile_plan(transport.observe(),primitives,selected['selection'],session_binding=session.binding())
        deltas=environment_deltas(engine,selected['selection']['origin'],
            tenant=selected['selection']['tenant'],issuer=selected['selection']['issuer'],
            audience=gateway['proposalIdentity']['audience'])
        co=prepare_cohort(engine,package,manifest,image_plan,postgres,digest(gateway['gatewayPlan']),
                          digest(auth_plan),deltas,digest(acceptance),selected['thsConfigurationBinding'])
        old_env=environment(retained['creationRequest']['Env'])
        token_target=str(Path(old_env['OUF_AUTHORIZATION_REGISTRY_TOKEN_FILE']).parent)
        mount={'source':owner.first.binding.output_directory,'target':token_target,'fileName':owner.first.binding.output_member,
            'gid':owner.first.binding.output_gid,'ownerBindingHash':owner.first.binding.digest(),
            'directoryCustodyScopeHash':digest(owner.output.scope),'maxBytes':16384,'minimumRemainingSeconds':30}
        proposal_identity=gateway['proposalIdentity']
        registry=prepare_file_only_installation(engine=engine,selection=retained_selection,package_directory=package,
            semantic_record=records['semantic'],image_audit=next(r['audit'] for r in image_plan['images'] if r['module']=='semantic'),
            postgres=postgres,producer_observations=list(co['observations'].values()),cohort_plan=co['cohortPlan'],
            owner_mount=mount,proposal_key=gateway['proposalKeyBinding'],proposal_identity=proposal_identity,
            source_closure_hash=digest(closure),authority_directory=context,command_binding=closure['executables']['docker'],
            source_directory=source,iam_profile=owner_input['owner']['iamProfile'])
        prepared={'schema':'ouf.chatbot-file-cohort-prepared-inputs.v1',
            'engine':{'socketPath':socket_path,'socketBinding':list(socket_binding)},'owner':owner_input['owner'],
            'registry':registry,'cohortPlan':co['cohortPlan'],'databasePlan':co['databasePlan'],
            'gatewayPlan':gateway['gatewayPlan'],'gatewayRuntimePlan':gateway['gatewayRuntimePlan'],'imagePlan':image_plan,
            'authorization':{'plan':auth_plan,'catalogue':catalogue.decode(),'helperBindings':OWNER_FILES,
                'adminTokenFile':str(session.token_path),'mcpTokenFile':str(session.token_path)},'acceptancePlan':acceptance}
        # Keep all preparation evidence private, while the final review binds its
        # exact bytes. No unbounded raw environment or diagnostics reach stdout.
        assemble.stage(stage,'preparation-evidence.json',encoded({'package':provenance,'selection':selected,
                        'owner':owner_input['evidence'],'acceptanceInput':acceptance_input}))
        compiled=assemble.assemble(prepared=prepared,sources=sources,loader=loader,
            bootstrap=source_bytes(source/'tools/chatbot_file_cohort/child_bootstrap.py'),closure=closure,
            staging_directory=stage,lineage=history,preparation_source_hash=args.preparation_source_hash,cohort_id=cohort_id)
        report('COMPLETE_REVIEW_READY',reviewPath=compiled['reviewBinding']['path'],reviewHash=compiled['reviewBinding']['sha256'])
        args.authority_issued=None
        receipt=assemble.approve_and_start(compiled,session,stop)
        args.authority_issued=True
        print(json.dumps(receipt,sort_keys=True,separators=(',',':')),flush=True)
        watch_child(receipt,closure['executables']['systemctl'])
        return receipt
    finally:
        stop.set()
        if session.thread is not None:session.thread.join(45)


def preparation_wait(session,stop,seconds):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        require(not stop.is_set() and time.time()<session.expires_at,'FINITE_PREPARATION_SESSION_ENDED')
        if session.failure is not None:raise session.failure
        stop.wait(min(1,deadline-time.monotonic()))


def configuration(actual,prefix):
    """Selected Spring/JVM scalar metadata; never read a bearer or secret file."""
    from tools.chatbot_file_cohort.target_selection import flattened
    from tools.chatbot_file_cohort.preparation import validate_json_overlay
    values=environment(actual['Config'].get('Env') or [])
    canonical=lambda key:re.sub('[^a-z0-9]','',key.lower())
    rows={}
    def add(key,value):
        if type(value) is bool:value=str(value).lower()
        if type(value) in (str,int,float):rows.setdefault(canonical(key),[]).append(str(value))
    for key,value in values.items():add(key,value)
    overlay={}
    if values.get('SPRING_APPLICATION_JSON'):
        validate_json_overlay(values['SPRING_APPLICATION_JSON'],prefix)
        overlay=json.loads(values['SPRING_APPLICATION_JSON'])
        for key,value in flattened(overlay).items():add('.'.join(key),value)
    argv=(actual['Config'].get('Entrypoint') or [])+(actual['Config'].get('Cmd') or [])
    for name in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','JAVA_OPTS'):
        if values.get(name):argv+=shlex.split(values[name])
    for argument in argv:
        if argument.startswith(('-D','--')) and '=' in argument:
            key,value=argument[2:].split('=',1);add(key,value)
    def read(name,*aliases,required=True):
        found=[v for key in (name,*aliases) for v in rows.get(canonical(key),[]) if v!='']
        require(len(set(found))<=1,'CONFLICTING_EFFECTIVE_RUNTIME_PROPERTY')
        require(found or not required,'EXISTING_RUNTIME_CHANNEL_PROPERTY_REQUIRED')
        return found[0] if found else None
    return values,overlay,read


def token_channel(actual,token):
    path=Path(token)
    require(path.is_absolute() and str(path)==token and '..' not in path.parts,
            'EXACT_EXISTING_WORKLOAD_TOKEN_REFERENCE_REQUIRED')
    matches=[]
    for mount in actual['Mounts']:
        target=Path(mount['Destination'])
        if path==target or target in path.parents:matches.append(mount)
    require(len(matches)==1 and matches[0].get('Type')=='bind' and matches[0].get('RW') is False,
            'EXISTING_READ_ONLY_WORKLOAD_TOKEN_MOUNT_REQUIRED')
    # No token content, issuance, rotation or new consumer is introduced.
    return token


def updated_overlay(overlay,updates):
    from tools.chatbot_file_cohort.target_selection import flattened
    norm=lambda value:re.sub('[^a-z0-9]','',value.lower())
    for key,value in updates.items():
        matches=[path for path in flattened(overlay) if norm('.'.join(path))==norm(key)]
        require(len(matches)<=1,'AMBIGUOUS_REVIEWED_RUNTIME_PROPERTY')
        if not matches:overlay[key]=value
        else:
            wanted=norm(key)
            def replace(node,prefix=''):
                for name,child in node.items():
                    full=prefix+'.'+name if prefix else name
                    if norm(full)==wanted:node[name]=value;return True
                    if type(child) is dict and replace(child,full):return True
                return False
            require(replace(overlay),'EXACT_REVIEWED_RUNTIME_PROPERTY_REQUIRED')
    return json.dumps(overlay,sort_keys=True,separators=(',',':'))


def environment_deltas(engine,origin,*,tenant=None,issuer=None,audience=None):
    """Preserve existing identity channels and explicitly enable the qualified loops."""
    ingestion=current(engine,'ouf-ingestion');onboarding=current(engine,'ouf-onboarding');udp=current(engine,'ouf-udp')
    _,ing_json,read=configuration(ingestion,'OUF_ING')
    require(read('ouf.ingestion.iam.enabled','OUF_ING_IAM_ENABLED')=='true',
            'CURRENT_INGESTION_IAM_ENABLED_REQUIRED')
    ing_updates={'ouf.ingestion.iam.enabled':True}
    if issuer is not None:
        actual=read('ouf.ingestion.iam.issuer','OUF_ING_IAM_ISSUER')
        require(actual==issuer,'CURRENT_INGESTION_ISSUER_REQUIRED');ing_updates['ouf.ingestion.iam.issuer']=actual
    if audience is not None:
        actual=read('ouf.ingestion.iam.audience','OUF_ING_IAM_AUDIENCE')
        require(actual==audience,'CURRENT_INGESTION_AUDIENCE_REQUIRED');ing_updates['ouf.ingestion.iam.audience']=actual
    def valid_origin(value):
        u=urlsplit(value)
        require(u.scheme in ('http','https') and u.hostname and not u.username and not u.password
                and not u.query and not u.fragment and u.path in ('','/'),'EXISTING_GATEWAY_CHANNEL_ORIGIN_REQUIRED')
        return value
    gateway=valid_origin(read('ouf.ingestion.activation.gateway-url'))
    retained_tenant=read('ouf.ingestion.activation.tenant-id')
    require(tenant is None or retained_tenant==tenant,'CURRENT_INGESTION_TENANT_REQUIRED')
    token=token_channel(ingestion,read('ouf.ingestion.activation.token-file'))
    ing_updates.update({'ouf.ingestion.activation.enabled':True,'ouf.ingestion.execution.enabled':True,
        'ouf.ingestion.activation.gateway-url':gateway,'ouf.ingestion.activation.token-file':token,
        'ouf.ingestion.activation.tenant-id':retained_tenant})
    _,onb_json,onb_read=configuration(onboarding,'OUF_ONB')
    onb_gateway=valid_origin(onb_read('ouf.onboarding.udp-identity.gateway-url','OUF_ONB_UDP_IDENTITY_GATEWAY_URL'))
    onb_token=token_channel(onboarding,onb_read('ouf.onboarding.udp-identity.token-file','OUF_ONB_UDP_IDENTITY_TOKEN_FILE'))
    resolution=onb_read('ouf.resolution.ths.gateway-base-url',required=False)
    require(resolution is None or resolution.rstrip('/')==origin,'CURRENT_RESOLUTION_THS_ORIGIN_DRIFT')
    onb_updates={'ouf.onboarding.udp-identity.gateway-url':onb_gateway,'ouf.onboarding.udp-identity.token-file':onb_token,
                 'ouf.workflow.ths.gateway-base-url':origin,'ouf.resolution.ths.gateway-base-url':origin}
    _,udp_json,udp_read=configuration(udp,'OUF_UDP')
    udp_gateway=valid_origin(udp_read('ouf.udp.execution.gateway-url'))
    udp_token=token_channel(udp,udp_read('ouf.udp.execution.token-file'))
    udp_tenant=udp_read('ouf.udp.lake.tenant-id','OUF_UDP_TENANT_ID')
    require(tenant is None or udp_tenant==tenant,'CURRENT_UDP_LAKE_TENANT_REQUIRED')
    udp_updates={'ouf.udp.execution.enabled':True,'ouf.udp.execution.gateway-url':udp_gateway,
                 'ouf.udp.execution.token-file':udp_token,'ouf.udp.lake.tenant-id':udp_tenant}
    # These explicit signed JSON deltas retain observed channels when the new
    # image supplies its qualified launch. They add no credential or grant.
    return {'udp':{'set':{'SPRING_APPLICATION_JSON':updated_overlay(udp_json,udp_updates)}},
        'onboarding':{'set':{'OUF_WORKFLOW_THS_GATEWAY_BASE_URL':origin,'OUF_RESOLUTION_THS_GATEWAY_BASE_URL':origin,
                            'SPRING_APPLICATION_JSON':updated_overlay(onb_json,onb_updates)}},
        'ingestion':{'set':{'SPRING_APPLICATION_JSON':updated_overlay(ing_json,ing_updates)}},'mcp':{}}


def watch_child(receipt,systemctl):
    import subprocess
    path=Path(receipt['context'])/'delivery-status.json';last=None
    deadline=time.monotonic()+3600
    while time.monotonic()<deadline:
        if path.exists():
            raw=source_bytes(path,maximum=8192)
            if raw!=last:
                value=json.loads(raw);print(json.dumps(value,sort_keys=True,separators=(',',':')),flush=True);last=raw
                if (value['phase']=='ACTUAL_CSV_OWNER_ACCEPTANCE_OBSERVED'
                        and value.get('ownerAcceptance',{}).get('phase')=='TWO_SOURCE_COMMIT_AND_REUSE_PROVEN'):
                    return
        result=subprocess.run([systemctl['path'],'show',receipt['unit'],'--property=ActiveState','--value'],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10)
        require(result.returncode==0 and result.stdout.strip() in (b'active',b'activating'),
                'FINITE_DELIVERY_PROCESS_STOPPED_INSPECT_RETAINED_STATUS')
        time.sleep(2)
    raise RuntimeError('FINITE_DELIVERY_OBSERVATION_WINDOW_ENDED')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('source-directory','package-archive','staging-directory','source-commit','preparation-source-hash'):
        parser.add_argument('--'+key,required=True)
    args=parser.parse_args()
    try:collect(args)
    except KeyboardInterrupt:
        report('INTAKE_INTERRUPTED',runtimeAuthorityIssued=getattr(args,'authority_issued',False));raise SystemExit(130)
    except Exception as error:
        # Exception bodies may contain private input. Emit only a bounded owner
        # reason when it is a constant diagnostic code, otherwise the class.
        reason=str(error)
        safe=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,159}',reason) else type(error).__name__
        report('BLOCKED',reason=safe,runtimeAuthorityIssued=getattr(args,'authority_issued',False));raise SystemExit(1)


if __name__=='__main__':main()
