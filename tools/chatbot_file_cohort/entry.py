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

import iam_binding_candidate as evidence
from engine_creation import Engine
from tools.chatbot_file_cohort.package_custody import extract_cohort,extract_source,new_directory
from tools.chatbot_file_cohort.plan import digest,encoded,require,environment,runtime_pin
from tools.semantic_policy_token_owner.producer import protected_directory

PRODUCER='8bff54a52a0ce15daccaf2aee932004f106dd178'
RUN=38584614991
ARCHIVE='144699ab7756c8312d49783967cfbb64acc02a617015ad89f5adf51e25a10300'
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


def compilation_owner(owner_inputs,sources,closure,stage,context,lineage,pregrant_recovery=None,renewal_actor=None):
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
                       {'owner':owner_inputs,**({'ownerPregrantRecovery':pregrant_recovery}
                           if pregrant_recovery is not None else {}),
                        **({'ownerRenewalActor':renewal_actor} if renewal_actor is not None else {})},sources)


def collect(args):
    source=Path(args.source_directory);stage=Path(args.staging_directory)
    require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode and sys.flags.no_site,
            'ROOT_ISOLATED_NO_SITE_PREPARATION_REQUIRED')
    require(re.fullmatch('[0-9a-f]{40}',args.source_commit)
        and re.fullmatch('[0-9a-f]{64}',args.preparation_source_hash),'EXACT_SOURCE_CAPSULE_IDENTITY_REQUIRED')
    with protected_directory(source):pass
    with protected_directory(stage):pass
    verify_preparation_capsule(source,stage,args.preparation_source_hash)
    from tools.chatbot_file_cohort.migration_recovery import CONTEXT as MIGRATION_CONTEXT
    if os.path.lexists(evidence.PARENT/MIGRATION_CONTEXT):
        from tools.chatbot_file_cohort.postgrant_preparation import collect as collect_migration
        return collect_migration(args,migration=True)
    from tools.chatbot_file_cohort.backup_recovery import CONTEXT as BACKUP_CONTEXT
    if os.path.lexists(evidence.PARENT/BACKUP_CONTEXT):
        from tools.chatbot_file_cohort.postgrant_preparation import collect as collect_backup
        return collect_backup(args,backup=True)
    from tools.chatbot_file_cohort.signed_recovery import CONTEXT as SIGNED_CONTEXT
    if os.path.lexists(evidence.PARENT/SIGNED_CONTEXT/'review.json'):
        from tools.chatbot_file_cohort.postgrant_preparation import collect as collect_signed
        return collect_signed(args,paused=True,mounted=True,signed=True)
    from tools.chatbot_file_cohort.mounted_recovery import CONTEXT as MOUNTED_CONTEXT
    if os.path.lexists(evidence.PARENT/MOUNTED_CONTEXT/'review.json'):
        from tools.chatbot_file_cohort.postgrant_preparation import collect as collect_mounted
        return collect_mounted(args,paused=True,mounted=True)
    from tools.chatbot_file_cohort.paused_recovery import CONTEXT as PAUSED_CONTEXT
    if os.path.lexists(evidence.PARENT/PAUSED_CONTEXT/'review.json'):
        from tools.chatbot_file_cohort.postgrant_preparation import collect as collect_paused
        return collect_paused(args,paused=True)
    from tools.chatbot_file_cohort.postgrant_recovery import CONTEXT as POSTGRANT_CONTEXT
    if os.path.lexists(evidence.PARENT/POSTGRANT_CONTEXT/'review.json'):
        from tools.chatbot_file_cohort.postgrant_preparation import collect as collect_postgrant
        return collect_postgrant(args)
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
    from tools.chatbot_file_cohort.preparation import prepare_cohort,database_binding,ingestion_properties
    from tools.chatbot_file_cohort.databases import observe_database
    from tools.chatbot_file_cohort.authorization import OwnerPrimitives,OwnerTransport,compile_plan
    from tools.chatbot_file_cohort.human_session import HumanSession
    from tools.chatbot_file_cohort.acceptance import compile_acceptance_plan,observe_acceptance_input
    from file_only_preparation import default_selection,retained_inputs,lineage,prepare_file_only_installation,preflight_retained_runtime
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
    retained_selection=default_selection()
    report('CURRENT_RETAINED_NATIVE_PREFLIGHT')
    native_preflight=preflight_retained_runtime(engine,retained_selection,command_binding=closure['executables']['docker'])
    report('CURRENT_RETAINED_NATIVE_PREFLIGHT_RESULT',**native_preflight)
    require(native_preflight['allRequiredChecksPass'],'RETAINED_NATIVE_PREFLIGHT_FAILED')
    from tools.chatbot_file_cohort.action_process import previous_authorization_actions
    previous=previous_authorization_actions(digest(manifest),closure['executables']['systemctl'])
    recoveries=[row['ownerPregrantRecovery'] for row in previous if row.get('ownerPregrantRecovery') is not None]
    require(len(recoveries)<=1,'ONE_PREGRANT_OWNER_CONTINUATION_REQUIRED')
    recovery=recoveries[0] if recoveries else None
    if recovery is not None:
        report('CURRENT_PREGRANT_RECOVERY_PREFLIGHT_PASSED',priorGrantAttempts=0,
            priorCredentialMutationAttempts=recovery['priorCredentialMutationAttempts'],priorRetirementCommandAttempts=1,
            existingImagesVerified=5,existingGatewayGenerationVerified=True)
    report('CURRENT_ADMINISTRATIVE_SESSION')
    ensure_admin_session(engine,closure['executables']['docker'],new_directory(stage,'iam-session'),emit=emit_line)
    cohort_id='chatbot-file-'+str(RUN)
    selected=select_target(engine,closure['executables']['docker'],picker,PICKER_HASH)
    from legacy_retirement import POST_PROFILE
    renewal_actor=({key:selected['selection'][key] for key in ('issuer','tenant','subject')}
        if recovery is not None and recovery['schema']==POST_PROFILE else None)
    retained,_=retained_inputs(retained_selection)
    history=lineage(retained_selection)
    report('CURRENT_OWNER_IAM_TLS_AND_ROOT_CUSTODY')
    owner_input=prepare_owner(source_commit=args.source_commit,source_closure_hash=digest(closure),cohort_id=cohort_id,
        docker_binding=closure['executables']['docker'],engine_path=engine.path)
    report('EXACT_IMAGE_AND_GATEWAY_PREPARATION')
    image_plan=prepare_imports(package,manifest,new_directory(stage,'images'),engine=engine)
    _,context=assemble.authority_directory(cohort_id,digest(closure),digest(manifest))
    owner=compilation_owner(owner_input['owner'],sources,closure,stage,context,history,recovery,renewal_actor)
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
        # Operational ingestion status is not part of the CSV-to-search flow.
        # Do not expand the HUMAN role or chatbot OAuth scope for that optional
        # read when the retained target descriptor cannot be proven.
        auth_plan=compile_plan(transport.observe(),primitives,selected['selection'],
                               include_ingestion_status=False,session_binding=session.binding())
        _,ingestion_binding=ingestion_properties(current(engine,'ouf-ingestion'))
        deltas=environment_deltas(engine,selected['selection']['origin'],
            tenant=selected['selection']['tenant'],issuer=selected['selection']['issuer'],
            audience=gateway['proposalIdentity']['audience'],ingestion_binding=ingestion_binding)
        co=prepare_cohort(engine,package,manifest,image_plan,postgres,digest(gateway['gatewayPlan']),
                          digest(auth_plan),deltas,digest(acceptance),selected['thsConfigurationBinding'],
                          ingestion_binding)
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
            'ingestionConfigurationBinding':ingestion_binding,
            'registry':registry,'cohortPlan':co['cohortPlan'],'databasePlan':co['databasePlan'],
            'gatewayPlan':gateway['gatewayPlan'],'gatewayRuntimePlan':gateway['gatewayRuntimePlan'],'imagePlan':image_plan,
            'authorization':{'plan':auth_plan,'catalogue':catalogue.decode(),'helperBindings':OWNER_FILES,
                'adminTokenFile':str(session.token_path),'mcpTokenFile':str(session.token_path)},'acceptancePlan':acceptance}
        if recovery is not None:prepared['ownerPregrantRecovery']=recovery
        if renewal_actor is not None:prepared['ownerRenewalActor']=renewal_actor
        # Keep all preparation evidence private, while the final review binds its
        # exact bytes. No unbounded raw environment or diagnostics reach stdout.
        assemble.stage(stage,'preparation-evidence.json',encoded({'package':provenance,'selection':selected,
                        'owner':owner_input['evidence'],'acceptanceInput':acceptance_input}))
        compiled=assemble.assemble(prepared=prepared,sources=sources,loader=loader,
            bootstrap=source_bytes(source/'tools/chatbot_file_cohort/child_bootstrap.py'),closure=closure,
            staging_directory=stage,lineage=history,preparation_source_hash=args.preparation_source_hash,cohort_id=cohort_id)
        return finish_review(args,compiled,session,stop,assemble,closure)
    finally:
        stop.set()
        if session.thread is not None:session.thread.join(45)


def finish_review(args,compiled,session,stop,assembler,closure):
    report('COMPLETE_REVIEW_READY',reviewPath=compiled['reviewBinding']['path'],reviewHash=compiled['reviewBinding']['sha256'])
    if getattr(args,'prepare_only',False):
        args.authority_issued=False
        receipt={'schema':'ouf.chatbot-file-preparation-result.v1','status':'COMPLETE_PRIVATE_REVIEW_READY_NOT_STARTED',
            'reviewPath':compiled['reviewBinding']['path'],'reviewHash':compiled['reviewBinding']['sha256'],
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'serviceMutations':0,
            'budgetReset':False,'chatbotEndToEndProven':False,'notReleaseAcceptance':True}
        print(json.dumps(receipt,sort_keys=True,separators=(',',':')),flush=True)
        return receipt
    args.authority_issued=None
    receipt=assembler.approve_and_start(compiled,session,stop)
    args.authority_issued=True
    print(json.dumps(receipt,sort_keys=True,separators=(',',':')),flush=True)
    watch_child(receipt,closure['executables']['systemctl'])
    return receipt


def preparation_wait(session,stop,seconds):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        require(not stop.is_set() and time.time()<session.expires_at,'FINITE_PREPARATION_SESSION_ENDED')
        if session.failure is not None:raise session.failure
        stop.wait(min(1,deadline-time.monotonic()))


def configuration(actual,prefix,ingestion_binding=None):
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
    if prefix == 'OUF_ING' and ingestion_binding is not None:
        from tools.chatbot_file_cohort.preparation import ingestion_properties
        properties,_=ingestion_properties(actual,ingestion_binding)
        for key,value in properties.items():add(key,value)
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


def environment_deltas(engine,origin,*,tenant=None,issuer=None,audience=None,ingestion_binding=None):
    """Preserve existing identity channels and explicitly enable the qualified loops."""
    ingestion=current(engine,'ouf-ingestion');onboarding=current(engine,'ouf-onboarding');udp=current(engine,'ouf-udp')
    _,ing_json,read=configuration(ingestion,'OUF_ING',ingestion_binding)
    require(read('ouf.ingestion.iam.enabled','OUF_ING_IAM_ENABLED')=='true',
            'CURRENT_INGESTION_IAM_ENABLED_REQUIRED')
    for loop in ('activation','execution'):
        require(read('ouf.ingestion.'+loop+'.enabled')=='true',
                'CURRENT_INGESTION_WORKER_LOOP_REQUIRED')
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
        'ingestion':({} if ingestion_binding is not None else
                     {'set':{'SPRING_APPLICATION_JSON':updated_overlay(ing_json,ing_updates)}}),'mcp':{}}


def human_action_message(value):
    """Explain the required browser decision outside machine JSON."""
    if value.get('phase')=='PAUSED_REQUIRES_RECONCILIATION':
        return 'Esecuzione sospesa; serve riconciliazione. Motivo: '+str(value.get('reason','UNKNOWN'))
    if value.get('phase')!='HUMAN_OWNER_ROLE_CONFIRMATION_REQUIRED':return None
    if value.get('state')!='PENDING':
        return 'La proposta dei ruoli non è approvabile: '+str(value.get('state','UNKNOWN'))+'. Non usare il vecchio link.'
    path=value.get('approvalPath');proposal=value.get('proposalId')
    require(type(path)is str and type(proposal)is str and re.fullmatch('[0-9a-f-]{36}',proposal),
            'EXACT_OWNER_ROLE_BROWSER_LINK_REQUIRED')
    parsed=urlsplit(path)
    require(parsed.scheme=='https' and parsed.hostname and not parsed.username and not parsed.password
            and not parsed.fragment and parsed.path=='/trusted-human/authorization/'
            and parsed.query=='proposal='+proposal,'EXACT_OWNER_ROLE_BROWSER_LINK_REQUIRED')
    return ('\nAZIONE RICHIESTA: apri questo link nel browser e revisiona i ruoli OUF:\n'+path+
        '\nConferma solo dopo aver letto la review. Scadenza proposta: '+str(value.get('expiresAt','UNKNOWN'))+
        '\nNon serve un device code XXXX-YYYY per questa conferma.\n'
        'Il mandato complessivo non viene esteso da questa attesa.\n')


def watch_child(receipt,systemctl):
    import subprocess
    path=Path(receipt['context'])/'delivery-status.json';last=None
    deadline=time.monotonic()+3600
    while time.monotonic()<deadline:
        if path.exists():
            raw=source_bytes(path,maximum=8192)
            if raw!=last:
                value=json.loads(raw);print(json.dumps(value,sort_keys=True,separators=(',',':')),flush=True);last=raw
                message=human_action_message(value)
                if message is not None:print(message,flush=True)
                if (value['phase']=='ACTUAL_CSV_OWNER_ACCEPTANCE_OBSERVED'
                        and value.get('ownerAcceptance',{}).get('phase')=='TWO_SOURCE_COMMIT_AND_REUSE_PROVEN'):
                    return
        result=subprocess.run([systemctl['path'],'show',receipt['unit'],'--property=ActiveState','--value'],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10)
        require(result.returncode==0 and result.stdout.strip() in (b'active',b'activating'),
                'FINITE_DELIVERY_PROCESS_STOPPED_INSPECT_RETAINED_STATUS')
        time.sleep(2)
    raise RuntimeError('FINITE_DELIVERY_OBSERVATION_WINDOW_ENDED')


def safe_failure_locations(error):
    """Bounded code locations only; no exception text, paths or local values."""
    locations=[];tb=error.__traceback__
    for _ in range(64):
        if tb is None:break
        module=tb.tb_frame.f_globals.get('__name__','');function=tb.tb_frame.f_code.co_name
        if module.startswith('tools.chatbot_file_cohort.') and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,79}',function):
            locations.append({'module':module,'function':function,'line':tb.tb_lineno})
        tb=tb.tb_next
    return {'schema':'ouf.chatbot-file-preparation-safe-failure-location.v1',
        'locations':locations[-8:],'messagesPrinted':False,'pathsPrinted':False,'localValuesPrinted':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('source-directory','package-archive','staging-directory','source-commit','preparation-source-hash'):
        parser.add_argument('--'+key,required=True)
    parser.add_argument('--prepare-only',action='store_true',help='Retain complete private review and exit before runtime authority or application start')
    args=parser.parse_args()
    try:collect(args)
    except KeyboardInterrupt:
        report('INTAKE_INTERRUPTED',runtimeAuthorityIssued=getattr(args,'authority_issued',False));raise SystemExit(130)
    except Exception as error:
        # Exception bodies may contain private input. Emit only a bounded owner
        # reason when it is a constant diagnostic code, otherwise the class.
        reason=str(error)
        safe=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,159}',reason) else type(error).__name__
        report('BLOCKED',reason=safe,diagnostic=safe_failure_locations(error),
            runtimeAuthorityIssued=getattr(args,'authority_issued',False));raise SystemExit(1)


if __name__=='__main__':main()
