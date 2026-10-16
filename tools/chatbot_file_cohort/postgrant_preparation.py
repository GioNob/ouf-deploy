"""Prepare the fixed post-grant continuation; no application/credential effects.

Reuse the independently pinned previous package/helper identities and loaded
images. No fresh package extraction, role proposal, first slot or secret read.
Native read-only preflight precedes every interactive login in this path.
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import threading
import time

import iam_binding_candidate as evidence
from engine_creation import Engine
from tools.chatbot_file_cohort.entry import source_bytes,qualified_module,OWNER_FILES,ONBOARDING,RUN,report,emit_line,finish_review
from tools.chatbot_file_cohort.plan import digest,encoded,require
from tools.chatbot_file_cohort.package_custody import new_directory
from tools.chatbot_file_cohort.postgrant_recovery import read_predecessor,current_baseline,proof_scope,CLAIM
from tools.semantic_policy_token_owner.producer import protected_directory


def qualified_helpers(stage,bundle):
    """Authenticate the two frozen helpers before importing their consumers."""
    aliases={'qualified_owner_authorization_lifecycle':'scripts/r4a_authorization_lifecycle.py',
        'qualified_owner_scope_catalogue':'scripts/r4a_keycloak_client_scope_catalogue.py'}
    result={}
    for alias,path in aliases.items():
        raw=base64.b64decode(bundle['sources'][alias],validate=True)
        require(hashlib.sha256(raw).hexdigest()==OWNER_FILES[path],
            'POSTGRANT_FROZEN_QUALIFIED_OWNER_HELPER_DRIFT')
        # assemble imports delivery, which consumes these helpers. Staging them
        # cannot depend on either consumer, even through a module-level import.
        with protected_directory(stage)as directory:
            fd=os.open(alias+'.py',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
            try:
                with os.fdopen(os.dup(fd),'wb')as output:
                    output.write(raw);output.flush();os.fsync(output.fileno())
                os.fsync(directory)
            finally:os.close(fd)
        result[alias]=qualified_module(alias,Path(stage)/(alias+'.py'),OWNER_FILES[path])
    return result


def validate_authorization_rebind(previous,current):
    """Only the fresh session binding may change before recompiling its hash."""
    left=copy.deepcopy(previous);right=copy.deepcopy(current)
    left.pop('sessionBinding',None);right.pop('sessionBinding',None)
    require(left==right and not right.get('addedDescriptors') and not right.get('roleProposal')
        and not right.get('scopeBindings'),'POSTGRANT_NEW_AUTHORIZATION_WRITES_DENIED')


def collect(args,*,paused=False,mounted=False,signed=False,backup=False,migration=False):
    source,stage=Path(args.source_directory),Path(args.staging_directory)
    profile=None;claim=CLAIM
    if paused:
        from tools.chatbot_file_cohort.paused_recovery import PROFILE,CLAIM as PAUSED_CLAIM
        profile=PROFILE;claim=PAUSED_CLAIM
        if mounted:
            from tools.chatbot_file_cohort.mounted_recovery import PROFILE as MOUNTED,CLAIM as MOUNTED_CLAIM
            profile=MOUNTED;claim=MOUNTED_CLAIM
        if signed:
            from tools.chatbot_file_cohort.signed_recovery import PROFILE as SIGNED,CLAIM as SIGNED_CLAIM
            profile=SIGNED;claim=SIGNED_CLAIM
    if backup:
        from tools.chatbot_file_cohort.backup_recovery import PROFILE as BACKUP,CLAIM as BACKUP_CLAIM
        profile=BACKUP;claim=BACKUP_CLAIM
    if migration:
        from tools.chatbot_file_cohort.migration_recovery import PROFILE as MIGRATION,CLAIM as MIGRATION_CLAIM
        profile=MIGRATION;claim=MIGRATION_CLAIM
    require(not os.path.lexists(evidence.PARENT/claim),'POSTGRANT_CONTINUATION_ALREADY_RESERVED_INSPECT_ONLY')
    report('POSTGRANT_RETAINED_HISTORY_PREFLIGHT')
    previous=read_predecessor(profile);old=previous['prepared'];bundle=previous['bundle']
    qualified_helpers(stage,bundle)
    from tools.chatbot_file_cohort import assemble
    from tools.chatbot_file_cohort.delivery import native_environment
    from tools.chatbot_file_cohort.owner_preparation import prepare_owner
    from tools.chatbot_file_cohort.iam_session import ensure_admin_session
    from tools.chatbot_file_cohort.human_session import HumanSession
    paths=json.loads(source_bytes(source/'tools/chatbot_file_cohort/source_paths.json'))
    sources={name:(base64.b64decode(bundle['sources'][name],validate=True) if path.startswith('ouf-onboarding:')
        else source_bytes(source/path))for name,path in paths.items()}
    loader=source_bytes(source/'tools/chatbot_file_cohort/runtime.py')
    closure=assemble.source_closure(source_commit=args.source_commit,
        source_pins={'ouf-deploy':args.source_commit,'ouf-onboarding':ONBOARDING},sources=sources,loader=loader)
    for command in ('python','docker','systemctl','systemdRun'):
        require(closure['executables'][command]==previous['review']['sourceClosure']['executables'][command],
            'POSTGRANT_NATIVE_EXECUTABLE_CHANGED')
    engine=Engine(old['engine']['socketPath'],tuple(old['engine']['socketBinding']))
    native_environment(engine,closure['executables']['docker'],new_directory(stage,'docker-cli'))
    if paused:report('PAUSED_COMPLETE_OCI_AND_ROOTFS_PREFLIGHT',maximumSeconds=180)
    native=current_baseline(previous,engine)
    report('POSTGRANT_RETAINED_HISTORY_AND_NATIVE_PREFLIGHT_PASSED',**native)
    report('CURRENT_ADMINISTRATIVE_SESSION')
    ensure_admin_session(engine,closure['executables']['docker'],new_directory(stage,'iam-session'),emit=emit_line)
    owner_input=prepare_owner(source_commit=args.source_commit,source_closure_hash=digest(closure),
        cohort_id='chatbot-file-'+str(RUN),docker_binding=closure['executables']['docker'],engine_path=engine.path)
    selected=copy.deepcopy(old['authorization']['plan']['selection'])
    actor={k:selected[k]for k in ('issuer','tenant','subject')}
    proof=proof_scope(previous,actor)
    human_dir=new_directory(stage,'human-session')
    session=HumanSession(selected,human_dir,human_dir/'human-access.jwt',int(time.time())+7200)
    stop=threading.Event();session.login(emit=emit_line,stop=stop);session.start_refresh(stop,emit=emit_line)
    try:
        prepared=copy.deepcopy(old)
        prepared.pop('previousFiniteActions',None);prepared.pop('ownerPregrantRecovery',None);prepared.pop('ownerRenewalActor',None)
        prepared['postGrantRecovery']=proof
        prepared['postGrantWorkerDirectory']=str(new_directory(stage,'postgrant-worker'))
        prepared['owner']=owner_input['owner']
        authorization=prepared['authorization']
        authorization['adminTokenFile']=authorization['mcpTokenFile']=str(session.token_path)
        authorization['plan']['sessionBinding']=session.binding()
        validate_authorization_rebind(old['authorization']['plan'],authorization['plan'])
        if backup:
            from tools.chatbot_file_cohort.databases import mcp_backup_preflight,compile_mcp_backup_reader
            db=prepared['databasePlan'];mcp=next(r for r in db['modules'] if r['module']=='mcp')
            facts=mcp_backup_preflight(db['postgresRuntimeBinding']['containerId'],mcp['database'],db['mcpAuditRoleAdministration']['admin'])
            prepared['databasePlan']=compile_mcp_backup_reader(db,facts)
            prepared['cohortPlan']['databasePlanHash']=digest(prepared['databasePlan'])
        prepared['cohortPlan']['authorizationPlanHash']=digest(authorization['plan'])
        cohort_hash=digest(prepared['cohortPlan'])
        registry=prepared['registry'];registry['postGrantRecovery']=copy.deepcopy(proof)
        _,context=assemble.authority_directory('chatbot-file-'+str(RUN),digest(closure),prepared['imagePlan']['cohortManifestHash'])
        root=Path(context)/'registry'
        registry['directoryPlan']={name:str(root if name=='root' else root/name)for name in old['registry']['directoryPlan']}
        registry['directoryPlan']['backup']=proof['retainedBackupDirectory']
        registry['cohortPlanHash']=cohort_hash
        if paused:
            from tools.chatbot_file_cohort.paused_recovery import proposed_recipe
            registry['nodeRecipe']=proposed_recipe(registry,retained_mount=mounted)
        recipe=registry['nodeRecipe'];recipe['sourceClosureHash']=digest(closure)
        mounted=recipe['renewableToken'];mounted.pop('directoryCustodyScopeHash',None)
        mounted.update(directoryDevice=previous['output']['outputIdentity']['device'],
            directoryInode=previous['output']['outputIdentity']['inode'])
        registry['intents']['ATTEST_NEW_OCI_PEER'].update(sourceClosureHash=digest(closure),nodeRecipeHash=digest(recipe))
        registry['intents']['RELEASE_PRODUCERS']['cohortReviewHash']=cohort_hash
        require(registry['creationRequest']==old['registry']['creationRequest']
            and all(registry['intents'][phase]==old['registry']['intents'][phase]
                for phase in list(old['registry']['intents'])if phase not in ('ATTEST_NEW_OCI_PEER','RELEASE_PRODUCERS')),
            'POSTGRANT_EXISTING_CONTAINER_AND_CONSUMED_INTENTS_MUST_REMAIN_EXACT')
        assemble.stage(stage,'postgrant-preparation-evidence.json',encoded({'schema':'ouf.postgrant-preparation-evidence.v1',
            'proof':proof,'native':native,'owner':owner_input['evidence'],'serviceMutations':0,'grantRequests':0}))
        compiled=assemble.assemble(prepared=prepared,sources=sources,loader=loader,
            bootstrap=source_bytes(source/'tools/chatbot_file_cohort/child_bootstrap.py'),closure=closure,
            staging_directory=stage,lineage={k:previous['review'][k]for k in ('predecessorHistoryHash','predecessorIncidentRef')},
            preparation_source_hash=args.preparation_source_hash,cohort_id='chatbot-file-'+str(RUN))
        return finish_review(args,compiled,session,stop,assemble,closure)
    finally:
        stop.set()
        if session.thread is not None:session.thread.join(45)
