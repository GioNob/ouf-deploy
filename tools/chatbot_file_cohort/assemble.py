"""Turn one complete private intake into one review and one finite process.

The compilation authority below deliberately has no mandate or signatures.
Its guard cannot succeed. It is used only by effect-free scope constructors;
the real current mandate is acquired and issued after the full review exists.
"""
import base64
import copy
import hashlib
import os
from pathlib import Path
import re
import subprocess
import time

import iam_binding_candidate as evidence
import iam_governance_intake as governance
from iam_owner_action import publish,stdlib_binding
from cutover_authority import CutoverAuthority
from file_only_profile import FileOnlyProfile
from file_only_installation import compile_scope as registry_scope
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.chatbot_file_cohort.action_process import compile_process_plan,FiniteActionProcess,private_file
from tools.chatbot_file_cohort.containers import installation_scope
from tools.chatbot_file_cohort.gateway import publication_scope,NamespaceAdmin
from tools.chatbot_file_cohort.gateway_runtime import runtime_scope
from tools.chatbot_file_cohort.images import image_import_scope
from tools.chatbot_file_cohort.authorization import authorization_scope
from tools.chatbot_file_cohort.delivery import build_owner
from tools.chatbot_file_cohort.review import compile_review,terminal_decision,issue,digest,encoded,require
from tools.chatbot_file_cohort.runtime import declaration


def source_closure(*,source_commit,source_pins,sources,loader):
    programs={name:governance.executable(path) for name,path in (
        ('python','/usr/bin/python3'),('docker','/usr/bin/docker'),('openssl','/usr/bin/openssl'),
        ('systemctl','/usr/bin/systemctl'),('systemdRun','/usr/bin/systemd-run'))}
    reply=subprocess.run([programs['openssl']['path'],'version'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,timeout=5,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    match=re.match(rb'OpenSSL ([0-9]+\.[0-9]+\.[0-9]+[a-z]?)\b',reply.stdout)
    require(reply.returncode==0 and len(reply.stdout)<=256 and match is not None,'OPENSSL_VERSION_OBSERVATION_UNPROVEN')
    programs['openssl']['version']=match[1].decode()
    library=stdlib_binding()
    return {'declaration':declaration(source_commit,sources,loader,source_pins),
        'executables':programs,'stdlibHash':digest(library),'stdlibFileCount':len(library['fileHashes'])}


def authority_directory(cohort_id,closure_hash,manifest_hash):
    operation=digest({'cohortId':cohort_id,'sourceClosureHash':closure_hash,'cohortManifestHash':manifest_hash,
                      'operation':'ONE_FINITE_CHATBOT_FILE_COHORT_ACCEPTANCE'})
    return operation,str(evidence.PARENT/('chatbot-file-cohort-signed-'+operation))


def directories(context,registry):
    names=('authorization','containers','databases','gateway','gatewayRuntime','backups','dockerCli',
           'imageSemantic','imageUdp','imageOnboarding','imageIngestion','imageMcp')
    result={name:str(Path(context)/name) for name in names}
    for name,path in registry['directoryPlan'].items():
        require(Path(path).is_relative_to(context) and Path(path)!=Path(context),
                'REGISTRY_PRIVATE_CHILDREN_MUST_USE_GROUPED_CONTEXT')
        result['registry'+name.capitalize()]=path
    require(len(set(result.values()))==len(result),'ALL_ACTION_DIRECTORIES_MUST_BE_DISTINCT')
    return result


def stage(directory,name,raw):
    require(type(raw) is bytes and 0<len(raw)<=8388608,'BOUNDED_COMPLETE_PRIVATE_INTAKE_ARTIFACT_REQUIRED')
    with protected_directory(directory) as fd:
        path=Path(directory)/name
        binding={'path':str(path),'sha256':hashlib.sha256(raw).hexdigest()}
        try:target=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
        except FileExistsError:
            require(private_file(binding,8388608)==raw,'PRIVATE_ACTION_ARTIFACT_RECONCILIATION_REQUIRED')
        else:
            try:
                with os.fdopen(os.dup(target),'wb') as output:
                    output.write(raw);output.flush();os.fsync(output.fileno())
                os.fsync(fd)
            finally:os.close(target)
        require(private_file(binding,8388608)==raw,'PRIVATE_ACTION_ARTIFACT_PUBLICATION_UNPROVEN')
    return binding


def assemble(*,prepared,sources,loader,bootstrap,closure,staging_directory,lineage,
             preparation_source_hash,cohort_id):
    require(type(prepared) is dict and prepared.get('schema')=='ouf.chatbot-file-cohort-prepared-inputs.v1',
            'COMPLETE_GROUPED_INTAKE_REQUIRED')
    closure_hash=digest(closure)
    require(prepared['gatewayPlan']['transportBinding']['pythonExecutable']==closure['executables']['python'],
            'GATEWAY_SUBPROCESS_MUST_USE_SAME_REVIEWED_PYTHON')
    expected_declaration=declaration(closure['declaration']['sourceCommit'],sources,loader,
        closure['declaration']['sourcePins'])
    require(expected_declaration==closure['declaration'],'COMPLETE_EXECUTING_SOURCE_CLOSURE_CHANGED')
    operation,context=authority_directory(cohort_id,closure_hash,prepared['imagePlan']['cohortManifestHash'])
    require(not os.path.lexists(context),'FULL_ACTION_CONTEXT_ALREADY_EXISTS_NO_REPLAY')
    profile=FileOnlyProfile(prepared['registry']['creationRequest'],prepared['registry']['configtree'])
    expected={'sourceClosureHash':closure_hash,'creationRequestHash':digest(profile.request),
              'intakeHash':digest(prepared),**lineage}
    # A real verifier object whose deliberately absent mandate denies all calls.
    # No permission callback or installed-owner surrogate is introduced.
    empty_hash=hashlib.sha256(b'UNISSUED_PREPARATION_ONLY').hexdigest()
    verifier=DetachedAuthenticator(governance.POLICY,str(staging_directory),closure['executables']['openssl'])
    gate=CutoverAuthority(verifier,{'path':str(Path(context)/'unissued-mandate.json'),'sha256':empty_hash},
        empty_hash,governance.CONTEXT,expected,execution_profile=profile)
    compiler_action=AggregateAction(gate,encoded({'schema':'ouf.preparation-without-authority.v1'}),closure_hash)
    owner=build_owner(compiler_action,prepared,sources)
    mounted=prepared['registry']['nodeRecipe']['renewableToken']
    require(mounted['directoryCustodyScopeHash']==digest(owner.output.scope)
        and mounted['source']==owner.first.binding.output_directory
        and mounted['fileName']==owner.first.binding.output_member
        and mounted['gid']==owner.first.binding.output_gid
        and mounted['ownerBindingHash']==owner.first.binding.digest(),
        'SAME_ACTION_FUTURE_OUTPUT_CUSTODY_AND_NATIVE_OWNER_REQUIRED')
    scopes=owner.scopes()
    scopes.update(applicationCohortInstallation=installation_scope(prepared['cohortPlan']),
        gatewayRoutePublication=publication_scope(prepared['gatewayPlan']),
        chatbotFileAuthorization=authorization_scope(prepared['authorization']['plan']),
        applicationRegistryCutover=registry_scope(prepared['registry'],closure_hash),
        cohortImageImport=image_import_scope(prepared['imagePlan']))
    runtime=prepared['gatewayRuntimePlan']
    scopes['gatewayRuntimeInstallation']=runtime_scope(runtime) if runtime is not None else {
        'profile':'ouf.chatbot-file-cohort.gateway-runtime.v1','required':False,
        'retainedTransportHash':digest(prepared['gatewayPlan']['transportBinding']),
        'proposalKeyHash':prepared['gatewayPlan']['proposalKeyBinding']['sha256'],
        'automaticRollbackAllowed':False,'automaticWriteReplayAllowed':False}
    bundle={'schema':'ouf.chatbot-file-cohort-closed-source-bundle.v1','declaration':expected_declaration,
        'loader':base64.b64encode(loader).decode('ascii'),
        'sources':{name:base64.b64encode(raw).decode('ascii') for name,raw in sorted(sources.items())},
        'prepared':copy.deepcopy(prepared)}
    bundle_binding=stage(staging_directory,'child-bundle.json',encoded(bundle))
    bootstrap_binding=stage(staging_directory,'finite-child.py',bootstrap)
    scopes['finiteActionProcess']=compile_process_plan(logical_operation=operation,source_closure_hash=closure_hash,
        programs={key:closure['executables'][key] for key in ('python','systemdRun','systemctl')},
        bootstrap=bootstrap_binding,bundle=bundle_binding,authority_directory=context,
        directory_plan=directories(context,prepared['registry']))
    review=compile_review(source_closure=closure,execution_profile=profile,scopes=scopes,
        phase_intents=prepared['registry']['intents'],lineage=lineage,
        input_hashes={'preparedInputs':digest(prepared),'preparationSourceClosure':preparation_source_hash,
                     'cohortManifest':prepared['imagePlan']['cohortManifestHash']})
    database=prepared.get('databasePlan')
    if database is not None and database.get('mcpAuditRoleAdministration') is not None:
        require(digest(database)==prepared['cohortPlan'].get('databasePlanHash'),
                'REVIEWED_DATABASE_PLAN_HASH_REQUIRED')
        selected=next(row for row in database['modules'] if row['module']=='mcp')
        # Include the concrete temporary privileges and identities in the
        # operator's private review, not just their digest in the closed bundle.
        review['mcpMigrationReview']={'databasePlanHash':digest(database),
            'database':selected['database'],'applicationRole':selected['user'],
            'administration':copy.deepcopy(database['mcpAuditRoleAdministration']),
            'preflight':copy.deepcopy(database['mcpAuditRolePreflight'])}
        require(len(encoded(review))<=262144,'BOUNDED_WHOLE_ACTION_REVIEW_REQUIRED')
    review_binding=stage(staging_directory,'full-action-review.json',encoded(review))
    return {'review':review,'reviewBinding':review_binding,'executionProfile':profile,
            'processPlan':scopes['finiteActionProcess'],'context':context}


def approve_and_start(compiled,session,refresh_stop):
    """Approval is the final step: the complete sources, plan and review exist."""
    decision=terminal_decision(compiled['review'],compiled['reviewBinding']['path'])
    # Stop the parent's refresh invocation before the child owns that same
    # retained session. This callback has no authority or policy semantics.
    from tools.chatbot_file_cohort.human_session import HumanSession,HumanSessionPaused
    import threading
    require(type(session) is HumanSession and type(refresh_stop) is threading.Event,
            'EXACT_PREPARATION_HUMAN_SESSION_REQUIRED')
    while True:
        require(time.time()<decision['expiresAt'] and not refresh_stop.is_set(),
                'HUMAN_DECISION_EXPIRED_OR_SESSION_CANCELLED_BEFORE_ISSUANCE')
        try:
            binding=session.binding()
            break
        except HumanSessionPaused as error:
            if error.retry_at is None:raise
            print('HUMAN_SESSION_PAUSED='+error.reason,flush=True)
            require(not refresh_stop.wait(min(5,max(1,error.retry_at-time.time()),
                max(0,decision['expiresAt']-time.time()))),
                'PREPARATION_HUMAN_SESSION_CANCELLED')
    require(decision['expiresAt']<=binding['expiresAt'],
            'HUMAN_SESSION_MUST_COVER_COMPLETE_REVIEWED_ACTION')
    refresh_stop.set()
    if session.thread is not None:
        session.thread.join(timeout=45)
        require(not session.thread.is_alive(),'PREPARATION_SESSION_HANDOFF_NOT_COMPLETE')
    action,context=issue(compiled['review'],decision,compiled['executionProfile'])
    evidence.require(str(context)==compiled['context'],'ISSUED_CONTEXT_DIFFERS_FROM_COMPLETE_REVIEW')
    started=FiniteActionProcess(action,compiled['processPlan']).start()
    return {'schema':'ouf.chatbot-file-cohort-start-receipt.v1','authorityHash':action.authority_hash,
        'context':str(context),'unit':compiled['processPlan']['unit'],'process':started,
        'maximumSessionSeconds':compiled['review']['maximumElapsedSeconds'],'budgetReset':False,
        'permanentRuntimeAcceptance':False,'chatbotEndToEndProven':False,'notReleaseAcceptance':True}
