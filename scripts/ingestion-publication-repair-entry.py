"""Standalone native administrative action. No infrastructure or source activation."""
import copy,hashlib,json,os,re,signal,stat,threading,time
from pathlib import Path
import qualified_owner_authorization_lifecycle as lifecycle
import qualified_owner_scope_catalogue as scope_catalogue
from tools.chatbot_file_cohort.human_session import HumanSession
from tools.linked_property_rollout.preparation import root_directory,read_file,write_new,encoded
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.source_revision_update.owner import require,digest
from tools.ingestion_read_authorization import authorization,authority

CAP='ingestion.operations.read'

def publish_json(context,name,value):
    """Only administrative documents; reuse exact private custody/write primitives.

    The rollout publisher deliberately excludes the plan and result names. Its
    whitelist stays unchanged; this administrative owner has its own contract.
    """
    schemas={'authorization-plan.json':'ouf.chatbot-file-authorization-plan.v1',
        'review.json':'ouf.semantic-scoped-infrastructure-review.v1',
        'administrative-result.json':'ouf.ingestion-read-administrative-result.v1'}
    require(name in schemas and type(value)is dict and value.get('schema')==schemas[name],
        'EXACT_ADMINISTRATIVE_DOCUMENT_REQUIRED')
    context=Path(context)
    require(context.parent==authority.evidence.PARENT and re.fullmatch(
        'ingestion-read-authorization-execution-[A-Za-z0-9_-]{8,64}',context.name),
        'EXACT_ADMINISTRATIVE_DOCUMENT_CONTEXT_REQUIRED')
    root_directory(context);row=context.lstat()
    require(row.st_uid==row.st_gid==0 and stat.S_IMODE(row.st_mode)==0o700,
        'PRIVATE_ADMINISTRATIVE_DOCUMENT_CONTEXT_REQUIRED')
    raw=encoded(value);require(0<len(raw)<=8388608,'BOUNDED_ADMINISTRATIVE_DOCUMENT_REQUIRED')
    path=context/name;write_new(path,raw)
    fd=os.open(context,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    require(read_file(path,hashlib.sha256(raw).hexdigest())==raw,'ADMINISTRATIVE_DOCUMENT_READBACK_FAILED')

def primitives(sources):
    catalogue=encoded([{'ownerRef':'ingestion','descriptor':{'capabilityId':CAP,
        'operation':'READ','requiredScope':CAP,'allowedActors':['HUMAN']}}])
    bindings={'scripts/r4a_authorization_lifecycle.py':hashlib.sha256(sources[lifecycle.__name__]).hexdigest(),
        'scripts/r4a_keycloak_client_scope_catalogue.py':hashlib.sha256(sources[scope_catalogue.__name__]).hexdigest(),
        'catalogue/chatbot-source-review-capabilities.json':hashlib.sha256(catalogue).hexdigest()}
    return authorization.OwnerPrimitives.from_qualified_modules(lifecycle,scope_catalogue,catalogue,bindings,
        profile=authorization.INGESTION_READ_PROFILE)


def validate_plan(plan,source_id):
    require(plan['profile']==authorization.INGESTION_READ_PROFILE and plan['roleProposal']is None
        and plan['addedPermissions']==[] and plan['targetRoles']==plan['baseline']['roles']
        and plan['candidatePolicy']['grants']==plan['baseline']['active']['policy']['grants']
        and plan['requiredScopes']=={'chatgpt':[CAP],'ths':[]}
        and set(plan['scopeCreations'])<={CAP}
        and all(b['purpose']=='chatgpt' and b['scopeName']==CAP for b in plan['scopeBindings'])
        and all(r['ownerRef']=='ingestion' and r['descriptor']=={'capabilityId':CAP,'operation':'READ',
            'requiredScope':CAP,'allowedActors':['HUMAN']} for r in plan['registrationAdditions'])
        and all(d['capabilityId']==CAP for d in plan['addedDescriptors'])
        and plan['readScope']=={'capabilityId':CAP,'constraints':authorization.owner_permission_constraints(
            'operational',{'module':'INGESTION','sourceRef':source_id},['TENANT_OPERATIONAL']),
            'grantPublicationAllowed':False,'separateFiniteGrantReviewRequired':True}
        and plan['issueTokens']is False and plan['revokeSessions']is False,
        'EXACT_REGISTRATION_POLICY_SCOPE_ONLY_PLAN_REQUIRED')


def validate_continuation(case,read,context):
    continuation=case['existingSessionContinuation']
    require(continuation['schema']=='ouf.ingestion-existing-session-continuation.v1'
        and continuation['newHumanLoginAllowed']is False and continuation['budgetReset']is False
        and continuation['maximumCumulativeOAuthAttempts']==256,
        'EXACT_EXISTING_SESSION_CONTINUATION_REQUIRED')
    for path,expected in continuation['fileBindings'].items():
        read(path,expected=expected)
    claim=continuation['claimBinding'];row=read(claim['path'],expected=claim['sha256'])
    require(row['context']==str(context)and row['originalContext']==continuation['originalContext']
        and row['preflightContext']==continuation['preflightContext']
        and row['planHash']==continuation['planHash']and row['priorOAuthAttempts']==case['priorOAuthAttempts']
        and row['maximumCumulativeOAuthAttempts']==256 and row['budgetReset']is False
        and row['automaticReplayAllowed']is False,'EXACT_ONE_USE_CONTINUATION_CLAIM_REQUIRED')
    for name in ('authority.json','review.json','authorization-plan.json','issuance.claim.json',
            'decision.json','human.json','administrative-result.json','authorization'):
        require(not os.path.lexists(Path(continuation['originalContext'])/name),
            'PREDECESSOR_AUTHORITY_OR_EFFECT_RECONCILIATION_REQUIRED')
    if 'publisherRepair'in case:
        repair=case['publisherRepair']
        require(repair['schema']=='ouf.ingestion-administrative-publisher-repair.v1'
            and repair['rejectedNames']==['authorization-plan.json','administrative-result.json']
            and repair['guardCode']=='EXACT_ROLLOUT_DOCUMENT_REQUIRED',
            'EXACT_PRIVATE_PUBLISHER_REPAIR_REQUIRED')
        for name in ('authority.json','review.json','authorization-plan.json','issuance.claim.json',
                'decision.json','human.json','administrative-result.json','authorization'):
            require(not os.path.lexists(Path(repair['predecessorContext'])/name),
                'REPAIRED_PREDECESSOR_EFFECT_RECONCILIATION_REQUIRED')
    plan=read(continuation['planPath'],expected=continuation['planHash'])
    require(digest(plan)==continuation['planHash']and plan['sessionBinding']==case['humanBinding'],
        'EXACT_VERIFIED_PLAN_AND_HUMAN_REQUIRED')
    validate_plan(plan,case['sourceId'])
    return plan


def refresh_existing(human,binding,minimum):
    row=human._read();human._check_identity_and_budget(row);human._check(row)
    require(row['binding']==binding and 212<=minimum<=row['attempts']<=256
        and row['state']!='BLOCKED'and not os.path.lexists(human.directory/'successor-window.claim.json'),
        'EXACT_UNEXTENDED_CUMULATIVE_HUMAN_REQUIRED')
    before=row['attempts'];human.refresh_if_due()
    require(human.current()==binding,'CURRENT_HUMAN_BINDING_CHANGED')
    row=human._read();human._check(row)
    require(before<=row['attempts']<=256,'CUMULATIVE_HUMAN_BUDGET_CHANGED')
    return row['attempts']


def main(original,sources,closure,case,context,read,emit):
    emit('OUF_INGESTION_ADMIN_PHASE=VERIFY_EXECUTABLE_CLOSURE')
    authority.closure_valid(closure);context=Path(context)
    emit('OUF_INGESTION_ADMIN_PHASE=VERIFY_PLAN_AND_PREDECESSOR')
    plan=validate_continuation(case,read,context)
    selection=original['authorization']['plan']['selection'];binding=case['humanBinding']
    require(plan['selection']==selection,'INSTALLATION_SELECTION_CHANGED')
    authorization.validate_session_binding(binding,selection,profile=authorization.INGESTION_READ_PROFILE)
    human=HumanSession(selection,Path(binding['sessionDirectory']),Path(binding['tokenPath']),binding['expiresAt'])
    emit('OUF_INGESTION_ADMIN_PHASE=EXISTING_HUMAN_REFRESH')
    refresh_existing(human,binding,case['priorOAuthAttempts'])
    authority.current_authorities(int(time.time())+910)
    emit('OUF_INGESTION_ADMIN_PHASE=OWNER_BASELINE_READ')
    transport=authorization.OwnerTransport(selection,human.token_path,human.token_path,human_session=human)
    owner=primitives(sources);observed=transport.observe()
    require(observed==plan['baseline'],'COMPLETE_AUTHORIZATION_PREFLIGHT_DRIFT')
    require(owner.bindings==plan['helperBindings'],'QUALIFIED_OWNER_PRIMITIVES_CHANGED')
    emit('OUF_INGESTION_ADMIN_PHASE=PRIVATE_PLAN_PUBLICATION')
    publish_json(context,'authorization-plan.json',plan)
    scopes={'chatbotFileAuthorization':authorization.authorization_scope(plan),
        'ingestionReadAdministration':authority.administrative_scope(digest(plan),case['sourceId'])}
    seconds=min(900,human.expires_at-int(time.time())-10)
    require(seconds>=600,'HUMAN_WINDOW_TOO_SHORT_FOR_ADMINISTRATIVE_ACTION')
    review=authority.compile_action_review('INGESTION_READ_AUTHORIZATION',closure,scopes,human.current(),context,
        {'predecessorHistoryHash':case['predecessorHistoryHash'],'predecessorIncidentRef':digest(case['sourceId'])},seconds)
    review['absoluteExpiresAt']=human.expires_at-5
    publish_json(context,'review.json',review)
    emit('OUF_INGESTION_ADMIN_PHASE=NATIVE_APPROVO_REQUIRED')
    decision=authority.terminal_consent(review,
        'Azione amministrativa HUMAN distinta: fonte '+case['sourceId']+'. Tecniche8/8; funzionali4/6.\n'
        'Registro la sola capability ingestion.operations.read per attori HUMAN; pubblico il descrittore nella policy\n'
        'e associo il solo scope OAuth corrispondente al client ChatGPT gia selezionato.\n'
        'Ruoli, assegnazioni e grant esistenti restano invariati. Nessun nuovo grant viene pubblicato.\n'
        'Il grant temporaneo sulla fonte richiedera una successiva proposta e decisione THS.\n'
        'Nessun servizio, database, rotta, attivazione della fonte, acquisizione o job viene modificato.\n'
        'Massimo15 minuti. Esiti incerti richiedono riconciliazione; nessun rilancio automatico.\n'
        'Piano privato completo: '+str(context/'authorization-plan.json')+'\nRevisione: '+str(context/'review.json'))
    validate_plan(plan,case['sourceId'])
    emit('OUF_INGESTION_ADMIN_PHASE=ISSUE_EXACT_AUTHORITY')
    action=authority.issue_action(review,decision,human)
    directory=context/'authorization';directory.mkdir(mode=0o700)
    cancelled=threading.Event();handlers={}
    for sig in(signal.SIGINT,signal.SIGTERM,signal.SIGHUP):
        handlers[sig]=signal.signal(sig,lambda *_:cancelled.set())
    def current_time():
        require(not cancelled.is_set(),'INGESTION_ADMINISTRATIVE_ACTION_CANCELLED')
        return time.time()
    action.authority.clock=current_time;human.start_refresh(cancelled,emit=emit)
    try:
        emit('OUF_INGESTION_ADMIN_PHASE=OWNER_DELTA_AND_READBACK')
        action.guard('ingestionReadAdministration',scopes['ingestionReadAdministration'])
        delta=authorization.AuthorizationDelta(action,plan,Journal(directory),transport,owner)
        delta.initialize();receipt=delta.apply()
        result={'schema':'ouf.ingestion-read-administrative-result.v1','status':'ADMINISTRATIVE_READBACK_COMPLETE',
            'contextPath':str(context),'sourceId':case['sourceId'],'authorizationReceipt':receipt,
            'rolesChanged':False,'grantsPublished':0,'sourceActivated':False,'infrastructureEffects':0,
            'separateFiniteGrantReviewRequired':True,'freshChatClientTokenScopesProven':False,'planHash':digest(plan),
            'oauthAttemptsAfter':human._read()['attempts'],'maximumCumulativeOAuthAttempts':256,
            'newHumanLoginAllowed':False,'budgetReset':False,'automaticReplayAllowed':False,
            'completedTechnicalPhases':8,'functionalMilestonesProven':4,'notReleaseAcceptance':True}
        publish_json(context,'administrative-result.json',result)
        emit('OUF_INGESTION_ADMIN_RESULT='+encoded(result).decode())
    finally:
        cancelled.set()
        if human.thread is not None:human.thread.join(35)
        for sig,handler in handlers.items():signal.signal(sig,handler)
