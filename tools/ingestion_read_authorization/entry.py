"""Standalone native administrative action. No infrastructure or source activation."""
import copy,hashlib,json,os,signal,threading,time
from pathlib import Path
import qualified_owner_authorization_lifecycle as lifecycle
import qualified_owner_scope_catalogue as scope_catalogue
from tools.chatbot_file_cohort.human_session import HumanSession
from tools.linked_property_rollout.preparation import publish_json,write_new,encoded
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.source_revision_update.owner import require,digest
from tools.ingestion_read_authorization import authorization,authority,login,iam

CAP='ingestion.operations.read'

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


def main(original,sources,closure,case,context,read,emit):
    authority.closure_valid(closure);context=Path(context)
    selection=original['authorization']['plan']['selection'];binding=case['humanBinding']
    authorization.validate_session_binding(binding,selection,profile=authorization.INGESTION_READ_PROFILE)
    human=HumanSession(selection,Path(binding['sessionDirectory']),Path(binding['tokenPath']),binding['expiresAt'])
    row=human._read();human._check_identity_and_budget(row)
    require(row['binding']==binding and not os.path.lexists(human.directory/'successor-window.claim.json'),
        'EXACT_LATEST_NATIVE_HUMAN_REQUIRED')
    transport=authorization.OwnerTransport(selection,human.token_path,human.token_path)
    iam.ensure(original,case,context,closure,transport)
    authority.current_authorities(int(time.time())+910)
    human=login.authenticate(human,case,context,closure,read,emit)
    transport=authorization.OwnerTransport(selection,human.token_path,human.token_path,human_session=human)
    owner=primitives(sources);observed=transport.observe()
    plan=authorization.compile_plan(observed,owner,selection,include_ingestion_status=False,
        source_id=case['sourceId'],session_binding=human.current())
    validate_plan(plan,case['sourceId']);publish_json(context,'authorization-plan.json',plan)
    scopes={'chatbotFileAuthorization':authorization.authorization_scope(plan),
        'ingestionReadAdministration':authority.administrative_scope(digest(plan),case['sourceId'])}
    seconds=min(900,human.expires_at-int(time.time())-10)
    require(seconds>=600,'HUMAN_WINDOW_TOO_SHORT_FOR_ADMINISTRATIVE_ACTION')
    review=authority.compile_action_review('INGESTION_READ_AUTHORIZATION',closure,scopes,human.current(),context,
        {'predecessorHistoryHash':case['predecessorHistoryHash'],'predecessorIncidentRef':digest(case['sourceId'])},seconds)
    review['absoluteExpiresAt']=human.expires_at-5
    publish_json(context,'review.json',review)
    decision=authority.terminal_consent(review,
        'Azione amministrativa HUMAN distinta: fonte '+case['sourceId']+'. Tecniche8/8; funzionali4/6.\n'
        'Registro la sola capability ingestion.operations.read per attori HUMAN; pubblico il descrittore nella policy\n'
        'e associo il solo scope OAuth corrispondente al client ChatGPT gia selezionato.\n'
        'Ruoli, assegnazioni e grant esistenti restano invariati. Nessun nuovo grant viene pubblicato.\n'
        'Il grant temporaneo sulla fonte richiedera una successiva proposta e decisione THS.\n'
        'Nessun servizio, database, rotta, attivazione della fonte, acquisizione o job viene modificato.\n'
        'Massimo15 minuti. Esiti incerti richiedono riconciliazione; nessun rilancio automatico.\n'
        'Piano privato completo: '+str(context/'authorization-plan.json')+'\nRevisione: '+str(context/'review.json'))
    validate_plan(plan,case['sourceId']);action=authority.issue_action(review,decision,human)
    directory=context/'authorization';directory.mkdir(mode=0o700)
    cancelled=threading.Event();handlers={}
    for sig in(signal.SIGINT,signal.SIGTERM,signal.SIGHUP):
        handlers[sig]=signal.signal(sig,lambda *_:cancelled.set())
    def current_time():
        require(not cancelled.is_set(),'INGESTION_ADMINISTRATIVE_ACTION_CANCELLED')
        return time.time()
    action.authority.clock=current_time;human.start_refresh(cancelled,emit=emit)
    try:
        action.guard('ingestionReadAdministration',scopes['ingestionReadAdministration'])
        delta=authorization.AuthorizationDelta(action,plan,Journal(directory),transport,owner)
        delta.initialize();receipt=delta.apply()
        result={'schema':'ouf.ingestion-read-administrative-result.v1','status':'ADMINISTRATIVE_READBACK_COMPLETE',
            'contextPath':str(context),'sourceId':case['sourceId'],'authorizationReceipt':receipt,
            'rolesChanged':False,'grantsPublished':0,'sourceActivated':False,'infrastructureEffects':0,
            'separateFiniteGrantReviewRequired':True,'freshChatClientTokenScopesProven':False,
            'completedTechnicalPhases':8,'functionalMilestonesProven':4,'notReleaseAcceptance':True}
        publish_json(context,'administrative-result.json',result)
        emit('OUF_INGESTION_ADMIN_RESULT='+encoded(result).decode())
    finally:
        cancelled.set()
        if human.thread is not None:human.thread.join(35)
        for sig,handler in handlers.items():signal.signal(sig,handler)
