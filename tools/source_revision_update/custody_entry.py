"""One reviewed infrastructure release, then the existing authorization owner.

Source revision preparation/publication and acquisition are deliberately absent.
"""
import copy
import json
from pathlib import Path
import signal
import threading
import time
from tools.chatbot_file_cohort import authorization
from tools.linked_property_rollout.entry import current_human
from tools.linked_property_rollout.preparation import publish_json, write_new, encoded
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.source_revision_update import authority,login,preparation
from tools.source_revision_update.owner import require,digest,scope,ReadinessUpdate,UpdatePaused
from tools.source_revision_update.database import Database
from tools.source_revision_update.native import NativePorts
from engine_creation import Engine


def wait_for_role(delta, transport, proposal, cancelled, emit):
    """Only idempotent proposal reads; reserve attempts before network dispatch.

    Never hold the journal lock during waits/HTTP, renew authority, extend a
    deadline, acknowledge a HUMAN decision or create a replacement proposal.
    """
    require(type(delta) is authorization.AuthorizationDelta and type(transport) is authorization.OwnerTransport,
            'REAL_NATIVE_AUTHORIZATION_OWNER_REQUIRED')
    key = 'sourceRevisionRoleObservation'
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    while True:
        delta.guard(); now = time.time(); mono = time.monotonic()
        with delta.journal.invocation():
            row = delta.record(); budget = copy.deepcopy(row.get(key))
            if budget is None:
                expiry = min(now+86400,json.loads(delta.action.raw)['expiresAt'])
                budget = {'proposalId':proposal,'planHash':delta.hash,'bootId':boot,'attempts':0,
                    'startedAt':now,'deadline':expiry,'monotonicDeadline':mono+expiry-now,
                    'nextReadAt':now,'nextMonotonic':mono,'state':'WAIT','budgetReset':False,
                    'lastWall':now,'lastMonotonic':mono}
            require(budget['proposalId'] == proposal and budget['planHash'] == delta.hash
                and budget['bootId'] == boot and budget['budgetReset'] is False
                and budget['state'] != 'ATTEMPTING' and now >= budget['lastWall']
                and mono >= budget['lastMonotonic'],'ROLE_OBSERVATION_RECONCILIATION_REQUIRED')
            require(budget['attempts'] < 128 and now < budget['deadline'] and mono < budget['monotonicDeadline'],
                    'ROLE_OBSERVATION_BUDGET_OR_AUTHORITY_EXHAUSTED')
            due = max(budget['nextReadAt']-now,budget['nextMonotonic']-mono)
            if due <= 0:
                budget.update(attempts=budget['attempts']+1,state='ATTEMPTING',lastWall=now,lastMonotonic=mono)
                delta.journal.compare_and_save(row,{**row,key:budget,'version':row['version']+1})
        if due > 0:
            require(not cancelled.wait(min(5,due)),'SOURCE_REVISION_RELEASE_CANCELLED')
            continue
        delta.guard()
        failure = None
        try:
            reply = transport.tool('authorization.proposal.read',{'proposalId':proposal},'source-revision:role-read')
            require(type(reply) is dict and reply.get('proposalId') == proposal,'EXACT_ROLE_PROPOSAL_ID_REQUIRED')
        except authorization.AuthorizationPaused as error:
            require(error.reason in ('AUTHORIZATION_TRANSPORT_OUTCOME_UNPROVEN','AUTHORIZATION_HTTP_408',
                    'AUTHORIZATION_HTTP_429','AUTHORIZATION_HTTP_502','AUTHORIZATION_HTTP_503','AUTHORIZATION_HTTP_504'),
                    'PERMANENT_ROLE_OBSERVATION_FAILURE')
            failure = error
            reply = None
        delta.guard(); now = time.time(); mono = time.monotonic()
        with delta.journal.invocation():
            row = delta.record(); retained = row[key]
            require(retained == budget,'ROLE_OBSERVATION_FENCE_CHANGED')
            delay = 31.0
            state = None if reply is None else reply.get('state')
            require(state in (None,'PENDING','PUBLISHED','EXPIRED','REJECTED'),'UNKNOWN_ROLE_PROPOSAL_STATE')
            if failure is not None:
                require(not failure.detail.get('retryAfterInvalid'),'ROLE_OBSERVATION_RETRY_AFTER_REVIEW_REQUIRED')
                base = (5,15,60,300,900)[min(budget['attempts']-1,4)]
                jitter = int(digest({'proposal':proposal,'attempt':budget['attempts']})[:4],16)/65535*.2
                retry = failure.detail.get('retryAfterSeconds')
                require(retry is None or type(retry) in (int,float) and 0 <= retry < float('inf'),
                        'BOUNDED_ROLE_OBSERVATION_RETRY_AFTER_REQUIRED')
                delay = max(delay,base*(1+jitter),retry or 0)
            next_budget = {**budget,'state':'COMPLETE' if state == 'PUBLISHED' else 'WAIT',
                'nextReadAt':now+delay,'nextMonotonic':mono+delay,'lastWall':now,'lastMonotonic':mono}
            delta.journal.compare_and_save(row,{**row,key:next_budget,'version':row['version']+1})
        if state == 'PUBLISHED': return
        require(state not in ('EXPIRED','REJECTED'),'NATIVE_ROLE_REVIEW_EXPIRED_OR_REJECTED')
        emit('OUF_SOURCE_REVISION_ROLE_WAIT='+encoded({'proposalId':proposal,'state':state or 'TRANSIENT',
            'attempts':budget['attempts'],'nextReadAt':next_budget['nextReadAt'],'budgetReset':False,
            'profilePublications':0,'jobsRetried':0}).decode())


def main(original,sources,closure,case,context,read,ns,emit):
    authority.closure_valid(closure); context = Path(context)
    plan,primitives,private = preparation.compile_private(original,closure,case,context,read,ns)
    if 'custodyContinuation'in case:
        from tools.source_revision_update.native import bind_custody_continuation
        plan=bind_custody_continuation(plan,case['custodyContinuation'])
    selection = original['authorization']['plan']['selection']
    postboot_history = None
    if 'postbootResumedHuman' in case:
        human = login.resumed_human(case,selection,read)
    elif 'postbootHumanHistory' in case:
        human,postboot_history = login.historical_human(case,selection,read)
    else:
        human = current_human(case['humanReviewBinding'],selection,read)
    transport = authorization.OwnerTransport(selection,human.token_path,human.token_path,human_session=human)
    # Detect an unavailable existing provider-admin session before opening any
    # fresh HUMAN window. oauth() performs fixed metadata GETs only; no login,
    # fallback credential lookup or infrastructure authority is issued here.
    provider_baseline = transport.oauth()
    emit('OUF_SOURCE_REVISION_PREPARED='+encoded({'contextPath':str(context),
        'effectiveFlywayConfigurationProven':True,'backupRequired':True,'onboardingFromVersion':33,
        'onboardingToVersion':34,'udpMigrationVersion':36,'maximumGatewayWrites':2,
        'providerSessionMetadataRead':True,'freshHumanWindowOpened':False,'runtimeAuthorityIssued':False,
        'completedTechnicalPhases':8,'functionalMilestonesProven':4,'profilePublications':0,'jobsRetried':0}).decode())
    authority.current_authorities(int(time.time())+910)
    signal.alarm(0)
    if 'postbootResumedHuman' in case:
        human = login.refresh_resumed_human(human,case,context,read,emit)
    else:
        human = (login.authenticate_postboot(human,postboot_history,case,context,closure,read,emit)
            if postboot_history is not None else login.authenticate(human,case,context,closure,read,emit))
    transport = authorization.OwnerTransport(selection,human.token_path,human.token_path,human_session=human)
    observed = transport.observe()
    require(observed['oauth'] == provider_baseline,'PROVIDER_METADATA_CHANGED_DURING_HUMAN_AUTHENTICATION')
    auth_plan = authorization.compile_plan(observed,primitives,selection,include_ingestion_status=False,
                                            session_binding=human.current())
    auth_directory = context/'authorization'; auth_directory.mkdir(mode=0o700)
    write_new(context/'authorization-plan.json',encoded(auth_plan))
    plan['humanBinding'] = human.current(); scope(plan)
    publish_json(context,'execution-plan.json',plan)
    seconds = min(900,human.expires_at-int(time.time())-10)
    require(seconds >= 600,'HUMAN_WINDOW_TOO_SHORT_FOR_SOURCE_REVISION_RELEASE')
    scopes = {'sourceRevisionUpdate':scope(plan),'chatbotFileAuthorization':authorization.authorization_scope(auth_plan)}
    review = authority.compile_action_review('SOURCE_REVISION_UPDATE',closure,scopes,human.current(),context,
        {'predecessorHistoryHash':case['preparedPlanBinding']['sha256'],
         'predecessorIncidentRef':plan['logicalUpdateRef']},seconds)
    review['absoluteExpiresAt'] = human.expires_at-5
    publish_json(context,'review.json',review)
    decision = authority.terminal_consent(review,
        'Nuovo successore dello scope scaduto: zero effetti riconciliati; claim e journal originali conservati.\n'
        'Custodia MCP root/gruppo servizio0440 vincolata al nuovo piano; nessun chmod/chown.\n'
        'Revisione generica di proprieta di una fonte esistente. Tecniche8/8; funzionali4/6.\n'
        'Aggiorno Onboarding e MCP con le immagini gia sotto custodia; UDP e Ingestion restano invariati.\n'
        'Fermo i due vecchi container e li conservo. Backup Onboarding con verifica integrale; poi sola Flyway V34.\n'
        'Ambiente, mount, indirizzi e metadati MCP conservati. Aggiungo esattamente due rotte, preservando tutte le altre.\n'
        'Registro e attivo le sole capability ouf.onboarding.revision.read e ouf.onboarding.revision.prepare,\n'
        'i relativi scope OAuth e la proposta per il ruolo '+auth_plan['roleId']+'. Gli altri permessi restano invariati.\n'
        'La conferma del ruolo avviene successivamente nella THS nativa; il programma non la esegue.\n'
        'Nessuna pubblicazione del profilo, acquisizione, decisione di identita o ripresa job. Nessun worker policy.\n'
        'Massimo15 minuti, nessun ripristino automatico del database e nessun replay dopo esito incerto.\n'
        'Revisione privata: '+str(context/'review.json'))
    action = authority.issue_action(review,decision,human)
    cancelled = threading.Event(); handlers = {}
    for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):
        handlers[sig] = signal.signal(sig,lambda *_:cancelled.set())
    def current_time():
        require(not cancelled.is_set(),'SOURCE_REVISION_RELEASE_CANCELLED')
        return time.time()
    action.authority.clock = current_time
    human.start_refresh(cancelled,emit=emit)
    try:
        engine = Engine(plan['engine']['socketPath'],tuple(plan['engine']['socketBinding']))
        database = Database(plan,original,ns); ports = NativePorts(action,engine,plan,human,database)
        update = ReadinessUpdate(action,Journal(context),plan,ports); update.initialize()
        last_wait = None
        while True:
            try:
                infrastructure = update.run(); break
            except UpdatePaused as error:
                require(str(error) == 'READINESS_RETRY_WAIT','SOURCE_REVISION_RELEASE_RECONCILIATION_REQUIRED')
                row = update.record()
                if row['version'] != last_wait:
                    emit('OUF_SOURCE_REVISION_WAIT='+encoded({'stage':row['effects'][-1]['stage'],
                        'attempts':row['readinessAttempts'],'nextReadAt':row['nextReadAt']}).decode())
                    last_wait = row['version']
                cancelled.wait(min(5,max(0,row['nextReadAt']-time.time())))
        delta = authorization.AuthorizationDelta(action,auth_plan,Journal(auth_directory),transport,primitives)
        delta.initialize()
        try:
            receipt = delta.apply()
        except authorization.AuthorizationPaused as error:
            require(error.reason == 'HUMAN_OWNER_ROLE_CONFIRMATION_REQUIRED',
                    'AUTHORIZATION_PARTIAL_EFFECTS_REQUIRE_RECONCILIATION')
            emit('OUF_SOURCE_REVISION_NATIVE_ROLE_REVIEW='+encoded(error.detail).decode())
            wait_for_role(delta,transport,error.detail['proposalId'],cancelled,emit)
            receipt = delta.apply()
        emit('OUF_SOURCE_REVISION_UPDATE_RESULT='+encoded({**infrastructure,'authorizationReceipt':receipt,
            'contextPath':str(context),'nativeProfilePublished':False,'identityDecisionsPerformed':False,
            'newPolicyWorkerStarted':False,'jobsRetried':0,'profilePublications':0,
            'completedTechnicalPhases':8,'functionalMilestonesProven':4,
            'freshChatClientTokenScopesProven':False,'functionalStage5Proven':False,'functionalStage6Proven':False}).decode())
    finally:
        cancelled.set()
        if human.thread is not None: human.thread.join(35)
        for sig,handler in handlers.items(): signal.signal(sig,handler)
