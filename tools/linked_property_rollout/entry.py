"""Native additive schema update, qualified images and one finite HUMAN decision."""
import copy,os,signal,threading,time
from pathlib import Path
from engine_creation import Engine
from tools.chatbot_file_cohort.gateway import NamespaceAdmin
from tools.chatbot_file_cohort.human_session import HumanSession
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.linked_property_rollout.preparation import publish_json
from tools.linked_property_rollout import authority,configuration,login,preparation,plan as compiler
from tools.linked_property_rollout.owner import require,digest,encoded,scope,MIGRATION,ReadinessUpdate,UpdatePaused
from tools.linked_property_rollout.native import NativePorts,runtime
from tools.linked_property_rollout.database import Database
from tools.semantic_mcp_update.native import private_file

def completed_plan(binding,read):
    review=read(binding['path'],8388608,binding['sha256']);context=Path(binding['path']).parent
    issued=read(context/'authority.json',131072);record=read(context/'recovery.json',131072)
    plan=read(context/'execution-plan.json',8388608)
    selected=review['scopes'][binding['scope']]
    require(review['authorityDirectory']==str(context)and digest(issued)==record['authorityHash']
            and issued[binding['scope']]==selected and selected['planHash']==digest(plan)
            and record['scopeHash']==digest(selected)and record['incidentState']=='RECOVERED'
            and record['nextStage']==len(record['effects'])==len(selected['stages'])
            and [e['stage']for e in record['effects']]==selected['stages']
            and all(e['state']=='APPLIED'and e['intentHash']==digest({'planHash':selected['planHash'],'stage':e['stage']})for e in record['effects']),
            'EXACT_COMPLETED_PREDECESSOR_REQUIRED')
    return review,plan,record

def current_human(binding,selection,read):
    receipt=read(binding['path'],8388608,binding['sha256']);hb=receipt['authenticatedHuman']
    # Follow existing immutable successor receipts, preserving the cumulative
    # budget and operator. Never pick a directory by mtime or credentials.
    for _ in range(8):
        human=HumanSession(selection,Path(hb['sessionDirectory']),Path(hb['tokenPath']),hb['expiresAt'])
        row=human._read();human._check_identity_and_budget(row)
        require(row['binding']==hb,'CURRENT_HUMAN_BINDING_CHANGED')
        path=human.directory/'successor-window.claim.json'
        if not os.path.lexists(path):return human
        claim=read(path,65536);destination=Path(claim['destination'])
        require(destination.parent==human.directory.parent and destination!=human.directory and claim['budgetReset']is False,
                'EXACT_HUMAN_SUCCESSOR_REQUIRED')
        following=read(destination/'recovery.json',65536);renewal=following.get('governedWindowRenewal',{})
        require(digest(renewal.get('review'))==claim['reviewHash']and digest(renewal.get('decision'))==claim['decisionHash']
                and following['attempts']>=row['attempts']and following['binding']['sessionDirectory']==str(destination),
                'HUMAN_SUCCESSOR_HISTORY_UNPROVEN')
        hb=following['binding']
    require(False,'HUMAN_SUCCESSOR_CHAIN_BOUND_EXHAUSTED')

def main(prepared,sources,closure,case,context,read,ns,emit):
    authority.closure_valid(closure);context=Path(context)
    private=read(case['preparedReview']['path'],8388608,case['preparedReview']['sha256'])
    binding=private['preparedPlanBinding'];require(binding==case['preparedPlanBinding'],'EXACT_PRIVATE_PLAN_REQUIRED')
    retained=read(binding['path'],8388608,binding['sha256'])
    require(retained['schema']=='ouf.linked-property-private-preparation.v1'and retained['readyForExecution']is False
            and retained['runtimeAuthorityIssued']is False and retained['engine']==prepared['engine'], 'RETAINED_PRIVATE_PREPARATION_CHANGED')
    engine=Engine(prepared['engine']['socketPath'],tuple(prepared['engine']['socketBinding']))
    histories={m:completed_plan(case['completedUpdates'][m],read) for m in('udp','onboarding')}
    previous,latest,record=histories['udp']
    routes=latest['gateway']['beforeRoutes'];gateway={'transport':copy.deepcopy(latest['gateway']['transport']),
            'beforeRoutes':routes,'afterRoutes':copy.deepcopy(routes),'projectionBinding':copy.deepcopy(latest['gateway']['projectionBinding'])}
    admin=NamespaceAdmin(engine,gateway['transport']);require(admin.routes()==routes,'GATEWAY_CHANGED_SINCE_COMPLETED_UPDATE')
    actuals={};replacements={}
    for module in('udp','onboarding'):
        pin=retained['beforeApplications'][module]
        actual=ns['engine_get'](prepared['engine'],'containers',pin['containerId'])
        require(actual is not None and preparation.runtime(actual)==pin,'APPLICATION_CHANGED_SINCE_PRIVATE_PREPARATION')
        old_plan=histories[module][1];old_record=histories[module][2]
        require(runtime(actual)==old_record['effects'][-1]['evidence']['applications'][module]['runtimeBinding'],
                'COMPLETED_APPLICATION_GENERATION_CHANGED')
        saved=old_plan['replacements'][module];candidate=retained['candidates'][module]
        private_file(candidate['imageArchive']['path'],candidate['imageArchive']['sha256'],1200000000)
        actuals[module]=actual
        replacements[module]=compiler.replacement({'module':module,'name':saved['name'],'creationRequest':saved['request']},actual,candidate,{**case,'readiness':{module:saved['readiness']}},module)
    pg=ns['engine_get'](prepared['engine'],'containers',retained['postgresRuntimeBinding']['containerId'])
    flyway=configuration.verify(actuals['udp'],retained['candidates']['udp'],pg,case['udpApplicationConfigurationSha256'])
    public={'preparedReviewBinding':case['preparedReview'],'preparedPlanBinding':binding,'nativeFlywayConfiguration':flyway,
            'databaseMigration':MIGRATION,'backupRequiredBeforeMigration':True,'runtimeAuthorityIssued':False}
    publish_json(context,'candidate-review.json',public)
    plan={'schema':'ouf.linked-property-native-update-plan.v1','authorityDirectory':str(context),
          'privateReviewBinding':{'path':str(context/'candidate-review.json'),'sha256':digest(public)},
          'engine':copy.deepcopy(prepared['engine']),'programs':{'docker':closure['executables']['docker']},
          'replacements':replacements,'unchangedApplications':{'ingestion':latest['unchangedApplications']['ingestion']},
          'gateway':gateway,'databaseMigration':MIGRATION,'backupRequiredBeforeMigration':True,
          'database':{'postgresRuntimeBinding':retained['postgresRuntimeBinding'],'before':retained['databaseFacts'],
                      'expected':{m:retained['candidates'][m]['migrations']for m in('udp','onboarding')}},
          'maximumExecutionSeconds':900,'maximumEffectAttemptsPerStage':1,'maximumGatewayWrites':0,
          **{k:False for k in('automaticReplayAllowed','manualSqlMigrationAllowed','grantChangesAllowed','semanticDispatchAllowed','automaticRollbackAllowed','identityDecisionsAllowed','profilePublicationAllowed','jobRetriesAllowed')}}
    plan['logicalUpdateRef']=digest({'retiredContainerIds':sorted(r['oldRuntimeBinding']['containerId']for r in replacements.values()),'migration':MIGRATION})
    scope(plan)
    # Fresh read-only DB preflight before any login/signature. Database.guard in
    # this preparation branch verifies the same reviewed Engine, not authority.
    facts={m:preparation.database_facts(ns,prepared,closure['executables']['docker']['path'],m,context)for m in('udp','onboarding')}
    for m in facts:
        require(all(facts[m][k]==retained['databaseFacts'][m][k]for k in('database','databaseOid','applicationRole','migrations')),'DATABASE_CHANGED_DURING_PREPARATION')
    require(not facts['udp']['profileTablePresent']and not facts['udp']['evidenceColumnPresent']and facts['udp']['rolePreflight']==retained['databaseFacts']['udp']['rolePreflight'],'V35_DATABASE_PREFLIGHT_CHANGED')
    publish_json(context,'prepared-plan.json',plan)
    emit('OUF_LINKED_PROPERTY_UPDATE_PREPARED='+encoded({'contextPath':str(context),'udpFromVersion':34,'udpToVersion':35,
         'nativeFlywayConfigurationVerified':True,'backupRequired':True,'newPolicyWorkerStarted':False,'newImagesDownloaded':False,
         'databaseMutations':0,'serviceMutations':0,'nativeProfilePublished':False}).decode())
    authority.current_authorities(int(time.time())+910)
    human=current_human(case['humanReviewBinding'],prepared['authorization']['plan']['selection'],read)
    signal.alarm(0);human=login.authenticate(human,case,context,closure,read,emit)
    plan['humanBinding']=human.current();scope(plan);publish_json(context,'execution-plan.json',plan)
    seconds=min(900,human.expires_at-int(time.time())-10);require(seconds>=600,'HUMAN_WINDOW_TOO_SHORT_FOR_MIGRATION')
    review=authority.compile_action_review('LINKED_PROPERTY_UPDATE',closure,{'linkedPropertyUpdate':scope(plan)},plan['humanBinding'],context,
             {'predecessorHistoryHash':digest(private),'predecessorIncidentRef':plan['logicalUpdateRef']},seconds)
    review['absoluteExpiresAt']=human.expires_at-5;publish_json(context,'review.json',review)
    decision=authority.terminal_consent(review,
      'Policy generiche di riconciliazione proprieta per file, API, delta e layer. Tecniche8/8; funzionali2/6.\n'
      'Aggiornamento UDP e Onboarding con immagini gia verificate. I vecchi container saranno fermati e conservati.\n'
      'Prima del nuovo UDP: backup privato del database, verifica integrale archivio; poi Flyway applica la sola V35 con il ruolo applicativo esistente.\n'
      'Ambiente, mount, rete, IP e MAC conservati. Nessuna modifica Gateway, IAM o grant; nessun worker policy.\n'
      'I profili richiedono una successiva pubblicazione nativa; nessuna ripetizione di decisioni, job o dati storici.\n'
      'Massimo15 minuti; esito incerto richiede riconciliazione, nessun ripristino automatico del database.\n'
      'Revisione privata: '+str(context/'review.json'))
    action=authority.issue_action(review,decision,human)
    cancelled=threading.Event();handlers={}
    for sig in(signal.SIGINT,signal.SIGTERM,signal.SIGHUP):handlers[sig]=signal.signal(sig,lambda *_:cancelled.set())
    def current_time():require(not cancelled.is_set(),'LINKED_PROPERTY_UPDATE_CANCELLED');return time.time()
    action.authority.clock=current_time;human.start_refresh(cancelled,emit=emit)
    try:
        database=Database(plan,prepared,ns);ports=NativePorts(action,engine,plan,human,database)
        update=ReadinessUpdate(action,Journal(context),plan,ports);update.initialize()
        while True:
            try:
                result=update.run();emit('OUF_LINKED_PROPERTY_UPDATE_RESULT='+encoded({**result,'contextPath':str(context),
                    'newPolicyWorkerStarted':False,'identityDecisionsPerformed':False,'maximumGatewayWrites':0,
                    'completedTechnicalPhases':8,'functionalMilestonesProven':2}).decode());break
            except UpdatePaused as error:
                require(str(error)=='READINESS_RETRY_WAIT','LINKED_PROPERTY_RECONCILIATION_REQUIRED')
                row=update.record();emit('OUF_LINKED_PROPERTY_UPDATE_WAIT='+encoded({'stage':row['effects'][-1]['stage'],'attempts':row['readinessAttempts'],'nextReadAt':row['nextReadAt']}).decode())
                cancelled.wait(min(5,max(0,row['nextReadAt']-time.time())))
    finally:
        cancelled.set()
        if human.thread is not None:human.thread.join(35)
        for sig,handler in handlers.items():signal.signal(sig,handler)
