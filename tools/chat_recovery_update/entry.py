"""One finite native release after all private checks; no implicit domain replay."""
import signal,threading,time
from pathlib import Path
from tools.linked_property_rollout.preparation import publish_json
from tools.linked_property_rollout.entry import current_human
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chat_recovery_update import authority,login,preparation
from tools.chat_recovery_update.owner import require,digest,encoded,scope,MIGRATION,ReadinessUpdate,UpdatePaused
from tools.chat_recovery_update.native import NativePorts
from tools.chat_recovery_update.database import Database

def main(prepared,sources,closure,case,context,read,ns,emit):
    authority.closure_valid(closure);context=Path(context)
    plan,retained,engine=preparation.compile_private(prepared,closure,case,context,read,ns)
    emit('OUF_CHAT_RECOVERY_UPDATE_PREPARED='+encoded({'contextPath':str(context),
        'udpFromVersion':35,'udpToVersion':36,'mcpMigrationsUnchanged':True,
        'nativeFlywayConfigurationVerified':True,'backupRequired':True,
        'completedTechnicalPhases':8,'functionalMilestonesProven':3,
        'runtimeAuthorityIssued':False,'serviceMutations':0,'databaseMutations':0,
        'profilePublications':0,'jobsRetried':0}).decode())
    authority.current_authorities(int(time.time())+910)
    human=current_human(case['humanReviewBinding'],prepared['authorization']['plan']['selection'],read)
    signal.alarm(0);human=login.authenticate(human,case,context,closure,read,emit)
    plan['humanBinding']=human.current();scope(plan);publish_json(context,'execution-plan.json',plan)
    seconds=min(900,human.expires_at-int(time.time())-10);require(seconds>=600,'HUMAN_WINDOW_TOO_SHORT_FOR_MIGRATION')
    review=authority.compile_action_review('CHAT_RECOVERY_UPDATE',closure,{'chatRecoveryUpdate':scope(plan)},plan['humanBinding'],context,
             {'predecessorHistoryHash':digest(case['preparedPlanBinding']),'predecessorIncidentRef':plan['logicalUpdateRef']},seconds)
    review['absoluteExpiresAt']=human.expires_at-5;publish_json(context,'review.json',review)
    decision=authority.terminal_consent(review,
      'Aggiornamento generico del recupero da chat. Tecniche8/8; funzionali3/6.\n'
      'Aggiornamento UDP e MCP con immagini gia verificate. I vecchi container saranno fermati e conservati.\n'
      'Prima del nuovo UDP: backup privato del database, verifica integrale archivio; poi Flyway applica la sola V36 con il ruolo applicativo esistente.\n'
      'Ambiente, mount, rete, IP e MAC conservati. Nessuna modifica Gateway, IAM o grant; nessun worker policy; migrazioni MCP invariate.\n'
      'I profili richiedono una successiva pubblicazione nativa; nessuna ripetizione di decisioni, job o dati storici.\n'
      'Massimo15 minuti; esito incerto richiede riconciliazione, nessun ripristino automatico del database.\n'
      'Revisione privata: '+str(context/'review.json'))
    action=authority.issue_action(review,decision,human)
    cancelled=threading.Event();handlers={}
    for sig in(signal.SIGINT,signal.SIGTERM,signal.SIGHUP):handlers[sig]=signal.signal(sig,lambda *_:cancelled.set())
    def current_time():require(not cancelled.is_set(),'CHAT_RECOVERY_UPDATE_CANCELLED');return time.time()
    action.authority.clock=current_time;human.start_refresh(cancelled,emit=emit)
    try:
        database=Database(plan,retained,ns);ports=NativePorts(action,engine,plan,human,database)
        update=ReadinessUpdate(action,Journal(context),plan,ports);update.initialize()
        while True:
            try:
                result=update.run();emit('OUF_CHAT_RECOVERY_UPDATE_RESULT='+encoded({**result,'contextPath':str(context),
                    'newPolicyWorkerStarted':False,'identityDecisionsPerformed':False,'maximumGatewayWrites':0,
                    'completedTechnicalPhases':8,'functionalMilestonesProven':3}).decode());break
            except UpdatePaused as error:
                require(str(error)=='READINESS_RETRY_WAIT','CHAT_RECOVERY_RECONCILIATION_REQUIRED')
                row=update.record();emit('OUF_CHAT_RECOVERY_UPDATE_WAIT='+encoded({'stage':row['effects'][-1]['stage'],'attempts':row['readinessAttempts'],'nextReadAt':row['nextReadAt']}).decode())
                cancelled.wait(min(5,max(0,row['nextReadAt']-time.time())))
    finally:
        cancelled.set()
        if human.thread is not None:human.thread.join(35)
        for sig,handler in handlers.items():signal.signal(sig,handler)
