"""One finite signed authority and fenced claims for the exact V35 update.

This module has no Docker/SQL ports and cannot dispatch an effect by itself.
"""
import copy,hashlib,json,os,stat,termios,time
from pathlib import Path
STAGES=('VERIFY_CURRENT_ADMISSION_AND_SIGNED_REVIEW','IMPORT_EXACT_IMAGE','DISABLE_OLD_RESTART','STOP_OLD_ONBOARDING',
 'VERIFY_QUIESCED_BACKUP','DETACH_OLD_ENDPOINT','RENAME_OLD','CREATE_REPLACEMENT','START_REVIEWED_V35_REPLACEMENT',
 'VERIFY_READINESS_AND_EXACT_V35_HISTORY','VERIFY_RETAINED_SOURCE_COUNTERS_AND_ZERO_BUDGET_SESSIONS','RESTORE_RESTART_POLICY','VERIFY_FINAL')
LIMITS={'engineGets':300,'engineWrites':8,'sqlSessions':6,'imageLoadAttempts':1,'backupProcesses':2,'readinessGets':128,'ownerConfigurationReads':32,'quarantineStops':1}
AUTHORITY_SCHEMA='ouf.onboarding-v35-native-authority.v1'
HUMAN_SCHEMA='ouf.onboarding-v35-native-mandate.v1'
DECISION='APPROVE_ONE_FINITE_ONBOARDING_V35_NATIVE_UPDATE_ONLY'
class Stop(RuntimeError):pass
def require(ok,code):
    if not ok:raise Stop(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def digest(v):return sha(encoded(v))
def validate_review(review):
    require(review['schema']=='ouf.onboarding-v35-native-review.v1'and review['maximumSeconds']==900
        and review['negativeCleanup']=={'maximumAdditionalSeconds':30,'startupSeconds':180,'candidateStopOnly':True,'maximumStops':1}
        and review['maximums']==LIMITS and review['stages']==list(STAGES)
        and review['nativePlanHash']==digest(review['nativePlan'])
        and review['frozenPlanHash']==review['nativePlan']['frozenPlanHash']
        and review['sourceClosureHash']==digest(review['sourceClosure'])
        and review['databaseRestoreAuthorized']is False and review['humanBudgetOrSourceActivationAuthorized']is False
        and review['automaticReplayAllowed']is False and review['budgetReset']is False and review['releaseAcceptance']is False,
        'EXACT_FINITE_ONBOARDING_V35_REVIEW_REQUIRED')
    return review
def scope(review):
    validate_review(review)
    return {'reviewHash':digest(review),**{k:copy.deepcopy(review[k])for k in('frozenPlanHash','nativePlanHash','sourceClosureHash','logicalOperationRef','bootId','maximumSeconds','maximums','stages','negativeCleanup')}}
def terminal_decision(review,path):
    validate_review(review);reviewed=digest(review)
    prompt=('\nAggiornamento della SOLA Onboarding: V34 -> V35, budget HUMAN NON concesso.\n'
        'Piano privato: '+str(path)+'\nSHA256 revisione: '+reviewed+'\n'
        'Immagine CI esatta, custodia/configurazione/Env/mount/endpoint conservati.\n'
        'Identita configurazione/manifest nativo legate senza rebuild o nuova label.\n'
        'Breve indisponibilita Onboarding; vecchio container trattenuto fermo.\n'
        'Backup quiescente verificato; migrazione Flyway V35 ESPLICITA, nessun repair o restore.\n'
        'Nessun IAM/OAuth, grant, attivazione fonte, lavoro Ingestion o worker Registry.\n'
        'Massimo900secondi +30 solo per fermare il nuovo candidato non provato.\n'
        'Watchdog effimero: arresto del solo nuovo candidato su perdita controller/scadenza; nessun rollback.\n'
        'Avvio candidato massimo180secondi; effetto ambiguo/interruzione resta CLAIMED, mai rollback/rilancio automatico.\n'
        'Scrivi APPROVO '+reviewed+' per questa sola revisione esatta.\n> ')
    fd=os.open('/dev/tty',os.O_RDWR|os.O_NOCTTY|os.O_NOFOLLOW)
    try:
        require(stat.S_ISCHR(os.fstat(fd).st_mode)and os.isatty(fd),'CONTROLLING_V35_TERMINAL_REQUIRED')
        termios.tcflush(fd,termios.TCIFLUSH);os.write(fd,prompt.encode());answer=bytearray()
        while len(answer)<=128:
            part=os.read(fd,1)
            if part in(b'',b'\n'):break
            answer.extend(part)
        require(bytes(answer)==('APPROVO '+reviewed).encode(),'EXACT_V35_REVIEW_NOT_APPROVED')
    finally:os.close(fd)
    return {'schema':'ouf.onboarding-v35-terminal-decision.v1','reviewHash':reviewed,'decision':DECISION,'approvedAt':int(time.time())}
class SignedAuthority:
    def __init__(self,review,raw,human_path,human_hash,verifier,read,clock=time.time):
        from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
        require(type(verifier)is DetachedAuthenticator,'REAL_EXISTING_INSTALLATION_ROLE_VERIFIER_REQUIRED')
        self.review=copy.deepcopy(validate_review(review));self.raw=raw;self.human_path=human_path;self.human_hash=human_hash
        self.verifier,self.read,self.clock=verifier,read,clock;self.started=time.monotonic();self.last_wall=clock();self.check()
    def check(self):
        from tools.semantic_provider_deployment_authentication import policy as current_policy
        now=self.clock();require(now>=self.last_wall,'V35_WALL_CLOCK_REGRESSION');self.last_wall=now
        human=self.read(self.human_path,self.human_hash);authority=json.loads(self.raw);v=self.review['verification'];ctx=v['context']
        require(encoded(authority)==self.raw and authority=={'schema':AUTHORITY_SCHEMA,'scope':scope(self.review),
            'issuedAt':human['issuedAt'],'expiresAt':human['expiresAt'],'cleanupExpiresAt':human['expiresAt']+30,'installationRef':ctx['installationRef'],
            'entityRef':ctx['entityRef'],'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False},'EXACT_V35_AUTHORITY_SCOPE_REQUIRED')
        require(human['schema']==HUMAN_SCHEMA and human['reviewHash']==digest(self.review)and human['authorityHash']==sha(self.raw)
            and human['decision']==DECISION and human['state']=='ACTIVE'and type(human['issuedAt'])is int and type(human['expiresAt'])is int
            and human['expiresAt']-human['issuedAt']==900 and human['issuedAt']<=now<human['expiresAt']
            and time.monotonic()-self.started<900,'CURRENT_FINITE_V35_MANDATE_REQUIRED')
        require(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==self.review['bootId'],'SAME_V35_AUTHORITY_BOOT_REQUIRED')
        require(self.verifier.policy_binding==v['trustPolicy']and self.verifier.openssl_binding==v['openssl'],'SAME_V35_ROLE_POLICY_REQUIRED')
        for role,key in(('DEPLOYMENT_INTENT','intentIssuerRef'),('FINAL_DEPLOYMENT_APPROVAL','approvalIssuerRef')):
            require(self.verifier(self.raw,role,ctx[key],ctx['installationRef'],ctx['entityRef'])is True,'DUAL_CURRENT_V35_SIGNATURES_REQUIRED')
        policy=current_policy(self.verifier.read_policy(),ctx['installationRef'],ctx['entityRef'],now)
        for role,key in(('DEPLOYMENT_INTENT','intentIssuerRef'),('FINAL_DEPLOYMENT_APPROVAL','approvalIssuerRef'),('CREATION_ATTESTATION','attestorRef')):
            keys=[v for v in policy['keys']if role in v['roles']and v['issuerRef']==ctx[key]and v['state']=='ACTIVE'and v['notBefore']<=human['issuedAt']]
            require(len(keys)==1 and keys[0]['expiresAt']>=human['expiresAt']+30,'WHOLE_V35_WINDOW_WITHIN_EXISTING_KEY_AUTHORITY_REQUIRED')
        return human
    def remaining(self):return self.check()['expiresAt']-self.clock()
def authentication_file(root,name,raw):
    # Existing authentication contracts require mode0600, unlike immutable evidence0400.
    root=Path(root);require(root.is_absolute()and root.resolve()==root,'EXACT_V35_AUTH_FILE_ROOT')
    fd=os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(os.dup(fd),'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    finally:os.close(fd)
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
def issue(review,root,profile,decision,write,read):
    from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
    from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
    validate_review(review);require(decision['reviewHash']==digest(review)and decision['decision']==DECISION
        and 0<=time.time()-decision['approvedAt']<=120,'FRESH_EXACT_V35_TERMINAL_DECISION_REQUIRED')
    root=Path(root);(root/'authority').mkdir(mode=0o700);target=root/'authority';now=int(time.time());ctx=review['verification']['context']
    raw=encoded({'schema':AUTHORITY_SCHEMA,'scope':scope(review),'issuedAt':now,'expiresAt':now+900,'cleanupExpiresAt':now+930,
        'installationRef':ctx['installationRef'],'entityRef':ctx['entityRef'],'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False})
    human={'schema':HUMAN_SCHEMA,'reviewHash':digest(review),'authorityHash':sha(raw),'decision':DECISION,'state':'ACTIVE','issuedAt':now,'expiresAt':now+900}
    write(target,'authority.json',raw);write(target,'human.json',human);write(target,'decision.json',decision)
    verifier=DetachedAuthenticator(review['verification']['trustPolicy'],str(target),review['verification']['openssl'])
    from tools.semantic_provider_deployment_authentication import policy as current_policy
    policy_raw=verifier.read_policy();policy=current_policy(policy_raw,ctx['installationRef'],ctx['entityRef'],now)
    authentication_file(target,'issued-trust-policy.json',policy_raw)
    for role,key in(('DEPLOYMENT_INTENT','intentIssuerRef'),('FINAL_DEPLOYMENT_APPROVAL','approvalIssuerRef'),('CREATION_ATTESTATION','attestorRef')):
        selected=[v for v in policy['keys']if role in v['roles']and v['issuerRef']==ctx[key]and v['state']=='ACTIVE'and v['notBefore']<=now]
        require(len(selected)==1 and selected[0]['expiresAt']>=now+930,'FULL_V35_KEY_WINDOW_REQUIRED_BEFORE_SIGNING')
    for role,key in(('DEPLOYMENT_INTENT','intentIssuerRef'),('FINAL_DEPLOYMENT_APPROVAL','approvalIssuerRef')):
        signer=ExistingEd25519Signer(profile['keyBindings']['installer'],profile['keyRefs']['installer'],verifier,
            {'role':role,'issuerRef':ctx[key],'installationRef':ctx['installationRef'],'entityRef':ctx['entityRef']})
        authentication_file(target,sha(raw)+'.'+role+'.json',signer.sign(raw))
    gate=SignedAuthority(review,raw,str(target/'human.json'),digest(human),verifier,read)
    return gate
class Execution:
    def __init__(self,gate,journal,ports):
        from tools.semantic_lease_recovery.recovery_journal import Journal
        require(type(gate)is SignedAuthority and type(journal)is Journal,'REAL_SIGNED_V35_GATE_AND_JOURNAL_REQUIRED')
        self.gate,self.journal,self.ports=gate,journal,ports;self.review=gate.review
        require(str(journal.root)==self.review['executionRoot']and ports.root==journal.root,'ONE_V35_AUTHORITY_JOURNAL_AND_PORTS_REQUIRED')
        ports.execution=self
    def initialize(self):
        human=self.gate.check();counts=copy.deepcopy(self.ports.ctx.preflight_counts)
        require(set(counts)==set(LIMITS)and all(type(v)is int and self.review['preflightCounts'][k]<=v<=LIMITS[k]for k,v in counts.items())
            and all(counts[k]==0 for k in('engineWrites','imageLoadAttempts','backupProcesses','readinessGets','quarantineStops')),
            'PRESERVED_ALL_PREFLIGHT_ATTEMPTS_REQUIRED')
        self.journal.initialize({'schema':'ouf.onboarding-v35-native-journal.v1','version':0,
            'reviewHash':digest(self.review),'authorityHash':sha(self.gate.raw),'nextStage':0,'effects':[],
            'counts':counts,'createdId':None,'createdGeneration':None,'createdConfigurationVerified':False,'startupDeadline':None,'quarantine':None,'backup':None,
            'expiresAt':human['expiresAt'],'expiresMonotonic':time.monotonic()+max(0,human['expiresAt']-time.time()),
            'readinessAttempts':0,'readinessNextWall':0,'readinessNextMonotonic':0,'readinessInFlight':False,
            'state':'OPEN','automaticReplayAllowed':False,'budgetReset':False})
    def record(self):
        self.gate.check();row=self.journal.read();n=row['nextStage']
        require(row['schema']=='ouf.onboarding-v35-native-journal.v1'and row['reviewHash']==digest(self.review)
            and row.get('quarantine')is None and row['authorityHash']==sha(self.gate.raw)and row['budgetReset']is False and row['automaticReplayAllowed']is False
            and type(n)is int and 0<=n<=len(STAGES)and len(row['effects'])in(n,n+1)
            and time.time()<row['expiresAt']and time.monotonic()<row['expiresMonotonic'],'CURRENT_FENCED_V35_HISTORY_REQUIRED')
        for i,e in enumerate(row['effects']):
            require(e['stage']==STAGES[i]and e['intentHash']==digest({'reviewHash':digest(self.review),'stage':STAGES[i]})
                and e['state']==('APPLIED'if i<n else'CLAIMED'),'V35_ORDERED_EFFECT_HISTORY_REQUIRED')
        require(set(row['counts'])==set(LIMITS)and all(type(v)is int and 0<=v<=LIMITS[k]for k,v in row['counts'].items()),'V35_DURABLE_BUDGET_LIMIT_REQUIRED')
        return row
    def save(self,row,**changes):
        following={**row,**changes,'version':row['version']+1};self.journal.compare_and_save(row,following);return following
    def reserve(self,kind):
        row=self.record();require(row['counts'][kind]<LIMITS[kind],'V35_OPERATION_BUDGET_EXHAUSTED')
        counts=copy.deepcopy(row['counts']);counts[kind]+=1;self.save(row,counts=counts)
    def run(self):
        with self.journal.invocation():
            while True:
                row=self.record();i=row['nextStage']
                if i==len(STAGES):self.save(row,state='COMPLETE');return self.ports.final_result()
                require(len(row['effects'])==i,'V35_CLAIMED_EFFECT_REQUIRES_RECONCILIATION_NO_REPLAY')
                stage=STAGES[i];self.ports.guard(stage)
                minimum={'IMPORT_EXACT_IMAGE':210,'DISABLE_OLD_RESTART':600,'STOP_OLD_ONBOARDING':500,'VERIFY_QUIESCED_BACKUP':220,'START_REVIEWED_V35_REPLACEMENT':240}.get(stage,30)
                require(self.gate.remaining()>minimum,'INSUFFICIENT_V35_AUTHORITY_WINDOW_FOR_STAGE')
                effects=copy.deepcopy(row['effects']);effects.append({'stage':stage,'state':'CLAIMED','intentHash':digest({'reviewHash':digest(self.review),'stage':stage})})
                self.save(row,effects=effects);proof=self.ports.execute(stage);self.gate.check()
                require(type(proof)is dict and proof,'EXPLICIT_V35_EFFECT_PROOF_REQUIRED')
                row=self.record();effects=copy.deepcopy(row['effects']);effects[-1].update(state='APPLIED',proof=proof)
                self.save(row,effects=effects,nextStage=i+1)
