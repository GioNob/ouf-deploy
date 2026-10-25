"""One finite signed authority and fenced claims for the exact ACQUISITION update.

This module has no Docker/SQL ports and cannot dispatch an effect by itself.
"""
import copy,hashlib,json,os,stat,termios,time
from pathlib import Path
STAGES=('VERIFY_CURRENT_ADMISSION','IMPORT_INGESTION','IMPORT_UDP','IMPORT_MCP',
 'CREATE_INGESTION_READ','CREATE_UDP_READ','START_INGESTION_READ','START_UDP_READ','VERIFY_READ_REPLICAS',
 'DISABLE_OLD_MCP_RESTART','STOP_OLD_MCP','DETACH_OLD_MCP','RENAME_OLD_MCP','CREATE_MCP','START_MCP','VERIFY_MCP_READINESS',
 'ADD_INGESTION_ROUTE','ADD_UDP_ROUTE','VERIFY_GATEWAY','RESTORE_INGESTION_RESTART','RESTORE_UDP_RESTART','RESTORE_MCP_RESTART','VERIFY_FINAL')
LIMITS={'engineGets':500,'engineWrites':22,'imageLoadAttempts':3,'readinessGets':128,'adminGets':32,'adminPuts':2,'ownerConfigurationReads':64,'serviceCredentialFileReads':1,'quarantineStops':3}
RETAINED_COUNTS={'adminGets':1,'adminPuts':0,'engineGets':9,'engineWrites':0,'imageLoadAttempts':0,'ownerConfigurationReads':5,'quarantineStops':0,'readinessGets':0,'serviceCredentialFileReads':1}
CONTINUATION_LIMITS={**LIMITS,'serviceCredentialFileReads':2}
RECOVERY_RETAINED_COUNTS={'adminGets':2,'adminPuts':0,'engineGets':128,'engineWrites':14,'imageLoadAttempts':3,'ownerConfigurationReads':42,'quarantineStops':2,'readinessGets':2,'serviceCredentialFileReads':2}
RECOVERY_LIMITS={**CONTINUATION_LIMITS,'engineWrites':28,'ownerConfigurationReads':96,'serviceCredentialFileReads':3,'quarantineStops':5}
RECOVERY_STAGES=('LOAD_EXISTING_ADMIN_KEY','VERIFY_RESIDUAL_ADMISSION','RESTART_INGESTION_READ','RESTART_UDP_READ','VERIFY_RESTARTED_READ_REPLICAS','RENAME_OLD_MCP','CREATE_MCP','START_MCP','VERIFY_MCP_READINESS','ADD_INGESTION_ROUTE','ADD_UDP_ROUTE','VERIFY_GATEWAY','RESTORE_INGESTION_RESTART','RESTORE_UDP_RESTART','RESTORE_MCP_RESTART','VERIFY_FINAL')
AUTHORITY_SCHEMA='ouf.acquisition-read-native-authority.v1'
HUMAN_SCHEMA='ouf.acquisition-read-native-mandate.v1'
DECISION='APPROVE_ONE_FINITE_ACQUISITION_READ_DEPLOYMENT_ONLY'
class Stop(RuntimeError):pass
def require(ok,code):
    if not ok:raise Stop(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def digest(v):return sha(encoded(v))
def review_profile(review):
    if review['schema']=='ouf.acquisition-detached-mcp-recovery-review.v1':
        r=review['recovery'];counts=r['retainedCounts'];require(counts==RECOVERY_RETAINED_COUNTS,'EXACT_RECORDED_RECOVERY_COUNTS_REQUIRED')
        require(set(r)=={'originalExecutionRoot','originalReviewHash','journalHash','diagnosticReceiptHash','privateEvidenceHash','retainedCounts','retainedMaximums','retainedAppliedStages','retainedQuarantineApplied','adoptedIds','legacyMacPolicy','newPositiveWritesMaximum','newNegativeWritesMaximum','additionalCredentialFileReadsMaximum','noOriginalStageReplay'}and r['noOriginalStageReplay']is True and r['retainedAppliedStages']==13 and r['retainedQuarantineApplied']is True and 'continuation'not in review and r['retainedMaximums']==CONTINUATION_LIMITS and set(counts)==set(LIMITS)and all(type(v)is int and 0<=v<=CONTINUATION_LIMITS[k]for k,v in counts.items())and counts['imageLoadAttempts']==3 and counts['engineWrites']>=14 and counts['serviceCredentialFileReads']==2 and counts['quarantineStops']==2
            and review['nativePlan']['recovery']==r and review['nativePlan']['legacyConfigMacDetachPolicy']==r['legacyMacPolicy']and set(r['adoptedIds'])=={'ingestion','udp'}and len(set(r['adoptedIds'].values()))==2 and all(type(v)is str and len(v)==64 and all(c in'0123456789abcdef'for c in v)for v in[*r['adoptedIds'].values(),*[r[k]for k in('originalReviewHash','journalHash','diagnosticReceiptHash','privateEvidenceHash')]])
            and Path(review['executionRoot'])==Path(r['originalExecutionRoot'])/'detached-mcp-recovery-v1'
            and r['newPositiveWritesMaximum']==8 and r['newNegativeWritesMaximum']==6 and r['additionalCredentialFileReadsMaximum']==1
            and set(review['preflightCounts'])==set(LIMITS)and all(type(v)is int and counts[k]<=v<=CONTINUATION_LIMITS[k]for k,v in review['preflightCounts'].items()),'EXACT_DETACHED_RESIDUAL_RECOVERY_PROFILE_REQUIRED')
        return RECOVERY_LIMITS,RECOVERY_STAGES
    if review['schema']=='ouf.acquisition-read-native-review.v1':
        require('continuation'not in review,'NO_IMPLICIT_CONTINUATION_PROFILE')
        return LIMITS,STAGES
    require(review['schema']=='ouf.acquisition-read-continuation-review.v1','EXACT_ACQUISITION_REVIEW_SCHEMA_REQUIRED')
    c=review['continuation']
    require(type(c)is dict and set(c)=={'originalExecutionRoot','originalReviewHash','reconciliationReceiptHash','retainedPreflightCounts','retainedMaximums','maximumAdditionalCredentialFileReads','cumulativeCredentialReadMaximum','noOriginalScopeReplay','preConsentUsesRetainedRouteSnapshot','freshRoutesRequiredBeforeFirstMutation'}
        and c['retainedPreflightCounts']==RETAINED_COUNTS and c['retainedMaximums']==LIMITS
        and c['maximumAdditionalCredentialFileReads']==1 and c['cumulativeCredentialReadMaximum']==2
        and all(c[k]is True for k in('noOriginalScopeReplay','preConsentUsesRetainedRouteSnapshot','freshRoutesRequiredBeforeFirstMutation'))
        and review['nativePlan']['continuation']==c
        and all(type(c[k])is str and len(c[k])==64 and all(v in'0123456789abcdef'for v in c[k])for k in('originalReviewHash','reconciliationReceiptHash'))
        and Path(review['executionRoot'])==Path(c['originalExecutionRoot'])/'terminal-continuation-v1'
        and all(type(v)is int and v>=RETAINED_COUNTS[k]for k,v in review['preflightCounts'].items()),'EXACT_RECONCILED_CUMULATIVE_CONTINUATION_REQUIRED')
    return CONTINUATION_LIMITS,('LOAD_EXISTING_ADMIN_KEY',*STAGES)
def validate_review(review):
    limits,stages=review_profile(review)
    require(review['maximumSeconds']==900
        and review['negativeCleanup']=={'maximumAdditionalSeconds':30,'startupSeconds':180,'candidateStopOnly':True,'maximumStops':3,'disableCandidateRestartFirst':True}
        and review['maximums']==limits and review['stages']==list(stages)
        and review['nativePlanHash']==digest(review['nativePlan'])
        and review['frozenPlanHash']==review['nativePlan']['frozenPlanHash']
        and review['sourceClosureHash']==digest(review['sourceClosure'])
        and review['databaseRestoreAuthorized']is False and review['humanBudgetOrSourceActivationAuthorized']is False
        and review['automaticReplayAllowed']is False and review['budgetReset']is False and review['releaseAcceptance']is False,
        'EXACT_FINITE_ACQUISITION_REVIEW_REQUIRED')
    return review
def scope(review):
    validate_review(review)
    return {'reviewHash':digest(review),**{k:copy.deepcopy(review[k])for k in('frozenPlanHash','nativePlanHash','sourceClosureHash','logicalOperationRef','bootId','maximumSeconds','maximums','stages','negativeCleanup')}}
def terminal_decision(review,path):
    validate_review(review);reviewed=digest(review)
    credential=('Una ulteriore lettura del file admin ESISTENTE, SOLO dopo questa approvazione.\n'
        'Limite cumulativo letture credenziale:2, inclusa la1 gia consumata. Altri massimi invariati.\n'
        'Contatori iniziali conservati:9EngineGET,1adminGET,5ownerConfig,1fileadmin,zero mutazioni.\n'
        'Le82rotte prima della conferma sono lo snapshot retained; verifica fresca prima della prima mutazione.\n')if'continuation'in review else'Un file admin esistente letto in memoria per verificare e aggiungere le2rotte.\n'
    if'recovery'in review:
        credential=('Recupero dei SOLI2READ propri gia quarantinati: riavvio, nuova generazione e readiness fresche.\n'
            'Nessun import, CREATE dei READ, STOP/DETACH del vecchio MCP o vecchi stage ripetuti.\n'
            'Una ulteriore lettura del file admin ESISTENTE solo dopo APPROVO/firme/claim.\n'
            'Limiti cumulativi proposti: writes22->28 (8residue positive+6negative da14), ownerConfig64->96, fileadmin2->3, quarantena3->5.\n'
            'Tutti i contatori precedenti restano incorporati; altri massimi invariati. Nessun reset.\n'
            'La negativa puo fermare solo i2READ propri adottati e il nuovoMCP, mai i5owner originali.\n')
    old_mcp=('Vecchio MCP gia fermo/scollegato: resta fermo; nessun avvio o rollback del vecchio.\n'if'recovery'in review else'Breve indisponibilita MCP: vecchio fermato e scollegato prima del nuovo, trattenuto fermo.\n')
    prompt=('\nInstallazione delle letture E2E con limiti finiti:2READ separati,1sostituzione MCP,2rotte aggiuntive.\n'
        'Piano e configurazioni privati: '+str(path)+'\nSHA256 revisione: '+reviewed+'\n'
        +old_mcp+
        'Ingestion/UDP/Postgres/Gateway originali e worker Registry restano intatti.\n'
        'Tre immagini CI esatte, identita native config/manifest dimostrate senza rebuild/relabel.\n'
        'READ senza Flyway/esecuzione, mount RO, rootfs RO; readiness DB/policy richiesta.\n'
        'Normale bootstrap OAuth del SOLO MCP sostitutivo puo avvenire sotto il mandato esistente.\n'
        'Il normale avvio MCP puo aggiornare il proprio catalogo manifest; nessuna migrazioneDB.\n'
        'Solo dopo STOP/DETACH provati, la proiezione legacy Config.MacAddress puo risultare assente.\n'
        'La MAC endpoint resta conservata; nessun altro campo Config viene escluso dal confronto.\n'
        'Nessun grant IAM, budget fonte, attivazione o acquisizione; nessun reset o replay.\n'
        +credential+
        'Massimo900secondi+30 di sola quarantena dei3candidati propri non committed.\n'
        'Watchdog effimero; stop solo candidati propri se controller perso/scaduto. Nessun rollback.\n'
        'Effetto ambiguo resta CLAIMED e richiede riconciliazione, mai rilancio automatico.\n'
        'Questa operazione NON concede accettazione E2E o release.\n'
        'Per approvare questa sola revisione, digita ESCLUSIVAMENTE la riga seguente.\n'
        'Non aggiungere parole o punteggiatura dopo l\'hash.\n'
        'APPROVO '+reviewed+'\n> ')
    fd=os.open('/dev/tty',os.O_RDWR|os.O_NOCTTY|os.O_NOFOLLOW)
    try:
        require(stat.S_ISCHR(os.fstat(fd).st_mode)and os.isatty(fd),'CONTROLLING_ACQUISITION_TERMINAL_REQUIRED')
        termios.tcflush(fd,termios.TCIFLUSH);os.write(fd,prompt.encode());answer=bytearray()
        while len(answer)<=128:
            part=os.read(fd,1)
            if part in(b'',b'\n'):break
            answer.extend(part)
        require(bytes(answer)==('APPROVO '+reviewed).encode(),'EXACT_ACQUISITION_REVIEW_NOT_APPROVED')
    finally:os.close(fd)
    return {'schema':'ouf.acquisition-read-native-terminal-decision.v1','reviewHash':reviewed,'decision':DECISION,'approvedAt':int(time.time())}
class SignedAuthority:
    def __init__(self,review,raw,human_path,human_hash,verifier,read,clock=time.time):
        from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
        require(type(verifier)is DetachedAuthenticator,'REAL_EXISTING_INSTALLATION_ROLE_VERIFIER_REQUIRED')
        self.review=copy.deepcopy(validate_review(review));self.raw=raw;self.human_path=human_path;self.human_hash=human_hash
        self.verifier,self.read,self.clock=verifier,read,clock;self.started=time.monotonic();self.last_wall=clock();self.check()
    def check(self):
        from tools.semantic_provider_deployment_authentication import policy as current_policy
        now=self.clock();require(now>=self.last_wall,'ACQUISITION_WALL_CLOCK_REGRESSION');self.last_wall=now
        human=self.read(self.human_path,self.human_hash);authority=json.loads(self.raw);v=self.review['verification'];ctx=v['context']
        require(encoded(authority)==self.raw and authority=={'schema':AUTHORITY_SCHEMA,'scope':scope(self.review),
            'issuedAt':human['issuedAt'],'expiresAt':human['expiresAt'],'cleanupExpiresAt':human['expiresAt']+30,'installationRef':ctx['installationRef'],
            'entityRef':ctx['entityRef'],'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False},'EXACT_ACQUISITION_AUTHORITY_SCOPE_REQUIRED')
        require(human['schema']==HUMAN_SCHEMA and human['reviewHash']==digest(self.review)and human['authorityHash']==sha(self.raw)
            and human['decision']==DECISION and human['state']=='ACTIVE'and type(human['issuedAt'])is int and type(human['expiresAt'])is int
            and human['expiresAt']-human['issuedAt']==900 and human['issuedAt']<=now<human['expiresAt']
            and time.monotonic()-self.started<900,'CURRENT_FINITE_ACQUISITION_MANDATE_REQUIRED')
        require(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==self.review['bootId'],'SAME_ACQUISITION_AUTHORITY_BOOT_REQUIRED')
        require(self.verifier.policy_binding==v['trustPolicy']and self.verifier.openssl_binding==v['openssl'],'SAME_ACQUISITION_ROLE_POLICY_REQUIRED')
        for role,key in(('DEPLOYMENT_INTENT','intentIssuerRef'),('FINAL_DEPLOYMENT_APPROVAL','approvalIssuerRef')):
            require(self.verifier(self.raw,role,ctx[key],ctx['installationRef'],ctx['entityRef'])is True,'DUAL_CURRENT_ACQUISITION_SIGNATURES_REQUIRED')
        policy=current_policy(self.verifier.read_policy(),ctx['installationRef'],ctx['entityRef'],now)
        for role,key in(('DEPLOYMENT_INTENT','intentIssuerRef'),('FINAL_DEPLOYMENT_APPROVAL','approvalIssuerRef'),('CREATION_ATTESTATION','attestorRef')):
            keys=[v for v in policy['keys']if role in v['roles']and v['issuerRef']==ctx[key]and v['state']=='ACTIVE'and v['notBefore']<=human['issuedAt']]
            require(len(keys)==1 and keys[0]['expiresAt']>=human['expiresAt']+30,'WHOLE_ACQUISITION_WINDOW_WITHIN_EXISTING_KEY_AUTHORITY_REQUIRED')
        return human
    def remaining(self):return self.check()['expiresAt']-self.clock()
def authentication_file(root,name,raw):
    # Existing authentication contracts require mode0600, unlike immutable evidence0400.
    root=Path(root);require(root.is_absolute()and root.resolve()==root,'EXACT_ACQUISITION_AUTH_FILE_ROOT')
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
        and 0<=time.time()-decision['approvedAt']<=120,'FRESH_EXACT_ACQUISITION_TERMINAL_DECISION_REQUIRED')
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
        require(len(selected)==1 and selected[0]['expiresAt']>=now+930,'FULL_ACQUISITION_KEY_WINDOW_REQUIRED_BEFORE_SIGNING')
    for role,key in(('DEPLOYMENT_INTENT','intentIssuerRef'),('FINAL_DEPLOYMENT_APPROVAL','approvalIssuerRef')):
        signer=ExistingEd25519Signer(profile['keyBindings']['installer'],profile['keyRefs']['installer'],verifier,
            {'role':role,'issuerRef':ctx[key],'installationRef':ctx['installationRef'],'entityRef':ctx['entityRef']})
        authentication_file(target,sha(raw)+'.'+role+'.json',signer.sign(raw))
    gate=SignedAuthority(review,raw,str(target/'human.json'),digest(human),verifier,read)
    return gate
class Execution:
    def __init__(self,gate,journal,ports):
        from tools.semantic_lease_recovery.recovery_journal import Journal
        require(type(gate)is SignedAuthority and type(journal)is Journal,'REAL_SIGNED_ACQUISITION_GATE_AND_JOURNAL_REQUIRED')
        self.gate,self.journal,self.ports=gate,journal,ports;self.review=gate.review;self.limits,self.stages=review_profile(self.review);ports.execution=self
        require(str(journal.root)==self.review['executionRoot']and ports.root==journal.root,'ONE_EXACT_ACQUISITION_SCOPE_REQUIRED')
    def initialize(self):
        human=self.gate.check();counts=copy.deepcopy(self.ports.ctx.counts)
        require(set(counts)==set(self.limits)and all(type(v)is int and self.review['preflightCounts'][k]<=v<=self.limits[k]for k,v in counts.items())and all(counts[k]==(self.review['recovery']['retainedCounts'][k]if'recovery'in self.review else 0)for k in('engineWrites','imageLoadAttempts','adminPuts','readinessGets','quarantineStops')),'PRESERVED_PREFLIGHT_ATTEMPTS_REQUIRED')
        candidates=self.ports.initial_candidates()if'recovery'in self.review else{}
        self.journal.initialize({'schema':'ouf.acquisition-read-native-journal.v1','version':0,'reviewHash':digest(self.review),'authorityHash':sha(self.gate.raw),'nextStage':0,'effects':[],'counts':counts,'candidates':candidates,'quarantine':None,'expiresAt':human['expiresAt'],'expiresMonotonic':time.monotonic()+max(0,human['expiresAt']-time.time()),'state':'OPEN','automaticReplayAllowed':False,'budgetReset':False})
    def read_journal(self):
        for attempt in range(8):
            try:return self.journal.read()
            except BlockingIOError:
                if attempt==7:raise
                time.sleep(.02)
    def record(self):
        self.gate.check();row=self.read_journal();n=row['nextStage']
        require(row['schema']=='ouf.acquisition-read-native-journal.v1'and row['reviewHash']==digest(self.review)and row['authorityHash']==sha(self.gate.raw)and row['quarantine']is None and row['automaticReplayAllowed']is False and row['budgetReset']is False and row['state']=='OPEN'and type(n)is int and 0<=n<=len(self.stages)and len(row['effects'])in(n,n+1)and time.time()<row['expiresAt']and time.monotonic()<row['expiresMonotonic'],'CURRENT_FINITE_ACQUISITION_HISTORY_REQUIRED')
        require(set(row['counts'])==set(self.limits)and all(type(v)is int and self.review['preflightCounts'][k]<=v<=self.limits[k]for k,v in row['counts'].items()),'DURABLE_ACQUISITION_BUDGET_REQUIRED')
        for i,e in enumerate(row['effects']):require(e['stage']==self.stages[i]and e['intentHash']==digest({'reviewHash':digest(self.review),'stage':self.stages[i]})and e['state']==('APPLIED'if i<n else'CLAIMED'),'ORDERED_ACQUISITION_EFFECT_HISTORY_REQUIRED')
        return row
    def save(self,row,**changes):
        following={**row,**changes,'version':row['version']+1}
        for attempt in range(8):
            try:self.journal.compare_and_save(row,following);return following
            except BlockingIOError:
                if attempt==7:raise
                time.sleep(.02)
    def reserve(self,kind):
        row=self.record();require(row['counts'][kind]<self.limits[kind],'ACQUISITION_OPERATION_BUDGET_EXHAUSTED');counts=copy.deepcopy(row['counts']);counts[kind]+=1;self.save(row,counts=counts)
    def candidate(self,role,**changes):
        row=self.record();values=copy.deepcopy(row['candidates']);values[role]={**values.get(role,{}),**changes};self.save(row,candidates=values)
    def run(self):
        with self.journal.invocation():
            while True:
                row=self.record();i=row['nextStage']
                if i==len(self.stages):
                    result=self.ports.final_result();self.gate.check();self.save(self.record(),state='COMPLETE');return result
                require(len(row['effects'])==i,'CLAIMED_ACQUISITION_EFFECT_NO_REPLAY')
                stage=self.stages[i];print(encoded({'schema':'ouf.acquisition-read-native-progress.v1','stage':stage,'counts':row['counts'],'runtimeAuthorityIssued':True,'automaticReplayAllowed':False,'budgetReset':False}).decode(),flush=True);self.ports.guard(stage)
                minimum=330 if stage=='DISABLE_OLD_MCP_RESTART'else 220 if stage.startswith(('START_','RESTART_'))else 120 if stage.startswith('IMPORT_')else 35
                require(self.gate.remaining()>minimum,'INSUFFICIENT_ACQUISITION_AUTHORITY_WINDOW')
                row=self.record();effects=copy.deepcopy(row['effects']);effects.append({'stage':stage,'state':'CLAIMED','intentHash':digest({'reviewHash':digest(self.review),'stage':stage})});self.save(row,effects=effects)
                proof=self.ports.execute(stage);self.gate.check();require(type(proof)is dict and proof,'EXPLICIT_ACQUISITION_EFFECT_PROOF_REQUIRED')
                row=self.record();effects=copy.deepcopy(row['effects']);effects[-1].update(state='APPLIED',proof=proof);self.save(row,effects=effects,nextStage=i+1)
