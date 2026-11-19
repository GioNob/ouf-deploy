"""Finite two-owner scope; reuses qualified signing/CAS/journal algorithms with NEW typed authority."""
import copy,hashlib,json,os,time
from pathlib import Path
ROLES=('onboarding','mcp')
STAGES=('VERIFY_CURRENT_ADMISSION','IMPORT_ONBOARDING_OWNER','IMPORT_MCP_OWNER','VERIFY_PRESTOP_STATE','DISABLE_OLD_RESTART_ONBOARDING_OWNER','STOP_OLD_ONBOARDING_OWNER','VERIFY_QUIESCED_BACKUP','DETACH_OLD_ONBOARDING_OWNER','RENAME_OLD_ONBOARDING_OWNER','CREATE_ONBOARDING_OWNER','VERIFY_PRESTART_STATE','START_ONBOARDING_OWNER','VERIFY_READINESS_ONBOARDING_OWNER','VERIFY_POSTSTART_STATE','RESTORE_RESTART_ONBOARDING_OWNER','VERIFY_BEFORE_MCP','DISABLE_OLD_RESTART_MCP_OWNER','STOP_OLD_MCP_OWNER','DETACH_OLD_MCP_OWNER','RENAME_OLD_MCP_OWNER','CREATE_MCP_OWNER','START_MCP_OWNER','VERIFY_READINESS_MCP_OWNER','RESTORE_RESTART_MCP_OWNER','VERIFY_FINAL','VERIFY_FINAL_STATE',)
LIMITS={"engineGets":1024,"engineWrites":20,"imageLoadAttempts":2,"readinessGets":128,"adminGets":0,"adminPuts":0,"ownerConfigurationReads":64,"ownerConfigurationContentReads":1,"serviceCredentialFileReads":0,"quarantineStops":2,"sqlSessions":8,"backupProcesses":2}
AUTHORITY_SCHEMA='ouf.managed-csv-control-update-authority.v1'
HUMAN_SCHEMA='ouf.managed-csv-control-update-mandate.v1'
DECISION='APPROVE_ONE_FINITE_ONBOARDING_AND_MCP_CONTROL_UPDATE_ONLY'

def review_profile(review):
    require(review['schema']=='ouf.managed-csv-control-update-review.v1' and 'recovery'not in review and 'continuation'not in review,'EXACT_TWO_OWNER_ONLY_REVIEW_REQUIRED')
    return LIMITS,STAGES

def validate_review(review):
    review_profile(review)
    require(review['maximumSeconds']==900 and review['maximums']==LIMITS and review['stages']==list(STAGES)
        and review['negativeCleanup']=={'maximumAdditionalSeconds':30,'startupSeconds':180,'candidateStopOnly':True,'maximumStops':2,'disableCandidateRestartFirst':True}
        and review['nativePlanHash']==digest(review['nativePlan']) and review['sourceClosureHash']==digest(review['sourceClosure'])
        and review['frozenPlanHash']==review['nativePlan']['frozenPlanHash']
        and review['maintenanceSqlAuthorized']is True and review['databaseMigrationAuthorized']is False
        and review['databaseMigration']=={'from':36,'to':36,'newMigrations':0}
        and review['maximumBackupBytes']==268435456 and review['maximumBackupSeconds']==90
        and review['operationalSqlHash']==review['nativePlan']['proposal']['operationalSqlHash']
        and review['databaseRestoreAuthorized']is False and review['humanBudgetOrSourceActivationAuthorized']is False
        and review['acquisitionCallsAuthorized']is False and review['gatewayMutationAuthorized']is False
        and review['automaticReplayAllowed']is False and review['budgetReset']is False and review['releaseAcceptance']is False,
        'EXACT_FINITE_TWO_OWNER_ONLY_REVIEW_REQUIRED')
    return review


class Stop(RuntimeError):pass

def require(ok,code):
    if not ok:raise Stop(code)

def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()

def sha(raw):return hashlib.sha256(raw).hexdigest()

def digest(v):return sha(encoded(v))

def scope(review):
    validate_review(review)
    return {'reviewHash':digest(review),**{k:copy.deepcopy(review[k])for k in('frozenPlanHash','nativePlanHash','sourceClosureHash','logicalOperationRef','bootId','maximumSeconds','maximums','stages','negativeCleanup')}}

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
        require(set(counts)==set(self.limits)and all(type(v)is int and self.review['preflightCounts'][k]<=v<=self.limits[k]for k,v in counts.items())and all(counts[k]==0 for k in('engineWrites','imageLoadAttempts','adminPuts','readinessGets','quarantineStops','sqlSessions','backupProcesses')),'PRESERVED_PREFLIGHT_ATTEMPTS_REQUIRED')
        candidates={}
        self.journal.initialize({'schema':'ouf.managed-csv-control-update-journal.v1','version':0,'reviewHash':digest(self.review),'authorityHash':sha(self.gate.raw),'nextStage':0,'effects':[],'counts':counts,'candidates':candidates,'quarantine':None,'expiresAt':human['expiresAt'],'expiresMonotonic':time.monotonic()+max(0,human['expiresAt']-time.time()),'state':'OPEN','automaticReplayAllowed':False,'budgetReset':False})
    def read_journal(self):
        for attempt in range(8):
            try:return self.journal.read()
            except BlockingIOError:
                if attempt==7:raise
                time.sleep(.02)
    def record(self):
        self.gate.check();row=self.read_journal();n=row['nextStage']
        require(row['schema']=='ouf.managed-csv-control-update-journal.v1'and row['reviewHash']==digest(self.review)and row['authorityHash']==sha(self.gate.raw)and row['quarantine']is None and row['automaticReplayAllowed']is False and row['budgetReset']is False and row['state']=='OPEN'and type(n)is int and 0<=n<=len(self.stages)and len(row['effects'])in(n,n+1)and time.time()<row['expiresAt']and time.monotonic()<row['expiresMonotonic'],'CURRENT_FINITE_ACQUISITION_HISTORY_REQUIRED')
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
                    result=self.ports.final_result();self.gate.check();return result
                require(len(row['effects'])==i,'CLAIMED_ACQUISITION_EFFECT_NO_REPLAY')
                stage=self.stages[i];print(encoded({'schema':'ouf.managed-csv-control-update-progress.v1','stage':stage,'counts':row['counts'],'runtimeAuthorityIssued':True,'automaticReplayAllowed':False,'budgetReset':False}).decode(),flush=True);self.ports.guard(stage)
                minimum=540 if stage=='DISABLE_OLD_RESTART_ONBOARDING_OWNER'else 330 if stage.startswith('DISABLE_OLD_RESTART_')else 220 if stage.startswith('START_')else 120 if stage.startswith('IMPORT_')else 35
                require(self.gate.remaining()>minimum,'INSUFFICIENT_ACQUISITION_AUTHORITY_WINDOW')
                row=self.record();effects=copy.deepcopy(row['effects']);effects.append({'stage':stage,'state':'CLAIMED','intentHash':digest({'reviewHash':digest(self.review),'stage':stage})});self.save(row,effects=effects)
                proof=self.ports.execute(stage);self.gate.check();require(type(proof)is dict and proof,'EXPLICIT_ACQUISITION_EFFECT_PROOF_REQUIRED')
                row=self.record();effects=copy.deepcopy(row['effects']);effects[-1].update(state='APPLIED',proof=proof);self.save(row,effects=effects,nextStage=i+1)
