"""One signed reconciliation of the retained CREATE, then stages 8..12 only.

Original source bytes, review, authority and seven applied proofs stay immutable.
The original journal is CAS-advanced under its invocation lock; counts never reset.
"""
import copy,hashlib,json,os,re,stat,termios,time
from pathlib import Path
import verified_v35_recovery_base as base
import verified_v35_recovery_protocol as core
import verified_v35_recovery_ports as ports
import verified_v35_recovery_quarantine as quarantine
import verified_v35_recovery_sql as sql_session

PARENT_REVIEW='828d9d6c5f04f8535801e45c2d284a71256232b778b3d6dc14afe6d468e5a94b'
PARENT_AUTHORITY='af9a8fbd77a7d5d7caabb436360650eb9ab4ea126684ea15cc70c1fd42f37d63'
PARENT_JOURNAL='255437a61e8b435862e85ddffa5edfef7365a42735301cefffbc299a9d149879'
READER='/etc/ouf/deploy-snapshots/onboarding-v35-retained-reader-bf4b2bc711802b25'
READER_HASH='bf4b2bc711802b25c386f24da4e9733af79c895a9bf2b4e102749f0b69b90a32'
BASE_COUNTS={'backupProcesses':2,'engineGets':139,'engineWrites':4,'imageLoadAttempts':1,'ownerConfigurationReads':18,'quarantineStops':0,'readinessGets':0,'sqlSessions':5}
SCOPE='created-hostname-recovery-v1'
require=core.require

def load_parent(ctx):
    from tools.semantic_lease_recovery.recovery_journal import Journal
    ctx.parent_review=ctx.files.json(ctx.parent/'review.json',PARENT_REVIEW);core.validate_review(ctx.parent_review)
    ctx.parent_authority=ctx.files.json(ctx.parent/'authority/authority.json',PARENT_AUTHORITY)
    require(ctx.parent_review['frozenPlanHash']==base.FROZEN_HASH and ctx.parent_review['executionRoot']==str(ctx.parent)
        and ctx.parent_review['logicalOperationRef']==ctx.frozen['logicalOperationRef']and ctx.parent_authority['scope']==core.scope(ctx.parent_review)
        and time.time()>ctx.parent_authority['cleanupExpiresAt'],'EXPIRED_PREVIOUS_V35_AUTHORITY_AND_EXACT_LINEAGE_REQUIRED')
    ctx.journal=Journal(ctx.parent);ctx.parent_row=ctx.journal.read()
    require(core.digest(ctx.parent_row)==PARENT_JOURNAL and ctx.parent_row['reviewHash']==PARENT_REVIEW and ctx.parent_row['authorityHash']==PARENT_AUTHORITY
        and ctx.parent_row['counts']==BASE_COUNTS and ctx.parent_row['nextStage']==7 and len(ctx.parent_row['effects'])==8
        and ctx.parent_row['createdConfigurationVerified']is False and ctx.parent_row['createdGeneration']is None
        and ctx.parent_row['startupDeadline']is None and ctx.parent_row['quarantine']is None
        and ctx.parent_row['automaticReplayAllowed']is False and ctx.parent_row['budgetReset']is False,'EXACT_UNREPLAYED_V35_CREATE_CLAIM_REQUIRED')
    for i,effect in enumerate(ctx.parent_row['effects']):
        require(effect['stage']==core.STAGES[i]and effect['state']==('APPLIED'if i<7 else'CLAIMED')
            and effect['intentHash']==core.digest({'reviewHash':PARENT_REVIEW,'stage':core.STAGES[i]}),'EXACT_PARENT_V35_EFFECT_PROOFS_REQUIRED')
    ctx.created=ctx.parent_row['createdId'];require(type(ctx.created)is str and re.fullmatch('[a-f0-9]{64}',ctx.created),'ONE_RETAINED_V35_CANDIDATE_REQUIRED')
    base.protected(Path(READER)/'read.py',READER_HASH)
    retained=ctx.files.json(Path(READER)/'reader-result.json')
    require(retained['status']=='RETAINED_CREATED_CONFIG_DIFFERENCE_OBSERVED'and retained['complete']is True
        and retained['reviewHash']==PARENT_REVIEW and retained['authorityHash']==PARENT_AUTHORITY and retained['retainedJournalHash']==PARENT_JOURNAL
        and retained['retainedCumulativeCounts']==BASE_COUNTS and len(retained['retainedCandidateConfigDifferences'])==1
        and retained['retainedCandidateConfigDifferences'][0]['field']=='Hostname'
        and retained['retainedCandidateConfigDifferences'][0]['expectedEmpty']is True
        and retained['retainedCandidateConfigDifferences'][0]['observedEmpty']is False,'EXACT_CONSUMED_HOSTNAME_RECONCILIATION_REQUIRED')
    ctx.retained_reader_hash=core.digest(retained)

class Context(base.Context):
    def __init__(self,n,p,q,l,c,d,m,r,configuration,replacement,code_root,entry_path):
        self.n,self.p,self.q,self.l,self.c,self.d,self.m,self.r=n,p,q,l,c,d,m,r
        self.configuration_raw,self.replacement_raw=configuration,replacement;self.core,self.ports_module=core,ports
        self.importer=base.image_import_definitions(n,base.protected(Path(base.__file__).parent/'image_import.py',base.IMAGE_IMPORT_HASH))
        self.files=m.Facts();self.frozen=self.files.json(base.FROZEN,base.FROZEN_HASH)
        completion=self.files.json(Path(base.FROZEN).parent/'complete.json')
        require(completion['privatePlanHash']==base.FROZEN_HASH and completion['complete']is True
            and self.frozen['schema']=='ouf.onboarding-v35-frozen-native-plan.v1'and self.frozen['proposalHash']==n.PROPOSAL_HASH
            and self.frozen['inputHash']==d.INPUT_HASH and self.frozen['databaseMigration']['flywayChecksum']==1095739786
            and [v['name']for v in self.frozen['stages']]==list(core.STAGES),'SAME_FROZEN_V35_PROPOSAL_REQUIRED')
        self.inputs=self.files.json(d.INPUT,d.INPUT_HASH)
        require(self.inputs['bootId']==self.frozen['bootId']==Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'SAME_RECONCILIATION_BOOT_REQUIRED')
        for ref in self.frozen['retainedFiles']:self.files.json(ref['path'],ref['sha256'])
        logical=self.frozen['logicalOperationRef'];require(re.fullmatch('[a-f0-9]{64}',logical),'EXACT_RECONCILIATION_LOGICAL_OPERATION')
        self.parent=Path(base.PARENT)/('onboarding-v35-apply-'+logical)
        require(str(self.parent)==self.frozen['proposedAuthorityDirectory'],'SAME_EXISTING_LOGICAL_JOURNAL_REQUIRED')
        load_parent(self)
        self.profile=copy.deepcopy(self.parent_review['nativePlan']['databaseProfile'])
        require(self.profile==self.frozen['boundDatabaseProfile'],'SAME_EXISTING_DATABASE_PROFILE_REQUIRED')
        self.contract,self.manifest,self.image,self.jar=p.packaged(m,self.files)
        # The original entry retained psql's raw JSON bytes, while its signed
        # review binds the canonical decoded object. Bind both representations.
        self.before=self.files.json(self.parent/'before-database.json')
        require(core.digest(self.before)==self.parent_review['beforeDatabaseHash'],'EXACT_RETAINED_DATABASE_OBJECT_REQUIRED')
        self.native_plan=copy.deepcopy(self.parent_review['nativePlan']);request=self.native_plan['replacement']['request']
        require(request.get('Hostname')==''and request['HostConfig']['NetworkMode']in(self.native_plan['replacement']['network']['id'],self.native_plan['replacement']['network']['name']),'ONLY_DEFAULT_HOSTNAME_ON_RETAINED_NETWORK_REQUIRED')
        request['Hostname']=self.created[:12]
        self.native_plan['existingCandidateAdoption']={'containerId':self.created,'parentNativePlanHash':self.parent_review['nativePlanHash'],
            'profile':'EMPTY_CREATE_HOSTNAME_TO_EXACT_CONTAINER_SHORT_ID','expectedHostname':self.created[:12],'creationRequestWillNotBeReplayed':True}
        self.candidate=self.native_plan['candidate'];self.preflight_counts=copy.deepcopy(BASE_COUNTS);self.in_preflight=True
        self.source_bindings=dict(self.parent_review['sourceClosure'])
        for path in (Path(entry_path),code_root/'recovery.py',code_root/'recovery_sql.py'):
            self.source_bindings[str(path)]=hashlib.sha256(base.protected(path)).hexdigest()
        for path,expected in self.source_bindings.items():base.protected(path,expected)
        fd=os.open(self.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.mkdir(SCOPE,0o700,dir_fd=fd);os.fsync(fd)
        finally:os.close(fd)
        self.root=self.parent/SCOPE
        m.new_file(self.root,'preparation.claim.json',{'schema':'ouf.onboarding-v35-existing-create-claim.v1','logicalOperationRef':logical,
            'parentJournalHash':PARENT_JOURNAL,'parentReviewHash':PARENT_REVIEW,'parentAuthorityHash':PARENT_AUTHORITY,'automaticReplayAllowed':False,'budgetReset':False})
        m.new_file(self.root,'parent-journal.json',self.parent_row);(self.root/'empty-docker-config').mkdir(mode=0o700)
        backup=self.parent_row['backup'];require(backup['payloadParsed']is True and backup['restorePerformed']is False
            and backup['path']==str(self.parent/'onboarding.dump'),'RETAINED_QUIESCENT_BACKUP_REQUIRED')
        p.hash_file(m,backup['path'],1073741824,backup['sha256'])
        previous=r.json_at(r.REVIEW,r.REVIEW_HASH);binding=previous['proposal']['inputsBinding']
        retained=r.json_at(binding['path'],binding['sha256']);self.authority_inputs=retained['review']['authorityInputs']
        self.session=None;self.check_sources()

class ObservationGate:
    def __init__(self,ctx):self.ctx=ctx
    def check(self):
        self.ctx.check_sources();require(core.digest(self.ctx.journal.read())==PARENT_JOURNAL,'ORIGINAL_CREATE_CLAIM_CHANGED')
    def remaining(self):return 900

class PreflightRecord:
    def __init__(self,ctx):self.ctx=ctx
    def record(self):return copy.deepcopy(self.ctx.parent_row)
    def read_journal(self):return self.record()

class RecoveryPorts(ports.NativePorts):
    def reserve(self,kind):
        if self.ctx.in_preflight:self.ctx.preflight_reserve(kind)
        else:super().reserve(kind)
    def request(self,method,path,body=None):
        allowed=('/v1.44/containers/'+self.ctx.created+'/start','/v1.44/containers/'+self.ctx.created+'/update')
        require(method=='GET'or(not self.ctx.in_preflight and method=='POST'and path in allowed),'ONLY_EXISTING_CANDIDATE_START_OR_POLICY_RESTORE_ALLOWED')
        return super().request(method,path,body)
    def candidate_guard(self,cid,stage,**kwargs):
        require(cid==self.ctx.created and self.row['request']['Hostname']==cid[:12],'EXACT_CREATED_SHORT_ID_HOSTNAME_REQUIRED')
        result=super().candidate_guard(cid,stage,**kwargs)
        if self.ctx.in_preflight:
            require(result['RestartCount']==0 and result['State'].get('StartedAt')=='0001-01-01T00:00:00Z','EXISTING_CANDIDATE_MUST_NEVER_HAVE_STARTED')
            self.ctx.current_candidate_proof={'containerId':cid,'configHash':core.digest(result['Config']),'hostConfigHash':core.digest(result['HostConfig']),
                'mountsHash':core.digest(sorted(result['Mounts'],key=lambda v:v['Destination'])),'exactHostnameVerified':True,'neverStarted':True}
        return result
    def snapshot(self,*,after=False):
        require(self.ctx.session is not None,'ONE_FINITE_RECOVERY_SQL_SESSION_REQUIRED')
        result=self.ctx.session.query(after=after);self.last_sql=result
        if after:self.ctx.session.close(success=True)
        return result
    def execute(self,stage):
        require(stage in core.STAGES[8:],'CONSUMED_V35_STAGE_MUST_NOT_BE_DISPATCHED')
        return super().execute(stage)

class Execution(core.Execution):
    def __init__(self,ctx,gate,adapter,review):
        from tools.semantic_lease_recovery.recovery_journal import Journal
        require(type(gate)is core.SignedAuthority and type(ctx.journal)is Journal,'EXISTING_REAL_V35_GATE_AND_JOURNAL_REQUIRED')
        self.ctx,self.gate,self.journal,self.ports,self.review=ctx,gate,ctx.journal,adapter,review;adapter.execution=self
    def adopt(self):
        human=self.gate.check();row=self.journal.read();require(core.digest(row)==PARENT_JOURNAL,'EXACT_PARENT_CREATE_CLAIM_CAS_REQUIRED')
        require(self.ctx.preflight_counts['sqlSessions']==5 and self.ctx.preflight_counts['engineWrites']==4
            and all(BASE_COUNTS[k]<=v<=core.LIMITS[k]for k,v in self.ctx.preflight_counts.items()),'RETAINED_AND_PREFLIGHT_COUNTERS_MUST_BE_PRESERVED')
        require(self.ctx.current_candidate_proof==self.review['recovery']['currentCandidate'],'SAME_REVIEWED_CURRENT_CANDIDATE_PROOF_REQUIRED')
        effects=copy.deepcopy(row['effects']);effects[7].update(state='APPLIED',proof={'creationReconciledWithoutReplay':True,
            'retainedJournalHash':PARENT_JOURNAL,'reconciliationReviewHash':core.digest(self.review),'currentCandidate':self.ctx.current_candidate_proof})
        self.save(row,effects=effects,nextStage=8,reviewHash=core.digest(self.review),authorityHash=core.sha(self.gate.raw),
            createdConfigurationVerified=True,counts=copy.deepcopy(self.ctx.preflight_counts),expiresAt=human['expiresAt'],
            expiresMonotonic=time.monotonic()+max(0,human['expiresAt']-time.time()),
            reconciliation={'schema':'ouf.onboarding-v35-created-reconciliation.v1','parentJournalHash':PARENT_JOURNAL,'parentReviewHash':PARENT_REVIEW,
                'parentAuthorityHash':PARENT_AUTHORITY,'recoveryReviewHash':core.digest(self.review),'existingCandidateAdopted':True,'creationReplayed':False})
        self.ctx.in_preflight=False
    def record(self):
        self.gate.check();row=self.read_journal();i=row['nextStage']
        require(row['schema']=='ouf.onboarding-v35-native-journal.v1'and row['reviewHash']==core.digest(self.review)
            and row['authorityHash']==core.sha(self.gate.raw)and row['automaticReplayAllowed']is False and row['budgetReset']is False
            and row['quarantine']is None and 8<=i<=13 and len(row['effects'])in(i,i+1)
            and time.time()<row['expiresAt']and time.monotonic()<row['expiresMonotonic'],'CURRENT_RECONCILED_V35_FENCE_REQUIRED')
        require(row['effects'][:7]==self.ctx.parent_row['effects'][:7]and row['backup']==self.ctx.parent_row['backup']
            and row['createdId']==self.ctx.created and row['createdConfigurationVerified']is True
            and row['reconciliation']['parentJournalHash']==PARENT_JOURNAL,'ALL_PARENT_APPLIED_PROOFS_AND_BACKUP_MUST_BE_PRESERVED')
        for n,effect in enumerate(row['effects']):
            expected=PARENT_REVIEW if n<=7 else core.digest(self.review)
            require(effect['stage']==core.STAGES[n]and effect['state']==('APPLIED'if n<i else'CLAIMED')
                and effect['intentHash']==core.digest({'reviewHash':expected,'stage':core.STAGES[n]}),'ORDERED_OLD_AND_NEW_V35_INTENT_HISTORY_REQUIRED')
        require(set(row['counts'])==set(core.LIMITS)and all(BASE_COUNTS[k]<=v<=core.LIMITS[k]for k,v in row['counts'].items()),'UNCHANGED_CUMULATIVE_V35_CEILINGS_REQUIRED')
        return row
    def run(self):
        # Caller holds the SAME original invocation lock before preflight and TTY.
        while True:
            row=self.record();i=row['nextStage']
            if i==13:self.save(row,state='COMPLETE');return self.ports.final_result()
            require(len(row['effects'])==i,'CLAIMED_RECOVERY_EFFECT_REQUIRES_RECONCILIATION_NO_REPLAY')
            stage=core.STAGES[i];self.ports.guard(stage);require(self.gate.remaining()>(240 if i==8 else 30),'FINITE_REMAINING_V35_RECOVERY_WINDOW_REQUIRED')
            row=self.record();effects=copy.deepcopy(row['effects']);effects.append({'stage':stage,'state':'CLAIMED','intentHash':core.digest({'reviewHash':core.digest(self.review),'stage':stage})})
            self.save(row,effects=effects);proof=self.ports.execute(stage);self.gate.check();require(type(proof)is dict and proof,'EXPLICIT_V35_RECOVERY_EFFECT_PROOF_REQUIRED')
            row=self.record();effects=copy.deepcopy(row['effects']);effects[-1].update(state='APPLIED',proof=proof);self.save(row,effects=effects,nextStage=i+1)

def terminal_decision(review,path):
    reviewed=core.digest(review)
    prompt=('\nRecupero della STESSA Onboarding: adozione candidato gia creato, nessuna seconda creazione.\n'
        'Hostname esatto derivato dal suo Id; tutti gli altri Config/HostConfig/mount/endpoint conservati.\n'
        'Vecchio container trattenuto fermo; backup esistente verificato, nessun nuovo import/stop/backup/restore.\n'
        'Una sessione SQL residua: due transazioni READ ONLY chiuse prima delle attese, controllo V34 prima e V35 dopo.\n'
        'Contatori cumulativi e limiti originali conservati. Nessun budget HUMAN fonte o attivazione.\n'
        'Nuova autorita900secondi +30 solo stop candidato non provato; avvio180secondi.\n'
        'Revisione privata: '+str(path)+'\nSHA256 revisione: '+reviewed+'\nScrivi APPROVO '+reviewed+'\n> ')
    fd=os.open('/dev/tty',os.O_RDWR|os.O_NOCTTY|os.O_NOFOLLOW)
    try:
        require(stat.S_ISCHR(os.fstat(fd).st_mode)and os.isatty(fd),'CONTROLLING_RECOVERY_TERMINAL_REQUIRED');termios.tcflush(fd,termios.TCIFLUSH);os.write(fd,prompt.encode());answer=bytearray()
        while len(answer)<=128:
            part=os.read(fd,1)
            if part in(b'',b'\n'):break
            answer.extend(part)
        require(bytes(answer)==('APPROVO '+reviewed).encode(),'EXACT_RECOVERY_REVIEW_NOT_APPROVED')
    finally:os.close(fd)
    return {'schema':'ouf.onboarding-v35-terminal-decision.v1','reviewHash':reviewed,'decision':core.DECISION,'approvedAt':int(time.time())}

def operator(ctx):
    from tools.semantic_registry_recovery_execution.postboot_authority import authority_metadata
    from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
    with ctx.journal.invocation():
        observation=ObservationGate(ctx);adapter=RecoveryPorts(core,ctx,ctx.root,{'nativePlan':ctx.native_plan},observation);adapter.execution=PreflightRecord(ctx)
        print(core.encoded({'schema':'ouf.onboarding-v35-recovery-progress.v1','phase':'VERIFY_EXISTING_CANDIDATE_AND_RETAINED_BACKUP','runtimeEffectsDispatched':0}).decode(),flush=True)
        observation.check();adapter.guard(core.STAGES[7]);require(adapter.image()is not None,'EXISTING_EXACT_V35_IMAGE_REQUIRED_NO_IMPORT')
        profile,policy=authority_metadata(ctx.authority_inputs);closure=dict(sorted(ctx.source_bindings.items()))
        review={**copy.deepcopy(ctx.parent_review),'executionRoot':str(ctx.root),'nativePlan':ctx.native_plan,'nativePlanHash':core.digest(ctx.native_plan),
            'sourceClosure':closure,'sourceClosureHash':core.digest(closure),'preflightCounts':copy.deepcopy(ctx.preflight_counts),
            'recovery':{'kind':'RECONCILE_EXISTING_CREATE_THEN_STAGES_8_TO_12','logicalOperationRef':ctx.frozen['logicalOperationRef'],
                'parentExecutionRoot':str(ctx.parent),'parentJournalHash':PARENT_JOURNAL,'parentReviewHash':PARENT_REVIEW,'parentAuthorityHash':PARENT_AUTHORITY,
                'retainedReaderResultHash':ctx.retained_reader_hash,'retainedCumulativeCounts':BASE_COUNTS,'maximumsUnchanged':True,
                'currentCandidate':ctx.current_candidate_proof,'remainingStages':list(core.STAGES[8:]),'onePhysicalSqlSession':True,'readOnlyTransactions':2,
                'noOpenTransactionDuringWaits':True,'createImportBackupStopOldReplayAuthorized':False},
            'verification':{'trustPolicy':ctx.authority_inputs['trustPolicy'],'openssl':ctx.authority_inputs['executables']['openssl'],'context':ctx.authority_inputs['context']}}
        core.validate_review(review);ctx.m.new_file(ctx.root,'review.json',review);decision=terminal_decision(review,ctx.root/'review.json')
        require(ctx.r.json_at(ctx.root/'review.json',core.digest(review))==review and authority_metadata(ctx.authority_inputs)==(profile,policy),'RECOVERY_REVIEW_OR_POLICY_CHANGED_DURING_DECISION')
        observation.check();adapter.guard(core.STAGES[7]);require(adapter.image()is not None,'CURRENT_EXACT_V35_IMAGE_REQUIRED')
        gate=core.issue(review,ctx.root,profile,decision,ctx.m.new_file,ctx.r.json_at);adapter.gate=gate
        execution=Execution(ctx,gate,adapter,review);execution.adopt()
        print(core.encoded({'schema':'ouf.onboarding-v35-recovery-issued.v1','reviewHash':core.digest(review),'authorityHash':core.sha(gate.raw),
            'parentJournalHash':PARENT_JOURNAL,'runtimeAuthorityIssued':True,'containerWrites':0,'existingCandidateAdopted':True,'automaticReplayAllowed':False,'budgetReset':False}).decode(),flush=True)
        try:
            ctx.watchdog_pid=quarantine.launch(ctx,review,gate,ctx.journal)
            ctx.session=sql_session.ReadOnlySession(ctx,adapter);ctx.session.start();adapter.snapshot(after=False)
            result=execution.run()
        except BaseException:
            if ctx.session is not None:ctx.session.close()
            try:quarantine.stop_unproven(ctx,review,gate.raw,ctx.journal,'RECOVERY_CONTROLLER_STOPPED')
            except BaseException:ctx.m.new_file(ctx.root,'controller-quarantine-unproven.json',{'status':'STOP_RECONCILE','automaticReplayAllowed':False,'negativeEffectMayBePartial':True})
            raise
        finally:
            if ctx.session is not None:ctx.session.close()
        result.update(status='ONBOARDING_V35_EXISTING_CANDIDATE_RECOVERED_SOURCE_PRESERVED',parentJournalHash=PARENT_JOURNAL,
            existingCandidateAdopted=True,creationReplayed=False,oldStageReplayPerformed=False,maximumsUnchanged=True,
            recoverySqlSessions=1,recoveryReadOnlyTransactions=2,retainedCumulativeCountsBefore=BASE_COUNTS)
        context=review['verification']['context'];signer=ExistingEd25519Signer(profile['keyBindings']['attestor'],profile['keyRefs']['attestor'],gate.verifier,
            {'role':'CREATION_ATTESTATION','issuerRef':context['attestorRef'],'installationRef':context['installationRef'],'entityRef':context['entityRef']})
        gate.check();ctx.m.new_file(ctx.root,'result.json',result);core.authentication_file(ctx.root/'authority',core.sha(core.encoded(result))+'.CREATION_ATTESTATION.json',signer.sign(core.encoded(result)))
        require(gate.verifier(core.encoded(result),'CREATION_ATTESTATION',context['attestorRef'],context['installationRef'],context['entityRef'])is True,'SIGNED_V35_RECOVERY_RESULT_REQUIRED')
        return result
