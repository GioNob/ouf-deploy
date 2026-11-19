"""One reviewed provider sequence, contained by the owned Registry gate window.

Create, initial mandates, profile publication, wrapper CAS, then one start.
The short reconciliation profile deliberately fits the original maintenance
window: only bounded read-only observations, cumulative durable counts and
backoff/jitter; no mutation retry, expiry extension or closed-window reopening.
"""
import copy,errno,http.client,os,secrets,time
from pathlib import Path
from .custody_capture import digest,require
from .provider_creation import ProviderCreation,PROVIDER_STAGES,provider_sequence_scope
from .provider_runtime_installation import ProviderRuntimeInstallation
from .provider_profile_publication import ProviderProfilePublication
from .provider_profiles import ProviderInitialIssuer
from .gate_peer_window import GatePeerWindow
from tools.semantic_policy_token_owner.producer import protected_directory
from recovery_journal import Journal
from engine_creation import CreationDenied

STAGES=PROVIDER_STAGES
EVIDENCE_SCHEMAS=dict(zip(STAGES,('ouf.discovery-provider-created.v1',
    'ouf.discovery-provider-initial-mandates-issued.v1','ouf.discovery-provider-profiles-published.v1',
    'ouf.discovery-provider-runtime-wrapper-switched.v1','ouf.discovery-provider-started-and-admitted.v1')))

def transient(error):
    # Engine deliberately redacts its transport exception. Follow only that
    # exact typed boundary's retained local context; malformed JSON, custody
    # denials and arbitrary ValueErrors remain permanent/unknown and block.
    if type(error) is CreationDenied and str(error)=='ENGINE_OUTCOME_REQUIRES_RECONCILIATION':
        return isinstance(error.__context__,http.client.IncompleteRead) or transient(error.__context__)
    if isinstance(error,(TimeoutError,ConnectionError)):return True
    if isinstance(error,OSError):return error.errno in {errno.ECONNRESET,errno.ETIMEDOUT,errno.EPIPE,errno.ECONNABORTED}
    d=getattr(error,'diagnosis',None)
    return type(d) is dict and d.get('errorType')=='TimeoutError' and d.get('switchOutcome')=='REPLACED'

class ProviderInstallationPhase:
    def __init__(self,runtime):
        require(type(runtime) is ProviderRuntimeInstallation and type(runtime.creation) is ProviderCreation
            and type(runtime.publication) is ProviderProfilePublication and type(runtime.issuer) is ProviderInitialIssuer
            and type(runtime.creation.window) is GatePeerWindow,'TYPED_SHARED_PROVIDER_SEQUENCE_OWNERS_REQUIRED')
        self.runtime=runtime;self.creation=runtime.creation;self.publication=runtime.publication;self.issuer=runtime.issuer
        self.parent=self.creation.parent;self.window=self.creation.window
        component=self.creation.component
        require(component['schema']=='ouf.discovery-composed-provider-installation-scope.v2',
            'EXPLICIT_PARENT_REVIEWED_PROVIDER_SEQUENCE_REQUIRED')
        self.scope=copy.deepcopy(component['sequence']);self.scope_hash=digest(self.scope)
        self.root=Path(self.scope['journalDirectory']);self.journal=Journal(self.root);self.parent_hash=self.parent.sha
        require(all(not self.root.is_relative_to(p) and not Path(p).is_relative_to(self.root)
            for p in (self.window.root,self.window.store.root)),'SEPARATE_PROVIDER_SEQUENCE_AND_GATE_EVIDENCE_REQUIRED')
        self.owner_ids=[id(v) for v in (self.runtime,self.creation,self.publication,self.issuer,self.window)]
        self.current()
    def current(self,*,open_window=False):
        require(self.owner_ids==[id(v) for v in (self.runtime,self.creation,self.publication,self.issuer,self.window)]
            and self.runtime.creation is self.creation and self.runtime.publication is self.publication
            and self.runtime.issuer is self.issuer and self.creation.window is self.window
            and self.creation.parent is self.parent and self.parent.sha==self.parent_hash
            and self.scope==provider_sequence_scope(self.creation.scope,self.runtime.scope,self.runtime.admission.scope,
                journal_directory=self.root) and digest(self.scope)==self.scope_hash
            and self.creation.component['sequence']==self.scope,'PROVIDER_SEQUENCE_SCOPE_OR_OWNER_DRIFT')
        self.journal.check_directory();self.runtime.check_scope()
        if open_window:self.creation.current()
    def initial(self):
        return {'schema':'ouf.discovery-provider-installation-sequence.v1','scopeHash':self.scope_hash,
            'parentAuthorityHash':self.parent_hash,'childAuthorityHash':self.window.child_hash,
            'version':0,'stageIndex':0,'state':'READY','effects':[],'closedGateEvidenceHash':None}
    def read(self):
        self.current();row=self.journal.read();initial=self.initial()
        require(type(row) is dict and set(row)==set(initial) and all(row[k]==initial[k] for k in (
            'schema','scopeHash','parentAuthorityHash','childAuthorityHash'))
            and type(row['stageIndex']) is int and 0<=row['stageIndex']<=len(STAGES)
            and row['state'] in {'READY','IN_FLIGHT','INSTALLED','DONE'} and type(row['effects']) is list,
            'EXACT_RETAINED_PROVIDER_SEQUENCE_REQUIRED')
        index=row['stageIndex'];pending=row['state']=='IN_FLIGHT'
        require((row['state'] in {'INSTALLED','DONE'})==(index==len(STAGES))
            and (type(row['closedGateEvidenceHash']) is str and len(row['closedGateEvidenceHash'])==64
                if row['state']=='DONE' else row['closedGateEvidenceHash'] is None)
            and len(row['effects'])==index+int(pending)
            and [v.get('stage') for v in row['effects']]==list(STAGES[:index+int(pending)]),
            'PROVIDER_SEQUENCE_ORDER_OR_CLOSURE_DRIFT')
        for n,effect in enumerate(row['effects']):
            require(type(effect) is dict and set(effect)=={'stage','dispatches','observations','nextObservationMonotonic','state','evidence'}
                and type(effect['dispatches']) is int and effect['dispatches']==1
                and type(effect['observations']) is int and 0<=effect['observations']<=3
                and effect['state']==('IN_FLIGHT' if pending and n==index else 'APPLIED')
                and (type(effect['nextObservationMonotonic']) in (int,float) and 0<=effect['nextObservationMonotonic']<float('inf'))
                and (effect['evidence'] is None if effect['state']=='IN_FLIGHT' else type(effect['evidence']) is dict),
                'PROVIDER_SEQUENCE_DISPATCH_OR_OBSERVATION_BUDGET_DRIFT')
            if effect['state']=='APPLIED':
                require(effect['evidence'].get('schema')==EVIDENCE_SCHEMAS[effect['stage']]
                    and (effect['evidence'].get('exactInitialLedgerReadback') is True if effect['stage']=='PUBLISH' else True),
                    'EXACT_PROVIDER_SEQUENCE_SUBSTAGE_EVIDENCE_REQUIRED')
        require(type(row['version']) is int and row['version']==2*index+int(pending)
            +sum(e['observations'] for e in row['effects'])+int(row['state']=='DONE'),
            'PROVIDER_SEQUENCE_VERSION_DRIFT')
        return row
    def save(self,row,**changes):
        value={**row,**copy.deepcopy(changes),'version':row['version']+1}
        self.journal.compare_and_save(row,value);observed=self.read()
        require(observed==value,'PROVIDER_SEQUENCE_COMMIT_READBACK_DRIFT');return observed
    def observer(self,stage):
        if stage=='CREATE':return self.creation.observe()
        if stage=='ISSUE':return self.issuer.observe()
        if stage=='PUBLISH':return self.publication.observe(initial=True)
        if stage=='SWITCH':return self.runtime.observe_switch()
        require(stage=='START','EXACT_PROVIDER_SEQUENCE_STAGE_REQUIRED');return self.runtime.observe_started()
    def dispatch(self,stage):
        if stage=='CREATE':return self.creation.create_once()
        if stage=='ISSUE':return self.issuer.issue_once()
        if stage=='PUBLISH':return self.publication.apply()
        if stage=='SWITCH':return self.runtime.switch_once()
        require(stage=='START','EXACT_PROVIDER_SEQUENCE_STAGE_REQUIRED');return self.runtime.start_once()
    def reconcile(self,row,*,wait):
        require(row['state']=='IN_FLIGHT','ATTEMPTED_PROVIDER_STAGE_REQUIRED')
        while True:
            self.current(open_window=wait);require(self.read()==row,'PROVIDER_SEQUENCE_INVOKING_RECORD_DRIFT')
            effect=row['effects'][-1];attempt=effect['observations']
            require(attempt<3,'PROVIDER_OBSERVATION_BUDGET_EXHAUSTED_NO_RESET')
            if wait:
                remaining=max(0,effect['nextObservationMonotonic']-time.monotonic())
                require(time.monotonic()+remaining<self.window.retained()['deadlineMonotonic'],
                    'ORIGINAL_PROVIDER_GATE_WINDOW_EXPIRED_NO_RENEWAL')
                # Only the exclusive sequence fence is held while waiting.
                # Native/common and short journal locks are never held here.
                if remaining:time.sleep(remaining)
            elif time.monotonic()<effect['nextObservationMonotonic']:
                return row,'UNKNOWN'
            effects=copy.deepcopy(row['effects']);effects[-1]['observations']+=1
            delay=(1,3,0)[attempt]*(1+secrets.randbelow(200001)/1000000)
            effects[-1]['nextObservationMonotonic']=time.monotonic()+delay
            row=self.save(row,effects=effects)
            try:outcome,evidence=self.observer(effect['stage'])
            except Exception as error:
                if not wait or not transient(error):raise
                outcome,evidence='UNKNOWN',None
            require(outcome in {'APPLIED','UNKNOWN'},'EXACT_PROVIDER_STAGE_OBSERVATION_REQUIRED')
            self.current(open_window=wait);require(self.read()==row,'PROVIDER_SEQUENCE_CHANGED_DURING_OBSERVATION')
            if outcome=='APPLIED':
                effects=copy.deepcopy(row['effects']);effects[-1].update(state='APPLIED',evidence=evidence)
                index=row['stageIndex']+1
                return self.save(row,effects=effects,stageIndex=index,state='INSTALLED' if index==len(STAGES) else 'READY'),'APPLIED'
            if not wait:return row,'UNKNOWN'
    def drive(self):
        expected=self.read()
        while True:
            self.current(open_window=True);row=self.read()
            require(row==expected,'PROVIDER_SEQUENCE_INVOKING_RECORD_DRIFT')
            if row['state'] in {'INSTALLED','DONE'}:return row
            if row['state']=='IN_FLIGHT':
                expected,outcome=self.reconcile(row,wait=True)
                require(outcome=='APPLIED','PROVIDER_STAGE_UNPROVEN_NO_REDISPATCH');continue
            stage=STAGES[row['stageIndex']]
            effect={'stage':stage,'dispatches':1,'observations':0,'nextObservationMonotonic':0,'state':'IN_FLIGHT','evidence':None}
            expected=self.save(row,state='IN_FLIGHT',effects=[*row['effects'],effect])
            self.current(open_window=True);require(self.read()==expected,'PROVIDER_SEQUENCE_DISPATCH_RECORD_DRIFT')
            try:self.dispatch(stage)
            except Exception as error:
                if not transient(error):raise
                # Never re-enter dispatch, even if the result remains unknown.
                # The next loop only reconciles this durable consumed stage.
    def close_commit(self,row):
        require(row['state']=='INSTALLED','COMPLETE_PROVIDER_SEQUENCE_REQUIRED_BEFORE_CLOSURE_COMMIT')
        closed=self.window.observe_closed();require(self.read()==row,'PROVIDER_SEQUENCE_CHANGED_DURING_GATE_CLOSURE')
        return self.save(row,state='DONE',closedGateEvidenceHash=digest(closed))
    def apply(self):
        self.current()
        with protected_directory(self.root):
            self.journal.initialize(self.initial())
            with self.journal.invocation():
                with self.window.peer_window():row=self.drive()
                self.close_commit(row)
    def observe(self):
        self.current()
        if not os.path.lexists(self.journal.record):return 'UNKNOWN',{'sequenceClaimPresent':False,'automaticReplayAllowed':False}
        with protected_directory(self.root),self.journal.invocation():
            row=self.read()
            if row['state']=='IN_FLIGHT':row,_=self.reconcile(row,wait=False)
            if row['state']=='INSTALLED':row=self.close_commit(row)
            if row['state']!='DONE':return 'UNKNOWN',{'completedSubstages':row['stageIndex'],
                'unattemptedStagesBlockedByOriginalGate':True,'automaticReplayAllowed':False,'budgetReset':False}
            outcome,evidence=self.runtime.observe_started()
            if outcome!='APPLIED':return outcome,evidence
            return 'APPLIED',{'schema':'ouf.discovery-provider-installation-sequence-complete.v1','scopeHash':self.scope_hash,
                'sequenceHash':digest(row),'currentProviderAdmissionHash':digest(evidence),
                'registryGateClosedBeforeReturn':True,'applicationReadinessProven':False,'automaticReplayAllowed':False,
                'runtimeAuthorityIssued':False,'releaseAcceptance':False}
