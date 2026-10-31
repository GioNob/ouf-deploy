"""One signed worker phase: attest, publish, register, then start once.

Substage claims survive interruption. Explicit continuation dispatches only
unattempted stages; attempted stages are observed, never called again. observe()
does not dispatch native effects. Unknown/partial effects stop the sequence.
"""
import copy,os
from pathlib import Path
from .custody_capture import digest,encoded,require
from .lease_installation_template import recompile
from .lease_unit import path,beneath
from .lease_attestation import LeaseAttestationIssuer
from .lease_file_installation import LeaseFileInstallation
from .lease_registration import LeaseRegistration
from tools.semantic_policy_token_owner.producer import protected_directory
from recovery_journal import Journal

STAGES=('ATTEST','FILES','REGISTER','START')


def sequence_scope(template,component,*,directory):
    t=recompile(template);root=path(directory)
    require(type(component) is dict and component.get('schema')=='ouf.discovery-worker-attested-installation-and-start-scope.v1'
        and component['installation'].get('schema')=='ouf.discovery-worker-registered-installation-and-start-scope.v1',
        'REVIEWED_ATTESTED_REGISTERED_WORKER_INSTALLATION_REQUIRED')
    managed=component['installation'];bare=managed['installation']
    roots=(t['installationRoot'],t['configurationTemplate']['ledgerRoot'],t['sandboxRoot'],
        bare['publication']['journalDirectory'],bare['start']['journalDirectory'],
        managed['registration']['journalDirectory'],component['issuance']['journalDirectory'])
    require(len(Path(root).parts)>=4 and all(not beneath(root,p) and not beneath(p,root) for p in roots),
        'DISTINCT_WORKER_INSTALLATION_SEQUENCE_JOURNAL_REQUIRED')
    return {'schema':'ouf.discovery-worker-installation-sequence-scope.v1','templateHash':digest(t),
        'componentHash':digest(component),'journalDirectory':root,'stages':list(STAGES),
        'maximumDispatchesPerStage':1,'unknownEffectsBlockContinuation':True,
        'automaticReplayAllowed':False,'budgetReset':False}


def sequenced_component(template,component,scope):
    require(scope==sequence_scope(template,component,directory=scope['journalDirectory']),
        'EXACT_WORKER_INSTALLATION_SEQUENCE_SCOPE_REQUIRED')
    return {'schema':'ouf.discovery-worker-sequenced-installation-scope.v1',
        'component':copy.deepcopy(component),'sequence':copy.deepcopy(scope)}


def checked_row(start):
    scope=start.sequence_scope
    require(type(scope) is dict and start.parent_component==sequenced_component(start.template,start.attested_component,scope),
        'CURRENT_REVIEWED_WORKER_SEQUENCE_REQUIRED')
    row=Journal(scope['journalDirectory']).read()
    fields={'schema','scopeHash','parentAuthorityHash','childAuthorityHash','intentHash','transitionContextHash',
        'version','state','stageIndex','effects'}
    require(type(row) is dict and set(row)==fields and row['schema']=='ouf.discovery-worker-installation-sequence.v1'
        and row['scopeHash']==digest(scope) and row['parentAuthorityHash']==start.parent_hash
        and row['childAuthorityHash']==start.authority_hash and row['intentHash']==start.intent_hash
        and row['transitionContextHash']==start.transition.context and type(row['version']) is int and row['version']>=0
        and type(row['stageIndex']) is int and 0<=row['stageIndex']<=len(STAGES)
        and type(row['effects']) is list and row['state'] in {'READY','IN_FLIGHT','DONE'},
        'EXACT_RETAINED_WORKER_INSTALLATION_SEQUENCE_REQUIRED')
    index=row['stageIndex'];pending=row['state']=='IN_FLIGHT'
    require(row['version']==2*index+int(pending),'WORKER_INSTALLATION_SEQUENCE_VERSION_DRIFT')
    require((row['state']=='DONE')==(index==len(STAGES)) and len(row['effects'])==index+int(pending)
        and [e.get('stage') for e in row['effects']]==list(STAGES[:index+int(pending)])
        and all(set(e)=={'stage','dispatches','state','evidence'} and type(e['dispatches']) is int and e['dispatches']==1
            and e['state']==('IN_FLIGHT' if pending and n==index else 'APPLIED')
            and (e['evidence'] is None if e['state']=='IN_FLIGHT' else type(e['evidence']) is dict)
            for n,e in enumerate(row['effects'])), 'WORKER_INSTALLATION_STAGE_ORDER_OR_DISPATCH_DRIFT')
    return row


def read_prefix(start):
    row=checked_row(start)
    require((row['state']=='IN_FLIGHT' and row['stageIndex']==3) or row['state']=='DONE',
        'ATTESTED_PUBLISHED_REGISTERED_PREFIX_REQUIRED_BEFORE_WORKER_START')
    proofs=[e['evidence'] for e in row['effects'][:3]]
    require(proofs[0].get('schema')=='ouf.discovery-worker-attestations-issued.v1'
        and proofs[0].get('signaturesIssued')==3
        and proofs[1].get('schema')=='ouf.discovery-worker-files-installed.v1'
        and proofs[1].get('exactInitialLedgerReadback') is True
        and proofs[2].get('schema')=='ouf.discovery-worker-manager-registered.v1',
        'COMPLETE_INITIAL_WORKER_INSTALLATION_PROOFS_REQUIRED')
    return {'workerInstallationSequenceScopeHash':digest(start.sequence_scope),
        'workerInstallationSequencePrefixHash':digest(row['effects'][:3])}


class WorkerInstallationPhase:
    def __init__(self,*,issuer,registration):
        require(type(issuer) is LeaseAttestationIssuer and type(registration) is LeaseRegistration
            and registration.installation is issuer.installation and type(issuer.installation) is LeaseFileInstallation,
            'SHARED_TYPED_WORKER_ISSUER_PUBLICATION_REGISTRATION_AND_START_REQUIRED')
        self.issuer,self.registration,self.files=issuer,registration,issuer.installation;self.start=self.files.start
        self.scope=copy.deepcopy(self.start.sequence_scope)
        require(type(self.scope) is dict,'EXPLICIT_PARENT_WORKER_SEQUENCE_SCOPE_REQUIRED')
        self.root=Path(self.scope['journalDirectory']);self.journal=Journal(self.root)
        self.scope_hash=digest(self.scope)
        for name in ('phase','transition','store','authority','authority_raw','request_hash','intent_hash'):
            setattr(self,name,getattr(self.start,name))
        self.owners={'ATTEST':issuer,'FILES':self.files,'REGISTER':registration,'START':self.start}
        self.owner_ids={k:id(v) for k,v in self.owners.items()}

    def current(self,intent):
        require(self.scope==self.start.sequence_scope and digest(self.scope)==self.scope_hash
            and self.start.parent_component==sequenced_component(self.start.template,self.start.attested_component,self.scope)
            and set(self.owners)==set(STAGES) and all(id(self.owners[k])==v for k,v in self.owner_ids.items())
            and self.files.start is self.start and self.issuer.installation is self.files and self.registration.installation is self.files,
            'WORKER_INSTALLATION_SEQUENCE_COMPONENT_DRIFT')
        self.journal.check_directory();self.start.current(intent)

    def initial(self):
        return {'schema':'ouf.discovery-worker-installation-sequence.v1','scopeHash':self.scope_hash,
            'parentAuthorityHash':self.start.parent_hash,'childAuthorityHash':self.start.authority_hash,
            'intentHash':self.intent_hash,'transitionContextHash':self.transition.context,
            'version':0,'state':'READY','stageIndex':0,'effects':[]}

    def save(self,row,**changes):
        value={**row,**copy.deepcopy(changes),'version':row['version']+1}
        self.journal.compare_and_save(row,value);observed=checked_row(self.start)
        require(observed==value,'WORKER_SEQUENCE_COMMIT_READBACK_DRIFT')
        return observed

    def reconcile(self,intent,row):
        require(row['state']=='IN_FLIGHT','ATTEMPTED_WORKER_STAGE_REQUIRED_FOR_RECONCILIATION')
        owner=self.owners[STAGES[row['stageIndex']]];outcome,evidence=owner.observe(intent)
        require(outcome in {'APPLIED','NO_EFFECT','UNKNOWN'},'EXACT_WORKER_SUBSTAGE_OUTCOME_REQUIRED')
        self.current(intent)
        if outcome!='APPLIED':return row,outcome,evidence
        require(checked_row(self.start)==row,'WORKER_SEQUENCE_CHANGED_DURING_SUBSTAGE_OBSERVATION')
        effects=copy.deepcopy(row['effects']);effects[-1].update(state='APPLIED',evidence=evidence)
        index=row['stageIndex']+1
        return self.save(row,effects=effects,stageIndex=index,state='DONE' if index==len(STAGES) else 'READY'),outcome,evidence

    def drive(self,intent):
        expected=checked_row(self.start)
        while True:
            self.current(intent);row=checked_row(self.start)
            require(row==expected,'WORKER_SEQUENCE_INVOKING_RECORD_DRIFT')
            if row['state']=='DONE':return
            if row['state']=='IN_FLIGHT':
                row,outcome,_=self.reconcile(intent,row)
                require(outcome=='APPLIED','WORKER_SUBSTAGE_UNPROVEN_NO_REDISPATCH')
                expected=row
                continue
            stage=STAGES[row['stageIndex']]
            effects=[*row['effects'],{'stage':stage,'dispatches':1,'state':'IN_FLIGHT','evidence':None}]
            dispatched=self.save(row,state='IN_FLIGHT',effects=effects)
            expected=dispatched
            self.current(intent)
            require(checked_row(self.start)==dispatched,'WORKER_SEQUENCE_DISPATCH_RECORD_DRIFT')
            if stage=='ATTEST':self.issuer.issue(intent)
            else:self.owners[stage].apply(intent)

    def apply(self,intent):
        self.current(intent)
        with protected_directory(self.root):
            self.journal.initialize(self.initial())
            with self.journal.invocation():self.drive(intent)

    def continue_installation(self,intent):
        """Explicit same-authority continuation; no consumed action is replayed."""
        self.current(intent)
        with protected_directory(self.root),self.journal.invocation():self.drive(intent)

    def observe(self,intent):
        self.current(intent)
        if not os.path.lexists(self.journal.record):return 'UNKNOWN',{'sequenceClaimPresent':False,'automaticReplayAllowed':False}
        with protected_directory(self.root),self.journal.invocation():
            row=checked_row(self.start)
            if row['state']=='IN_FLIGHT':row,outcome,evidence=self.reconcile(intent,row)
            if row['state']!='DONE':
                unknown={'sequenceClaimPresent':True,'completedSubstages':row['stageIndex'],
                    'unattemptedSubstagesRequireExplicitContinuation':row['state']=='READY','automaticReplayAllowed':False}
                if row['state']=='IN_FLIGHT':
                    unknown.update(unprovenStage=STAGES[row['stageIndex']],substageObservation=copy.deepcopy(evidence))
                return 'UNKNOWN',unknown
            # The worker now owns its mutable recovery/coordination records.
            # Keep the immutable initial-publication proof; never demand or
            # restore an initial ledger over a live worker's cumulative state.
            require(self.issuer.observe(intent)[0]=='APPLIED' and self.registration.observe(intent)[0]=='APPLIED',
                'CURRENT_ATTESTATION_AND_MANAGER_REGISTRATION_REQUIRED')
            return self.start.observe(intent)
