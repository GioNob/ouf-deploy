"""One parent-owned running wait-gate window before Registry attestation.

The caller installs/admit the provider separately. This component never signals
Java, starts a container, grants OCI acceptance or retransmits an ambiguous POST.
Closure is narrowing and remains possible after the finite approval expires.
"""
from contextlib import contextmanager
import copy,hashlib,os,time
from pathlib import Path
from .custody_capture import decode,digest,require
from .parent_authority import DiscoveryParentAuthority
from .native_profile import DiscoveryProfile
from engine_creation import Engine
from gated_process_observation import GatedProcessObservation
from native_evidence_store import NativeEvidenceStore
from transition_journal import Transition,PHASES
from cutover_authority import CutoverAuthority
from recovery_journal import Journal
from tools.semantic_policy_token_owner.producer import protected_directory


def window_scope(request_hash,profile_hash,source_closure_hash,directory,maximum_seconds):
    require(all(type(v) is str and len(v)==64 and set(v)<=set('0123456789abcdef')
        for v in (request_hash,profile_hash,source_closure_hash))
        and Path(directory).is_absolute() and '..' not in Path(directory).parts
        and type(maximum_seconds) is int and 1<=maximum_seconds<=300,'EXACT_STATIC_GATE_WINDOW_SCOPE_REQUIRED')
    return {'schema':'ouf.discovery-gate-peer-window-scope.v1','creationRequestHash':request_hash,
        'executionProfileHash':profile_hash,'sourceClosureHash':source_closure_hash,
        'journalDirectory':str(Path(directory)),'maximumSeconds':maximum_seconds,
        'maximumUnpauseAttempts':1,'maximumPauseAttempts':1,'applicationSignalAuthorized':False,
        'providerAdmissionIsSeparate':True,'mustReturnPausedBeforeRegistryAttestation':True}


class GatePeerWindow:
    def __init__(self,*,parent,child,child_raw,engine,transition,request,profile,store,directory,maximum_seconds=120):
        require(type(parent) is DiscoveryParentAuthority and type(child) is CutoverAuthority
            and type(engine) is Engine and type(transition) is Transition and type(store) is NativeEvidenceStore
            and type(profile) is DiscoveryProfile and transition.execution_profile is None and transition.phases==PHASES
            and type(maximum_seconds) is int and 1<=maximum_seconds<=300,
            'TYPED_SEPARATE_DISCOVERY_GATE_PEER_WINDOW_REQUIRED')
        self.parent,self.child,self.raw=parent,child,bytes(child_raw)
        self.engine,self.transition,self.store=engine,transition,store
        self.request,self.profile=copy.deepcopy(request),profile
        self.request_hash,self.profile_hash=digest(request),profile.verify(request)
        require(child.expected['creationRequestHash']==self.request_hash
            and child.expected['sourceClosureHash']==parent.scope['sourceClosureHash'],
            'SAME_GATE_WINDOW_CHILD_CREATION_AND_SOURCE_REQUIRED')
        self.parent_hash,self.child_hash=parent.sha,hashlib.sha256(child_raw).hexdigest()
        self.root=Path(directory);self.journal=Journal(self.root)
        require(self.root!=store.root and not self.root.is_relative_to(store.root)
            and not store.root.is_relative_to(self.root),'SEPARATE_GATE_WINDOW_JOURNAL_REQUIRED')
        self.process=GatedProcessObservation(request)
        self.scope=window_scope(self.request_hash,self.profile_hash,child.expected['sourceClosureHash'],self.root,maximum_seconds)
        self.scope_hash=digest(self.scope)

    def sealed(self):
        require(self.parent.sha==self.parent_hash and hashlib.sha256(self.raw).hexdigest()==self.child_hash
            and self.profile.verify(self.request)==self.profile_hash and digest(self.request)==self.request_hash
            and digest(self.scope)==self.scope_hash,'DISCOVERY_GATE_WINDOW_SCOPE_CHANGED')
    def current(self):
        self.sealed()
        self.parent.registry_child(self.child,self.raw)
        self.parent.guard('registryGatePeerWindow',self.scope)
        return True

    def boundary(self):
        row=self.transition.read()
        intents=decode(self.raw)['phaseIntentHashes']
        require(row['state']=='READY' and row['nextPhase']==6 and row['creationRequestHash']==self.request_hash
            and len(row['effects'])==6 and [e['phase'] for e in row['effects']]==list(PHASES[:6])
            and all(e['state']=='APPLIED' for e in row['effects'])
            and row['transitionAuthorityEvidenceHash']==self.child_hash
            and all(e['intentHash']==intents[e['phase']] for e in row['effects'])
            and all(e['authorityEvidenceHash']==self.child_hash for e in row['effects']),
            'EXACT_GATE_WINDOW_AFTER_STAGE_BEFORE_ATTESTATION_REQUIRED')
        stage=row['effects'][-1];native=self.store.read('STAGE_PAUSED_REPLACEMENT',stage['nativeEvidenceHash'])
        return row,native

    def snapshot(self):
        actual=self.engine.matching_configuration(self.transition,self.request,self.engine.inspect(self.transition))
        require(actual['State']['Running'] is True and actual.get('RestartCount')==0,
            'SAME_LIVE_GATE_WINDOW_PROCESS_REQUIRED')
        binding=self.engine.runtime_binding(actual);process=self.process.observe(binding['pid'])
        require(process['nonRootIdentityVerified'] is True and process['capabilitiesEmpty'] is True
            and process['noNewPrivileges'] is True,'CURRENT_NONROOT_GATE_WINDOW_PROCESS_REQUIRED')
        return actual,binding,process

    def retained(self):
        value=self.journal.read()
        require(value.get('schema')=='ouf.discovery-gate-peer-window-journal.v1'
            and value['scopeHash']==self.scope_hash and value['parentAuthorityHash']==self.parent_hash
            and value['childAuthorityHash']==self.child_hash and value['transitionContext']==self.transition.context
            and value['creationRequestHash']==self.request_hash,'EXACT_RETAINED_GATE_WINDOW_CLAIM_REQUIRED')
        return value

    def publish(self,before,**changes):
        value={**before,**changes};self.journal.compare_and_save(before,value);return value

    def prepare_open(self):
        self.current();row,native=self.boundary();actual,binding,process=self.snapshot()
        require(actual['State']['Paused'] is True and process['processKind']=='GATE_WAITING'
            and binding==self.engine.runtime_binding(native),'EXACT_PAUSED_WAIT_GATE_BEFORE_PEER_WINDOW_REQUIRED')
        now=time.monotonic();self.journal.initialize({'schema':'ouf.discovery-gate-peer-window-journal.v1',
            'scopeHash':self.scope_hash,'parentAuthorityHash':self.parent_hash,'childAuthorityHash':self.child_hash,
            'transitionContext':self.transition.context,'creationRequestHash':self.request_hash,
            'boundaryHash':digest(row),'runtimeBinding':binding,'generation':process['generation'],
            'startedMonotonic':now,'deadlineMonotonic':now+self.scope['maximumSeconds'],
            'state':'OPENING','unpauseAttempts':1,'pauseAttempts':0})
        # Initialization consumes the action before any native effect. It is
        # never repeated or repaired if partial files already exist.
    def unpause_once(self):
        self.current();self.boundary();value=self.retained();actual,binding,process=self.snapshot()
        require(value['state']=='OPENING' and value['unpauseAttempts']==1 and value['pauseAttempts']==0
            and binding==value['runtimeBinding'] and process['generation']==value['generation']
            and actual['State']['Paused'] is True and process['processKind']=='GATE_WAITING'
            and digest(self.transition.read())==value['boundaryHash']
            and time.monotonic()<value['deadlineMonotonic'],'EXACT_OWNED_GATE_BEFORE_UNPAUSE_REQUIRED')
        # A separate durable dispatch marker prevents manual re-entry into this
        # method from retransmitting an ambiguous native command.
        self.journal.create(self.root/'unpause-dispatch.json',b'{"attempt":1}');self.journal.sync()
        status,_=self.engine.request('POST','/v1.44/containers/'+binding['containerId']+'/unpause')
        require(status==204,'GATE_UNPAUSE_OUTCOME_REQUIRES_RECONCILIATION')

    def open_once(self):
        self.prepare_open()
        with self.journal.invocation():
            self.unpause_once();return self.observe_open()

    def observe_open(self):
        self.current();value=self.retained();actual,binding,process=self.snapshot()
        require(value['state'] in {'OPENING','OPEN'} and value['unpauseAttempts']==1 and value['pauseAttempts']==0
            and binding==value['runtimeBinding'] and process['generation']==value['generation']
            and process['processKind']=='GATE_WAITING' and actual['State']['Paused'] is False
            and digest(self.transition.read())==value['boundaryHash']
            and time.monotonic()<value['deadlineMonotonic'],'CURRENT_RUNNING_WAIT_GATE_WINDOW_REQUIRED')
        if value['state']=='OPENING':value=self.publish(value,state='OPEN')
        return {'schema':'ouf.discovery-running-gate-peer-window.v1','windowHash':digest(value),
            'runtimeBinding':binding,'generation':process['generation'],'applicationSignalAuthorized':False,
            'ociAdmissionGranted':False,'providerAdmissionIsSeparate':True}

    def close_once(self):
        # No Parent/HUMAN renewal is needed to pause this exact owned process.
        # Historical artifacts identify it; they do not authorize another open.
        self.sealed();value=self.retained();actual,binding,process=self.snapshot()
        require(binding==value['runtimeBinding'] and process['generation']==value['generation'],
            'SAME_OWNED_PROCESS_REQUIRED_FOR_GATE_WINDOW_CLOSURE')
        if value['state']=='CLOSED':
            require(actual['State']['Paused'] is True and process['processKind']=='GATE_WAITING',
                'CLOSED_GATE_WINDOW_NATIVE_STATE_CHANGED');return value
        require(value['state'] in {'OPENING','OPEN'} and value['pauseAttempts']==0,
            'GATE_WINDOW_CLOSE_ALREADY_ATTEMPTED_NO_REPLAY')
        pending=self.publish(value,state='CLOSING',pauseAttempts=1)
        breach=process['processKind']!='GATE_WAITING' or digest(self.transition.read())!=value['boundaryHash']
        if actual['State']['Paused'] is not True:
            status,_=self.engine.request('POST','/v1.44/containers/'+binding['containerId']+'/pause')
            require(status==204,'GATE_PAUSE_OUTCOME_REQUIRES_RECONCILIATION')
        after,after_binding,after_process=self.snapshot()
        require(after['State']['Paused'] is True and after_binding==binding and after_process['generation']==value['generation'],
            'EXACT_GATE_WINDOW_PAUSED_CLOSURE_REQUIRED')
        breach=breach or after_process['processKind']!='GATE_WAITING'
        return self.publish(pending,state='CLOSED_RECONCILE' if breach else 'CLOSED')

    def observe_closed(self):
        self.sealed();value=self.retained();actual,binding,process=self.snapshot()
        require(value['state'] in {'CLOSING','CLOSED'} and value['pauseAttempts']==1
            and actual['State']['Paused'] is True and binding==value['runtimeBinding']
            and process['generation']==value['generation'],'NATIVE_GATE_CLOSURE_REQUIRES_RECONCILIATION')
        breach=process['processKind']!='GATE_WAITING' or digest(self.transition.read())!=value['boundaryHash']
        if value['state']=='CLOSING':value=self.publish(value,state='CLOSED_RECONCILE' if breach else 'CLOSED')
        require(value['state']=='CLOSED' and not breach,'GATE_CLOSURE_BOUNDARY_OR_APPLICATION_BREACH')
        return value

    @contextmanager
    def peer_window(self):
        with protected_directory(self.root):
            self.prepare_open()
            with self.journal.invocation():
                try:
                    self.unpause_once();self.observe_open();yield self
                finally:
                    self.close_once();self.observe_closed()
