"""Compose a distinct durable discovery lease worker from existing native owners.

No CLI, journal initialization, service installation, authority issuance, old R12
attachment or budget reset. The sealed process entrypoint supplies current runtime
admission, generation and custody guards; boot/rotation admission remains separate.
"""
import copy,dataclasses,hashlib,json,os,re,stat,time,uuid
from bounded_recovery import Policy,Permanent,Recovery,fingerprint,require,number
from recovery_journal import Journal
from lease_recovery_budget import LeaseRecovery
from continuous_supervisor import RenewingLeaseAdapter,Supervisor
from adaptive_supervisor import window
from tools.semantic_provider_lease_coordination import Coordinator
from tools.semantic_policy_token_owner.producer import protected_directory,identity

SCOPE_FIELDS={'sourceClosureHash','installationInputsHash','contextRef','generationRef','policyHash',
    'coordinatorBindingHash','configurationHash','dnsProfileHash','leaseStructureHash','pollSeconds','heartbeatSeconds'}



class DiscoveryRecovery(LeaseRecovery):
    """Only independently observed positive kernel TTL can count as healthy.

    Unobserved downtime after a process crash or a delayed scheduler wake counts
    against recovery time. It cannot extend the finite budget as a healthy gap.
    """
    PROFILE='ouf.discovery-lease-cumulative-recovery-time.v1'
    def initial(self):
        return {**super().initial(),'healthyUntilWall':None,'healthyUntilMonotonic':None}
    def credit(self,row,wall,mono):
        self.validate_time_accounting(row)
        healthy_wall,healthy_mono=row['healthyWallSeconds'],row['healthyMonotonicSeconds']
        if row['state']=='ACTIVE':
            require(number(row.get('healthyUntilWall')) and number(row.get('healthyUntilMonotonic')),
                'OBSERVED_HEALTHY_LEASE_DEADLINE_REQUIRED')
            healthy_wall+=max(0,min(wall,row['healthyUntilWall'])-row['lastWall'])
            healthy_mono+=max(0,min(mono,row['healthyUntilMonotonic'])-row['lastMonotonic'])
        return healthy_wall,healthy_mono
    def remaining(self,row):
        wall,mono=self.now();healthy_wall,healthy_mono=self.credit(row,wall,mono)
        wall_elapsed,mono_elapsed=wall-row['startedWall'],mono-row['startedMonotonic']
        require(0<=healthy_wall<=wall_elapsed and 0<=healthy_mono<=mono_elapsed,
            'DISCOVERY_RECOVERY_TIME_ACCOUNTING_UNPROVEN')
        return min(self.policy.max_elapsed-(wall_elapsed-healthy_wall),
            self.policy.max_elapsed-(mono_elapsed-healthy_mono))
    def save(self,previous,state,reason,**values):
        wall,mono=self.now();healthy_wall,healthy_mono=self.credit(previous,wall,mono)
        count=previous.get('publicationCount')
        require(type(count) is int and count>=0,'LEASE_PUBLICATION_COUNT_UNPROVEN')
        values.update(healthyWallSeconds=healthy_wall,healthyMonotonicSeconds=healthy_mono,
            publicationCount=count+(1 if state=='ACTIVE' and reason in {'RECOVERED','RENEWED'} else 0))
        if state=='ACTIVE':
            observed=window(self.coordinator,self.poll_seconds,clock=lambda:self.now()[1])
            end_wall,end_mono=self.now()
            require(end_wall>=wall and end_mono>=mono
                and observed['deadlineMonotonic']>end_mono,'CURRENT_POSITIVE_HEALTHY_WINDOW_REQUIRED')
            values.update(healthyUntilWall=end_wall+observed['deadlineMonotonic']-end_mono,
                healthyUntilMonotonic=observed['deadlineMonotonic'])
        # Bypass the legacy override which credits the entire ACTIVE interval.
        # Journal CAS, cumulative counters and the common base state machine stay.
        return Recovery.save(self,previous,state,reason,**values)

def build_worker(coordinator,journal,policy,scope,*,runtime_guard,generation_guard,custody_guard,
                 dns,compiler,clock=lambda:(time.time(),time.monotonic()),random_value=None):
    require(type(coordinator) is Coordinator and type(journal) is Journal and type(policy) is Policy
        and type(scope) is dict and set(scope)==SCOPE_FIELDS
        and all(type(scope[k]) is str and re.fullmatch('[0-9a-f]{64}',scope[k])
            for k in SCOPE_FIELDS-{'pollSeconds','heartbeatSeconds'})
        and type(scope['pollSeconds']) is int and 1<=scope['pollSeconds']<=300
        and type(scope['heartbeatSeconds']) is int and 1<=scope['heartbeatSeconds']<=30
        and all(callable(g) for g in (runtime_guard,generation_guard,custody_guard,clock)),
        'EXACT_SEALED_DISCOVERY_LEASE_WORKER_INPUTS_REQUIRED')
    selected=copy.deepcopy(scope);scope_hash=fingerprint(selected)
    def immutable():
        require(fingerprint(coordinator.binding)==selected['coordinatorBindingHash']
            and fingerprint(coordinator.configuration)==selected['configurationHash']
            and fingerprint(coordinator.owner.profile)==selected['dnsProfileHash']
            and coordinator.owner.backend.expected==selected['leaseStructureHash']
            and fingerprint(dataclasses.asdict(policy))==selected['policyHash'],
            'DISCOVERY_LEASE_WORKER_OWNER_OR_POLICY_DRIFT')
        row=journal.read()
        require(row.get('contextRef')==selected['contextRef'] and row.get('generationRef')==selected['generationRef']
            and row.get('policyHash')==selected['policyHash']
            and row.get('discoveryLeaseScopeHash')==scope_hash
            and row.get('timeAccountingProfile')==DiscoveryRecovery.PROFILE,
            'RETAINED_DISCOVERY_LEASE_SCOPE_AND_ACCOUNTING_REQUIRED')
        return row
    immutable()
    def guard():
        immutable()
        if runtime_guard(scope_hash) is not True:raise Permanent('AUTHORITY_REVOKED')
        if generation_guard(selected['generationRef']) is not True:raise Permanent('GENERATION_CHANGED')
        immutable()
    def custody():
        if custody_guard(selected['configurationHash'],selected['leaseStructureHash']) is not True:
            raise Permanent('INTEGRITY_UNPROVEN')
    adapter=RenewingLeaseAdapter(coordinator,dns,compiler,guard,custody,lambda:clock()[1])
    random_value=__import__('random').SystemRandom().random if random_value is None else random_value
    require(callable(random_value),'BOUNDED_DISCOVERY_WORKER_JITTER_SOURCE_REQUIRED')
    recovery=DiscoveryRecovery(journal,adapter,policy,selected['contextRef'],selected['generationRef'],clock,random_value)
    recovery.coordinator,recovery.poll_seconds=coordinator,selected['pollSeconds']
    recovery.validate_time_accounting(immutable())
    worker=Supervisor(recovery,coordinator,selected['pollSeconds'],heartbeat=selected['heartbeatSeconds'])
    worker.discovery_scope_hash=scope_hash
    return worker


class LeaseReporter:
    """Minimized durable owner status; no addresses, credentials or native records."""
    def __init__(self,journal,emit):
        require(type(journal) is Journal and callable(emit),'TYPED_DISCOVERY_LEASE_REPORTER_REQUIRED')
        self.journal,self.emit,self.last=journal,emit,None
    def report(self,value):
        require(type(value) is dict and set(value)=={'state','reason','attempts','renewals','incidentRef','ready','live'}
            and value['state'] in {'NEW','ACTIVE','RETRY_WAIT','PAUSED_EXHAUSTED','BLOCKED','RECONCILE_REQUIRED',
                'CANCELLED','ATTEMPTING','PUBLISHING'}
            and type(value['reason']) is str and re.fullmatch('[A-Z][A-Z0-9_]{0,120}',value['reason'])
            and type(value['attempts']) is int and value['attempts']>=0
            and type(value['renewals']) is int and value['renewals']>=0
            and type(value['incidentRef']) is str and re.fullmatch('[0-9a-f]{64}',value['incidentRef'])
            and value['ready'] is (value['state']=='ACTIVE') and value['live'] is True,
            'MINIMIZED_DISCOVERY_LEASE_STATUS_REQUIRED')
        raw=json.dumps({**value,'applicationReady':False,'runtimeAuthorityIssued':False},
            sort_keys=True,separators=(',',':')).encode()
        if raw==self.last:return
        with protected_directory(self.journal.root) as directory:
            self.journal.check_directory();temporary='.lease-status-'+uuid.uuid4().hex
            try:
                before=os.stat('lease-worker-status.json',dir_fd=directory,follow_symlinks=False)
                self.journal.check_file(before)
            except FileNotFoundError:before=None
            fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
            try:
                position=0
                while position<len(raw):
                    count=os.write(fd,raw[position:]);require(count>0,'LEASE_STATUS_WRITE_UNPROVEN');position+=count
                os.fsync(fd)
                if before is not None:
                    require(identity(before)==identity(os.stat('lease-worker-status.json',dir_fd=directory,follow_symlinks=False)),
                        'DISCOVERY_LEASE_STATUS_CHANGED')
                os.replace(temporary,'lease-worker-status.json',src_dir_fd=directory,dst_dir_fd=directory);os.fsync(directory)
            finally:
                os.close(fd)
                try:os.unlink(temporary,dir_fd=directory)
                except FileNotFoundError:pass
        self.last=raw;self.emit('OUF_DISCOVERY_LEASE_WORKER_STATUS='+raw.decode())
    def unavailable(self):
        value='OUF_DISCOVERY_LEASE_WORKER_STATUS_UNAVAILABLE reason=PERSISTENCE_OR_OBSERVER_UNPROVEN'
        if self.last!=value:
            self.last=value
            try:self.emit(value)
            except Exception:pass


def serve(worker,stop,reporter):
    """Exclusive process lifetime; observer/storage failure parks alive, no retry."""
    import threading
    require(type(worker) is Supervisor and hasattr(worker,'discovery_scope_hash')
        and type(stop) is threading.Event and type(reporter) is LeaseReporter
        and reporter.journal is worker.r.journal,'EXACT_DISCOVERY_WORKER_AND_REPORTER_REQUIRED')
    with protected_directory(worker.r.journal.root),worker.r.journal.invocation():
        return _serve_claimed(worker,stop,reporter)


def _serve_claimed(worker,stop,reporter):
    """Internal serve body: caller must retain the process invocation fence."""
    try:
        return worker._serve(stop,reporter.report)
    except Exception:
        worker.active_here=False
        try:
            row=worker.r.pause(worker.r.journal.read(),'BLOCKED','LOCAL_STATE_UNPROVEN')
            reporter.report({'state':row['state'],'reason':row['reason'],'attempts':row['attempts'],
                'renewals':worker.renewals,'incidentRef':worker.r.context,'ready':False,'live':True})
        except Exception:
            try:worker.r.adapter.pause()
            except Exception:pass
        reporter.unavailable()
        # Persistent liveness does not recover ambiguity or reset a budget.
        while not stop.wait(worker.heartbeat):reporter.unavailable()
    finally:
        worker.active_here=False
        try:worker.r.adapter.pause()
        except Exception:reporter.unavailable()
