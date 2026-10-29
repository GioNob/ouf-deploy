"""Same-boot operational invocation; no installation, adoption or budget reset.

The completed installed guard owns runtime authority. A prior ACTIVE lease is
revoked before a new attempt. Interrupted effects and parked incidents remain
parked; this is not the boot/generation migration controller or service entry.
"""
from contextlib import contextmanager
import copy,dataclasses
from pathlib import Path
from .custody_capture import digest,encoded,require
from .installed_lease_guard import InstalledLeaseGuard,boot_id
from .lease_worker import DiscoveryRecovery,SCOPE_FIELDS
from bounded_recovery import fingerprint,number
from continuous_supervisor import Supervisor,RenewingLeaseAdapter
from recovery_journal import Journal
from tools.semantic_policy_token_owner.producer import protected_directory

MODULE='tools.m2_discovery_installation_profile.installed_lease_session'
REENTRY_REASON='DISCOVERY_TECHNICAL_REENTRY_IN_PROGRESS'


def retained(worker,guard,scope):
    require(type(worker) is Supervisor and type(worker.r) is DiscoveryRecovery
        and type(worker.r.journal) is Journal and type(worker.r.adapter) is RenewingLeaseAdapter
        and type(guard) is InstalledLeaseGuard and type(scope) is dict and set(scope)==SCOPE_FIELDS,
        'EXACT_INSTALLED_DISCOVERY_WORKER_SESSION_REQUIRED')
    c=guard.configuration
    require(MODULE in c['sourceManifest']['sourceHashes']
        and scope['sourceClosureHash']==c['sourceManifest']['dependencyClosureHash']
        and scope['installationInputsHash']==c['installationInputsHash']
        and scope['policyHash']==c['scopePolicyHash']==fingerprint(dataclasses.asdict(worker.r.policy))
        and worker.r.journal.root==Path(c['ledgerRoot'])
        and scope['contextRef']==worker.r.context and scope['generationRef']==worker.r.generation
        and worker.discovery_scope_hash==fingerprint(scope)
        and worker.c is worker.r.adapter.c,
        'EXACT_INSTALLED_DISCOVERY_WORKER_BINDINGS_REQUIRED')
    coordinator=worker.c
    require(scope['coordinatorBindingHash']==fingerprint(coordinator.binding)
        and scope['configurationHash']==fingerprint(coordinator.configuration)
        and scope['dnsProfileHash']==fingerprint(coordinator.owner.profile)
        and scope['leaseStructureHash']==coordinator.owner.backend.expected,
        'INSTALLED_DISCOVERY_WORKER_OWNER_DRIFT')
    row=worker.r.journal.read()
    require(row.get('schema')=='ouf.bounded-recovery.v1'
        and row.get('contextRef')==scope['contextRef'] and row.get('generationRef')==scope['generationRef']
        and row.get('policyHash')==scope['policyHash']
        and row.get('discoveryLeaseScopeHash')==fingerprint(scope)
        and type(row.get('attempts')) is int and row['attempts']>=0
        and type(row.get('publicationCount')) is int and row['publicationCount']>=0
        and type(row.get('reentryCount',0)) is int and row.get('reentryCount',0)>=0,
        'RETAINED_DISCOVERY_WORKER_HISTORY_REQUIRED')
    worker.r.validate_time_accounting(row)
    wall,mono=worker.r.now()
    require(all(number(row.get(k)) for k in ('startedWall','startedMonotonic','lastWall','lastMonotonic'))
        and row['startedWall']<=row['lastWall']<=wall
        and row['startedMonotonic']<=row['lastMonotonic']<=mono,
        'SAME_BOOT_NONREGRESSING_DISCOVERY_WORKER_CLOCKS_REQUIRED')
    return row


def archive(journal,row):
    """Immutable predecessor before a pending reentry; never overwrite/adopt it."""
    reference=digest(row);path=journal.root/('reentry-predecessor-'+reference+'.json')
    journal.create(path,encoded(row));journal.sync()
    return reference


def prepare(worker,guard,scope):
    row=retained(worker,guard,scope)
    guard.current(fingerprint(scope),scope['generationRef'])
    # These records represent an interrupted effect, exhaustion, explicit
    # cancellation or a local incident. A process restart grants no retry.
    if row['state'] not in {'NEW','RETRY_WAIT','ACTIVE'}:return row
    if row['state']=='RETRY_WAIT':
        require(number(row.get('nextWall')) and number(row.get('nextMonotonic')),
            'RETAINED_DISCOVERY_RETRY_DEADLINES_REQUIRED')
    coordinator=worker.c;current=coordinator.journal()
    require(current['state'] in {'QUIESCED','LEASE_READY'},
        'COMPLETE_DISCOVERY_COORDINATION_CHECKPOINT_REQUIRED')
    coordinator.guard()  # Exact ownership + subset membership, including expiry.
    if row['state']=='ACTIVE':
        require(current['state']=='LEASE_READY' and current['leaseAuthorized'] is True
            and row.get('resultRef')==fingerprint(current),
            'EXACT_PRECEDING_DISCOVERY_PUBLICATION_REQUIRED')
    else:
        require(current['state']=='QUIESCED' and current['leaseAuthorized'] is False,
            'QUIESCENT_DISCOVERY_RECOVERY_CHECKPOINT_REQUIRED')
    guard.current(fingerprint(scope),scope['generationRef'])
    require(worker.r.journal.read()==row,'DISCOVERY_REENTRY_CHECKPOINT_CHANGED')
    prior=archive(worker.r.journal,row)
    pending=worker.r.save(row,'RECONCILE_REQUIRED',REENTRY_REASON,
        reentryPredecessorHash=prior,reentryCount=row.get('reentryCount',0)+1,
        reentryBootId=boot_id(guard.configuration['hostBootIdPath']))
    # Pending is durable BEFORE the first kernel narrowing. A crash here cannot
    # become an automatic reentry, replay, counter reset or adopted publication.
    worker.r.adapter.pause()
    require(coordinator.guard()['state']=='QUIESCED' and not any(coordinator.sets()),
        'DISCOVERY_REENTRY_REVOCATION_UNPROVEN')
    guard.current(fingerprint(scope),scope['generationRef'])
    require(worker.r.journal.read()==pending,'DISCOVERY_REENTRY_PENDING_CHANGED')
    target='NEW' if row['state']=='ACTIVE' else row['state']
    result=worker.r.save(pending,target,'DISCOVERY_TECHNICAL_REENTRY_REVOKED',
        healthyUntilWall=None,healthyUntilMonotonic=None)
    require(result['attempts']==row['attempts'] and result['publicationCount']==row['publicationCount'],
        'DISCOVERY_REENTRY_HISTORY_MUST_BE_PRESERVED')
    worker.active_here=False
    return result


@contextmanager
def installed_invocation(worker,guard,scope):
    """Hold both logical installation and recovery process fences through serve.

    The source-built factory's custody guard remains; the runtime authority
    callback is replaced with this concrete installed guard for every turn.
    This function never initializes a journal or admits another generation.
    """
    selected=copy.deepcopy(scope);retained(worker,guard,selected)
    previous=worker.r.adapter.scope_guard
    def current():
        retained(worker,guard,selected)
        require(scope==selected,'DISCOVERY_SESSION_SCOPE_CHANGED')
        require(guard.current(fingerprint(selected),selected['generationRef']) is True,
            'CURRENT_INSTALLED_DISCOVERY_SESSION_AUTHORITY_REQUIRED')
    with protected_directory(worker.r.journal.root),guard.invocation(),worker.r.journal.invocation():
        worker.r.adapter.scope_guard=current
        try:
            prepare(worker,guard,selected)
            current()
            yield worker
        finally:
            worker.active_here=False
            try:worker.r.adapter.pause()
            finally:worker.r.adapter.scope_guard=previous
