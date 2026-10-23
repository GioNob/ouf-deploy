"""Finite coordinated recovery; no daemon, implicit authentication or replay.

The real token worker and native recovery share one process and coordination
lock. A positive GET is reported immediately, then the worker retains its lease
for the remaining approved window. It is never called permanent renewal or
reboot resilience. Uncertain native effects stop for read-only reconciliation.
"""
import copy
import math
import threading
import time

from .core import require, digest
from . import bootstrap

# These are additional restrictive controller ceilings, not new read budgets.
# Every observation still consumes the original durable Runner/native counters
# and requires the same live signed authority and current owner admission.
COLD_START_WAIT_SECONDS = 90
COLD_START_ADDITIONAL_OBSERVATIONS = 12
COLD_START_POLL_SECONDS = 5


class ColdStartWait:
    """Only observe a known successful release while its application settles.

    No exception, missing ACK, earlier stage, changed generation or concurrent
    journal movement is retried. Runner itself never re-applies a CLAIMED
    effect. The wait spans stages 9..11 without resetting its local ceiling.
    """
    def __init__(self, *, monotonic=time.monotonic):
        self.clock = monotonic
        self.started = None
        self.last = None
        self.observations = 0
        self.pending = None
        self.generation = None

    def _time(self):
        now = self.clock()
        require(type(now) in (int, float) and math.isfinite(now)
                and (self.last is None or now >= self.last), 'POSTBOOT_WAIT_CLOCK_CHANGED')
        self.last = now
        if self.started is None:
            self.started = now
        remaining = COLD_START_WAIT_SECONDS - (now - self.started)
        require(remaining > 0, 'POSTBOOT_COLD_START_OBSERVATION_WINDOW_EXHAUSTED')
        return remaining

    def defer(self, runner, before, row, witness):
        index = row['nextStage']
        require(index == before['nextStage'] and index in (9, 10, 11)
                and row['state'] == 'IN_FLIGHT' and len(row['effects']) == index + 1,
                'POSTBOOT_NATIVE_OUTCOME_REQUIRES_RECONCILIATION')
        release = row['effects'][9]
        require(release['stage'] == 'RELEASE_SAME_GENERATION_SIGUSR1'
                and release.get('nativeRequestAttempted') is True
                and release.get('nativeResponse204') is True
                and release['state'] == ('CLAIMED' if index == 9 else 'APPLIED')
                and row['effects'][index]['state'] == 'CLAIMED',
                'POSTBOOT_AMBIGUOUS_RELEASE_REQUIRES_RECONCILIATION')
        require(runner.current() == row and row['newGeneration'] == before['newGeneration'],
                'POSTBOOT_WAIT_JOURNAL_OR_GENERATION_CHANGED')
        proof = witness.observe(stage='ACTIVE')
        require(proof['checkpoint'] == index and proof['runtimeGeneration'] == row['newGeneration']
                and (self.generation is None or self.generation == row['newGeneration'])
                and runner.current() == row, 'POSTBOOT_WAIT_CURRENT_GENERATION_REQUIRED')
        remaining = self._time()
        require(self.observations < COLD_START_ADDITIONAL_OBSERVATIONS,
                'POSTBOOT_COLD_START_OBSERVATION_LIMIT_EXHAUSTED')
        self.observations += 1
        self.pending = copy.deepcopy(row)
        self.generation = copy.deepcopy(row['newGeneration'])
        return min(COLD_START_POLL_SECONDS, remaining)

    def before_poll(self, runner, witness):
        if self.pending is None:
            return
        self._time()
        require(runner.current() == self.pending, 'POSTBOOT_WAIT_JOURNAL_CHANGED')
        proof = witness.observe(stage='ACTIVE')
        require(proof['checkpoint'] == self.pending['nextStage'] and proof['runtimeGeneration'] == self.generation
                and runner.current() == self.pending, 'POSTBOOT_WAIT_CURRENT_GENERATION_REQUIRED')
        self.pending = None


def public_row(row):
    return {'schema': 'ouf.semantic-registry-postboot-progress.v1',
            'checkpoint': row['nextStage'], 'recoveryState': row['state'],
            'originalSemanticGetSucceeded': row['originalSemanticGetSucceeded'],
            'runtimeEffectAttempts': sum(e.get('nativeRequestAttempted') is True for e in row['effects']),
            'automaticReplayAllowed': False, 'budgetReset': False,
            'permanentRenewalProven': False, 'releaseAcceptance': False}


def advance(runner, target, emit):
    require(type(target) is int and 0 <= target <= 12, 'CLOSED_POSTBOOT_CHECKPOINT_REQUIRED')
    while True:
        before = runner.current()
        if before['nextStage'] >= target:
            return before
        row = runner.step()
        emit(public_row(row))
        # An ambiguous outcome never becomes another dispatch or a busy poll.
        # The existing durable claim remains available to a later explicit
        # read-only reconciliation within the same valid authority/window.
        require(row['nextStage'] > before['nextStage'], 'POSTBOOT_NATIVE_OUTCOME_REQUIRES_RECONCILIATION')


def bootstrap_gate(native_context, authority, raw, emit):
    runner = bootstrap.build(native_context, authority, raw)
    row = advance(runner, 4, emit)
    require(row['nextStage'] == 4, 'POSTBOOT_BOOTSTRAP_STOPS_AT_FOUR')
    proof = runner.ports.witness.observe(stage='PREGRANT')
    return {'schema': 'ouf.semantic-registry-postboot-paused-result.v1',
            'checkpoint': 4, 'freshPausedGateObserved': True,
            'gateWitnessHash': digest(proof), 'javaReleased': False,
            'tokenGrantAttempts': 0, 'originalSemanticGetSucceeded': False,
            'automaticReplayAllowed': False, 'budgetReset': False}


def install_owner(native_context, owner_context, authority, raw):
    from tools.semantic_registry_postboot_owner import installer as owner_installer
    runner = bootstrap.build(native_context, authority, raw)
    receipt = owner_installer.install(owner_context, authority, raw, runner.ports.witness)
    return {'schema': 'ouf.semantic-registry-postboot-owner-installed-result.v1',
            'installationHash': digest(receipt), 'currentSessionBootEstablished': True,
            'retainedFirstGrantReplayed': False,
            'priorControlledGrantAttempts': receipt['predecessorGrantAttempts'],
            'oauthRequests': 0, 'runtimeAuthorityIssued': False,
            'automaticReplayAllowed': False, 'budgetReset': False}


def continue_recovery(native_context, owner_context, authority, raw, verifier, signer, emit):
    from .postboot_factory import build_on_bootstrap
    from tools.semantic_registry_postboot_owner.owner import build_worker
    from tools.semantic_registry_postboot_owner.scheduler import PostbootRenewalWorker
    prefix = bootstrap.build(native_context, authority, raw)
    require(prefix.current()['nextStage'] == 4,
            'NEW_POSTBOOT_WORKER_START_REQUIRES_PAUSED_CHECKPOINT_FOUR')
    worker = build_worker(owner_context, authority, raw, prefix.ports.witness)
    require(type(worker) is PostbootRenewalWorker, 'ACTUAL_FINITE_POSTBOOT_WORKER_REQUIRED')
    lock, stop, ready, finished = threading.RLock(), threading.Event(), threading.Event(), threading.Event()
    outcome = {}
    cold_start = ColdStartWait()

    def observed(status):
        # This notification wakes the main thread only. It is not evidence:
        # build_on_bootstrap reconstructs and rechecks the actual observer.
        if status.get('state') == 'ACTIVE':
            ready.set()

    def maintain():
        try:
            outcome['row'] = worker.run(stop, observed, coordination_lock=lock)
        except Exception:
            outcome['failed'] = True
        finally:
            finished.set()
            ready.set()

    thread = threading.Thread(target=maintain, name='ouf-postboot-token-owner', daemon=False)
    thread.start()
    success = False
    try:
        while not ready.wait(1):
            prefix.current()  # Real signed window, both clocks and same boot.
        with lock:
            require(thread.is_alive() and not finished.is_set() and not outcome.get('failed'),
                    'CURRENT_POSTBOOT_WORKER_DID_NOT_ESTABLISH_ADMISSION')
            runner = build_on_bootstrap(prefix, native_context, owner_context, authority, raw, verifier, signer)
        while True:
            delay = None
            with lock:
                require(thread.is_alive() and not finished.is_set() and not outcome.get('failed'),
                        'POSTBOOT_OWNER_ENDED_BEFORE_RECOVERY')
                cold_start.before_poll(runner, prefix.ports.witness)
                row = runner.current()
                if row['nextStage'] == 12:
                    success = row['originalSemanticGetSucceeded'] is True
                    require(success, 'ORIGINAL_SERVICE_SEMANTIC_GET_REQUIRED')
                    token_row = worker.r.journal.read()
                    wall, mono = worker.r.now()
                    valid_until = min(row['expiresUnix'], token_row['tokenExpiresWall'],
                                      wall + token_row['tokenExpiresMonotonic'] - mono,
                                      wall + worker.r.remaining(token_row))
                    emit({**public_row(row), 'status': 'ORIGINAL_SERVICE_GET_200_WITH_FINITE_OWNER',
                          'httpStatus': 200, 'ownerWindowEndsNoLaterThanUnix': valid_until,
                          'continuousServiceRenewalEstablished': False})
                    break
                advanced = runner.step()
                emit(public_row(advanced))
                if advanced['nextStage'] == row['nextStage']:
                    delay = cold_start.defer(runner, row, advanced, prefix.ports.witness)
                    emit({**public_row(advanced), 'status': 'READ_ONLY_COLD_START_WAIT',
                          'additionalObservationNumber': cold_start.observations,
                          'maximumAdditionalObservations': COLD_START_ADDITIONAL_OBSERVATIONS,
                          'maximumWaitSeconds': COLD_START_WAIT_SECONDS})
                else:
                    require(advanced['nextStage'] > row['nextStage'], 'POSTBOOT_CHECKPOINT_REGRESSED')
            if delay is not None:
                # The real owner must keep its invocation lock and renew under
                # the SAME approved budget while the application initializes.
                # Never hold the coordination lock across this finite wait.
                finished.wait(delay)
        # Keep the actual owner alive for its reviewed finite window. Returning
        # immediately would revoke its marker as soon as the GET succeeded.
        while thread.is_alive():
            thread.join(timeout=1)
        return {'schema': 'ouf.semantic-registry-postboot-finite-session-result.v1',
                'originalSemanticGetSucceededDuringWindow': success,
                'ownerSessionEnded': True, 'currentOwnerAdmissionProven': False,
                'continuousServiceRenewalEstablished': False,
                'automaticReplayAllowed': False, 'budgetReset': False,
                'releaseAcceptance': False}
    finally:
        stop.set()
        # The grant/native transports have independent bounded timeouts. Do not
        # release the process while an unjoined publisher can still mutate files.
        thread.join(timeout=owner_context['budget']['attemptTimeoutSeconds'] + 5)
        require(not thread.is_alive(), 'POSTBOOT_WORKER_TERMINATION_REQUIRES_RECONCILIATION')
