"""Durable cutover checkpoints, not installation or retry authority.

The sealed installer authenticates commands/authority and natively reconciles
effects. This journal never issues effects, signs, waits, reopens or restores.
Use the existing owner-supplied Journal in a NEW private directory, never R12's.
"""
import copy
from contextlib import contextmanager
import hashlib
import json
import re

PHASES = ('STOP_REVOKE_OLD_LEASE', 'QUIESCE_PRODUCERS', 'FENCED_BACKUP',
          'RELEASE_OLD_ENDPOINT', 'CREATE_REPLACEMENT', 'STAGE_PAUSED_REPLACEMENT', 'ATTEST_NEW_OCI_PEER',
          'INSTALL_AUTHENTICATED_TRANSPORT', 'START_DISTINCT_LEASE_WORKER',
          'ADMIT_MIGRATION', 'START_REPLACEMENT', 'VERIFY_APPLICATION',
          'RELEASE_PRODUCERS')


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    allow_nan=False).encode()).hexdigest()


def hash_value(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


class Transition:
    """One-use ordered effects with CAS versions and persistent ambiguity.

    Each operation is durably marked IN_FLIGHT BEFORE its local effect. An
    interruption is reconciled against fresh native evidence, never replayed.
    Even proof of no effect leaves the original attempt consumed; a new scoped
    technical decision is needed to supersede it. No auto retry loop lives here.
    Journal invocation fencing must surround the whole installer invocation;
    short journal transactions never encompass Docker/DB/provider operations.
    """
    def __init__(self, journal, context_hash):
        require(hash_value(context_hash), 'EXACT_TRANSITION_CONTEXT_REQUIRED')
        self.journal, self.context = journal, context_hash
        self._invoked = False

    @contextmanager
    def invocation(self):
        require(not self._invoked, 'CUTOVER_NESTED_INVOCATION_DENIED')
        with self.journal.invocation():
            self._invoked = True
            try:
                yield self
            finally:
                self._invoked = False

    @staticmethod
    def initial(context_hash, creation_request_hash, predecessor_history_hash,
                predecessor_incident_ref):
        require(all(hash_value(x) for x in (context_hash, creation_request_hash,
                predecessor_history_hash, predecessor_incident_ref)), 'EXACT_SEALED_HISTORY_REQUIRED')
        bindings = {'transitionAuthorityEvidenceHash': context_hash,
                    'creationRequestHash': creation_request_hash,
                    'predecessorHistoryHash': predecessor_history_hash,
                    'predecessorIncidentRef': predecessor_incident_ref}
        return {'schema': 'ouf.semantic-cutover-journal.v1', 'contextHash': digest(bindings),
                'transitionAuthorityEvidenceHash': context_hash,
                'creationRequestHash': creation_request_hash,
                'predecessorHistoryHash': predecessor_history_hash,
                'predecessorIncidentRef': predecessor_incident_ref,
                'version': 0, 'nextPhase': 0, 'state': 'READY', 'effects': [],
                'databaseMayHaveChanged': False, 'applicationWritesMayHaveOccurred': False,
                'automaticReplayAllowed': False, 'preMigrationRestoreAllowed': False,
                'releaseAcceptance': False}

    def read(self):
        row = self.journal.read()
        require(row.get('schema') == 'ouf.semantic-cutover-journal.v1'
                and row.get('contextHash') == self.context, 'CUTOVER_CONTEXT_DRIFT')
        require(type(row.get('version')) is int and row['version'] >= 0
                and type(row.get('nextPhase')) is int and 0 <= row['nextPhase'] <= len(PHASES)
                and type(row.get('effects')) is list and len(row['effects']) <= len(PHASES),
                'CUTOVER_JOURNAL_SHAPE_INVALID')
        require(row.get('automaticReplayAllowed') is False
                and row.get('preMigrationRestoreAllowed') is False,
                'CUTOVER_RECOVERY_POLICY_DRIFT')
        require(all(hash_value(row.get(k)) for k in ('creationRequestHash',
                'predecessorHistoryHash', 'predecessorIncidentRef', 'transitionAuthorityEvidenceHash')),
                'CUTOVER_HISTORY_DRIFT')
        require(digest({k: row[k] for k in ('creationRequestHash', 'predecessorHistoryHash',
                'predecessorIncidentRef', 'transitionAuthorityEvidenceHash')}) == self.context,
                'CUTOVER_SEALED_BINDINGS_DRIFT')
        require(len(row['effects']) == row['nextPhase'] + (1 if row['state'] in
                {'IN_FLIGHT', 'NO_EFFECT_REQUIRES_NEW_DECISION'} else 0), 'CUTOVER_PHASE_HISTORY_INCONSISTENT')
        for i, effect in enumerate(row['effects']):
            require(effect['phase'] == PHASES[i] and hash_value(effect['intentHash'])
                    and hash_value(effect['authorityEvidenceHash'])
                    and effect['state'] in {'IN_FLIGHT', 'APPLIED', 'NO_EFFECT_REQUIRES_NEW_DECISION'},
                    'CUTOVER_EFFECT_HISTORY_INVALID')
            if i < row['nextPhase']:
                require(effect['state'] == 'APPLIED' and hash_value(effect.get('nativeEvidenceHash')),
                        'CUTOVER_APPLIED_NATIVE_PROOF_REQUIRED')
        require(row['state'] in {'READY', 'IN_FLIGHT', 'NO_EFFECT_REQUIRES_NEW_DECISION', 'COMPLETED'},
                'CUTOVER_STATE_INVALID')
        if row['state'] in {'IN_FLIGHT', 'NO_EFFECT_REQUIRES_NEW_DECISION'}:
            require(row['effects'][-1]['state'] == row['state'], 'CUTOVER_LAST_EFFECT_STATE_DRIFT')
        require((row['nextPhase'] == len(PHASES)) == (row['state'] == 'COMPLETED'),
                'CUTOVER_COMPLETION_INVALID')
        # These conservative flags become durable before possible migration or
        # app writes, including a crash before a successful acknowledgement.
        require(type(row['databaseMayHaveChanged']) is bool
                and type(row['applicationWritesMayHaveOccurred']) is bool,
                'CUTOVER_DATABASE_BOUNDARY_INVALID')
        require(not any(e['phase'] == 'ADMIT_MIGRATION' for e in row['effects'])
                or row['databaseMayHaveChanged'], 'CUTOVER_MIGRATION_BOUNDARY_LOST')
        require(not any(e['phase'] in {'STAGE_PAUSED_REPLACEMENT','START_REPLACEMENT'} for e in row['effects'])
                or row['applicationWritesMayHaveOccurred'], 'CUTOVER_WRITE_BOUNDARY_LOST')
        return row

    def begin(self, phase, intent_hash, authority_evidence_hash, expected_version):
        """Hash receipts only. Caller must authenticate authority BEFORE this.

        A hash is a binding, never signature verification or runtime permission.
        Unknown effects cannot be bypassed with another intent or authority hash.
        """
        require(hash_value(intent_hash) and hash_value(authority_evidence_hash),
                'EXACT_INTENT_AND_AUTHENTICATION_RECEIPT_REQUIRED')
        require(self._invoked, 'CUTOVER_EXCLUSIVE_INVOCATION_REQUIRED')
        previous = self.read()
        require(previous['version'] == expected_version, 'CUTOVER_EXPECTED_VERSION_CONFLICT')
        require(previous['state'] == 'READY', 'CUTOVER_RECONCILIATION_OR_NEW_DECISION_REQUIRED')
        require(previous['nextPhase'] < len(PHASES) and phase == PHASES[previous['nextPhase']],
                'CUTOVER_PHASE_ORDER_DENIED')
        following = copy.deepcopy(previous)
        following['version'] += 1; following['state'] = 'IN_FLIGHT'
        following['effects'].append({'phase': phase, 'intentHash': intent_hash,
                                     'authorityEvidenceHash': authority_evidence_hash, 'state': 'IN_FLIGHT'})
        if phase == 'ADMIT_MIGRATION': following['databaseMayHaveChanged'] = True
        if phase in {'STAGE_PAUSED_REPLACEMENT','START_REPLACEMENT'}:
            following['applicationWritesMayHaveOccurred'] = True
        self.journal.compare_and_save(previous, following)
        return following

    def reconcile(self, phase, intent_hash, outcome, native_evidence_hash, expected_version):
        """Record owner-proven exact effects; UNKNOWN leaves durable ambiguity.

        The caller must freshly verify complete native state and exact generation,
        custody and intent. A timeout, absent receipt or name-only Docker match is
        never proof of absence. Reconciliation is not permission for the next step.
        """
        require(outcome in {'APPLIED', 'NO_EFFECT', 'UNKNOWN'} and hash_value(native_evidence_hash),
                'EXACT_NATIVE_RECONCILIATION_REQUIRED')
        require(self._invoked, 'CUTOVER_EXCLUSIVE_INVOCATION_REQUIRED')
        previous = self.read()
        require(previous['version'] == expected_version, 'CUTOVER_EXPECTED_VERSION_CONFLICT')
        require(previous['state'] == 'IN_FLIGHT' and previous['effects'][-1]['phase'] == phase
                and previous['effects'][-1]['intentHash'] == intent_hash, 'CUTOVER_IN_FLIGHT_INTENT_REQUIRED')
        following = copy.deepcopy(previous); following['version'] += 1
        effect = following['effects'][-1]; effect['nativeEvidenceHash'] = native_evidence_hash
        if outcome == 'APPLIED':
            effect['state'] = 'APPLIED'; following['nextPhase'] += 1
            following['state'] = 'COMPLETED' if following['nextPhase'] == len(PHASES) else 'READY'
        elif outcome == 'NO_EFFECT':
            effect['state'] = following['state'] = 'NO_EFFECT_REQUIRES_NEW_DECISION'
        self.journal.compare_and_save(previous, following)
        return following
