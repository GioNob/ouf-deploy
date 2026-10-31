"""One reviewed checkpoint-four authority epoch; no prefix effect replay.

The predecessor stays available verbatim. A successor is not a retry or a
retrospective signature over past effects: it authorizes only future reads and
the remaining effects, on the same durably started, paused process generation.
"""
import copy
import math
from .core import digest, encoded, require, hashed, validate_current, generation

KEY = 'semanticRegistryCheckpointResumption'
SCHEMA = 'ouf.semantic-registry-checkpoint-four-resumption-scope.v1'
EPOCH = 'ouf.semantic-registry-recovery-journal.v2'


def predecessor(plan, row, reads):
    require(type(row) is dict and row.get('schema') == 'ouf.semantic-registry-recovery-journal.v1'
            and row.get('nextStage') == 4 and row.get('state') == 'IN_FLIGHT'
            and len(row.get('effects', [])) == 5 and row.get('readAttempts') == 5,
            'EXACT_SINGLE_PREDECESSOR_CHECKPOINT_FOUR_REQUIRED')
    validate_current(plan, row, row['bootId'], (row['lastUnix'], row['lastMonotonic']))
    start, pause = row['effects'][1], row['effects'][3]
    pin = generation(row['newGeneration'])
    require(all(e.get('nativeRequestAttempted') is True and e.get('nativeResponse204') is True
                and e['nativeEvidence'].get('newGeneration') == pin for e in (start, pause))
            and start['nativeEvidence'].get('durableNativeStartEvidence') is True
            and start['nativeEvidence'].get('processKind') == pause['nativeEvidence'].get('processKind') == 'GATE_WAITING'
            and start['nativeEvidence'].get('paused') is False and pause['nativeEvidence'].get('paused') is True
            and start.get('nativeFirstProcess', {}).get('newGeneration') == pin
            and all(row['effects'][4].get(k) is not True for k in
                    ('nativeRequestAttempted', 'nativeAttestationAttempted')),
            'DURABLE_START_AND_PAUSE_WITH_NO_LATER_EFFECT_REQUIRED')
    require(type(reads) is dict and reads.get('schema') == 'ouf.semantic-registry-recovery-native-read-journal.v1'
            and set(reads)=={'schema','scopeHash','authorityHash','counts','version','budgetReset'}
            and hashed(reads.get('scopeHash'))
            and reads.get('authorityHash') == row['authorityHash'] and reads.get('budgetReset') is False
            and reads.get('counts') == {'databaseSessions': 1, 'gatewayAdminGets': 6, 'semanticGets': 0}
            and all(type(value) is int for value in reads['counts'].values())
            and type(reads.get('version')) is int and reads['version'] >= 0,
            'EXACT_CONSUMED_PREDECESSOR_NATIVE_READS_REQUIRED')


def scope(plan, owner_context):
    require(owner_context.get('schema') == 'ouf.semantic-registry-postboot-successor-owner-context.v1',
            'EXPLICIT_SUCCESSOR_OWNER_CONTEXT_REQUIRED')
    inputs = owner_context['resumptionInputs']; binding = owner_context['resumptionBinding']
    require(type(binding) is dict and set(binding) == {'path', 'sha256'} and hashed(binding['sha256'])
            and digest(inputs) == binding['sha256']
            and inputs.get('schema') == 'ouf.semantic-registry-resumption-inputs.v1'
            and inputs.get('newGrantAllowance') == 0 and inputs.get('retainedControlledGrantAttempts') == 320
            and inputs.get('runtimeAuthorityIssued') is False and inputs.get('targetApplyAuthorized') is False,
            'EXACT_RETAINED_INPUTS_NOT_RUNTIME_AUTHORITY_REQUIRED')
    old, reads = inputs['retainedNativeJournal'], inputs['retainedNativeReads']
    predecessor(plan, old, reads)
    result = inputs['maintenanceResult']
    require(result.get('status') == 'JVM_RESIDUE_REMOVED_ORIGINAL_SEAL_RESTORED'
            and result.get('complete') is True and result.get('originalIndependentRootfsSealMatches') is True
            and result.get('expectedRootfsSealUnchanged') is True
            and result.get('samePausedGenerationBeforeAndAfter') is True
            and result.get('directoryRemovalAttempts') == result.get('directoryRemovalsConfirmed') == 6
            and result.get('retainedControlledGrantAttempts') == 320 and result.get('javaReleased') is False
            and inputs['identity']['nativeJournalHash'] == digest(old)
            and inputs['identity']['ownerJournalHash'] == digest(inputs['retainedOwnerJournal'])
            and inputs['identity']['maintenanceResultHash'] == digest(result)
            and inputs['identity']['priorAuthorityHash'] == old['authorityHash']
            and inputs['identity']['bootId'] == old['bootId'] == owner_context['recovery']['bootId'],
            'COMPLETED_MAINTENANCE_AND_SAME_BOOT_LINEAGE_REQUIRED')
    return {'schema': SCHEMA, 'inputs': copy.deepcopy(binding), 'planHash': digest(plan),
            'predecessorJournalHash': digest(old), 'predecessorNativeReadsHash': digest(reads),
            'maintenanceResultHash': digest(result), 'ownerContextHash': digest(owner_context),
            'sourceClosureHash': owner_context['sourceClosureHash'], 'checkpoint': 4,
            'sameGeneration': copy.deepcopy(old['newGeneration']), 'retainedControlledGrantAttempts': 320,
            'remainingNativeReadAttempts': 128 - old['readAttempts'],
            'maximumNewDockerEffectAttempts': 2, 'maximumNewAttestationAttempts': 1,
            'prefixEffectReplayAllowed': False, 'oldClaimsRemainConsumed': True,
            'automaticReplayAllowed': False, 'budgetReset': False}


def validate_epoch(plan, row):
    require(row.get('schema') == EPOCH and type(row.get('resumption')) is dict,
            'EXPLICIT_RECOVERY_AUTHORITY_EPOCH_REQUIRED')
    epoch = row['resumption']; value = epoch['scope']
    require(set(epoch) == {'scope','predecessorJournal','predecessorNativeReads'}, 'EXACT_SUCCESSOR_EPOCH_FIELDS_REQUIRED')
    old, reads = epoch['predecessorJournal'], epoch['predecessorNativeReads']
    predecessor(plan, old, reads)
    require(value.get('schema') == SCHEMA and value.get('planHash') == digest(plan)
            and value.get('predecessorJournalHash') == digest(old) and value.get('predecessorNativeReadsHash') == digest(reads)
            and value.get('sameGeneration') == old['newGeneration'] == row['newGeneration']
            and old['bootId'] == row['bootId'] and old['authorityHash'] != row['authorityHash']
            and row['createdUnix'] >= old['lastUnix'] and row['createdMonotonic'] >= old['lastMonotonic']
            and row['version'] > old['version'] and row['readAttempts'] >= old['readAttempts']
            and row['maximumReadAttempts'] == old['maximumReadAttempts']
            and value.get('remainingNativeReadAttempts') == 128 - old['readAttempts']
            and all(value.get(k) is False for k in ('prefixEffectReplayAllowed', 'automaticReplayAllowed', 'budgetReset'))
            and value.get('oldClaimsRemainConsumed') is True and row['nextStage'] >= 4
            and row['effects'][:4] == old['effects'][:4],
            'UNCHANGED_PREDECESSOR_PREFIX_GENERATION_AND_BUDGET_REQUIRED')
    before, current = old['effects'][4], row['effects'][4]
    if row['nextStage'] == 4:
        require(current == before, 'PREDECESSOR_READ_CLAIM_MUST_REMAIN_UNCHANGED')
    else:
        expected = copy.deepcopy(before)
        expected.update(state='APPLIED', nativeEvidence=current.get('nativeEvidence'),
                        nativeEvidenceHash=current.get('nativeEvidenceHash'), completionAuthorityHash=row['authorityHash'])
        require(current == expected, 'EXPLICIT_CURRENT_AUTHORITY_FOR_RECONCILED_READ_REQUIRED')
    return old


def proposed_epoch(plan, old, reads, signed_scope, authority_hash, issued, expires, wall, mono):
    predecessor(plan, old, reads)
    require(signed_scope.get('predecessorJournalHash') == digest(old) and signed_scope.get('predecessorNativeReadsHash') == digest(reads)
            and signed_scope.get('schema') == SCHEMA and signed_scope.get('planHash') == digest(plan)
            and all(type(v) in (int, float) and math.isfinite(v) for v in (issued, expires, wall, mono))
            and issued <= wall < expires and 0 < expires - wall <= 900
            and wall >= old['lastUnix'] and mono >= old['lastMonotonic'] and hashed(authority_hash),
            'FRESH_SIGNED_SUCCESSOR_SCOPE_REQUIRED')
    result = copy.deepcopy(old)
    result.update(schema=EPOCH, authorityHash=authority_hash, createdUnix=wall, createdMonotonic=mono,
                  lastUnix=wall, lastMonotonic=mono, expiresUnix=expires,
                  expiresMonotonic=mono + expires - wall, version=old['version'] + 1,
                  resumption={'scope':copy.deepcopy(signed_scope),'predecessorJournal':copy.deepcopy(old),'predecessorNativeReads':copy.deepcopy(reads)})
    validate_epoch(plan, result)
    # These are a PROPOSAL only. Native installer must authenticate, lock,
    # re-observe the exact paused gate, consume a durable claim, and CAS.
    following = copy.deepcopy(reads)
    following.update(authorityHash=authority_hash, version=reads['version'] + 1)
    return result, following
