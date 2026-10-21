"""Separate exact stage18 continuation; frozen native executor stays unchanged.

No initialize-at-zero, login, refresh, automatic retry, effect loop or old replay.
All dependencies are supplied as verified namespaces by the sealed delivery.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import time

CHECKPOINT = {'phase': 'NOT_STARTED', 'contextPath': None}
SCHEMA = 'ouf.ingestion-rollout-stage18-control.v1'


def boot_id(): return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def read(snapshot, path): return snapshot['decode'](snapshot['private_read'](str(path)))


def preflight(entry, case, snapshot, budget, common):
    p, review, row = common.retained(case, snapshot, budget)
    a, c = entry.authority, entry.c
    closure = review['sourceClosure']
    c.require(c.digest(closure['declaration']) == case['nativeDeclarationHash']
        and getattr(entry, '__qualified_source_sha256__', None)
            == closure['declaration']['sourceHashes']['tools.ingestion_rollout_execution.entry']
        and row['readAttempts'] < 128, 'EXACT_FROZEN_NATIVE_CLOSURE_AND_UNEXHAUSTED_READ_BUDGET_REQUIRED')
    a.verify_closure(closure); a.current_issuer(review['issuerProfile'], int(time.time()) + 900)
    # Check all public file custody seals from the original preparation; this
    # never reads key material or old HUMAN/bearer values.
    preparation = read(snapshot, Path(p['predecessorContext']) / 'preparation.json')
    for seal in preparation['retainedDocuments'].values(): a.private_file.check_metadata(seal)
    c.require(preparation['sourceClosure'] == closure, 'SAME_RETAINED_PREPARATION_AND_SOURCE_CLOSURE_REQUIRED')
    return p, review, row


def human(entry, case, snapshot, common):
    claim = read(snapshot, common.root(case) / 'stage18-human-window.claim.json')
    c = entry.c
    c.require(claim['caseHash'] == c.digest(case)
        and claim['budgetDecisionHash'] == case['budgetReceipt']['decisionHash'], 'EXACT_STAGE18_HUMAN_GRANT_CLAIM_REQUIRED')
    ctl = Path(claim['controlPath']); config = read(snapshot, ctl / 'control.json')
    binding = read(snapshot, ctl / 'binding.json'); profile = read(snapshot, ctl / 'human-read-profile.json')
    review, decision = config['review'], config['decision']
    c.require(config['case'] == case and config['confirmedRead'] == {}
        and review['operationBinding']['stage18CaseHash'] == c.digest(case)
        and review['operationBinding']['budgetDecisionHash'] == case['budgetReceipt']['decisionHash']
        and review['operationBinding']['runtimeControllerHash'] == case['runtimeControllerHash']
        and config['sourceClosureHash'] == review['sourceClosureHash']
        and c.hashed(review['sourceClosureHash'])
        and claim['reviewHash'] == c.digest(review) == decision['reviewHash']
        and claim['decisionHash'] == c.digest(decision)
        and config['selection'] == profile['selection'] and profile['expectedBinding'] == binding
        and profile['minimumCumulativeAttempts'] == profile['maximumCumulativeAttempts'] == 292
        and profile['governedWindowReceiptHash'] == c.digest({'review': review, 'decision': decision})
        and review['priorOAuthAttempts'] == 288 and review['maximumCumulativeOAuthAttempts'] == 292
        and decision['approvedAt'] == binding['createdAt'] and decision['expiresAt'] == binding['expiresAt']
        and decision['expiresAt'] - decision['approvedAt'] == 7200,
        'SAME_STAGE18_VERIFIED292_PROVIDER_SESSION_REQUIRED')
    h = entry.authority.human_reader.open_existing(profile)
    c.require(h._read()['accessExpiresAt'] > time.time() + 930,
        'CURRENT_STAGE18_HUMAN_TOKEN_MARGIN930_REQUIRED_NO_REFRESH')
    return h, profile, str(ctl)


def update(journal, **changes):
    row = journal.read(); journal.compare_and_save(row, {**row, **changes}); return journal.read()


def publish(entry, target, name, value):
    journal = entry.Journal(target); journal.create(Path(target) / name, entry.c.encoded(value)); journal.sync()


def prepare_review(entry, manifest, case, snapshot, budget, common):
    p, old_review, old_row = preflight(entry, case, snapshot, budget, common)
    c, a = entry.c, entry.authority
    c.require(manifest == old_review['sourceClosure']['declaration'], 'EXACT_FROZEN_STAGE18_MANIFEST_REQUIRED')
    h, profile, ctl = human(entry, case, snapshot, common)
    target = common.context(case); claim = common.root(case) / 'stage18-runtime-review.claim.json'
    c.require(not os.path.lexists(target) and not os.path.lexists(claim), 'STAGE18_RUNTIME_REVIEW_ALREADY_CONSUMED_STATUS_ONLY')
    packet = read(snapshot, old_review['executionReview']['packetBinding']['path'])
    c.require(c.digest(packet) == old_review['packetHash'], 'EXACT_RETAINED_STAGE18_PACKET_REQUIRED')
    native = common.successor_native(case, p, old_review, old_row, profile)
    a.native_review.validate_review(native, packet)
    review = a.compile_action_review(native, packet, old_review['sourceClosure'], old_review['issuerProfile'],
        old_review['qualification'], 900)
    review['absoluteExpiresAt'] = min(h.expires_at - 5, int(h._read()['accessExpiresAt']) - 30)
    review['stage18OperatorBinding'] = {'caseHash': c.digest(case),
        'controllerHash': case['runtimeControllerHash'], 'commonHash': case['commonHash'],
        'continuationProofHash': c.digest(native['stage18ContinuationProof']), 'humanControlPath': ctl}
    a.validate_action_review(review)
    # This is a new control/review, not an extension/rewrite of the old context.
    entry.Journal(common.root(case)).create(claim, c.encoded({'schema': SCHEMA,
        'caseHash': c.digest(case), 'contextPath': str(target), 'reviewHash': c.digest(review),
        'predecessorJournalHash': p['predecessorJournalHash'], 'runtimeAuthorityIssued': False}))
    entry.Journal(common.root(case)).sync()
    with a.protected_directory(target.parent) as fd: os.mkdir(target.name, 0o700, dir_fd=fd); os.fsync(fd)
    operator = target / 'operator-control'; operator.mkdir(mode=0o700)
    journal = entry.Journal(operator)
    journal.initialize({'schema': SCHEMA, 'caseHash': c.digest(case), 'state': 'REVIEW_COMPILING',
        'complete': False, 'reviewHash': c.digest(review), 'runtimeAuthorityIssued': False, 'budgetReset': False})
    publish(entry, target, 'review.json', review)
    update(journal, state='REVIEW_READY')
    return {'status': 'STAGE18_RUNTIME_REVIEW_READY_EXPLICIT_APPROVAL_REQUIRED', 'complete': False,
        'contextPath': str(target), 'nextStage': 18, 'remainingStages': 10,
        'maximumRuntimeSeconds': 900, 'oauthRequests': 0, 'runtimeAuthorityIssued': False}


def load(entry, manifest, case, snapshot, budget, common):
    p, old_review, old_row = common.retained(case, snapshot, budget)
    target = common.context(case); journal = entry.Journal(target / 'operator-control'); row = journal.read()
    c, a = entry.c, entry.authority
    claim = read(snapshot, common.root(case) / 'stage18-runtime-review.claim.json')
    review = read(snapshot, target / 'review.json')
    c.require(row['schema'] == SCHEMA and row['caseHash'] == c.digest(case) and row['budgetReset'] is False
        and row['reviewHash'] == c.digest(review) == claim['reviewHash']
        and claim['caseHash'] == c.digest(case) and claim['contextPath'] == str(target)
        and claim['predecessorJournalHash'] == p['predecessorJournalHash'], 'EXACT_STAGE18_RUNTIME_CONTROL_REQUIRED')
    h, profile, ctl = human_for_execution(entry, case, snapshot, common)
    native = common.successor_native(case, p, old_review, old_row, profile)
    c.require(review['executionReview'] == native and review['sourceClosure'] == old_review['sourceClosure']
        and review['sourceClosure']['declaration'] == manifest
        and review['stage18OperatorBinding'] == {'caseHash': c.digest(case),
            'controllerHash': case['runtimeControllerHash'], 'commonHash': case['commonHash'],
            'continuationProofHash': c.digest(native['stage18ContinuationProof']), 'humanControlPath': ctl},
        'EXACT_STAGE18_NEW_SCOPE_AND_IMMUTABLE_PREFIX_REQUIRED')
    a.validate_action_review(review)
    if os.path.lexists(target / 'recovery.json'):
        imported = common.verify_imported_prefix(case, p, old_row, read(snapshot, target / 'recovery.json'))
        fence = read(snapshot, target.parent / ('ingestion-rollout-continuation-' + p['logicalOperationRef'] + '.claim.json'))
        c.require(fence == {'schema': SCHEMA, 'caseHash': c.digest(case), 'contextPath': str(target),
            'predecessorJournalHash': p['predecessorJournalHash'], 'authorityHash': imported['authorityHash'],
            'reviewHash': c.digest(review), 'budgetReset': False, 'automaticReplayAllowed': False}
            and imported['scopeHash'] == c.digest(c.scope(native)), 'EXACT_STAGE18_GLOBAL_IMPORT_FENCE_REQUIRED')
    return target, journal, row, review, h, p, old_row


def human_for_execution(entry, case, snapshot, common):
    # Execution uses the existing current read-only profile; the930s margin is
    # required before issuance, not before each of the ten residual stages.
    claim = read(snapshot, common.root(case) / 'stage18-human-window.claim.json')
    ctl = Path(claim['controlPath']); profile = read(snapshot, ctl / 'human-read-profile.json')
    c = entry.c; config = read(snapshot, ctl / 'control.json')
    c.require(claim['caseHash'] == c.digest(case)
        and claim['budgetDecisionHash'] == case['budgetReceipt']['decisionHash']
        and config['case'] == case and config['review']['operationBinding']['stage18CaseHash'] == c.digest(case)
        and claim['reviewHash'] == c.digest(config['review'])
        and claim['decisionHash'] == c.digest(config['decision'])
        and profile['governedWindowReceiptHash'] == c.digest({'review': config['review'], 'decision': config['decision']})
        and profile['selection'] == config['selection']
        and profile['expectedBinding'] == read(snapshot, ctl / 'binding.json'),
        'EXACT_CURRENT_STAGE18_HUMAN_CONTROL_REQUIRED')
    return entry.authority.human_reader.open_existing(profile), profile, str(ctl)


def approve(entry, case, snapshot, budget, common, loaded):
    target, journal, row, review, h, p, old_row = loaded; a, c = entry.authority, entry.c
    c.require(row['state'] == 'REVIEW_READY', 'STAGE18_ISSUANCE_ALREADY_CONSUMED_NO_REPLAY')
    c.require(h._read()['accessExpiresAt'] > time.time() + 930, 'CURRENT_STAGE18_HUMAN_TOKEN_MARGIN930_REQUIRED_NO_REFRESH')
    a.verify_closure(review['sourceClosure']); a.current_issuer(review['issuerProfile'], int(time.time()) + 900)
    decision = a.terminal_consent(review,
        'Continuazione infrastrutturale distinta dal rollout scaduto: massimo 900 secondi.\n'
        'Importo i 18 stadi APPLIED e tutti i contatori senza rieseguirli.\n'
        'Solo i 10 stadi residui: trasporto Gateway, due PUT route, verifiche e ripristino restart.\n'
        'Nessuna nuova chiave, immagine, sostituzione container, migrazione SQL o replay Owner/pubblicazione.\n'
        'Un comando per stadio; HUMAN/Owner/DB/readiness/generazioni restano obbligatori.\n'
        'Nessuna approvazione THS, attivazione fonte/job o pubblicazione profilo client.\n'
        'Revisione privata: ' + str(target / 'review.json'))
    # Recheck parent/grant after terminal input. Never hold shared locks while waiting.
    common.retained(case, snapshot, budget)
    update(journal, state='ISSUING', decisionHash=c.digest(decision))
    a.issue_action(review, decision, h, c.digest(decision))
    raw = snapshot['private_read'](str(target / 'human.json'))
    update(journal, state='ISSUED', mandateHash=hashlib.sha256(raw).hexdigest(), runtimeAuthorityIssued=True)
    return {'status': 'STAGE18_AUTHORITY_ISSUED_EXPLICIT_IMPORT_REQUIRED', 'complete': False,
        'contextPath': str(target), 'runtimeAuthorityIssued': True, 'runtimeEffectsDispatched': 0, 'oauthRequests': 0}


def import_prefix(entry, case, snapshot, budget, common, loaded, action, *, fault=lambda _: None):
    target, journal, row, review, h, p, old_row = loaded; c = entry.c
    c.require(row['state'] == 'ISSUED', 'STAGE18_IMPORT_ALREADY_CONSUMED_RECONCILE_ONLY')
    action.guard(c.AUTHORITY_KEY, c.scope(review['executionReview']))
    c.require(h.current() == review['authenticatedHuman'], 'SAME_CURRENT_STAGE18_HUMAN_REQUIRED')
    wall, mono = time.time(), time.monotonic(); expiry = json.loads(action.raw)['expiresAt']
    record = common.imported_record(case, p, old_row, c.digest(c.scope(review['executionReview'])),
        action.authority_hash, expiry, wall=wall, mono=mono, boot=boot_id())
    # Fence the original logical operation across every alias/context, before
    # writing the new journal. An ambiguous/partial import can never restart.
    with entry.authority.protected_directory(target.parent) as fd:
        c.require(entry.authority.publish(fd, 'ingestion-rollout-continuation-' + p['logicalOperationRef'] + '.claim.json',
            c.encoded({'schema': SCHEMA, 'caseHash': c.digest(case), 'contextPath': str(target),
                'predecessorJournalHash': p['predecessorJournalHash'], 'authorityHash': action.authority_hash,
                'reviewHash': c.digest(review), 'budgetReset': False, 'automaticReplayAllowed': False})),
            'STAGE18_LOGICAL_CONTINUATION_ALREADY_CLAIMED_NO_REIMPORT')
    fault('AFTER_IMPORT_CLAIM')
    common.retained(case, snapshot, budget)
    update(journal, state='IMPORTING')
    entry.Journal(target).initialize(record); fault('AFTER_IMPORTED_JOURNAL')
    update(journal, state='INITIALIZED')
    return {'status': 'STAGE18_PREFIX_IMPORTED_NO_RUNTIME_EFFECTS', 'complete': False,
        'contextPath': str(target), 'nextStage': 18, 'appliedStageCount': 18,
        'retainedReadAttempts': record['readAttempts'], 'runtimeEffectsDispatched': 0,
        'runtimeAuthorityIssued': False, 'oauthRequests': 0}


def execute(entry, manifest, case, snapshot, budget, common, mode):
    c = entry.c
    c.require(mode in ('preflight', 'review', 'approve', 'import-prefix', 'step', 'reconcile', 'status'),
        'ONE_EXPLICIT_STAGE18_RUNTIME_MODE_REQUIRED')
    target = common.context(case); CHECKPOINT.update(phase=mode.upper(), contextPath=str(target))
    if mode == 'preflight':
        preflight(entry, case, snapshot, budget, common)
        result = {'status': 'STAGE18_RUNTIME_PREFLIGHT_NO_AUTHORITY', 'complete': True,
            'readOnly': True, 'humanCredentialJournalsRead': 0, 'bearerFilesOpened': 0,
            'privateKeysRead': 0, 'runtimeAuthorityIssued': False, 'oauthRequests': 0}
    elif mode == 'review': result = prepare_review(entry, manifest, case, snapshot, budget, common)
    elif mode == 'status':
        common.retained(case, snapshot, budget)
        row = read(snapshot, target / 'operator-control/recovery.json')
        c.require(row['schema'] == SCHEMA and row['caseHash'] == c.digest(case), 'EXACT_STAGE18_STATUS_CONTROL_REQUIRED')
        result = {'status': 'STAGE18_RETAINED_METADATA_ONLY', 'state': row['state'], 'complete': row['complete'],
            'contextPath': str(target), 'readOnly': True, 'humanCredentialJournalsRead': 0,
            'runtimeAuthorityIssued': False, 'oauthRequests': 0}
        if os.path.lexists(target / 'recovery.json'):
            native = read(snapshot, target / 'recovery.json')
            result.update(nextStage=native['nextStage'], readAttempts=native['readAttempts'],
                appliedStageCount=native['nextStage'], pendingStageClaim=len(native['effects']) > native['nextStage'])
    else:
        # The invocation fence protects the whole explicit operator call. Short
        # CAS locks are released before any native network/DB operation.
        with entry.Journal(target / 'operator-control').invocation():
            loaded = load(entry, manifest, case, snapshot, budget, common)
            target, journal, row, review, h, p, old_row = loaded
            if mode == 'approve': result = approve(entry, case, snapshot, budget, common, loaded)
            else:
                decision = read(snapshot, target / 'decision.json')
                action = entry.load_action(review, decision, h, row['decisionHash'], row['mandateHash'])
                if mode == 'import-prefix': result = import_prefix(entry, case, snapshot, budget, common, loaded, action)
                else:
                    allowed = ('INITIALIZED', 'RUNNING') if mode == 'step' else ('INITIALIZED', 'RUNNING', 'DISPATCHING', 'RECONCILE_REQUIRED')
                    c.require(row['state'] in allowed, 'STAGE18_EXPLICIT_STATE_RECONCILIATION_REQUIRED')
                    packet = read(snapshot, review['executionReview']['packetBinding']['path'])
                    native = entry.Journal(target).read()
                    if mode == 'reconcile' and len(native['effects']) == native['nextStage']:
                        c.require(native['readState'] in ('IDLE', 'RETRY_WAIT'), 'STAGE18_INTERRUPTED_READ_REQUIRES_RECONCILIATION')
                        update(journal, state='RUNNING')
                        result = {'status': 'STAGE18_CONTROL_METADATA_RECONCILED_NO_NATIVE_DISPATCH', 'complete': False,
                            'nextStage': native['nextStage'], 'runtimeEffectsDispatched': 0, 'runtimeAuthorityIssued': False}
                    else:
                        update(journal, state='DISPATCHING', lastExplicitMode=mode)
                        try: result = entry.execute(mode, review, packet, h, action, manifest)
                        except BaseException:
                            update(journal, state='RECONCILE_REQUIRED'); raise
                        update(journal, state='COMPLETE' if result.get('complete') else 'RUNNING', complete=result.get('complete', False))
                        result = {'status': 'STAGE18_EXPLICIT_NATIVE_INVOCATION_COMPLETED', 'contextPath': str(target), **result}
    return {'schema': 'ouf.ingestion-rollout-stage18-result.v1', 'completedTechnicalPhases': 8,
        'functionalMilestonesProven': 4, 'notReleaseAcceptance': True, 'budgetReset': False,
        'automaticReplayAllowed': False, 'newLoginPerformed': False, 'refreshPerformed': False, **result}
