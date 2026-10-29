"""Explicit operator entry for the sealed, finite Registry recovery capsule.

The private preparation and complete review are deterministic for this exact
case, closure and boot. No command discovers a manager, resets a consumed
attempt, or accepts an arbitrary execution path. Public receipts omit contexts,
addresses, credentials and native error bodies.
"""
import json
import os
from pathlib import Path

from .core import require, digest, encoded, hashed
from . import bootstrap, postboot_prepare, postboot_authority, postboot_controller
from .postboot_scopes import compile_scopes
from file_only_profile import FileOnlyProfile

SCHEMA = 'ouf.semantic-registry-postboot-recovery-case.v1'
MODES = frozenset(('prepare', 'review', 'issue', 'install', 'bootstrap', 'owner', 'continue', 'status'))
SIGNED_MODES = frozenset(('issue', 'install', 'bootstrap', 'owner', 'continue'))


def emit(value):
    print(encoded(value).decode(), flush=True)


def public_preparation(value):
    proof = value['preparationProof']
    prior = proof.get('priorPreparationReconciliation')
    counts = prior['priorAttemptCounts'] if prior is not None else {'engineGets': 0, 'adminGets': 0, 'frozenConfigurationGets': 0}
    return {'schema': 'ouf.semantic-registry-postboot-preparation-result.v1',
        'status': 'CURRENT_POSTBOOT_INPUTS_PREPARED', 'complete': True,
        'privatePreparationPath': value['privatePreparationPath'],
        'privatePreparationHash': value['privatePreparationHash'],
        'sourceClosureHash': proof['sourceClosureHash'],
        'engineGets': proof['engineGets'], 'adminGets': proof['adminGets'],
        'frozenConfigurationGets': proof['frozenConfigurationGets'],
        'tlsHandshakes': proof.get('tlsHandshakes', 0),
        'originalTlsIdentityEstablished': proof.get('originalTlsObservation') is not None,
        'priorPreparationReconciled': prior is not None, 'priorPreparationAttemptCounts': counts,
        'cumulativePreparationAttemptCounts': {name: counts[name] + proof[name] for name in counts},
        'originalServiceBearerUsed': proof['originalServiceBearerUsed'],
        'ownerCredentialBytesRead': False, 'credentialValuesPrinted': False,
        'addressesPrinted': False, 'databaseCalls': 0, 'oauthRequests': 0,
        'runtimeEffectsDispatched': 0, 'runtimeAuthorityIssued': False,
        'targetApplyAuthorized': False, 'automaticReplayAllowed': False,
        'budgetReset': False, 'originalSemanticGetSucceeded': False,
        'serviceReadinessEstablished': False, 'releaseAcceptance': False}


def review_binding(root):
    files = postboot_prepare.Files()
    review, profile = files.json(str(root / 'review.json'), maximum=8388608)
    require(profile['metadata'][3] == 0 and profile['metadata'][4] & 0o777 == 0o600,
            'PRIVATE_POSTBOOT_REVIEW_CUSTODY_REQUIRED')
    return review, {key: profile[key] for key in ('path', 'sha256')}


def status(root, prepared):
    # Status is only a local artifact inventory, never live service health or
    # evidence that an old authority/admission remains valid.
    result = {'schema': 'ouf.semantic-registry-postboot-artifact-status.v1',
        'status': 'PREPARATION_PRESENT_NO_RUNTIME_OBSERVATION',
        'privatePreparationHash': prepared['privatePreparationHash'],
        'reviewPresent': False, 'issuanceReceiptPresent': False,
        'currentOwnerAdmissionProven': False, 'serviceReadinessEstablished': False,
        'engineGets': 0, 'oauthRequests': 0, 'runtimeEffectsDispatched': 0,
        'automaticReplayAllowed': False, 'budgetReset': False, 'releaseAcceptance': False}
    try:
        _, binding = review_binding(root)
    except FileNotFoundError:
        return result
    review = postboot_authority.read_review(root, binding)
    result.update(reviewPresent=True, reviewHash=digest(review))
    try:
        receipt, _ = postboot_prepare.Files().json(str(root / 'authority' / 'receipt.json'), maximum=131072)
    except FileNotFoundError:
        return result
    require(receipt.get('schema') == 'ouf.semantic-registry-postboot-issued-authority.v1'
            and receipt.get('reviewHash') == binding['sha256'], 'EXACT_POSTBOOT_ISSUANCE_RECEIPT_REQUIRED')
    result['issuanceReceiptPresent'] = True
    return result


def execute(case, manifest, sources, argv):
    require(os.geteuid() == os.getegid() == 0, 'ROOT_POSTBOOT_ENTRY_REQUIRED')
    if type(case) is dict and 'resumption' in case:
        from . import resumption_entry
        return resumption_entry.execute(case, manifest, sources, argv)
    require(type(case) is dict and set(case) == {'schema', 'preparation'} and case['schema'] == SCHEMA,
            'EXACT_POSTBOOT_OPERATOR_CASE_REQUIRED')
    require(type(argv) is list and argv and all(type(arg) is str for arg in argv)
            and argv[0] in MODES, 'ONE_EXPLICIT_POSTBOOT_MODE_REQUIRED')
    mode = argv[0]
    require(len(argv) == (2 if mode in SIGNED_MODES else 1)
            and (mode not in SIGNED_MODES or hashed(argv[1])), 'EXACT_POSTBOOT_MODE_ARGUMENTS_REQUIRED')
    preparation = case['preparation']
    root = postboot_prepare.prepared_root(preparation, manifest)
    if mode == 'prepare':
        return public_preparation(postboot_prepare.prepare(preparation, manifest, sources))
    prepared = postboot_prepare.read_prepared(preparation, manifest)
    require(Path(prepared['privatePreparationPath']).parent == root,
            'SAME_DETERMINISTIC_POSTBOOT_PREPARATION_REQUIRED')
    if mode == 'status':
        return status(root, prepared)
    context, owner = prepared['nativeContext'], prepared['ownerContext']
    if mode == 'review':
        registry = prepared['registryInputs']
        profile = FileOnlyProfile(registry['creationRequest'], registry['configtree'])
        scopes = compile_scopes(context, owner, registry, profile, owner['recovery']['bootId'])
        review = postboot_authority.compile_review(context, owner, prepared['authorityInputs'], manifest, scopes)
        binding = postboot_authority.publish_review(root, review)
        return {'schema': 'ouf.semantic-registry-postboot-review-result.v1',
            'status': 'COMPLETE_PRIVATE_POSTBOOT_REVIEW_PREPARED',
            'privateReviewPath': binding['path'], 'reviewHash': binding['sha256'],
            'sourceClosureHash': digest(manifest), 'signedScopeCount': len(scopes),
            'proposedMaximumNewServiceGrantAttempts': owner['budget']['maximumGrantAttempts'],
            'retainedControlledGrantAttempts': scopes['semanticRegistryPostbootOwner']['predecessorGrantAttempts'],
            'proposedMaximumSeconds': owner['budget']['maximumSeconds'],
            'runtimeAuthorityIssued': False, 'runtimeEffectsDispatched': 0,
            'targetApplyAuthorized': False, 'automaticReplayAllowed': False,
            'budgetReset': False, 'continuousServiceRenewalEstablished': False, 'releaseAcceptance': False}
    _, binding = review_binding(root)
    require(argv[1] == binding['sha256'], 'EXPLICIT_PUBLISHED_POSTBOOT_REVIEW_HASH_REQUIRED')
    if mode == 'issue':
        return postboot_authority.issue(root, binding, argv[1])
    authority, raw, verifier, signer = postboot_authority.load_runtime(root, binding)
    if mode == 'install':
        receipt = bootstrap.install(context, authority, raw)
        return {'schema': 'ouf.semantic-registry-postboot-installation-result.v1',
            'status': 'CURRENT_BOOT_RECOVERY_LEDGERS_INSTALLED', 'installationHash': digest(receipt),
            'expiresUnix': receipt['expiresUnix'], 'runtimeEffectsDispatched': 0, 'oauthRequests': 0,
            'automaticReplayAllowed': False, 'budgetReset': False, 'releaseAcceptance': False}
    if mode == 'bootstrap':
        return postboot_controller.bootstrap_gate(context, authority, raw, emit)
    if mode == 'owner':
        return postboot_controller.install_owner(context, owner, authority, raw)
    require(mode == 'continue', 'CLOSED_POSTBOOT_DISPATCH_REQUIRED')
    return postboot_controller.continue_recovery(context, owner, authority, raw, verifier, signer, emit)
