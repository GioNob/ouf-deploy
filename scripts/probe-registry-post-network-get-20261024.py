#!/usr/bin/env python3
"""One fresh original-caller GET after the completed signed network repair.

Read-only runtime observation; does not reopen old diagnostic or native claims.
The embedded transport definitions are byte-pinned, never their old entry point.
"""
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import types

LEGACY_SOURCE_HASH = 'e36d39186023298177adf5aaa85bc4b0db289d19f8c9e0d40af0671c16362d4e'
LEGACY_PACKED = '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'
REPAIR = '/etc/ouf/deploy-snapshots/semantic-network-repair-dbd7bccc32904974/repair.py'
REPAIR_HASH = 'dbd7bccc32904974e0b9e85491c9dc3a5100c9c51d550e0951e773523fcbd808'
NETWORK_REVIEW = 'ebbac33ca55a0b8625eebeafe29d3ca8750c705cc20bc5f0ffd44050082021c3'
NETWORK_AUTHORITY = 'e33353a3b74777b5233c3b684b5bdef2aafa20d97a26bf725f3aa1a7cee04e3f'
INSTALL = '/etc/ouf/deploy-snapshots/semantic-registry-operational-7cb59501000058b5dc5030adf8624c5b38567de0c8bfeb21dd49435644ea3da2'
NETWORK_ROOT = INSTALL + '/network-projection-repair-v1'
SCOPE_ROOT = NETWORK_ROOT + '/post-network-original-get-v1'
SCHEMA = 'ouf.registry-post-network-original-get.v1'
D = None


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def legacy():
    packed = base64.b64decode(LEGACY_PACKED, validate=True)
    # The compressed input is an immutable part of this delivered source.
    raw = gzip.decompress(packed)
    require(len(raw) == 28741 and hashlib.sha256(raw).hexdigest() == LEGACY_SOURCE_HASH,
            'EXACT_RETAINED_CALLER_TRANSPORT_SOURCE_REQUIRED')
    module = types.ModuleType('ouf_retained_caller_transport')
    exec(compile(raw, '<pinned-caller-diagnostic-definitions>', 'exec'), module.__dict__)
    return module


def verify_completed(r, root):
    """Verify completed facts with current public authorities, not expired effect authority."""
    from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
    review = r.json_at(root / 'review.json', NETWORK_REVIEW)
    r.source_check(review)
    c = r.json_at(INSTALL + '/configuration.json', r.CONFIG_HASH)
    require(c['destinations']['installationRoot'] == INSTALL,
            'EXACT_REPAIRED_OPERATIONAL_INSTALLATION_REQUIRED')
    authority = r.read(root / 'authority/authority.json', 131072, NETWORK_AUTHORITY)
    value = json.loads(authority)
    human = r.json_at(root / 'authority/human.json')
    ctx = review['verification']['context']
    require(value == {'schema': r.AUTHORITY_SCHEMA, 'scope': r.scope(review),
            'issuedAt': human['issuedAt'], 'expiresAt': human['expiresAt'],
            'installationRef': ctx['installationRef'], 'entityRef': ctx['entityRef'],
            'automaticReplayAllowed': False, 'budgetReset': False, 'releaseAcceptance': False}
            and r.encoded(value) == authority
            and human == {'schema': r.HUMAN_SCHEMA, 'reviewHash': NETWORK_REVIEW,
                'authorityHash': NETWORK_AUTHORITY, 'decision': r.DECISION, 'state': 'ACTIVE',
                'issuedAt': value['issuedAt'], 'expiresAt': value['expiresAt']}
            and type(value['issuedAt']) is int and type(value['expiresAt']) is int
            and value['expiresAt'] - value['issuedAt'] == 900
            and value['issuedAt'] <= time.time(),
            'EXACT_COMPLETED_NETWORK_AUTHORITY_FACT_REQUIRED')
    # No SignedProjection.check()/issue()/apply: the old 900s window is not renewed.
    v = review['verification']
    verifier = DetachedAuthenticator(v['trustPolicy'], str(root / 'authority'), v['openssl'])
    for role, key in (('DEPLOYMENT_INTENT', 'intentIssuerRef'),
                      ('FINAL_DEPLOYMENT_APPROVAL', 'approvalIssuerRef')):
        require(verifier(authority, role, ctx[key], ctx['installationRef'], ctx['entityRef']) is True,
                'CURRENT_VERIFICATION_OF_COMPLETED_NETWORK_SIGNATURE_REQUIRED')
    receipt = r.json_at(root / 'receipt.json')
    require(receipt.get('schema') == 'ouf.registry-network-projection-receipt.v1'
            and receipt['reviewHash'] == NETWORK_REVIEW and receipt['authorityHash'] == NETWORK_AUTHORITY
            and receipt['configurationHash'] == r.CONFIG_HASH
            and receipt['unitBaseHash'] == review['unitHash']
            and receipt['providerPinHash'] == digest(review['providerPin'])
            and receipt['effectiveAllowlist'] == review['projectedAllowlist']
            and receipt['persistentProjectionInstalled'] is True
            and receipt['workerRestarted'] is False and receipt['normalGrantMandateChanged'] is False
            and type(receipt['managerMutationAttempts']) is int and receipt['managerMutationAttempts'] == 1
            and receipt['ownerLedgerWrites'] == 0 and receipt['automaticReplayAllowed'] is False
            and receipt['budgetReset'] is False and receipt['releaseAcceptance'] is False,
            'EXACT_COMPLETED_NETWORK_RECEIPT_REQUIRED')
    require(verifier(encoded(receipt), 'CREATION_ATTESTATION', ctx['attestorRef'],
                     ctx['installationRef'], ctx['entityRef']) is True,
            'CURRENT_VERIFICATION_OF_NETWORK_ATTESTATION_REQUIRED')
    fresh = r.json_at(root / 'fresh-origin-proof.json', receipt['freshOriginProofHash'])
    require(fresh['flow']['kernelOriginAuthenticated'] is True
            and fresh['flow']['reply']['source'] == review['candidate']['address']
            and fresh['flow']['reply']['sourcePort'] == review['candidate']['port'],
            'SIGNED_REPAIR_FLOW_RECEIPT_REQUIRED')
    drop = receipt['dropInBinding']
    require(drop['path'].startswith('/etc/systemd/system.control/')
            and drop['path'].endswith('/50-IPAddressAllow.conf'),
            'PERSISTENT_NETWORK_RECEIPT_DROPIN_REQUIRED')
    r.read(drop['path'], 65536, drop['sha256'])
    result = r.json_at(root / 'result.json')
    require(result['status'] == 'NETWORK_PROJECTION_INSTALLED_OWNER_PUBLISHED'
            and result['complete'] is True and result['reviewHash'] == NETWORK_REVIEW
            and result['kernelNatPathProven'] is True and result['originalIamTlsAndDiscoveryProven'] is True
            and result['projectedWorkerDiscoveryStatus'] == 200
            and result['workerGenerationUnchanged'] is True and result['workerRestartedByRepair'] is False
            and result['managerRestarts'] == 0 and result['managerMutationAttempts'] == 1
            and result['controlledCumulativeGrantAttempts'] == 416
            and result['newOperationalGrantAttempts'] == 95 and result['publications'] == 1,
            'EXACT_REPORTED_COMPLETED_NETWORK_RESULT_REQUIRED')
    return review, c, receipt, result


def owner_progress(r, c, baseline=None):
    row = r.ledger(c)
    require(type(row['publications']) is int and row['publications'] >= 1
            and row['cumulativeAttempts'] >= 416 and row['state'] not in ('BLOCKED', 'REVOKED')
            and type(row['tokenExpiresWall']) in (int, float) and row['tokenExpiresWall'] > time.time(),
            'CURRENT_NORMAL_OWNER_PUBLISHED_WINDOW_REQUIRED')
    if baseline is not None:
        require(row['cumulativeAttempts'] >= baseline['cumulativeAttempts']
                and row['publications'] >= baseline['publications'] and row['version'] >= baseline['version'],
                'NORMAL_OWNER_PROGRESS_REGRESSION')
    return row


def manager(r, capture, review, receipt):
    program = review['executables']['systemctl']
    binding = {'path': program['path'], 'resolved': str(Path(program['path']).resolve()),
               'sha256': program['sha256']}
    capture.DEADLINE = time.monotonic() + 15
    actual = capture.unit_properties(binding, review['unitName'])
    require(all(actual[key] == review['originalUnitProperties'][key] for key in
            ('ActiveState', 'MainPID', 'NRestarts', 'ControlGroup', 'RootDirectory', 'IPAddressDeny', 'FragmentPath'))
            and actual['ActiveState'] == 'active'
            and receipt['dropInBinding']['path'] in actual.get('DropInPaths', '').split(),
            'SAME_REPAIRED_OWNER_MANAGER_GENERATION_REQUIRED')
    networks = capture.network_list(actual['IPAddressAllow'])
    require(networks is not None and sorted(str(n) for n in networks) == review['projectedAllowlist'],
            'CURRENT_SIGNED_NETWORK_PROJECTION_REQUIRED')
    return actual


def new_claim(r, d, bindings):
    # Stable fresh purpose tied to completed signed repair, never source/hash/random path.
    root = r.exclusive_root(NETWORK_ROOT, 'post-network-original-get-v1')
    d.publish_evidence(root / 'claim.json', {'schema': 'ouf.post-network-original-get-claim.v1',
        'networkReviewHash': NETWORK_REVIEW, 'networkAuthorityHash': NETWORK_AUTHORITY,
        **bindings, 'legacyTransportSourceHash': LEGACY_SOURCE_HASH,
        'maximumHttpGetAttempts': 1, 'maximumEngineGets': 4, 'maximumOAuthRequests': 0,
        'credentialSource': 'CURRENT_CONFIGURED_CALLER_MOUNT', 'referenceOrdinal': 0,
        'oldDiagnosticClaimsReopened': False, 'nativeJournalWritesAllowed': False,
        'ownerLedgerWritesAllowed': False, 'automaticReplayAllowed': False, 'budgetReset': False})
    return root


def finish(result, before, after, bindings):
    require(result.get('complete') is True and result['httpGetAttempts'] == 1
            and result['engineGets'] == 4 and result['tlsHostnameChainAndPeerPinVerified'] is True
            and result['mountedTokenMetadataMatchesCurrentHostSource'] is True
            and result['callerConfigurationAndGenerationMatchReviewed'] is True
            and result['registryRunning'] is True and result['registryPaused'] is False
            and result['registryRestarting'] is False and result['registryDead'] is False
            and result['registryImageMatchesReviewed'] is True
            and result['registrySameDurableProcessGeneration'] is True
            and result['registryLiveNetworkEndpointCount'] == 1,
            'BOUNDED_ORIGINAL_CALLER_CURRENT_RESULT_REQUIRED')
    proven = (result['httpStatus'] == 200 and result['exactActiveReferenceMatched'] is True
              and result['allConfiguredReferencesProven'] is True)
    result = dict(result)
    result.update(schema=SCHEMA, status='POST_NETWORK_ORIGINAL_CALLER_GET_OBSERVED',
        networkReviewHash=NETWORK_REVIEW, networkAuthorityHash=NETWORK_AUTHORITY, **bindings,
        originalRequestResource200Proven=proven, originalSemanticGetSucceeded=proven,
        applicationReadinessProven=False, serviceReadinessEstablished=False,
        ownerCumulativeAttemptsBefore=before['cumulativeAttempts'],
        ownerCumulativeAttemptsAfter=after['cumulativeAttempts'],
        ownerPublicationsBefore=before['publications'], ownerPublicationsAfter=after['publications'],
        normalOwnerCurrentWindowPositive=True, oldDiagnosticClaimsReopened=False,
        nativeRecoveryJournalCompleted=False, nativeRecoveryCountersUnchanged=True,
        ownerLedgerWrites=0, oauthGrantRequests=0, managerMutations=0,
        permanentRenewalProven=False, runtimeAuthorityIssued=False,
        releaseAcceptance=False, automaticReplayAllowed=False, budgetReset=False)
    return result


def execute():
    global D
    require(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site
            and sys.dont_write_bytecode and len(sys.argv) == 1,
            'ONE_ISOLATED_ROOT_POST_NETWORK_GET_REQUIRED')
    d = D = legacy()
    raw = d.Reader().raw(REPAIR, 131072, REPAIR_HASH)
    r = types.ModuleType('ouf_completed_network_repair_definitions')
    exec(compile(raw, REPAIR, 'exec'), r.__dict__)
    old_review = r.json_at(r.REVIEW, r.REVIEW_HASH)
    r.rebind_python(old_review)
    # Load the sealed closure exactly once. Its loader deliberately refuses an
    # application module already present in sys.modules.
    native = d.sealed_native_modules(r.read(r.CAPSULE, 2097152, r.CAPSULE_HASH))
    def same_preloaded(raw):
        require(hashlib.sha256(raw).hexdigest() == r.CAPSULE_HASH,
                'EXACT_ALREADY_VERIFIED_NATIVE_CLOSURE_REQUIRED')
        return native
    d.sealed_native_modules = same_preloaded
    from tools.semantic_registry_recovery_execution.postboot_authority import authority_metadata
    from tools.semantic_policy_token_owner.iam_owner_action import stdlib_binding
    retained_binding = old_review['proposal']['inputsBinding']
    retained = r.json_at(retained_binding['path'], retained_binding['sha256'])
    public = retained['review']['authorityInputs']
    authority_metadata(public)
    require(digest(stdlib_binding()) == public['stdlibHash'], 'RETAINED_INTERPRETER_STDLIB_CUSTODY_REQUIRED')
    root = Path(NETWORK_ROOT)
    review, c, receipt, completed = verify_completed(r, root)
    bindings = {'networkReceiptHash': digest(receipt), 'networkResultHash': digest(completed)}
    capture = r.helper(r.CAPTURE_HELPER, r.CAPTURE_HELPER_HASH, 'ouf_post_network_capture_dependencies')
    initial_manager = manager(r, capture, review, receipt)
    before = owner_progress(r, c)
    # Prove both diagnostic scopes already completed403; retain their bytes unchanged.
    previous = []
    for name in ('current-caller-get-v1', 'current-caller-403-attribution-v1'):
        path = Path(d.PREPARATION_ROOT) / name / 'result.json'
        value = r.json_at(path)
        require(value.get('complete') is True and value.get('httpStatus') == 403
                and value.get('httpGetAttempts') == 1, 'TWO_RETAINED_COMPLETED_DIAGNOSTIC_GETS_REQUIRED')
        previous.append((path, digest(value)))
    bindings['priorDiagnosticResultHashes'] = [h for _, h in previous]
    scope = new_claim(r, d, bindings)
    # The old inspect composition calls this fresh claim callback once, under the
    # original native invocation lock, before any Engine/HTTP access.
    called = []
    def claimed():
        require(not called, 'SINGLE_FRESH_POST_NETWORK_CLAIM_CALLBACK_REQUIRED')
        called.append(True)
        return scope
    d.claim_diagnostic = claimed
    result = d.inspect(d.Reader())
    require(called == [True], 'NEW_POST_NETWORK_SCOPE_MUST_BE_USED')
    r.source_check(review)
    require(r.json_at(root / 'review.json', NETWORK_REVIEW) == review
            and r.json_at(root / 'receipt.json', bindings['networkReceiptHash']) == receipt
            and r.json_at(root / 'result.json', bindings['networkResultHash']) == completed,
            'COMPLETED_NETWORK_REPAIR_FACTS_CHANGED_DURING_GET')
    r.read(receipt['dropInBinding']['path'], 65536, receipt['dropInBinding']['sha256'])
    require(manager(r, capture, review, receipt) == initial_manager,
            'REPAIRED_MANAGER_CHANGED_DURING_ORIGINAL_GET')
    after = owner_progress(r, c, before)
    for path, h in previous:
        r.json_at(path, h)
    result = finish(result, before, after, bindings)
    d.publish_evidence(scope / 'acceptance-result.json', result)
    return result


def main():
    try:
        result = execute()
    except Exception as error:
        reason = str(error) if type(error) is ValueError else ''
        if re.fullmatch('[A-Z][A-Z0-9_]{0,127}', reason) is None:
            reason = 'POST_NETWORK_GET_UNPROVEN_PRIVATE_DETAILS_REDACTED'
        attempted = D.REQUEST_ATTEMPTS if D is not None else 0
        result = {'schema': SCHEMA, 'status': 'STOP_RECONCILE', 'reasonCode': reason,
            'complete': False, 'diagnosticHttpGetAttempts': attempted,
            'diagnosticEngineGetAttempts': D.ENGINE_ATTEMPTS if D is not None else 0,
            'httpOutcomeMayBeUnrecorded': attempted > 0, 'runtimeAuthorityIssued': False,
            'ownerLedgerWrites': 0, 'managerMutations': 0, 'oauthGrantRequests': 0,
            'automaticReplayAllowed': False, 'budgetReset': False, 'releaseAcceptance': False}
    print(encoded(result).decode(), flush=True)
    return 0 if result['status'] == 'POST_NETWORK_ORIGINAL_CALLER_GET_OBSERVED' else 2


if __name__ == '__main__':
    raise SystemExit(main())
