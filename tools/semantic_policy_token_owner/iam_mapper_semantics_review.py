"""Review known Keycloak mapper effects from exact retained metadata only.

Source semantics pinned to Keycloak 26.0.8, not proof of target implementation,
bearer, credential, peer, accounting or current runtime authority.
"""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import iam_binding_candidate as binding

EXTRA_PROVIDERS = frozenset({'oidc-acr-mapper', 'oidc-allowed-origins-mapper',
                           'oidc-usersessionmodel-note-mapper', 'oidc-sub-mapper'})

def standard_client_id(mapper):
    cfg = mapper['config']
    return (mapper['protocolMapper'] == 'oidc-usersessionmodel-note-mapper'
            and cfg.get('claim.name') == 'client_id'
            and cfg.get('user.session.note') in {'client_id', 'clientId'}
            and cfg.get('jsonType.label') == 'String'
            and cfg.get('access.token.claim') == 'true'
            and cfg.get('introspection.token.claim') == 'true'
            and cfg.get('multivalued', 'false') == 'false')

def review(snapshot, snapshot_hash, reference):
    candidate, public = binding.compile_binding(snapshot, snapshot_hash, reference)
    sources = [snapshot['client']] + snapshot['defaultScopes'] + [s for s in snapshot['optionalScopes']
                if s['name'] in snapshot['requestedScopes']]
    mappers = [m for source in sources for m in source.get('protocolMappers', [])]
    complete = not public['uninterpretableMapperCount']
    valid = [m for m in mappers if not binding.mapper_shape(m)]
    known = complete and all(m['protocolMapper'] in binding.SAFE_MAPPERS | EXTRA_PROVIDERS for m in valid)
    reasons = set(candidate['reviewReasons'])
    if known: reasons.discard('UNSUPPORTED_EFFECTIVE_MAPPER')
    reserved = [m for m in valid if m['config'].get('claim.name', '').split('.')[0]
                in {'iss', 'client_id', 'azp', 'scope', 'exp', 'iat'}]
    client_notes = [m for m in valid if m['config'].get('claim.name', '').split('.')[0] == 'client_id']
    client_ok = complete and bool(client_notes) and all(standard_client_id(m) for m in client_notes)
    if complete and reserved and all(standard_client_id(m) for m in reserved):
        reasons.discard('RESERVED_CLAIM_MAPPER_REQUIRES_REVIEW')
    subjects = [m for m in valid if m['protocolMapper'] == 'oidc-sub-mapper']
    subject_ok = complete and bool(subjects) and all(m['config'].get('access.token.claim') == 'true'
                  and m['config'].get('introspection.token.claim') == 'true' for m in subjects)
    if subjects and not subject_ok: reasons.add('STANDARD_SUBJECT_MAPPING_NOT_EXPLICIT')
    facts = {'knownProviderEffectsReviewed': known,
             'serviceAccountClientIdMapperMatchesRegisteredClientSemantics': client_ok,
             'standardSubjectMapperObserved': bool(subjects),
             'standardSubjectMapperMatchesServiceAccountSemantics': subject_ok,
             'reservedClaimOverrideRequiresReview': 'RESERVED_CLAIM_MAPPER_REQUIRES_REVIEW' in reasons,
             'targetProviderImplementationProven': False,
             'sourceSemanticsProfile': 'keycloak-26.0.8-retained-mapper-effects.v1'}
    candidate.update(schema='ouf.policy-token-iam-binding-candidate.v3',
        parentBindingCandidateHash=binding.sha(binding.encoded(candidate)),
        mapperEffectsReview=facts, reviewReasons=sorted(reasons))
    public.update(facts, reviewReasons=sorted(reasons), staticMapperConstraintsComplete=not reasons)
    return candidate, public

def prepare(path, expected_hash, reference, report):
    path = Path(path)
    binding.require(path.parent == binding.PARENT and re.fullmatch(r'policy-token-iam-metadata-[0-9a-f]{32}\.private\.json', path.name)
                    and re.fullmatch('[0-9a-f]{64}', expected_hash), 'EXACT_RETAINED_SNAPSHOT_REFERENCE_REQUIRED')
    with binding.protected_parent() as directory:
        raw = binding.read_member(directory, path.name)
        binding.require(binding.sha(raw) == expected_hash, 'RETAINED_SNAPSHOT_HASH_MISMATCH')
        report['phase'] = 'MAPPER_EFFECTS_REVIEW'
        candidate, public = review(binding.decode(raw), expected_hash, reference)
        binding.require(binding.read_member(directory, path.name) == raw, 'RETAINED_SNAPSHOT_CHANGED')
        body = binding.encoded(candidate)
        name = 'policy-token-iam-binding-' + binding.sha(body) + '.private.json'
        report.update(phase='PRIVATE_REVIEW_CANDIDATE_PUBLICATION', candidatePath=str(binding.PARENT / name))
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        except FileExistsError:
            binding.require(binding.read_member(directory, name) == body, 'CANDIDATE_RECONCILIATION_REQUIRED')
            report['newCandidatePublished'] = False
        else:
            report.update(privateEvidenceWrites=1, newCandidatePublished=True)
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(os.dup(fd), 'wb') as stream:
                    stream.write(body); stream.flush(); os.fsync(stream.fileno())
                os.fsync(directory)
                binding.require(binding.identity(os.fstat(fd)) == binding.identity(os.stat(name, dir_fd=directory, follow_symlinks=False)), 'CANDIDATE_MEMBER_CHANGED')
            finally: os.close(fd)
        binding.require(binding.read_member(directory, name) == body, 'CANDIDATE_RECONCILIATION_REQUIRED')
        report.update(status='MAPPER_EFFECTS_REVIEWED_NOT_ACCEPTED', phase='REVIEWED_NOT_ACCEPTED',
                      snapshotHash=expected_hash, candidateHash=binding.sha(body), **public)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--snapshot', required=True); parser.add_argument('--snapshot-sha256', required=True)
    parser.add_argument('--issuer', required=True); parser.add_argument('--tenant', required=True)
    parser.add_argument('--audience', required=True)
    args = parser.parse_args()
    report = {'schema': 'ouf.policy-token-iam-mapper-semantics-review-receipt.v1', 'phase': 'RETAINED_SNAPSHOT_READ',
        'status': 'BLOCKED', 'privateEvidenceWrites': 0, 'credentialFilesRead': 0, 'mountedTokenFilesRead': 0,
        'providerCalls': 0, 'tokenGrantRequests': 0, 'iamMutations': 0, 'serviceMutations': 0,
        'runtimeAuthorityIssued': False, 'productionApplyReady': False, 'baselineRefreshed': False,
        'budgetReset': False, 'r12Touched': False, 'notReleaseAcceptance': True}
    try:
        def timeout(*_): raise binding.CandidateDenied('REVIEW_DEADLINE')
        signal.signal(signal.SIGALRM, timeout); signal.alarm(30)
        prepare(args.snapshot, args.snapshot_sha256, {'issuer': args.issuer, 'tenant': args.tenant,
                'audience': args.audience, 'actor': 'SERVICE'}, report)
        code = 0
    except Exception as error:
        report['reason'] = str(error) if type(error) is binding.CandidateDenied else type(error).__name__
        if isinstance(error, OSError): report['errno'] = error.errno
        report['evidencePublicationMayBePartial'] = report['phase'] == 'PRIVATE_REVIEW_CANDIDATE_PUBLICATION'
        code = 1
    finally: signal.alarm(0)
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))
    return code

if __name__ == '__main__': raise SystemExit(main())
