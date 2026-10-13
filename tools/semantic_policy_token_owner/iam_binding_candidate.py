"""Compile a review-only claim binding from one exact retained IAM snapshot.

No IAM call, credential/token read, grant, runtime root creation, accounting
initialization or authority issuance. A metadata proposal is not token admission.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import urllib.parse

PARENT = Path('/etc/ouf/deploy-snapshots')
SAFE_MAPPERS = frozenset({
    'oidc-hardcoded-claim-mapper', 'oidc-audience-mapper',
    'oidc-audience-resolve-mapper', 'oidc-usermodel-property-mapper',
    'oidc-usermodel-attribute-mapper', 'oidc-usermodel-realm-role-mapper',
    'oidc-usermodel-client-role-mapper', 'oidc-full-name-mapper',
    'oidc-address-mapper', 'oidc-sha256-pairwise-sub-mapper',
})

class CandidateDenied(RuntimeError):
    pass

def require(ok, reason):
    if not ok:
        raise CandidateDenied(reason)

def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'DUPLICATE_SNAPSHOT_KEY')
        result[key] = value
    return result

def decode(raw):
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: require(False, 'NONFINITE_SNAPSHOT_VALUE'))

def identity(s):
    return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode,
            s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)

@contextmanager
def protected_parent():
    require(os.geteuid() == os.getegid() == 0 and PARENT.is_absolute()
            and '..' not in PARENT.parts and len(PARENT.parts) <= 32, 'ROOT_AND_EXACT_EVIDENCE_PARENT_REQUIRED')
    fds, bindings = [], []
    try:
        parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        fds.append(parent)
        for part in PARENT.parts[1:]:
            before = os.stat(part, dir_fd=parent, follow_symlinks=False)
            require(stat.S_ISDIR(before.st_mode) and before.st_uid == before.st_gid == 0
                    and not before.st_mode & 0o022, 'EVIDENCE_PARENT_CUSTODY_UNPROVEN')
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            fds.append(child)
            require(identity(before) == identity(os.fstat(child)), 'EVIDENCE_PARENT_CHANGED')
            bindings.append((parent, part, child, (before.st_dev, before.st_ino, before.st_uid, before.st_gid, before.st_mode)))
            parent = child
        yield parent
        for parent, part, child, seal in bindings:
            for s in (os.fstat(child), os.stat(part, dir_fd=parent, follow_symlinks=False)):
                require(seal == (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode), 'EVIDENCE_PARENT_CHANGED')
    finally:
        for fd in reversed(fds): os.close(fd)

def read_member(directory, name):
    before = os.stat(name, dir_fd=directory, follow_symlinks=False)
    require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
            and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
            and 0 < before.st_size <= 524288, 'PRIVATE_SNAPSHOT_CUSTODY_UNPROVEN')
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        require(identity(before) == identity(os.fstat(fd)), 'SNAPSHOT_CHANGED')
        chunks, count = [], 0
        while count <= 524288:
            raw = os.read(fd, min(65536, 524289 - count))
            if not raw: break
            chunks.append(raw); count += len(raw)
        require(count == before.st_size and identity(before) == identity(os.fstat(fd))
                == identity(os.stat(name, dir_fd=directory, follow_symlinks=False)), 'SNAPSHOT_CHANGED')
        return b''.join(chunks)
    finally: os.close(fd)

def compile_binding(snapshot, snapshot_hash, reference):
    require(type(snapshot_hash) is str and re.fullmatch('[0-9a-f]{64}', snapshot_hash), 'EXACT_SNAPSHOT_HASH_REQUIRED')
    fields = {'schema', 'issuerSelection', 'realm', 'client', 'serviceAccount', 'defaultScopes',
              'optionalScopes', 'requestedScopes', 'credentialProvenanceAccepted',
              'actualTokenIntrospectionProven', 'targetHttpsPeerBindingProven',
              'historicalAccountingReconciled', 'runtimeAuthorityIssued', 'notReleaseAcceptance'}
    require(type(snapshot) is dict and set(snapshot) == fields
            and snapshot['schema'] == 'ouf.policy-token-existing-iam-metadata.v1'
            and all(snapshot[k] is False for k in ('credentialProvenanceAccepted', 'actualTokenIntrospectionProven',
                      'targetHttpsPeerBindingProven', 'historicalAccountingReconciled', 'runtimeAuthorityIssued'))
            and snapshot['notReleaseAcceptance'] is True, 'EXACT_RETAINED_METADATA_SCOPE_REQUIRED')
    require(type(reference) is dict and set(reference) == {'issuer', 'tenant', 'audience', 'actor'}
            and all(type(v) is str and 0 < len(v) <= 256 and not any(c.isspace() for c in v) for v in reference.values())
            and reference['actor'] == 'SERVICE', 'EXPLICIT_REVIEW_REFERENCE_REQUIRED')
    issuer = urllib.parse.urlsplit(reference['issuer'])
    require(issuer.scheme == 'https' and issuer.hostname and not issuer.username and not issuer.password
            and not issuer.query and not issuer.fragment and re.fullmatch(r'/realms/[A-Za-z0-9_.-]{1,64}', issuer.path),
            'EXPLICIT_KEYCLOAK_ISSUER_REQUIRED')
    require(snapshot['issuerSelection'] == reference['issuer'] and snapshot['realm'] == issuer.path.split('/')[-1],
            'RETAINED_ISSUER_REFERENCE_MISMATCH')
    client, service = snapshot['client'], snapshot['serviceAccount']
    require(type(client) is dict and client.get('enabled') is True and client.get('serviceAccountsEnabled') is True
            and client.get('publicClient') is False and client.get('clientAuthenticatorType') == 'client-secret'
            and client.get('protocol') == 'openid-connect' and type(client.get('clientId')) is str
            and re.fullmatch('[A-Za-z0-9_.:-]{1,128}', client['clientId']) is not None,
            'EXISTING_SERVICE_CLIENT_REQUIRED')
    require(type(service) is dict and service.get('enabled') is True and type(service.get('id')) is str
            and re.fullmatch('[0-9a-fA-F-]{36}', service['id']) is not None, 'EXISTING_SERVICE_ACCOUNT_REQUIRED')
    default, optional, requested = snapshot['defaultScopes'], snapshot['optionalScopes'], snapshot['requestedScopes']
    require(type(default) is list and type(optional) is list and len(default) + len(optional) <= 128
            and all(type(s) is dict and type(s.get('name')) is str
                    and re.fullmatch('[A-Za-z0-9_.:/-]{1,128}', s['name']) for s in default + optional), 'BOUNDED_SCOPE_METADATA_REQUIRED')
    names = [s['name'] for s in default + optional]
    require(len(names) == len(set(names)) and type(requested) is list and 1 <= len(requested) <= 32
            and all(type(s) is str for s in requested) and len(requested) == len(set(requested))
            and set(requested) <= set(names) and 'authorization.bundle.read' in requested, 'EXACT_ASSIGNED_REQUESTED_SCOPES_REQUIRED')
    selected_optional = [s for s in optional if s['name'] in requested]
    effective = [client] + default + selected_optional
    mappers = []
    for source in effective:
        items = source.get('protocolMappers', [])
        require(type(items) is list and len(items) <= 64, 'BOUNDED_MAPPER_METADATA_REQUIRED')
        for mapper in items:
            require(type(mapper) is dict and mapper.get('protocol') == 'openid-connect'
                    and type(mapper.get('protocolMapper')) is str and type(mapper.get('config')) is dict
                    and len(mapper['config']) <= 64 and all(type(k) is str and type(v) is str
                    and len(k) <= 256 and len(v) <= 4096 for k, v in mapper['config'].items()), 'MAPPER_SCHEMA_UNPROVEN')
            mappers.append(mapper)
    require(len(mappers) <= 256, 'EFFECTIVE_MAPPER_SET_UNBOUNDED')
    reasons = []
    known = all(m['protocolMapper'] in SAFE_MAPPERS for m in mappers)
    if not known: reasons.append('UNSUPPORTED_EFFECTIVE_MAPPER')
    facts = {}
    for claim, expected, label in (('tenant_id', reference['tenant'], 'tenant'),
                                  ('ouf_actor_type', reference['actor'], 'actor')):
        selected = [m for m in mappers if m['config'].get('claim.name') == claim
                    and m['config'].get('access.token.claim') == 'true']
        match = bool(selected) and all(m['protocolMapper'] == 'oidc-hardcoded-claim-mapper'
                    and m['config'].get('jsonType.label') == 'String'
                    and m['config'].get('claim.value') == expected for m in selected)
        facts[label + 'StaticMapperMatchesReference'] = match
        facts[label + 'IntrospectionMappingExplicit'] = bool(selected) and all(
                    m['config'].get('introspection.token.claim') == 'true' for m in selected)
        if not match: reasons.append(label.upper() + '_MAPPER_NOT_PROVEN')
        if not facts[label + 'IntrospectionMappingExplicit']: reasons.append(label.upper() + '_INTROSPECTION_MAPPING_NOT_EXPLICIT')
    audience = [m for m in mappers if m['protocolMapper'] == 'oidc-audience-mapper'
                and m['config'].get('access.token.claim') == 'true'
                and reference['audience'] in (m['config'].get('included.client.audience'),
                                             m['config'].get('included.custom.audience'))]
    facts['audienceStaticMapperMatchesReference'] = bool(audience)
    facts['audienceIntrospectionMappingExplicit'] = bool(audience) and all(
                m['config'].get('introspection.token.claim') == 'true' for m in audience)
    if not audience: reasons.append('AUDIENCE_MAPPER_NOT_PROVEN')
    if not facts['audienceIntrospectionMappingExplicit']: reasons.append('AUDIENCE_INTROSPECTION_MAPPING_NOT_EXPLICIT')
    # Keycloak service account id is only the candidate subject. Any mapper
    # capable of rewriting sub is explicitly unresolved, including pairwise.
    subject_override = any(m['config'].get('claim.name') == 'sub'
                           or m['protocolMapper'] == 'oidc-sha256-pairwise-sub-mapper' for m in mappers)
    facts['subjectOverrideMapperObserved'] = subject_override
    if subject_override: reasons.append('SUBJECT_MAPPER_REQUIRES_REVIEW')
    candidate = {'schema': 'ouf.policy-token-iam-binding-candidate.v1', 'snapshotHash': snapshot_hash,
                 'reference': dict(reference), 'issuer': reference['issuer'], 'clientId': client['clientId'],
                 'candidateSubjectId': service['id'], 'requestedScopes': sorted(requested),
                 'candidateAllowedScopeEnvelope': sorted(set(s['name'] for s in default) | set(requested)),
                 'unrequestedOptionalScopesExcluded': True,
                 'effectiveMapperCount': len(mappers), 'mapperFacts': facts, 'reviewReasons': sorted(set(reasons)),
                 'scopeEnvelopeIsConservativeNotObservedTokenScope': True,
                 'metadataOnlyNoBearerAdmission': True, 'peerAddressesBound': False,
                 'credentialProvenanceAccepted': False, 'historicalAccountingReconciled': False,
                 'runtimeAuthorityIssued': False, 'productionApplyReady': False,
                 'budgetReset': False, 'notReleaseAcceptance': True}
    public = {'effectiveMapperCount': len(mappers), 'selectedOptionalScopeCount': len(selected_optional),
              'unrequestedOptionalScopesExcluded': True, 'staticMapperConstraintsComplete': not reasons,
              'reviewReasons': candidate['reviewReasons'], **facts}
    return candidate, public

def prepare(snapshot_path, snapshot_hash, reference, report):
    path = Path(snapshot_path)
    require(path.parent == PARENT and re.fullmatch(r'policy-token-iam-metadata-[0-9a-f]{32}\.private\.json', path.name)
            and re.fullmatch('[0-9a-f]{64}', snapshot_hash), 'EXACT_RETAINED_SNAPSHOT_REFERENCE_REQUIRED')
    with protected_parent() as directory:
        report['phase'] = 'RETAINED_SNAPSHOT_READ'
        raw = read_member(directory, path.name)
        require(sha(raw) == snapshot_hash, 'RETAINED_SNAPSHOT_HASH_MISMATCH')
        report['phase'] = 'CLAIM_CONSTRAINT_COMPILATION'
        candidate, public = compile_binding(decode(raw), snapshot_hash, reference)
        require(read_member(directory, path.name) == raw, 'RETAINED_SNAPSHOT_CHANGED')
        body = encoded(candidate)
        name = 'policy-token-iam-binding-' + sha(body) + '.private.json'
        report.update(phase='PRIVATE_CANDIDATE_PUBLICATION', candidatePath=str(PARENT / name))
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        except FileExistsError:
            require(read_member(directory, name) == body, 'CANDIDATE_RECONCILIATION_REQUIRED')
            report['newCandidatePublished'] = False
        else:
            report.update(privateEvidenceWrites=1, newCandidatePublished=True)
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(os.dup(fd), 'wb') as stream:
                    stream.write(body); stream.flush(); os.fsync(stream.fileno())
                os.fsync(directory)
                require(identity(os.fstat(fd)) == identity(os.stat(name, dir_fd=directory, follow_symlinks=False)),
                        'CANDIDATE_MEMBER_CHANGED')
            finally: os.close(fd)
        require(read_member(directory, name) == body, 'CANDIDATE_RECONCILIATION_REQUIRED')
        report.update(status='CLAIM_CONSTRAINTS_COMPILED_REVIEW_ONLY', phase='COMPILED_NOT_ACCEPTED',
                      candidateHash=sha(body), **public)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--snapshot', required=True); parser.add_argument('--snapshot-sha256', required=True)
    parser.add_argument('--issuer', required=True); parser.add_argument('--tenant', required=True)
    parser.add_argument('--audience', required=True)
    args = parser.parse_args()
    report = {'schema': 'ouf.policy-token-iam-binding-compilation-receipt.v1', 'phase': 'ROOT_ENTRY',
              'status': 'BLOCKED', 'privateEvidenceWrites': 0, 'credentialFilesRead': 0,
              'mountedTokenFilesRead': 0, 'providerCalls': 0, 'tokenGrantRequests': 0,
              'serviceMutations': 0, 'runtimeAuthorityIssued': False, 'productionApplyReady': False,
              'budgetReset': False, 'r12Touched': False, 'notReleaseAcceptance': True}
    try:
        def timeout(*_): raise CandidateDenied('COMPILATION_DEADLINE')
        signal.signal(signal.SIGALRM, timeout); signal.alarm(30)
        prepare(args.snapshot, args.snapshot_sha256, {'issuer': args.issuer, 'tenant': args.tenant,
                'audience': args.audience, 'actor': 'SERVICE'}, report)
        code = 0
    except Exception as error:
        report['reason'] = str(error) if type(error) is CandidateDenied else type(error).__name__
        if isinstance(error, OSError): report['errno'] = error.errno
        report['evidencePublicationMayBePartial'] = report['phase'] == 'PRIVATE_CANDIDATE_PUBLICATION'
        code = 1
    finally: signal.alarm(0)
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))
    return code

if __name__ == '__main__': raise SystemExit(main())
