"""Read complete owner mapper representations; preserve the retained snapshot.

Uses only the already selected client/account/scope IDs and existing kcadm
session. No secrets/grants/IAM writes or changes to the frozen runtime baseline.
The independently hash-checked binding compiler is loaded by the sealed launcher.
"""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time
import uuid
import iam_binding_candidate as binding

CONTAINER = 'ouf-keycloak'
SERVER = 'http://localhost:8080'
REALM = 'ouf'
CORE_CLIENT_FIELDS = 'id,clientId,enabled,serviceAccountsEnabled,publicClient,clientAuthenticatorType,protocol'

def require(ok, reason): binding.require(ok, reason)

def identifier(value):
    require(type(value) is str and re.fullmatch('[0-9a-fA-F-]{36}', value), 'EXACT_REGISTERED_IAM_ID_REQUIRED')
    return value

class Reader:
    def __init__(self, report):
        self.report = report; self.started = time.monotonic(); self.calls = 0
    def get(self, resource, fields=None):
        remaining = 180 - (time.monotonic() - self.started)
        require(remaining > 0 and self.calls < 48, 'FINITE_METADATA_OBSERVATION_EXHAUSTED')
        require(re.fullmatch(r'(clients/[0-9a-fA-F-]{36}(/(service-account-user|default-client-scopes|optional-client-scopes|protocol-mappers/models))?|client-scopes/[0-9a-fA-F-]{36}/protocol-mappers/models)', resource),
                'EXACT_SELECTED_IAM_RESOURCE_REQUIRED')
        argv = ['/usr/bin/docker', 'exec', CONTAINER, '/opt/keycloak/bin/kcadm.sh', 'get', resource,
                '--server', SERVER, '-r', REALM]
        if fields is not None: argv += ['--fields', fields]
        self.calls += 1; self.report['iamMetadataGetAttempts'] = self.calls
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=min(15, remaining))
        require(result.returncode == 0, 'EXISTING_IAM_GET_UNAVAILABLE')
        require(0 < len(result.stdout) <= 262144, 'IAM_METADATA_RESPONSE_UNBOUNDED')
        return binding.decode(result.stdout)

def core(reader, client_id):
    resource = 'clients/' + identifier(client_id)
    client = reader.get(resource, CORE_CLIENT_FIELDS)
    require(type(client) is dict and set(client) == set(CORE_CLIENT_FIELDS.split(',')), 'CORE_CLIENT_METADATA_UNPROVEN')
    service = reader.get(resource + '/service-account-user', 'id,enabled')
    require(type(service) is dict and set(service) == {'id', 'enabled'}, 'CORE_SERVICE_ACCOUNT_METADATA_UNPROVEN')
    default = reader.get(resource + '/default-client-scopes', 'id,name,protocol')
    optional = reader.get(resource + '/optional-client-scopes', 'id,name,protocol')
    for scopes in (default, optional):
        require(type(scopes) is list and len(scopes) <= 64 and all(type(s) is dict
                and {'id', 'name'} <= set(s) <= {'id', 'name', 'protocol'} for s in scopes), 'CORE_SCOPE_METADATA_UNPROVEN')
        for s in scopes: identifier(s['id'])
    return {'client': client, 'serviceAccount': service, 'defaultScopes': default, 'optionalScopes': optional}

def anchor(snapshot):
    require(type(snapshot) is dict and snapshot.get('schema') == 'ouf.policy-token-existing-iam-metadata.v1',
            'EXACT_RETAINED_SNAPSHOT_REQUIRED')
    result = {}
    for name, fields in (('client', CORE_CLIENT_FIELDS.split(',')), ('serviceAccount', ['id', 'enabled'])):
        source = snapshot.get(name)
        require(type(source) is dict and all(k in source for k in fields), 'RETAINED_CORE_BINDING_UNPROVEN')
        result[name] = {k: source[k] for k in fields}
    for name in ('defaultScopes', 'optionalScopes'):
        source = snapshot.get(name)
        require(type(source) is list and len(source) <= 64 and all(type(s) is dict
                and all(k in s for k in ('id', 'name')) for s in source), 'RETAINED_SCOPE_BINDING_UNPROVEN')
        result[name] = [{k: s[k] for k in ('id', 'name', 'protocol') if k in s} for s in source]
    return result

def canonical(value):
    return {**value, **{name: sorted(value[name], key=lambda s: s['id']) for name in ('defaultScopes', 'optionalScopes')}}

def complete_mappers(reader, snapshot, current):
    # Only effective scopes: default plus requested optional. No blanket reads
    # of unrequested optional mapper collections or client-secret endpoints.
    selected = current['defaultScopes'] + [s for s in current['optionalScopes'] if s['name'] in snapshot['requestedScopes']]
    require(len(selected) <= 19, 'EFFECTIVE_SCOPE_OBSERVATION_UNBOUNDED')
    resources = ['clients/' + identifier(current['client']['id']) + '/protocol-mappers/models']
    resources += ['client-scopes/' + identifier(s['id']) + '/protocol-mappers/models' for s in selected]
    sets = {}; total = 0
    for resource in resources:
        # Deliberately no --fields: that CLI projection removes nested fields.
        rows = reader.get(resource)
        require(type(rows) is list and len(rows) <= 64, 'BOUNDED_MAPPER_COLLECTION_REQUIRED')
        total += len(rows); require(total <= 256, 'EFFECTIVE_MAPPER_SET_UNBOUNDED')
        sets[resource] = rows
    return sets

def enriched(snapshot, current, mappers):
    result = {**snapshot, **current}
    result['client'] = {**current['client'], 'protocolMappers': mappers['clients/' + current['client']['id'] + '/protocol-mappers/models']}
    for name in ('defaultScopes', 'optionalScopes'):
        result[name] = [{**s, 'protocolMappers': mappers['client-scopes/' + s['id'] + '/protocol-mappers/models']}
                       if 'client-scopes/' + s['id'] + '/protocol-mappers/models' in mappers else dict(s)
                       for s in current[name]]
    return result

def execute(path, expected_hash, reference, report):
    path = Path(path)
    require(path.parent == binding.PARENT and re.fullmatch(r'policy-token-iam-metadata-[0-9a-f]{32}\.private\.json', path.name)
            and re.fullmatch('[0-9a-f]{64}', expected_hash), 'EXACT_RETAINED_SNAPSHOT_REFERENCE_REQUIRED')
    with binding.protected_parent() as directory:
        report['phase'] = 'RETAINED_SNAPSHOT_READ'
        raw = binding.read_member(directory, path.name); require(binding.sha(raw) == expected_hash, 'RETAINED_SNAPSHOT_HASH_MISMATCH')
        old = binding.decode(raw); binding.compile_binding(old, expected_hash, reference)
        expected_core = canonical(anchor(old)); reader = Reader(report)
        report['phase'] = 'CURRENT_CORE_BINDING_READ'
        current = core(reader, old['client']['id'])
        require(canonical(current) == expected_core, 'CURRENT_IAM_CORE_BINDING_DRIFT')
        report['phase'] = 'COMPLETE_MAPPER_READ'
        mappers = complete_mappers(reader, old, current)
        report['phase'] = 'STABLE_OWNER_RECHECK'
        require(mappers == complete_mappers(reader, old, current), 'CURRENT_IAM_MAPPER_DRIFT')
        require(canonical(core(reader, old['client']['id'])) == expected_core, 'CURRENT_IAM_CORE_BINDING_DRIFT')
        require(binding.read_member(directory, path.name) == raw, 'RETAINED_SNAPSHOT_CHANGED')
        fresh = enriched(old, current, mappers); body = binding.encoded(fresh)
        require(len(body) <= 524288, 'ENRICHED_SNAPSHOT_UNBOUNDED')
        # Verify compilation before preserving the fresh metadata. No live
        # client/claims are promoted into runtime authority by either artifact.
        binding.compile_binding(fresh, binding.sha(body), reference)
        name = 'policy-token-iam-metadata-' + uuid.uuid4().hex + '.private.json'
        report.update(phase='PRIVATE_ENRICHED_METADATA_PUBLICATION', enrichedMetadataPath=str(binding.PARENT / name))
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        report['privateEvidenceWrites'] += 1
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(os.dup(fd), 'wb') as stream:
                stream.write(body); stream.flush(); os.fsync(stream.fileno())
            os.fsync(directory)
        finally: os.close(fd)
        require(binding.read_member(directory, name) == body, 'ENRICHED_METADATA_PUBLICATION_UNPROVEN')
        report.update(enrichedMetadataHash=binding.sha(body), parentSnapshotHash=expected_hash,
                      mapperMetadataReadWithoutFieldsFilter=True, baselineRefreshed=False)
    candidate_report = {'privateEvidenceWrites': 0}
    try:
        binding.prepare(str(binding.PARENT / name), binding.sha(body), reference, candidate_report)
    finally:
        writes = report['privateEvidenceWrites'] + candidate_report.pop('privateEvidenceWrites')
        report.update(candidate_report); report['privateEvidenceWrites'] = writes

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--snapshot', required=True); parser.add_argument('--snapshot-sha256', required=True)
    parser.add_argument('--issuer', required=True); parser.add_argument('--tenant', required=True); parser.add_argument('--audience', required=True)
    args = parser.parse_args()
    report = {'schema': 'ouf.policy-token-iam-mapper-enrichment-receipt.v1', 'phase': 'ROOT_ENTRY', 'status': 'BLOCKED',
              'observationProfile': 'ouf.policy-token-effective-mapper-enrichment.single-attempt.v1',
              'privateEvidenceWrites': 0, 'iamMetadataGetAttempts': 0, 'credentialFilesRead': 0,
              'mountedTokenFilesRead': 0, 'tokenGrantRequests': 0, 'iamMutations': 0, 'serviceMutations': 0,
              'runtimeAuthorityIssued': False, 'productionApplyReady': False, 'budgetReset': False,
              'r12Touched': False, 'notReleaseAcceptance': True}
    try:
        def timeout(*_): raise binding.CandidateDenied('ENRICHMENT_DEADLINE')
        signal.signal(signal.SIGALRM, timeout); signal.alarm(180)
        execute(args.snapshot, args.snapshot_sha256, {'issuer': args.issuer, 'tenant': args.tenant,
                'audience': args.audience, 'actor': 'SERVICE'}, report)
        code = 0
    except Exception as error:
        report['reason'] = str(error) if type(error) is binding.CandidateDenied else type(error).__name__
        report['status'] = 'BLOCKED'
        if isinstance(error, OSError): report['errno'] = error.errno
        report['evidencePublicationMayBePartial'] = report['phase'] in ('PRIVATE_ENRICHED_METADATA_PUBLICATION', 'PRIVATE_CANDIDATE_PUBLICATION')
        code = 1
    finally: signal.alarm(0)
    print(json.dumps(report, sort_keys=True, separators=(',', ':')))
    return code

if __name__ == '__main__': raise SystemExit(main())
