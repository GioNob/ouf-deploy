"""Authenticate a complete target transaction before compiling an install plan.

Read/verify/assemble only. No signing, key reads, target writes or runtime calls.
The installer review and both role mandates must already be externally issued.
The known target bindings below are evidence selections, never authority grants.
"""
import copy
from datetime import datetime, timezone
from pathlib import PurePosixPath
import re
import time

from assemble_provider_profiles import assemble_profiles, digest, encoded
from compile_creation_frame_policy import compile_policy
from tools.semantic_provider_deployment_authentication import DetachedAuthenticator, decode
from tools.semantic_provider_deployment_protocol import validate_intent, window, identity


TARGETS = {
    'adapter': {
        'containerId': 'f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67',
        'imageManifestDigest': 'sha256:277dcefd4744c244f4f6f23f8969f3d0acd64369e2ff1bd67594955c4ca7fbbc',
        'imageConfigDigest': 'sha256:62e066bd021f386291f5de21ce0e1f9e67904a74b4146326070c7784493ad320',
        'runtimeSeal': {'schema': 'ouf.semantic-rootfs-seal.v1', 'sha256': '8744724088d02145b86b433058a4336fcb9c873a4a92e7009753209c284d3d73', 'entries': 3390, 'bytes': 46079786}},
    'southbound': {
        'containerId': '1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916',
        'imageManifestDigest': 'sha256:c15541037a08276e36715a3c3798c2d07fe6faabf5547d3885a66cd10575e366',
        'imageConfigDigest': 'sha256:d4c47bbeca75d94e2231e17ca14552885b7b339a5f33dbace411e275c79ded04',
        'runtimeSeal': {'schema': 'ouf.semantic-rootfs-seal.v1', 'sha256': '52e06f47e1da5a107525e2260b9d375329997181dd13de7023654278aeaf3f39', 'entries': 7458, 'bytes': 255900260}}}

AUTHORITIES = {'installationRef': 'ouf-lab-netcup-01', 'entityRef': 'ouf-lab',
               'intentIssuerRef': 'ouf-lab-infrastructure-installer',
               'approvalIssuerRef': 'ouf-lab-infrastructure-installer',
               'attestorRef': 'ouf-lab-node-attestor'}
DOCUMENTS = {'template', 'launch', 'context', 'framePolicy', 'preparerTemplate', 'deploymentConstraints',
             'provenanceEvidence', 'dependencyEvidence', 'review', 'intent',
             'liveAuthorization', 'finalMandate'}


class TransactionDenied(ValueError):
    def __init__(self, stage, reason, role=None, differences=()):
        self.diagnosis = {'status': 'BLOCKED', 'stage': stage, 'reason': reason,
                          'role': role, 'differentFields': list(differences),
                          'secretValuesPrinted': False, 'startAuthorized': False,
                          'containerLifecycleOperations': 0, 'privateKeysRead': 0}
        super().__init__(reason)


def require(ok, stage, reason, role=None, differences=()):
    if not ok:
        raise TransactionDenied(stage, reason, role, differences)


def same(actual, expected, stage, reason, role):
    different = [k for k, v in expected.items() if encoded(actual.get(k)) != encoded(v)]
    require(not different, stage, reason, role, different)


def signed(verifier, raw, signature_role, issuer, ctx, name, role, stage):
    try:
        result = verifier(raw, signature_role, issuer, ctx['installationRef'], ctx['entityRef'])
    except FileNotFoundError:
        raise TransactionDenied(stage, 'SIGNED_TARGET_RECORD_MISSING', role, [name]) from None
    require(result is True, stage, 'TARGET_RECORD_SIGNATURE_REQUIRED', role, [name])


def validate_preparer_template(value, role):
    """Check the sealed broker/preparer outer contract before any issuance.

    Structural closure only: native kernel/coordination custody and actual
    command bytes still require the locked runtime verifier and production CLIs.
    """
    stage = 'VERIFY_COMPLETE_PREPARER_CONTRACT'
    fields = {'schema','pythonPath','pythonHash','commands','commandHashes','candidate','kernel','dns',
              'coordinationBinding','coordinationJournal','lockFile','budgetSeconds','hostNetworkNamespace'}
    require(type(value) is dict and set(value) == fields
            and value['schema'] == 'ouf.semantic-admission-preparer-template.v1',
            stage, 'EXACT_COMPLETE_BROKER_PREPARER_TEMPLATE_REQUIRED', role,
            sorted(fields.symmetric_difference(value)) if type(value) is dict else ())
    candidate = value['candidate']
    require(type(candidate) is dict and set(candidate) == {
        'containerId','transactionId','networkBindings','transport','tableName','runtimeBinding'},
        stage, 'EXACT_BROKER_CANDIDATE_TEMPLATE_REQUIRED', role)
    commands = {'nft','ip','nsenter','unshare','mount','umount'}
    require(type(value['commands']) is dict and type(value['commandHashes']) is dict
            and set(value['commands']) == set(value['commandHashes']) == commands,
            stage, 'COMPLETE_PREPARER_NATIVE_COMMANDS_REQUIRED', role)
    bindings = [('python', value['pythonPath'], value['pythonHash'])]
    runtime = candidate['runtimeBinding']
    require(type(runtime) is dict and set(runtime) == {'path','sha256'},
            stage, 'EXACT_PREPARER_RUNTIME_BINDING_REQUIRED', role)
    bindings.append(('runtime',runtime['path'],runtime['sha256']))
    bindings.extend((name,value['commands'][name],value['commandHashes'][name]) for name in commands)
    for name, path, sha in bindings:
        require(type(path) is str and PurePosixPath(path).is_absolute() and '..' not in PurePosixPath(path).parts
                and type(sha) is str and re.fullmatch('[0-9a-f]{64}',sha),
                stage, 'EXACT_PREPARER_COMMAND_BINDING_REQUIRED', role, [name])
    for name in ('coordinationJournal','lockFile'):
        path = value[name]
        require(type(path) is str and PurePosixPath(path).is_absolute() and '..' not in PurePosixPath(path).parts,
                stage, 'ABSOLUTE_PREPARER_CUSTODY_PATH_REQUIRED', role, [name])
    require(type(value['budgetSeconds']) is int and 1 <= value['budgetSeconds'] <= 5
            and type(value['hostNetworkNamespace']) is int and value['hostNetworkNamespace'] > 0,
            stage, 'BOUNDED_PREPARER_AND_HOST_NAMESPACE_REQUIRED', role)
    require(all(type(value[name]) is dict for name in ('kernel','dns','coordinationBinding')),
            stage, 'PREPARER_KERNEL_DNS_COORDINATION_DOCUMENTS_REQUIRED', role)
    require(type(candidate['networkBindings']) is list and type(candidate['transport']) is list,
            stage, 'PREPARER_NETWORK_TRANSPORT_DOCUMENTS_REQUIRED', role)


def validate_dependency_evidence(value, role, now, authority_expires):
    """Bound signed review metadata, not a scanner/provenance verifier.

    Issuer independently verifies the reports before approving their hashes.
    Neither this document nor its counters can grant authority. Enforce the
    existing 48-hour DB policy again at every authenticated checkpoint.
    """
    stage='VERIFY_REVIEWED_DEPENDENCY_FRESHNESS'
    fields={'schema','role','imageConfigDigest','databasePin','reportSha256','inventorySha256',
            'sourceArtifactSha256','scanDatabaseBuilt','scanDatabaseSchemaVersion','severityCounts',
            'packageAlertCount','ignoredMatchCount'}
    require(type(value) is dict and set(value)==fields,stage,'EXACT_REVIEWED_DEPENDENCY_EVIDENCE_REQUIRED',role)
    same(value,{'schema':'ouf.semantic-provider-dependency-evidence.v1','role':role,
               'imageConfigDigest':TARGETS[role]['imageConfigDigest']},stage,'DEPENDENCY_IMAGE_SCOPE_DRIFT',role)
    for key in ('reportSha256','inventorySha256','sourceArtifactSha256'):
        require(type(value[key]) is str and re.fullmatch('[0-9a-f]{64}',value[key]),stage,'DEPENDENCY_EVIDENCE_HASH_REQUIRED',role,[key])
    pin=value['databasePin']
    require(type(pin) is dict and set(pin)=={'status','schemaVersion','built','path','checksum'}
            and pin['status']=='active' and type(pin['schemaVersion']) is str
            and re.fullmatch(r'v6\.[0-9]+\.[0-9]+',pin['schemaVersion'])
            and type(pin['checksum']) is str and re.fullmatch('sha256:[0-9a-f]{64}',pin['checksum'])
            and type(pin['path']) is str and re.fullmatch('[A-Za-z0-9_.:-]{1,160}',pin['path']),
            stage,'EXACT_REVIEWED_DATABASE_PIN_REQUIRED',role)
    require(type(pin['built']) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z',pin['built']),
            stage,'DATABASE_BUILD_TIMESTAMP_REQUIRED',role)
    try:built=datetime.strptime(pin['built'],'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp()
    except ValueError:raise TransactionDenied(stage,'DATABASE_BUILD_TIMESTAMP_REQUIRED',role) from None
    require(built<=now<built+48*3600 and now<authority_expires<=built+48*3600,
            stage,'DATABASE_FRESHNESS_DOES_NOT_COVER_AUTHORITY_WINDOW',role,['databasePin.built'])
    same(value,{'scanDatabaseBuilt':pin['built'],'scanDatabaseSchemaVersion':pin['schemaVersion']},
         stage,'REVIEWED_SCAN_DATABASE_DRIFT',role)
    counts=value['severityCounts']
    require(type(counts) is dict and set(counts)=={'Critical','High','Medium','Low','Negligible','Unknown'}
            and all(type(count) is int and 0<=count<=1000000 for count in counts.values()),
            stage,'EXACT_REVIEWED_SEVERITY_COUNTS_REQUIRED',role)
    require(all(counts[key]==0 for key in ('Critical','High','Unknown'))
            and type(value['packageAlertCount']) is int and value['packageAlertCount']==0
            and type(value['ignoredMatchCount']) is int and value['ignoredMatchCount']==0,
            stage,'REVIEWED_DEPENDENCY_THRESHOLD_NOT_MET',role)


def _authenticate_role(role, records, authority, sources, observer_raw, verifier, clock=time.time):
    """Validate actual signatures and all documents before producing any profiles.

    A signed review binds independently prepared full template/launch/context,
    publisher/dependency evidence, exact node seal, and preparer/source closure.
    The complete OCI is recompiled from those inputs; observed OCI is never used.
    """
    stage = 'AUTHENTICATE_TARGET_INPUTS'
    require(type(verifier) is DetachedAuthenticator, stage, 'PRODUCTION_DETACHED_VERIFIER_REQUIRED', role)
    require(role in TARGETS and set(records) == DOCUMENTS, stage, 'COMPLETE_TARGET_DOCUMENT_SET_REQUIRED', role)
    require(authority['authorities'] == AUTHORITIES, stage, 'TARGET_AUTHORITIES_DRIFT', role)
    values = {name: decode(raw, 131072) for name, raw in records.items()}
    target, ctx = TARGETS[role], authority['authorities']
    review = values['review']
    hashes = {name + 'Hash': digest(records[name]) for name in
              ('template', 'launch', 'context', 'framePolicy', 'preparerTemplate', 'deploymentConstraints',
               'provenanceEvidence', 'dependencyEvidence')}
    source_hashes = {path: digest(raw) for path, raw in sources.items()}
    source_hashes['frame-observer.py'] = digest(observer_raw)
    expected = {'schema': 'ouf.semantic-provider-target-review.v1',
                'issuerRef': ctx['approvalIssuerRef'], 'installationRef': ctx['installationRef'],
                'entityRef': ctx['entityRef'], 'role': role, **target, **hashes,
                'sourceClosureHash': digest(encoded(source_hashes)),
                'decision': 'ACCEPT_PROVIDER_IMAGE_AND_COMPLETE_FRAME', 'state': 'ACTIVE'}
    require(set(review) == set(expected) | {'issuedAt', 'expiresAt'}, stage, 'EXACT_TARGET_REVIEW_REQUIRED', role)
    same(review, expected, stage, 'TARGET_REVIEW_SCOPE_DRIFT', role)
    window(review, clock())
    signed(verifier, records['review'], 'FINAL_DEPLOYMENT_APPROVAL', ctx['approvalIssuerRef'], ctx, 'review', role, stage)
    validate_preparer_template(values['preparerTemplate'], role)
    # Signed hashes attest the complete input set. Compile independently of any
    # candidate observation and compare the entire resulting policy, not a view.
    stage = 'COMPILE_AUTHENTICATED_FRAME'
    require(values['context']['containerId'] == target['containerId'], stage, 'CONTEXT_CANDIDATE_DRIFT', role)
    policy = compile_policy(values['template'], values['launch'], values['context'])
    require(encoded(policy) == records['framePolicy'], stage, 'COMPLETE_COMPILED_POLICY_DRIFT', role)
    intent = validate_intent(records['intent'], ctx, verifier, clock)
    template = values['preparerTemplate']
    candidate = template['candidate']
    same(candidate, {'containerId': target['containerId'], 'transactionId': intent['transactionId']},
         stage, 'PREPARER_CANDIDATE_SCOPE_DRIFT', role)
    constraints = digest(records['deploymentConstraints'])
    transport = digest(encoded({k: candidate[k] for k in ('networkBindings', 'transport', 'tableName')}))
    same(intent, {'containerId': target['containerId'], 'artifactHash': digest(records['framePolicy']),
                  'deploymentConstraintsHash': constraints, 'transportHash': transport,
                  'runtimeExecutableHash': candidate['runtimeBinding']['sha256']},
         stage, 'INTENT_COMPLETE_INPUT_SCOPE_DRIFT', role)
    stage = 'AUTHENTICATE_ROLE_MANDATES'
    scope = {k: intent[k] for k in ('installationRef', 'entityRef', 'containerId', 'transactionId',
              'artifactHash', 'deploymentConstraintsHash', 'transportHash', 'runtimeExecutableHash')}
    scope['intentHash'] = digest(records['intent'])
    live = values['liveAuthorization']
    live_expected = {'schema': 'ouf.semantic-node-live-acceptance-authorization.v1',
        'issuerRef': ctx['attestorRef'], **scope, 'applicationHash': digest(encoded(policy['expectedOci'])),
        'rootfsSeal': target['runtimeSeal'], 'generationBinding': 'OBSERVED_CREATED',
        'state': 'ACTIVE', 'mandateIssuanceAuthorized': True, 'attestationAuthorized': True,
        'completeCreationAccepted': True}
    final = values['finalMandate']
    final_expected = {'schema': 'ouf.semantic-final-approval-mandate.v1',
        'issuerRef': ctx['approvalIssuerRef'], **scope, 'state': 'ACTIVE',
        'issuanceAuthorized': True, 'applicationStartAuthorized': True}
    require(set(live) == set(live_expected) | {'issuedAt', 'expiresAt'}, stage, 'EXACT_LIVE_AUTHORIZATION_REQUIRED', role)
    require(set(final) == set(final_expected) | {'approvalRef', 'issuedAt', 'expiresAt'}
            and identity(final['approvalRef']), stage, 'EXACT_FINAL_MANDATE_REQUIRED', role)
    for name, expected, signature_role, issuer in (
        ('liveAuthorization', live_expected, 'CREATION_ATTESTATION', ctx['attestorRef']),
        ('finalMandate', final_expected, 'FINAL_DEPLOYMENT_APPROVAL', ctx['approvalIssuerRef'])):
        value = values[name]
        same(value, expected, stage, 'SIGNED_ROLE_SCOPE_DRIFT', role)
        window(value, clock())
        require(value['issuedAt'] >= intent['issuedAt'] and value['expiresAt'] <= intent['expiresAt'],
                stage, 'ROLE_MANDATE_EXCEEDS_INTENT', role)
        signed(verifier, records[name], signature_role, issuer, ctx, name, role, stage)
    for name in ('review', 'intent', 'liveAuthorization', 'finalMandate'):
        window(values[name], clock())
    validate_dependency_evidence(values['dependencyEvidence'],role,clock(),
                                 max(values[name]['expiresAt'] for name in ('review','intent','liveAuthorization','finalMandate')))
    return {'intent': intent, 'policy': policy, 'template': template,
            'inputHashes': {name: digest(raw) for name, raw in records.items()},
            'sourceHashes': source_hashes}


def authenticate_role(role, records, authority, sources, observer_raw, verifier, clock=time.time):
    try:
        return _authenticate_role(role, records, authority, sources, observer_raw, verifier, clock)
    except TransactionDenied:
        raise
    except Exception as error:
        reason = str(error)
        if not re.fullmatch('[A-Z][A-Z0-9_]{0,95}', reason):
            reason = 'COMPLETE_TARGET_AUTHENTICATION_UNPROVEN'
        raise TransactionDenied('AUTHENTICATE_TARGET_TRANSACTION', reason, role) from None


def validate_pair_closure(checked):
    """One reciprocal-declaration contract at preflight and signed publication."""
    stage='VERIFY_TWO_CANDIDATE_INPUT_CLOSURE'
    require(set(checked)==set(TARGETS),stage,'EXACT_TWO_TARGET_ROLES_REQUIRED')
    from tools.semantic_provider_peer_bindings import declarations
    for role,value in checked.items():
        for peer in declarations(value['template']['candidate']['transport'],TARGETS[role]['containerId']):
            other=[v for r,v in checked.items() if r!=role and TARGETS[r]['containerId']==peer['containerId']]
            require(len(other)==1,stage,'EXACT_COHORT_SIBLING_REQUIRED',role)
            same(peer,{'applicationHash':digest(encoded(other[0]['policy']['expectedOci'])),
                       'networkBindings':other[0]['template']['candidate']['networkBindings']},
                 stage,'COMPLETE_SIBLING_DECLARATION_DRIFT',role)


def preflight_input_pair(records_by_role):
    """Pure unsigned check before claims/keys; this grants no role authority.

    Recompile complete expected policies from independently prepared inputs.
    Actual root mandates and later signatures remain separately mandatory.
    """
    stage='PREFLIGHT_TWO_CANDIDATE_INPUTS'
    require(set(records_by_role)==set(TARGETS),stage,'EXACT_TWO_TARGET_ROLES_REQUIRED')
    checked={}
    for role,records in records_by_role.items():
        values={name:decode(raw,131072) for name,raw in records.items()}
        policy=compile_policy(values['template'],values['launch'],values['context'])
        require(encoded(policy)==records['framePolicy'],stage,'COMPLETE_COMPILED_POLICY_DRIFT',role)
        validate_preparer_template(values['preparerTemplate'],role)
        same(values['context'],{'containerId':TARGETS[role]['containerId']},stage,'CONTEXT_CANDIDATE_DRIFT',role)
        same(values['preparerTemplate']['candidate'],{'containerId':TARGETS[role]['containerId']},
             stage,'PREPARER_CANDIDATE_SCOPE_DRIFT',role)
        checked[role]={'policy':policy,'template':values['preparerTemplate']}
    validate_pair_closure(checked)


def build_install_plan(root, source_root, records_by_role, authority, sources,
                       observer_raw, python, crypto, verifier, runtime_adapter, clock=time.time):
    """Compile both candidate profiles and exact adapter configuration in memory.

    The caller retains original signed bytes and publishes durably under existing
    locks only after separately checking target custody and unchanged empty guard.
    This plan does not install an allowlist or grant runtime start/lease authority.
    """
    stage = 'ASSEMBLE_AUTHENTICATED_TRANSACTION'
    for path in (root, source_root):
        require(type(path) is str and str(PurePosixPath(path)) == path
                and PurePosixPath(path).is_absolute() and '..' not in PurePosixPath(path).parts,
                stage, 'EXACT_TRANSACTION_PATH_REQUIRED')
    require(set(records_by_role) == set(TARGETS), stage, 'EXACT_TWO_TARGET_ROLES_REQUIRED')
    require(type(verifier) is DetachedAuthenticator
            and verifier.policy_binding == crypto['policyBinding']
            and str(verifier.signature_directory) == crypto['signatureDirectory']
            and verifier.openssl_binding == crypto['opensslBinding'],
            stage, 'VERIFIER_PROFILE_BINDING_DRIFT')
    adapter_fields = {'schema','sourceHash','runtimePath','runtimeSha256','pythonPath','pythonSha256',
        'driverPath','driverSha256','admissionPath','admissionSha256','registryRoot','runtimeStateRoot','candidates'}
    require(set(runtime_adapter) == adapter_fields and runtime_adapter['schema'] == 'ouf.semantic-docker-runtime-adapter.v4'
            and runtime_adapter['candidates'] == {}, stage, 'EMPTY_V4_RUNTIME_CONFIGURATION_REQUIRED')
    require(runtime_adapter['pythonPath'] == python['path'] and runtime_adapter['pythonSha256'] == python['sha256'],
            stage, 'ADAPTER_INTERPRETER_DRIFT')
    checked = {role: authenticate_role(role, records, authority, sources, observer_raw, verifier, clock)
               for role, records in records_by_role.items()}
    require(len({v['intent']['transactionId'] for v in checked.values()}) == 2,
            stage, 'DISTINCT_ROLE_TRANSACTIONS_REQUIRED')
    validate_pair_closure(checked)
    registry = root + '/registry'
    adapter = copy.deepcopy(runtime_adapter)
    for field, relative in (('sourceHash', 'scripts/semantic_provider_docker_runtime.py'),
                            ('driverSha256', 'scripts/semantic_provider_preexec_hook.py'),
                            ('admissionSha256', 'scripts/semantic_provider_deployment_broker.py')):
        adapter[field] = digest(sources[relative])
    adapter.update(driverPath=source_root+'/scripts/semantic_provider_preexec_hook.py',
                   admissionPath=source_root+'/scripts/semantic_provider_deployment_broker.py', registryRoot=registry)
    files = {}
    limits = {'maxEntries': 100000, 'maxDepth': 64, 'maxBytes': 8589934592}
    for role, value in checked.items():
        cid = TARGETS[role]['containerId']; directory = registry + '/' + cid
        raw = records_by_role[role]
        template = value['template']
        require(template['pythonPath'] == python['path'] and template['pythonHash'] == python['sha256']
                and template['candidate']['runtimeBinding'] == {'path': adapter['runtimePath'], 'sha256': adapter['runtimeSha256']},
                stage, 'PREPARER_RUNTIME_OR_INTERPRETER_DRIFT', role)
        bind = lambda name, filename: {'path': directory+'/'+filename, 'sha256': digest(raw[name])}
        profiles = assemble_profiles(directory, source_root, sources, authority, python, crypto,
            bind('intent', 'intent.json'), value['intent'], template, bind('finalMandate', 'final-mandate.json'),
            {'python': python, 'source': {'path': source_root+'/frame-observer.py', 'sha256': digest(observer_raw)},
             'configuration': bind('framePolicy', 'frame-policy.json')},
            [adapter['runtimeStateRoot']], [registry], limits)
        for name, content in profiles.items(): files[directory+'/'+name] = encoded(content)
        for name, filename in (('intent', 'intent.json'), ('finalMandate', 'final-mandate.json'),
                               ('liveAuthorization', 'live-authorization.json'), ('framePolicy', 'frame-policy.json'),
                               ('review', 'target-review.json')):
            files[directory+'/'+filename] = raw[name]
        for name, content in raw.items():
            files[directory+'/inputs/'+name+'.json'] = content
        adapter['candidates'][cid] = {'intentRef': digest(raw['intent']),
            'bundleParents': [decode(raw['context'],131072)['bundleParent']],
            'admissionConfiguration': directory+'/broker.json',
            'admissionConfigurationHash': digest(files[directory+'/broker.json'])}
        files[directory+'/operation.lock'] = b''
    for cid in adapter['candidates']:
        binding = digest(encoded({**{k: v for k, v in adapter.items() if k != 'candidates'},
                                  'candidate': adapter['candidates'][cid]}))
        files[registry+'/'+cid+'/adapter.json'] = encoded({'schema': 'ouf.semantic-docker-runtime-journal.v1',
            'containerId': cid, 'configurationHash': binding, 'state': 'STAGED',
            'runtimeRoot': None, 'bundleHash': None, 'driverHash': None})
    return {'files': files, 'adapterConfiguration': adapter,
            'inputHashes': {role: v['inputHashes'] for role, v in checked.items()},
            'sourceHashes': checked['adapter']['sourceHashes'],
            'status': 'AUTHENTICATED_INSTALL_PLAN_ASSEMBLED', 'targetWrites': 0,
            'startAuthorized': False, 'leaseAuthorized': False, 'privateKeysRead': 0,
            'containerLifecycleOperations': 0, 'notReleaseAcceptance': True}
