"""Assemble broker/node/installer profiles from externally authorized inputs.

Pure assembly only: no keys, signatures, Docker, firewall, or writes. Callers
must authenticate the intent and mandates before installing the returned files.
Image equivalence is evidence, never an authorization or a replacement v1 seal.
"""
import ast
import copy
import hashlib
import json
from pathlib import PurePosixPath


class AssemblyDenied(ValueError):
    def __init__(self, code, role=None):
        self.diagnosis = {'status': 'BLOCKED', 'stage': 'ASSEMBLE_PROFILES',
                          'reason': code, 'role': role, 'secretValuesPrinted': False}
        super().__init__(code)


def require(value, reason):
    if not value:
        raise AssemblyDenied(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def source_closure(sources, entrypoint):
    """Read the actual CLI's static loader declaration, never import its code."""
    tree = ast.parse(sources[entrypoint])
    values = {}
    for statement in tree.body:
        if isinstance(statement, ast.Assign):
            for name in statement.targets:
                if isinstance(name, ast.Name) and name.id in {'SELF', 'MODULES', 'PREPARER', 'DRIVER'}:
                    values[name.id] = ast.literal_eval(statement.value)
    require(values.get('SELF') == entrypoint and isinstance(values.get('MODULES'), tuple),
            'SOURCE_CLOSURE_DECLARATION_REQUIRED')
    paths = [entrypoint, *('tools/' + name + '.py' for name in values['MODULES'])]
    paths.extend(values[k] for k in ('PREPARER', 'DRIVER') if k in values)
    require(all(p in sources for p in paths), 'SOURCE_CLOSURE_INCOMPLETE')
    return {p: digest(sources[p]) for p in paths}


def approved_runtime_seal(comparison, cid, frame_policy, live_authorization):
    require(comparison.get('status') == 'IMAGE_EQUIVALENCE_PASS'
            and comparison.get('imageEquivalent') is True, 'IMAGE_EQUIVALENCE_REQUIRED')
    selected = [r for r in comparison['roles'] if r['containerId'] == cid]
    require(len(selected) == 1, 'EXACT_COMPARISON_CANDIDATE_REQUIRED')
    record = selected[0]
    equivalence = record['imageEquivalence']
    require(record['neverStarted'] is True and record['exportMountReleased'] is True
            and equivalence['equivalent'] is True
            and equivalence['differences']['differentEntryCount'] == 0,
            'COMPLETE_IMAGE_EQUIVALENCE_REQUIRED')
    seal = record['actualSeal']
    require(set(seal) == {'schema', 'sha256', 'entries', 'bytes'}
            and seal['schema'] == 'ouf.semantic-rootfs-seal.v1', 'ACTUAL_V1_RUNTIME_SEAL_REQUIRED')
    require(live_authorization['containerId'] == cid
            and live_authorization['applicationHash'] == digest(encoded(frame_policy['expectedOci']))
            and live_authorization['artifactHash'] == digest(encoded(frame_policy)),
            'AUTHORIZATION_COMPLETE_FRAME_SCOPE_DRIFT')
    require(live_authorization['rootfsSeal'] == seal, 'AUTHORIZATION_RUNTIME_SEAL_DRIFT')
    # Do not substitute the portable image digest for the full node seal.
    return copy.deepcopy(seal)


def assemble_profiles(root, source_root, sources, authority, python, crypto,
                      intent_binding, intent, template, final_mandate_binding,
                      observer_binding, runtime_parents, bundle_parents, rootfs_limits):
    """Return exact CLI profiles and initial journals, without activating them.

    Signed-authority validation is deliberately left in the existing production
    CLIs, and must also be performed by an installation orchestrator. This
    function does not sign or manufacture mandate acceptance.
    """
    for path in (root, source_root):
        require(PurePosixPath(path).is_absolute() and '..' not in PurePosixPath(path).parts,
                'ABSOLUTE_PROFILE_ROOT_REQUIRED')
    root = str(PurePosixPath(root))
    require(set(authority) == {'authorities', 'keyBindings', 'keyRefs'}, 'AUTHORITY_BINDINGS_REQUIRED')
    authorities = authority['authorities']
    require(all(intent[k] == authorities[k] for k in ('installationRef', 'entityRef'))
            and intent['issuerRef'] == authorities['intentIssuerRef'], 'INTENT_AUTHORITY_SCOPE_DRIFT')
    require(intent_binding['sha256'] == digest(encoded(intent)), 'INTENT_PAYLOAD_BINDING_DRIFT')
    candidate = template['candidate']
    require(candidate['containerId'] == intent['containerId']
            and candidate['transactionId'] == intent['transactionId']
            and candidate['runtimeBinding']['sha256'] == intent['runtimeExecutableHash'],
            'CANDIDATE_INTENT_SCOPE_DRIFT')
    require(digest(encoded({k: candidate[k] for k in ('networkBindings', 'transport', 'tableName')}))
            == intent['transportHash'], 'SIGNED_TRANSPORT_SCOPE_DRIFT')
    require(observer_binding['configuration']['sha256'] == intent['artifactHash'],
            'SIGNED_FRAME_ARTIFACT_DRIFT')
    require(set(crypto) == {'policyBinding', 'signatureDirectory', 'opensslBinding'},
            'EXACT_VERIFICATION_BINDINGS_REQUIRED')
    require(set(authority['keyBindings']) == set(authority['keyRefs']) == {'installer', 'attestor'},
            'EXISTING_ROLE_KEYS_REQUIRED')
    files = {'preparer-template.json': copy.deepcopy(template)}
    common = {'sourceRoot': source_root, 'pythonBinding': python,
              'authorities': authorities, 'intentBinding': intent_binding, **crypto, 'budgetSeconds': 12}
    node_entry = 'scripts/semantic_provider_node_attestor.py'
    node = {'schema': 'ouf.semantic-node-attestor.v4', **common,
            'sourceHashes': source_closure(sources, node_entry),
            'acceptanceMandatePath': root + '/node-acceptance.json',
            'signingKeyBinding': authority['keyBindings']['attestor'], 'keyRef': authority['keyRefs']['attestor'],
            'brokerEmissionJournal': root + '/attestation-emission.json',
            'brokerStateJournal': root + '/broker-state.json', 'issuanceClaimPath': root + '/node-signing-claim.json',
            'runtimeBinding': candidate['runtimeBinding'], 'runtimeRootParents': runtime_parents,
            'bundleParents': bundle_parents,
            'commands': {k: {'path': template['commands'][k], 'sha256': template['commandHashes'][k]}
                         for k in ('ip', 'nsenter')},
            'candidate': {k: candidate[k] for k in ('networkBindings', 'transport', 'tableName')},
            'rootfsLimits': rootfs_limits, 'creationFrameObserverBinding': observer_binding,
            'liveAcceptanceAuthorizationPath': root + '/live-authorization.json'}
    approval_entry = 'scripts/semantic_provider_installer_approval.py'
    approval = {'schema': 'ouf.semantic-installer-approval-producer.v1', **common,
                'sourceHashes': source_closure(sources, approval_entry),
                'attestationPath': root + '/attestation.json', 'approvalMandateBinding': final_mandate_binding,
                'signingKeyBinding': authority['keyBindings']['installer'], 'keyRef': authority['keyRefs']['installer'],
                'brokerEmissionJournal': root + '/approval-emission.json',
                'issuanceClaimPath': root + '/installer-signing-claim.json'}
    files.update({'attestation-producer.json': node, 'approval-producer.json': approval})
    def binding(path, value):
        return {'path': path, 'sha256': digest(encoded(value))}
    producers = {}
    for role, entry, filename in (('attestation', node_entry, 'attestation-producer.json'),
                                 ('approval', approval_entry, 'approval-producer.json')):
        producers[role] = {'python': python, 'source': {'path': source_root + '/' + entry,
                           'sha256': digest(sources[entry])},
                           'configuration': binding(root + '/' + filename, files[filename])}
    broker = {'schema': 'ouf.semantic-deployment-broker.v1', 'sourceRoot': source_root,
              'sourceHashes': source_closure(sources, 'scripts/semantic_provider_deployment_broker.py'),
              'authorities': authorities, 'intentBinding': intent_binding, **crypto, 'producers': producers,
              'preparerTemplate': binding(root + '/preparer-template.json', template),
              'candidateRoot': root, 'runtimeRootParent': '/run'}
    files['broker.json'] = broker
    scope = {k: intent[k] for k in ('installationRef', 'entityRef', 'containerId', 'transactionId')}
    scope.update(intentHash=intent_binding['sha256'], configurationHash=digest(encoded(broker)))
    files['broker-state.json'] = {'schema': 'ouf.semantic-deployment-broker-journal.v1', **scope,
                                  'state': 'STAGED', 'runtimeRoot': None, 'bundleHash': None, 'driverHash': None}
    files['deployment.json'] = {'schema': 'ouf.semantic-deployment-consumption.v1', **scope, 'state': 'STAGED',
                               'bundleHash': None, 'generation': None, 'evidenceHash': None,
                               'approvalHash': None, 'driverHash': None}
    return copy.deepcopy(files)
