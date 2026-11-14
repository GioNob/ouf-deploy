"""Governed v1 -> v2 upgrade of the same logical Registry credential owner (task-30b, D-031).

The live v1 installation is bound by hash and read only until the approved
install. The install stops v1, reads its final counter under both locks,
writes the v2 ledger, signs a dated v2 receipt (attestor), then switches the
global and v1 fences by exact compare-and-swap and activates v2's fence.
Start enables v2. Rollback restores v1 only while v2 has never published.
No container, IAM permission or database change; no automatic replay.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from .core import require, digest, encoded

UPGRADE_REVIEW_SCHEMA = 'ouf.registry-operational-upgrade-review.v1'
UPGRADE_PROPOSAL_SCHEMA = 'ouf.registry-operational-upgrade-proposal.v1'
UPGRADE_RESULT_SCHEMA = 'ouf.registry-operational-upgrade-result.v1'
ROLLBACK_PLAN_SCHEMA = 'ouf.registry-operational-upgrade-rollback-plan.v1'
V1_RECEIPT_SCHEMA = 'ouf.registry-operational-token-installation-receipt.v1'
V2_RECEIPT_SCHEMA = 'ouf.registry-operational-token-installation-receipt.v2'
IN_FLIGHT = frozenset(('RESERVED', 'DISPATCHING', 'PUBLISHING'))
CONFIG_KEYS = ('schema', 'proposalHash', 'sourceManifest', 'sources', 'ownerInputs', 'policy', 'destinations',
               'priorControlledAttempts', 'predecessorInputsHash', 'fenceBinding', 'commonLockIdentity',
               'verification', 'tlsCa', 'serviceUnitPath', 'hostBootIdPath')
ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
CONTROL_ROOT = '/etc/systemd/system.control'
PROJECTION_DROPIN = '50-IPAddressAllow.conf'


def projection_allowlist(unit_path, profile_peers, control_root=CONTROL_ROOT):
    """The v1 unit's persistent IPAddressAllow projection (October repair), bound by hash.

    Returns {'path', 'sha256', 'extra'}: the extra single-host networks beyond the
    profile peers, or None when v1 has no projection drop-in. The upgrade must
    reproduce exactly these egress permissions, never widen them.
    """
    import ipaddress
    from .guard import protected_file
    path = Path(control_root) / (Path(unit_path).name + '.d') / PROJECTION_DROPIN
    if not os.path.lexists(path):
        return None
    raw = protected_file(path, 4096, modes=(0o644, 0o600, 0o400))
    lines = [line.strip() for line in raw.decode('ascii').splitlines() if line.strip() and not line.startswith('#')]
    require(lines[:1] == ['[Service]'] and len(lines) >= 2, 'EXACT_V1_IP_PROJECTION_REQUIRED')
    networks = []
    for line in lines[1:]:
        require(line.startswith('IPAddressAllow='), 'EXACT_V1_IP_PROJECTION_REQUIRED')
        for word in line.split('=', 1)[1].split():
            try:
                network = ipaddress.ip_network(word, strict=True)
            except ValueError:
                require(False, 'EXACT_V1_IP_PROJECTION_REQUIRED')
            require(network.prefixlen == network.max_prefixlen, 'SINGLE_HOST_V1_IP_PROJECTION_REQUIRED')
            networks.append(str(network))
    peers = {str(ipaddress.ip_network(ip + '/' + str(ipaddress.ip_address(ip).max_prefixlen))) for ip in profile_peers}
    extra = sorted(set(networks) - peers)
    require(set(networks) >= peers and 1 <= len(extra) <= 4, 'BOUNDED_V1_IP_PROJECTION_REQUIRED')
    return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest(), 'extra': extra}


def projected_unit(c, review_executables, projection):
    """v2 unit body: the reviewed service unit plus v1's exact IP projection."""
    from .installation import service_unit
    body = service_unit(c, digest(c), review_executables['python']['path'], c['destinations']['installationRoot'] + '/capsule.py')
    if projection is None:
        return body
    lines = body.decode('ascii').split('\n')
    last = max(i for i, line in enumerate(lines) if line.startswith('IPAddressAllow='))
    lines[last + 1:last + 1] = ['IPAddressAllow=' + network for network in projection['extra']]
    return '\n'.join(lines).encode('ascii')


def systemctl(review, args, runner=subprocess.run, check=True, timeout=60):
    program = review['executables']['systemctl']['path']
    result = runner([program, *args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    timeout=timeout, env=ENV)
    if check:
        require(result.returncode == 0, 'UPGRADE_MANAGER_COMMAND_REQUIRES_RECONCILIATION')
    out = result.stdout if isinstance(result.stdout, bytes) else (result.stdout or '').encode()
    require(len(out) <= 4096, 'BOUNDED_MANAGER_OBSERVATION_REQUIRED')
    return result.returncode, out.decode('ascii', 'replace')


def unit_state(review, unit, runner=subprocess.run):
    _, out = systemctl(review, ['show', Path(unit).name, '--property=ActiveState,UnitFileState', '--no-pager'], runner)
    values = dict(line.split('=', 1) for line in out.splitlines() if '=' in line)
    require(set(values) == {'ActiveState', 'UnitFileState'}, 'EXACT_NATIVE_MANAGER_PROPERTIES_REQUIRED')
    return values


# --- predecessor binding --------------------------------------------------------

def predecessor(v1_configuration_path, v1_configuration_sha256, global_fence_path, control_root=CONTROL_ROOT):
    """Bind the live v1 installation by hash. Read only."""
    from .installation import read_object
    from .guard import protected_file
    from .store import file_identity
    from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
    require(re.fullmatch('[a-f0-9]{64}', v1_configuration_sha256) is not None, 'EXACT_PREDECESSOR_CONFIGURATION_REQUIRED')
    c1 = read_object(v1_configuration_path, expected=v1_configuration_sha256)
    require(tuple(sorted(c1)) == tuple(sorted(CONFIG_KEYS)) and c1['schema'] == 'ouf.registry-operational-token-configuration.v1'
            and c1['priorControlledAttempts'] == 321
            and set(c1['verification']) == {'trustPolicy', 'openssl', 'context'}, 'EXACT_V1_CONFIGURATION_REQUIRED')
    root = Path(c1['destinations']['installationRoot'])
    require(Path(v1_configuration_path) == root / 'configuration.json', 'V1_CONFIGURATION_IN_ITS_INSTALLATION_ROOT_REQUIRED')
    receipt_raw = protected_file(root / 'installed.json', 1048576, modes=(0o400, 0o600))
    receipt = json.loads(receipt_raw)
    require(encoded(receipt) == receipt_raw and receipt.get('schema') == V1_RECEIPT_SCHEMA
            and receipt.get('complete') is True and receipt.get('configurationHash') == v1_configuration_sha256
            and receipt.get('serviceUnitPath') == c1['serviceUnitPath'], 'COMPLETED_V1_INSTALLATION_REQUIRED')
    unit_raw = protected_file(c1['serviceUnitPath'], 65536, expected=receipt['serviceUnitHash'], modes=(0o600, 0o644))
    require(('--configuration-sha256 ' + v1_configuration_sha256 + '\n').encode() in unit_raw,
            'V1_UNIT_PINS_ITS_CONFIGURATION_REQUIRED')
    ctx = c1['verification']['context']
    verifier = DetachedAuthenticator(c1['verification']['trustPolicy'], str(root / 'receipt-signatures'),
                                     c1['verification']['openssl'])
    require(verifier(receipt_raw, 'CREATION_ATTESTATION', ctx['attestorRef'], ctx['installationRef'], ctx['entityRef']) is True,
            'CURRENT_V1_RECEIPT_SIGNATURE_REQUIRED')
    fence = c1['fenceBinding']
    require(type(fence['value']) is dict and fence['value'].get('active') is True
            and read_object(fence['path']) == fence['value'], 'ACTIVE_V1_FENCE_REQUIRED')
    require(read_object(global_fence_path) == fence['value'], 'GLOBAL_FENCE_NAMES_V1_REQUIRED')
    require(list(file_identity(Path(c1['destinations']['commonInvocationLock']).lstat())) == c1['commonLockIdentity'],
            'SAME_LOGICAL_OWNER_COMMON_LOCK_REQUIRED')
    projection = projection_allowlist(c1['serviceUnitPath'], c1['ownerInputs']['iamProfile']['peer_addresses'], control_root)
    return {'configuration': c1, 'configurationPath': str(v1_configuration_path), 'configurationSha256': v1_configuration_sha256,
            'ipProjection': projection, 'controlRoot': str(control_root),
            'receiptSha256': hashlib.sha256(receipt_raw).hexdigest(),
            'unit': {'path': c1['serviceUnitPath'], 'sha256': receipt['serviceUnitHash']},
            'fence': copy.deepcopy(fence), 'globalFence': {'path': str(global_fence_path), 'value': copy.deepcopy(fence['value'])}}


# --- review ------------------------------------------------------------------

def compose(pred, manifest, capsule_source, authority_inputs, *, attempt, unit_parent, mandate_ledger_root,
            authority_public):
    """Exact v2 configuration, unit and review for one upgrade attempt. No writes."""
    from .installation import service_unit, absolute
    require(type(attempt) is int and 1 <= attempt <= 9, 'BOUNDED_UPGRADE_ATTEMPT_REQUIRED')
    c1 = pred['configuration']
    logical = c1['fenceBinding']['value']['logicalOwnerScopeHash']
    require(re.fullmatch('[a-f0-9]{64}', logical) is not None, 'EXACT_LOGICAL_REGISTRY_OWNER_REQUIRED')
    parent = str(Path(c1['destinations']['installationRoot']).parent)
    absolute(unit_parent)
    suffix = 'v2-' + str(attempt) + '-' + logical
    root = parent + '/semantic-registry-operational-' + suffix
    destinations = {'installationRoot': root, 'ledgerRoot': parent + '/semantic-registry-operational-state-' + suffix,
                    'commonInvocationLock': c1['destinations']['commonInvocationLock']}
    proposal = {'schema': UPGRADE_PROPOSAL_SCHEMA, 'predecessorConfigurationHash': pred['configurationSha256'],
                'sourceManifest': manifest, 'policy': c1['policy'], 'ownerInputs': c1['ownerInputs'],
                'destinations': destinations, 'attempt': attempt}
    old_capsule = c1['destinations']['installationRoot'] + '/capsule.py'
    sources = [{'path': root + '/capsule.py', 'sha256': capsule_source['sha256'], 'maximumBytes': 2097152}]
    sources.extend(copy.deepcopy(s) for s in c1['sources'] if s['path'] != old_capsule)
    require(len(sources) == len(c1['sources']), 'SAME_V1_EXECUTION_BINDINGS_REQUIRED')
    fence = {'path': root + '/fence/fence.json', 'value': {
        'schema': 'ouf.registry-operational-owner-fence.v1', 'logicalOwnerScopeHash': logical,
        'proposalHash': digest(proposal), 'sourceManifestHash': digest(manifest), 'journalPath': destinations['ledgerRoot'],
        'installationRoot': root, 'predecessorWorkerHash': pred['configurationSha256'], 'priorControlledAttempts': 321,
        'operationalFencePath': root + '/fence/fence.json', 'active': True}}
    verification = dict(copy.deepcopy(c1['verification']), mandateLedgerRoot=absolute(mandate_ledger_root))
    c2 = {'schema': c1['schema'], 'proposalHash': digest(proposal), 'sourceManifest': manifest, 'sources': sources,
          'ownerInputs': copy.deepcopy(c1['ownerInputs']), 'policy': copy.deepcopy(c1['policy']),
          'destinations': destinations, 'priorControlledAttempts': 321,
          'predecessorInputsHash': pred['configurationSha256'], 'fenceBinding': fence,
          'commonLockIdentity': list(c1['commonLockIdentity']), 'verification': verification,
          'tlsCa': {'path': root + '/iam-ca.pem', 'sha256': c1['tlsCa']['sha256']},
          'serviceUnitPath': unit_parent + '/ouf-registry-token-v2-' + str(attempt) + '-' + logical[:24] + '.service',
          'hostBootIdPath': c1['hostBootIdPath']}
    body = projected_unit(c2, authority_inputs['executables'], pred['ipProjection'])
    public = {k: v for k, v in pred.items() if k != 'configuration'}
    review = {'schema': UPGRADE_REVIEW_SCHEMA, 'predecessor': public, 'proposal': proposal, 'configuration': c2,
              'serviceUnit': {'path': c2['serviceUnitPath'], 'sha256': hashlib.sha256(body).hexdigest(),
                              'body': body.decode('ascii')},
              'capsuleSource': capsule_source,
              'publicCaSource': {'path': c1['tlsCa']['path'], 'sha256': c1['tlsCa']['sha256']},
              'verification': verification, 'executables': authority_inputs['executables'],
              'authorityProfile': authority_inputs['authorityProfile'], 'stdlibHash': authority_inputs['stdlibHash'],
              'stdlibFileCount': authority_inputs['stdlibFileCount'], 'logicalOwnerScopeHash': logical,
              'attempt': attempt, 'maximumInstallationSeconds': 900, 'maximumInitialPublicationWaitSeconds': 45,
              'retainedCounterReadUnderLocksAtInstall': True, 'runtimeAuthorityIssued': False,
              'targetApplyAuthorized': False, 'releaseAcceptance': False, 'authorityInputs': authority_public}
    upgrade_scope(review)
    return review


def upgrade_scope(review):
    """Approval scope of one upgrade review; same shape as the installation scope."""
    from .installation import service_unit
    require(type(review) is dict and review.get('schema') == UPGRADE_REVIEW_SCHEMA, 'COMPLETE_UPGRADE_REVIEW_REQUIRED')
    c, proposal, unit, pred = review['configuration'], review['proposal'], review['serviceUnit'], review['predecessor']
    require(c['proposalHash'] == digest(proposal) and c['sourceManifest'] == proposal['sourceManifest']
            and c['policy'] == proposal['policy'] and c['ownerInputs'] == proposal['ownerInputs']
            and c['destinations'] == proposal['destinations']
            and c['predecessorInputsHash'] == proposal['predecessorConfigurationHash'] == pred['configurationSha256']
            and c['priorControlledAttempts'] == 321 and review['maximumInstallationSeconds'] == 900
            and review['runtimeAuthorityIssued'] is False and review['targetApplyAuthorized'] is False
            and review['releaseAcceptance'] is False and review['verification'] == c['verification'],
            'EXACT_COMPLETE_UPGRADE_REVIEW_BINDINGS_REQUIRED')
    require(unit['path'] == c['serviceUnitPath'] and unit['sha256'] == hashlib.sha256(unit['body'].encode('ascii')).hexdigest()
            and unit['body'].encode('ascii') == projected_unit(c, review['executables'], pred['ipProjection']),
            'EXACT_RECOMPILED_UPGRADE_SERVICE_UNIT_REQUIRED')
    return {'schema': 'ouf.registry-operational-installation-scope.v1', 'reviewHash': digest(review),
            'configurationHash': digest(c), 'sourceManifestHash': digest(c['sourceManifest']),
            'serviceUnitHash': unit['sha256'], 'policyHash': digest(c['policy']),
            'predecessorInputsHash': c['predecessorInputsHash'], 'priorControlledAttempts': 321,
            'normalRenewalAfterInstallation': True, 'sameAttemptRedispatchAllowed': False,
            'legacyFiniteBudgetExtended': False, 'nativeRecoveryReplayAllowed': False,
            'containerLifecycleOperationsAllowed': False, 'iamPermissionChangesAllowed': False}


def rebind(review):
    """Recompose the review from the live predecessor; any drift stops."""
    pred = predecessor(review['predecessor']['configurationPath'], review['predecessor']['configurationSha256'],
                       review['predecessor']['globalFence']['path'], review['predecessor']['controlRoot'])
    authority_inputs = {'executables': review['executables'], 'authorityProfile': review['authorityProfile'],
                        'stdlibHash': review['stdlibHash'], 'stdlibFileCount': review['stdlibFileCount']}
    expected = compose(pred, review['configuration']['sourceManifest'], review['capsuleSource'], authority_inputs,
                       attempt=review['attempt'], unit_parent=str(Path(review['serviceUnit']['path']).parent),
                       mandate_ledger_root=review['verification']['mandateLedgerRoot'],
                       authority_public=review['authorityInputs'])
    require(expected == review, 'UPGRADE_PREDECESSOR_OR_REVIEW_CHANGED')
    return pred


# --- install -----------------------------------------------------------------

def cas(path, expected, value):
    """Exact compare-and-swap of one canonical fence file, same directory."""
    from .installation import directory, new_file, read_object
    from .store import file_identity
    path = Path(path)
    with directory(path.parent) as parent:
        before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        require(read_object(path) == expected, 'FENCE_CAS_EXPECTED_VALUE_REQUIRED')
        temporary = 'upgrade-' + hashlib.sha256(encoded(value)).hexdigest()[:16] + '.tmp'
        new_file(parent, temporary, encoded(value))
        require(file_identity(before) == file_identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False))
                and read_object(path) == expected, 'FENCE_CAS_CONFLICT')
        os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    require(read_object(path) == value, 'FENCE_CAS_READBACK_REQUIRED')


def wait_inactive(review, unit, runner, sleep=time.sleep, timeout=60):
    deadline = time.monotonic() + timeout
    while unit_state(review, unit, runner)['ActiveState'] not in ('inactive', 'failed'):
        require(time.monotonic() < deadline, 'V1_WORKER_DID_NOT_STOP')
        sleep(0.5)


def install(review, authority, attestor, runner=subprocess.run, sleep=time.sleep):
    """One approved upgrade attempt; claims survive every failure (no replay)."""
    from .installation import (SignedInstallation, directory, new_file, read_object, key_isolation)
    from .guard import protected_file
    from .core import initial, validate, RenewalPolicy
    from .store import Store, file_identity
    from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
    require(type(authority) is SignedInstallation and authority.review == review and type(attestor) is ExistingEd25519Signer
            and attestor.verifier is authority.verifier, 'ACTUAL_SIGNED_UPGRADE_AND_EXISTING_ATTESTOR_REQUIRED')
    ctx = review['verification']['context']
    require(attestor.scope == dict(role='CREATION_ATTESTATION', issuerRef=ctx['attestorRef'],
                                   installationRef=ctx['installationRef'], entityRef=ctx['entityRef']),
            'EXACT_EXISTING_UPGRADE_ATTESTOR_REQUIRED')
    c = review['configuration']
    key_isolation(c, [attestor.key['path']])
    authority.check()
    pred = rebind(review)
    c1 = pred['configuration']
    root, ledger, unit = Path(c['destinations']['installationRoot']), Path(c['destinations']['ledgerRoot']), Path(c['serviceUnitPath'])
    require(root.parent == ledger.parent == Path(c1['destinations']['installationRoot']).parent, 'SIBLING_UPGRADE_ROOTS_REQUIRED')
    capsule = protected_file(review['capsuleSource']['path'], 2097152, expected=review['capsuleSource']['sha256'], modes=(0o400, 0o600))
    ca = protected_file(review['publicCaSource']['path'], 4194304, expected=review['publicCaSource']['sha256'], modes=(0o400, 0o600))
    p = dict(c['policy'])
    p['failure_delays'] = tuple(p['failure_delays'])
    policy = RenewalPolicy(**p)
    claim = 'operational-upgrade-' + review['logicalOwnerScopeHash'] + '-' + str(review['attempt']) + '.claim.json'
    with directory(root.parent) as parent, directory(unit.parent) as unit_parent:
        new_file(parent, claim, encoded({'schema': 'ouf.registry-operational-upgrade-claim.v1', 'reviewHash': digest(review),
                                         'authorityHash': hashlib.sha256(authority.raw).hexdigest(),
                                         'automaticReplayAllowed': False, 'budgetReset': False}))
        for target in (root, ledger):
            os.mkdir(target.name, 0o700, dir_fd=parent)
        os.fsync(parent)
        with directory(root) as files:
            os.mkdir('sandbox', 0o700, dir_fd=files)
            os.mkdir('fence', 0o700, dir_fd=files)
            os.mkdir('receipt-signatures', 0o700, dir_fd=files)
            os.fsync(files)
            with directory(root / 'sandbox') as sandbox:
                for name in ('usr', 'lib', 'lib64', 'etc', 'run', 'proc', 'dev'):
                    os.mkdir(name, 0o755, dir_fd=sandbox)
                os.mkdir('tmp', 0o1777, dir_fd=sandbox)
                os.fsync(sandbox)
            with directory(root / 'fence') as fence_files:
                new_file(fence_files, 'fence.json', encoded(dict(c['fenceBinding']['value'], active=False)))
            new_file(files, 'capsule.py', capsule, 0o400)
            new_file(files, 'iam-ca.pem', ca, 0o600)
            new_file(files, 'configuration.json', encoded(c), 0o600)
        authority.check()
        new_file(unit_parent, unit.name, review['serviceUnit']['body'].encode('ascii'), 0o644)
        # Stop v1 inside the HUMAN window: it holds the common lock for its whole life.
        new_file(parent, claim + '.stop-v1.json', encoded({'unit': pred['unit']['path'], 'attemptNotCompletion': True}))
        systemctl(review, ['stop', Path(pred['unit']['path']).name], runner)
        wait_inactive(review, pred['unit']['path'], runner, sleep)
        authority.check()
        from .installation import existing_lock
        v1_store = Store(c1['destinations']['ledgerRoot'])
        try:
            with existing_lock(c['destinations']['commonInvocationLock']) as common, v1_store.invocation():
                require(common == c['commonLockIdentity'], 'SAME_REVIEWED_COMMON_INVOCATION_LOCK_REQUIRED')
                row = validate(v1_store.read(), policy)
                require(row['installationHash'] == pred['configurationSha256'], 'V1_LEDGER_BINDING_REQUIRED')
                require(row['state'] not in IN_FLIGHT, 'V1_ATTEMPT_IN_FLIGHT_RECONCILE_FIRST')
                prior = row['cumulativeAttempts']
                boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
                state = initial(digest(c), c['predecessorInputsHash'], prior, policy, boot, (time.time(), time.monotonic()))
                with directory(ledger) as files:
                    new_file(files, 'state.json', encoded(state))
                    new_file(files, 'invocation.lock', b'')
                    new_file(files, 'cas.lock', b'')
                attested = int(time.time())
                authority.check()
                human = json.loads(protected_file(authority.human['path'], 131072, expected=authority.approved_human, modes=(0o600,)))
                require(human['issuedAt'] <= attested < human['expiresAt'], 'ATTESTATION_INSIDE_HUMAN_WINDOW_REQUIRED')
                receipt = {'schema': V2_RECEIPT_SCHEMA, 'complete': True, 'attestedAt': attested,
                           'configurationHash': digest(c), 'proposalHash': c['proposalHash'],
                           'sourceManifestHash': digest(c['sourceManifest']), 'operationalRenewalInstalled': True,
                           'priorControlledAttempts': prior, 'serviceUnitPath': str(unit),
                           'serviceUnitHash': review['serviceUnit']['sha256'], 'reviewHash': digest(review),
                           'authorityHash': hashlib.sha256(authority.raw).hexdigest(),
                           'installationClaimHash': digest(read_object(root.parent / claim))}
                signature = attestor.sign(encoded(receipt))
                authority.check()
                with directory(root / 'receipt-signatures') as signatures:
                    new_file(signatures, digest(receipt) + '.CREATION_ATTESTATION.json', signature)
                with directory(root) as files:
                    new_file(files, 'installed.json', encoded(receipt))
                # Commit order: global fence names v2, then v1's own fence stops v1,
                # then v2's fence is activated. Each step is an exact CAS.
                cas(pred['globalFence']['path'], pred['globalFence']['value'], c['fenceBinding']['value'])
                cas(pred['fence']['path'], pred['fence']['value'], dict(pred['fence']['value'], active=False))
                cas(c['fenceBinding']['path'], dict(c['fenceBinding']['value'], active=False), c['fenceBinding']['value'])
        finally:
            v1_store.close()
        result = {'schema': UPGRADE_RESULT_SCHEMA, 'status': 'V2_INSTALLED_V1_FENCED_NOT_STARTED', 'complete': True,
                  'reviewHash': digest(review), 'configurationHash': digest(c), 'retainedCumulativeAttempts': prior,
                  'predecessorConfigurationHash': pred['configurationSha256'], 'tokenGrants': 0,
                  'automaticReplayAllowed': False, 'budgetReset': False, 'releaseAcceptance': False}
        with directory(root) as files:
            new_file(files, 'installation-result.json', encoded(result))
        return result


def start(review, authority, runner=subprocess.run, sleep=time.sleep, reader=None):
    """Disable v1, enable v2, wait for the first v2 publication."""
    from .installation import read_object
    from .store import Store
    c = review['configuration']
    root = Path(c['destinations']['installationRoot'])
    require(read_object(root / 'installation-result.json')['complete'] is True, 'COMPLETED_UPGRADE_INSTALLATION_REQUIRED')
    authority.check()
    v1 = Path(review['predecessor']['unit']['path']).name
    v2 = Path(c['serviceUnitPath']).name
    for args in (['disable', '--now', v1], ['daemon-reload'], ['enable', '--now', v2]):
        authority.check()
        systemctl(review, args, runner)
    read = reader or (lambda: _read(c['destinations']['ledgerRoot']))
    deadline = time.monotonic() + review['maximumInitialPublicationWaitSeconds']
    row = read()
    while (row['state'] != 'ACTIVE' or row['publications'] < 1) and time.monotonic() < deadline:
        sleep(0.5)
        row = read()
    states = (unit_state(review, review['predecessor']['unit']['path'], runner), unit_state(review, c['serviceUnitPath'], runner))
    return {'schema': 'ouf.registry-operational-upgrade-observation.v1',
            'status': 'V2_ACTIVE_PUBLISHED' if row['state'] == 'ACTIVE' and row['publications'] >= 1 else 'V2_NOT_YET_PUBLISHED',
            'v1': states[0], 'v2': states[1], 'workerState': row['state'], 'publications': row['publications'],
            'controlledCumulativeGrantAttempts': row['cumulativeAttempts'], 'automaticReplayAllowed': False}


def _read(path):
    from .store import Store
    store = Store(path)
    try:
        return store.read()
    finally:
        store.close()


# --- rollback ----------------------------------------------------------------

def rollback_plan(review, reader=None):
    """Read only: which fences to restore; refused once v2 has published."""
    from .installation import read_object
    c = review['configuration']
    pred = review['predecessor']
    ledger = Path(c['destinations']['ledgerRoot'])
    row = None
    if (ledger / 'state.json').exists():
        row = (reader or (lambda: _read(str(ledger))))()
        require(row['publications'] == 0, 'V2_ALREADY_PUBLISHED_ROLLBACK_REFUSED')
    steps = []
    for name, path, original, upgraded in (
            ('globalFence', pred['globalFence']['path'], pred['globalFence']['value'], c['fenceBinding']['value']),
            ('v1Fence', pred['fence']['path'], pred['fence']['value'], dict(pred['fence']['value'], active=False))):
        current = read_object(path)
        if current == upgraded:
            steps.append({'fence': name, 'path': path, 'restore': True})
        else:
            require(current == original, 'UNEXPECTED_FENCE_STATE_RECONCILE_MANUALLY')
            steps.append({'fence': name, 'path': path, 'restore': False})
    # Only stable facts are approved: a running v2 keeps counting failed attempts.
    return {'schema': ROLLBACK_PLAN_SCHEMA, 'reviewHash': digest(review), 'v2LedgerPresent': row is not None,
            'v2NeverPublished': True, 'steps': steps, 'v1Unit': pred['unit']['path'], 'v2Unit': c['serviceUnitPath']}


def rollback_apply(review, approved, runner=subprocess.run, reader=None):
    plan = rollback_plan(review, reader)
    require(digest(plan) == approved, 'FRESH_ROLLBACK_PLAN_HASH_MISMATCH')
    c = review['configuration']
    pred = review['predecessor']
    if os.path.lexists(c['serviceUnitPath']):
        systemctl(review, ['disable', '--now', Path(c['serviceUnitPath']).name], runner)
    for step in plan['steps']:
        if not step['restore']:
            continue
        if step['fence'] == 'globalFence':
            cas(step['path'], c['fenceBinding']['value'], pred['globalFence']['value'])
        else:
            cas(step['path'], dict(pred['fence']['value'], active=False), pred['fence']['value'])
    systemctl(review, ['daemon-reload'], runner)
    systemctl(review, ['enable', '--now', Path(pred['unit']['path']).name], runner)
    return {'schema': 'ouf.registry-operational-upgrade-rollback-result.v1', 'status': 'V1_RESTORED',
            'planSha256': approved, 'automaticReplayAllowed': False}


# --- capsule actions ---------------------------------------------------------

ACTIONS = ('upgrade-prepare', 'upgrade-issue', 'upgrade-install', 'upgrade-start', 'upgrade-rollback')


def issue(review, review_path):
    """Exact TTY approval of this upgrade review, then the installer's two roles."""
    import termios
    from .installation import (AUTHORITY_SCHEMA, HUMAN_SCHEMA, DECISION, SignedInstallation, directory, new_file,
                               read_object, source_custody, review_scope)
    from tools.semantic_registry_recovery_execution.postboot_authority import authority_metadata
    from tools.semantic_provider_deployment_authentication import DetachedAuthenticator
    from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
    rebind(review)
    source_custody(review)
    profile, _ = authority_metadata(review['authorityInputs'])
    prompt = ('\nAggiornamento del worker credenziali Registry da v1 a v2 (ricevuta datata, D-031). Revisione privata: '
              + str(review_path) + '\nSHA256: ' + digest(review)
              + '\nConfigurazione v1 sostituita: ' + review['predecessor']['configurationSha256']
              + "\nIl contatore cumulativo della v1 viene letto e conservato all'installazione; la v1 viene fermata dal suo fence."
              + '\nNessuna modifica a permessi IAM, container, gateway o database. Finestra: 900 secondi.'
              + '\nPer approvare questa revisione esatta scrivi: APPROVO ' + digest(review) + '\n> ')
    fd = os.open('/dev/tty', os.O_RDWR | os.O_NOCTTY | os.O_NOFOLLOW)
    try:
        require(stat.S_ISCHR(os.fstat(fd).st_mode) and os.isatty(fd), 'CONTROLLING_UPGRADE_TERMINAL_REQUIRED')
        termios.tcflush(fd, termios.TCIFLUSH)
        os.write(fd, prompt.encode())
        answer = bytearray()
        while len(answer) <= 128:
            char = os.read(fd, 1)
            if char in (b'', b'\n'):
                break
            answer.extend(char)
        require(bytes(answer) == ('APPROVO ' + digest(review)).encode(), 'EXACT_UPGRADE_NOT_APPROVED')
    finally:
        os.close(fd)
    require(read_object(review_path, expected=digest(review)) == review, 'UPGRADE_REVIEW_CHANGED_DURING_APPROVAL')
    rebind(review)
    source_custody(review)
    now = int(time.time())
    ctx = review['verification']['context']
    value = {'schema': AUTHORITY_SCHEMA, 'scope': review_scope(review), 'issuedAt': now, 'expiresAt': now + 900,
             'installationRef': ctx['installationRef'], 'entityRef': ctx['entityRef'],
             'automaticReplayAllowed': False, 'budgetReset': False, 'releaseAcceptance': False}
    raw = encoded(value)
    human = {'schema': HUMAN_SCHEMA, 'reviewHash': digest(review), 'authorityHash': hashlib.sha256(raw).hexdigest(),
             'decision': DECISION, 'state': 'ACTIVE', 'issuedAt': now, 'expiresAt': now + 900}
    root = Path(review_path).parent
    parent = Path(review['configuration']['destinations']['installationRoot']).parent
    with directory(parent) as files:
        new_file(files, 'operational-upgrade-issue-' + review['logicalOwnerScopeHash'] + '-' + str(review['attempt'])
                 + '.claim.json', encoded({'reviewHash': digest(review), 'authorityHash': hashlib.sha256(raw).hexdigest(),
                                           'automaticReplayAllowed': False}))
    with directory(root) as files:
        os.mkdir('authority', 0o700, dir_fd=files)
        os.fsync(files)
    with directory(root / 'authority') as files:
        new_file(files, 'authority.json', raw)
        new_file(files, 'human.json', encoded(human))
        verifier = DetachedAuthenticator(review['verification']['trustPolicy'], str(root / 'authority'),
                                         review['verification']['openssl'])
        for role, key in (('DEPLOYMENT_INTENT', 'intentIssuerRef'), ('FINAL_DEPLOYMENT_APPROVAL', 'approvalIssuerRef')):
            require(time.time() < now + 900, 'FINITE_UPGRADE_ISSUANCE_WINDOW_EXPIRED')
            signer = ExistingEd25519Signer(profile['keyBindings']['installer'], profile['keyRefs']['installer'], verifier,
                                           {'role': role, 'issuerRef': ctx[key], 'installationRef': ctx['installationRef'],
                                            'entityRef': ctx['entityRef']})
            new_file(files, hashlib.sha256(raw).hexdigest() + '.' + role + '.json', signer.sign(raw))
        SignedInstallation(review, raw, {'path': str(root / 'authority' / 'human.json'), 'sha256': digest(human)},
                           digest(human), verifier)
        receipt = {'schema': 'ouf.registry-operational-installation-issued.v1', 'reviewHash': digest(review),
                   'authorityHash': hashlib.sha256(raw).hexdigest(), 'humanHash': digest(human),
                   'runtimeEffectsDispatched': 0, 'installationAuthorityIssued': True, 'tokenGrants': 0,
                   'automaticReplayAllowed': False, 'budgetReset': False, 'releaseAcceptance': False}
        new_file(files, 'issued.json', encoded(receipt))
        return receipt


def operator(delivery, argv, capsule_path):
    import sys
    from .installation import (directory, new_file, read_object, load_installation_authority, key_isolation,
                               MANDATE_LEDGER_ROOT)
    from .guard import protected_file
    from tools.semantic_registry_recovery_execution.postboot_authority import authority_metadata
    from tools.semantic_policy_token_owner.iam_governance_intake import executable
    from tools.semantic_policy_token_owner.iam_owner_action import stdlib_binding
    require(bool(argv) and argv[0] in ACTIONS, 'ONE_EXACT_UPGRADE_ACTION_REQUIRED')
    if argv[0] == 'upgrade-prepare':
        require(len(argv) == 3 and re.fullmatch('[a-f0-9]{64}', argv[1]) is not None
                and re.fullmatch('[1-9]', argv[2]) is not None, 'EXACT_PREDECESSOR_HASH_AND_ATTEMPT_REQUIRED')
        binding = delivery['case']['inputs']
        inputs = read_object(binding['path'], expected=binding['sha256'])
        public = inputs['review']['authorityInputs']
        profile, _ = authority_metadata(public)
        require(public['executables']['python'] == executable(str(Path(sys.executable).resolve(strict=True))),
                'SAME_EXECUTED_UPGRADE_PYTHON_REQUIRED')
        require(digest(stdlib_binding()) == public['stdlibHash'], 'SAME_UPGRADE_STDLIB_REQUIRED')
        logical = inputs['review']['scopes']['semanticRegistryPostbootOwner']['logicalOwnerScopeHash']
        parent = Path(binding['path']).parent.parent
        v1_config = parent / ('semantic-registry-operational-' + logical) / 'configuration.json'
        pred = predecessor(str(v1_config), argv[1], inputs['retainedFence']['path'])
        capsule = protected_file(capsule_path, 2097152, modes=(0o400, 0o600))
        executables = {k: v for k, v in public['executables'].items() if k in ('python', 'openssl')}
        executables['systemctl'] = executable(str(Path('/usr/bin/systemctl').resolve(strict=True)))
        authority_inputs = {'executables': executables, 'authorityProfile': public['authorityProfile'],
                            'stdlibHash': public['stdlibHash'], 'stdlibFileCount': public['stdlibFileCount']}
        root = parent / ('semantic-registry-operational-upgrade-review-' + digest(
            {'predecessor': argv[1], 'sourceManifestHash': digest(delivery['sourceManifest']), 'attempt': argv[2]}))
        with directory(parent) as files:
            os.mkdir(root.name, 0o700, dir_fd=files)
            os.fsync(files)
        with directory(root) as files:
            new_file(files, 'capsule.py', capsule, 0o400)
            review = compose(pred, delivery['sourceManifest'], {'path': str(root / 'capsule.py'),
                             'sha256': hashlib.sha256(capsule).hexdigest()}, authority_inputs, attempt=int(argv[2]),
                             unit_parent='/etc/systemd/system', mandate_ledger_root=MANDATE_LEDGER_ROOT,
                             authority_public=public)
            key_isolation(review['configuration'], [v['path'] for v in profile['keyBindings'].values()])
            new_file(files, 'review.json', encoded(review), 0o600)
        return {'schema': 'ouf.registry-operational-upgrade-prepared.v1', 'status': 'UPGRADE_REVIEW_PREPARED',
                'privateReviewPath': str(root / 'review.json'), 'reviewHash': digest(review),
                'predecessorConfigurationHash': argv[1], 'attempt': int(argv[2]), 'runtimeEffectsDispatched': 0}
    require(len(argv) in (3, 4) and re.fullmatch('[a-f0-9]{64}', argv[2]) is not None, 'EXACT_PRIVATE_UPGRADE_REVIEW_REQUIRED')
    review = read_object(argv[1], expected=argv[2])
    require(review['configuration']['sourceManifest'] == delivery['sourceManifest'], 'SAME_SEALED_UPGRADE_DELIVERY_REQUIRED')
    if argv[0] == 'upgrade-issue':
        require(len(argv) == 3, 'EXACT_UPGRADE_ISSUE_REQUIRED')
        return issue(review, argv[1])
    if argv[0] == 'upgrade-rollback':
        if len(argv) == 3:
            plan = rollback_plan(review)
            return dict(plan, status='UPGRADE_ROLLBACK_PLANNED', planSha256=digest(plan))
        require(re.fullmatch('[a-f0-9]{64}', argv[3]) is not None, 'EXACT_ROLLBACK_PLAN_HASH_REQUIRED')
        return rollback_apply(review, argv[3])
    require(len(argv) == 3, 'EXACT_UPGRADE_ACTION_ARGUMENTS_REQUIRED')
    authority = load_installation_authority(review, argv[1])
    if argv[0] == 'upgrade-start':
        return start(review, authority)
    from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
    profile, _ = authority_metadata(review['authorityInputs'])
    key_isolation(review['configuration'], [v['path'] for v in profile['keyBindings'].values()])
    ctx = review['verification']['context']
    attestor = ExistingEd25519Signer(profile['keyBindings']['attestor'], profile['keyRefs']['attestor'], authority.verifier,
                                     {'role': 'CREATION_ATTESTATION', 'issuerRef': ctx['attestorRef'],
                                      'installationRef': ctx['installationRef'], 'entityRef': ctx['entityRef']})
    return install(review, authority, attestor)
