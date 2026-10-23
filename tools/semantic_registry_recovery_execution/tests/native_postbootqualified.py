"""Disposable native postboot gate prefix, real crypto and Gateway namespace I/O.

Actual Docker bridge, static endpoint, gated Alpine process, kernel pause,
Ed25519 signatures, private file profiles and namespace HTTP reads. The admin
server and HUMAN mandate are disposable fixtures. No Semantic JVM, full OCI
attestation, production IAM, target execution or 502 resolution is claimed.
"""
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT / 'tests'), str(ROOT)]
import test_file_only_preparation
import test_cutover_authority_native as signed
import native_runtime_executor as image_fixture
import test_iam_token_admission as iam_fixture
from engine_creation import Engine
from file_only_profile import FileOnlyProfile, PROFILE, PHASES
from gated_creation_plan import ENTRY
from gated_process_observation import GatedProcessObservation
from cutover_authority import CutoverAuthority
from tools.semantic_registry_recovery_execution import core as c, authorization as a, lifecycle as l
from tools.semantic_registry_recovery_execution.bootstrap import BootstrapPorts, BootstrapGateWitness, bootstrap_scope
from tools.semantic_registry_recovery_execution.gateway import CurrentGateway, gateway_scope
from tools.semantic_registry_recovery_execution.read_budget import ReadBudget, read_scope
from tools.semantic_registry_recovery_composition.compose import candidate_contract, GATES
from tools.ingestion_readiness_patch_execution import runtime_bindings
from tools.semantic_live_route_diagnostic import reader as route_transport
from tools.semantic_registry_postboot_owner import contract as owner_contract, owner as postboot_owner, installer as owner_installer
from tools.semantic_registry_postboot_owner.tests.fixture import make_context
from tools.semantic_policy_token_owner.producer import Binding
from tools.semantic_policy_token_owner.iam_admission import PinnedIamOpener
from tools.semantic_policy_token_owner.installed_owner import LegacyWriterFence


def private_profile(path):
    path = Path(path).resolve(strict=True)
    s = path.stat()
    metadata = [s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink,
                s.st_size, s.st_mtime_ns, s.st_ctime_ns]
    ancestors = []
    for parent in reversed(path.parents):
        q = parent.stat()
        ancestors.append({'path': str(parent), 'identity': [q.st_dev, q.st_ino, q.st_uid, q.st_gid, q.st_mode]})
    return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'metadata': metadata, 'ancestors': ancestors}


class NativePostbootQualified(unittest.TestCase):
    engine_socket = '/var/run/docker.sock'
    native = signed.SignedCutover.native
    write = signed.SignedCutover.write
    binding = signed.SignedCutover.binding
    sign = signed.SignedCutover.sign

    @classmethod
    def setUpClass(cls):
        image_fixture.NativeRuntime.setUpClass()
        cls.image = image_fixture.NativeRuntime.image
        subprocess.run(['docker', '--host', 'unix://' + cls.engine_socket,
                        'pull', 'python:3.12-alpine'], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, check=True, timeout=120)
        cls.gateway_image = subprocess.check_output(['docker', '--host',
            'unix://' + cls.engine_socket, 'image', 'inspect', 'python:3.12-alpine',
            '--format', '{{.Id}}'], timeout=15).decode().strip()

    def command(self, *args):
        if args and args[0] == 'docker':
            args = (args[0], '--host', 'unix://' + self.engine_socket, *args[1:])
        return subprocess.check_output(args, stderr=subprocess.PIPE, timeout=30).decode().strip()

    def registry_request(self, request, configtree):
        return request

    def gateway_request(self, request):
        return request

    def prior_gate_observed(self, actual):
        pass

    def network_created(self):
        pass

    def historical_chain_hash(self):
        return '9' * 64

    def inspect(self, cid=None):
        status, actual = self.engine.request('GET', '/v1.44/containers/' + (cid or self.cid) + '/json')
        self.assertEqual(status, 200)
        return actual

    def cleanup_container(self, cid):
        self.engine.request('DELETE', '/v1.44/containers/' + cid + '?force=true')

    def create_container(self, request, prefix):
        status, result = self.engine.request('POST', '/v1.44/containers/create?name=' + prefix + uuid.uuid4().hex, request)
        message = result.get('message', '') if type(result) is dict else ''
        classification = ('STATIC_IP_REQUIRES_EXPLICIT_SUBNET' if 'subnet' in message.lower()
                          else 'DOCKER_CREATE_FIXTURE_ERROR_' + hashlib.sha256(message.encode()).hexdigest()[:12])
        self.assertEqual(status, 201, classification)
        cid = result['Id']
        self.addCleanup(self.cleanup_container, cid)
        return cid

    def setUp(self):
        signed.SignedCutover.setUp(self)
        socket = self.engine_socket
        s = os.stat(socket, follow_symlinks=False)
        self.engine = Engine(socket, (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode & 0o777))
        network_name = 'ouf-postboot-fixture-' + uuid.uuid4().hex
        # Static endpoints require a user-declared Docker IPAM subnet. This
        # benchmark range belongs only to the disposable hosted fixture.
        subnet = '198.19.' + str(uuid.uuid4().int % 240) + '.0/24'
        self.nid = self.command('docker', 'network', 'create', '--internal', '--subnet', subnet, network_name)
        self.addCleanup(lambda: self.command('docker', 'network', 'rm', self.nid))
        network = json.loads(self.command('docker', 'network', 'inspect', self.nid))[0]
        subnet = ipaddress.IPv4Network(network['IPAM']['Config'][0]['Subnet'])
        registry_address, gateway_address = str(subnet.network_address + 2), str(subnet.network_address + 3)
        self.network_name, self.subnet = network_name, subnet
        self.registry_address, self.gateway_address = registry_address, gateway_address
        self.network_created()
        endpoint = lambda address: {'EndpointsConfig': {network_name: {'NetworkID': self.nid,
            'IPAMConfig': {'IPv4Address': address}}}}

        database = self.root / 'db'
        database.mkdir(mode=0o500)
        os.chown(database, 10001, 10001)
        password = database / 'OUF_SEM_DB_PASSWORD'
        password.write_bytes(b'DISPOSABLE_DATABASE_FIXTURE')
        password.chmod(0o400)
        os.chown(password, 10001, 10001)
        configtree = {'source': str(database), 'target': '/run/fixture-db', 'readOnly': True,
            'uid': 10001, 'gid': 10001, 'directoryMode': 0o500, 'fileName': password.name,
            'fileMode': 0o400, 'maxBytes': 64, 'sha256': signed.sha(password.read_bytes())}
        self.token_root = self.root / 'token'
        self.token_root.mkdir(mode=0o750)
        os.chown(self.token_root, 0, 10001)
        token = self.token_root / 'token.jwt'
        token.write_text('DISPOSABLE_NOT_CURRENTLY_ADMITTED')
        token.chmod(0o440)
        os.chown(token, 0, 10001)

        request = {'Image': self.image, 'User': '10001:10001', 'Entrypoint': ENTRY,
            'Cmd': ['java', '-XX:MaxRAMPercentage=75', '-jar', '/app/application.jar'],
            'Env': ['OUF_SCHEMA_GOV_ENABLED=false', 'OUF_DISCOVERY_WORKER_ENABLED=false',
                    'SPRING_CONFIG_IMPORT=configtree:/run/fixture-db/', 'PORT=8080'],
            'HostConfig': {'NetworkMode': network_name, 'CapDrop': ['ALL'],
                'SecurityOpt': ['no-new-privileges'], 'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0},
                'Binds': [str(database) + ':/run/fixture-db:ro', str(self.token_root) + ':/run/fixture-token:ro']},
            'NetworkingConfig': endpoint(registry_address)}
        request = self.registry_request(request, configtree)
        self.profile = FileOnlyProfile(request, configtree)
        self.cid = self.create_container(request, 'ouf-postboot-registry-')
        self.assertEqual(self.engine.request('POST', '/v1.44/containers/' + self.cid + '/start')[0], 204)
        process = GatedProcessObservation(request)
        deadline = time.monotonic() + 8
        while True:
            actual = self.inspect()
            if process.observe(actual['State']['Pid'])['processKind'] == 'GATE_WAITING':
                break
            self.assertLess(time.monotonic(), deadline)
            time.sleep(.05)
        self.previous_pid = actual['State']['Pid']
        self.prior_gate_observed(actual)
        self.assertEqual(self.engine.request('POST', '/v1.44/containers/' + self.cid + '/stop?t=1')[0], 204)
        self.baseline = self.inspect()
        self.assertEqual(self.baseline['State']['Status'], 'exited')

        self.routes = {'fixture-semantic-read': {'id': 'fixture-semantic-read', 'uri': route_transport.OPERATION,
            'methods': ['GET'], 'upstream': {'type': 'roundrobin', 'nodes': {registry_address + ':8080': 1}}}}
        self.www = self.root / 'www'
        (self.www / 'apisix/admin').mkdir(parents=True, mode=0o755)
        self.www.chmod(0o755)
        (self.www / 'apisix').chmod(0o755)
        self.route_file = self.www / 'apisix/admin/routes'
        self.route_file.write_bytes(c.encoded({'list': list(self.routes.values()), 'total': 1}))
        self.route_file.chmod(0o444)
        config = self.root / 'gateway.yaml'
        self.write(config, b'deployment:\n  admin:\n    admin_key:\n      - name: fixture\n        key: DISPOSABLE_ADMIN_FIXTURE_KEY\n        role: admin\n')
        # Use an executable guaranteed by this dedicated fixture image. Alpine's
        # base filesystem does not promise an /usr/sbin/httpd entry point.
        gateway_request = {'Image': self.gateway_image, 'User': '10001:10001',
            'Entrypoint': ['python3'], 'Cmd': ['-m', 'http.server', '9180', '--directory', '/www'],
            'HostConfig': {'NetworkMode': network_name, 'CapDrop': ['ALL'], 'SecurityOpt': ['no-new-privileges'],
                'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0},
                'Binds': [str(self.www) + ':/www:ro', str(config) + ':/usr/local/apisix/conf/config.yaml:ro']},
            'NetworkingConfig': endpoint(gateway_address)}
        gateway_request = self.gateway_request(gateway_request)
        self.gateway_id = self.create_container(gateway_request, 'ouf-postboot-gateway-')
        status, started = self.engine.request('POST', '/v1.44/containers/' + self.gateway_id + '/start')
        message = started.get('message', '') if type(started) is dict else ''
        classification = ('GATEWAY_FIXTURE_EXECUTABLE_MISSING' if 'no such file' in message.lower()
            or 'executable file not found' in message.lower() else
            'GATEWAY_FIXTURE_START_ERROR_' + hashlib.sha256(message.encode()).hexdigest()[:12])
        self.assertEqual(status, 204, classification)
        actual_gateway = self.inspect(self.gateway_id)
        self.gateway_pin = {'binding': runtime_bindings.observed(actual_gateway, runtime_bindings.SORTED),
                            'restartCount': 0, 'bindingProfile': runtime_bindings.SORTED}
        python = Path(sys.executable).resolve(strict=True)
        self.gateway_profile = {'schema': 'ouf.ingestion-rollout-gateway-transport.v1',
            'endpoint': {'host': '127.0.0.1', 'port': 9180},
            'pythonExecutable': {'path': str(python), 'sha256': signed.sha(python.read_bytes())},
            'config': private_profile(config), 'adminKey': None}
        # The admin fixture is only a transport/route source. Wait before
        # opening the signed finite recovery; no test-side retry consumes it.
        deadline = time.monotonic() + 10
        while True:
            try:
                observed_routes = route_transport.admin_routes(self.gateway_profile, actual_gateway)
                self.assertEqual(observed_routes, self.routes)
                break
            except route_transport.Stop:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.05)

        proposal = {'registry': {'containerId': self.cid, 'imageId': self.image,
            'configHash': c.digest(self.baseline['Config']), 'hostConfigHash': c.digest(self.baseline['HostConfig']),
            'mountsHash': c.digest(sorted(self.baseline['Mounts'], key=lambda m: m['Destination']))},
            'requiredGates': list(GATES), 'unresolvedGateCount': 8}
        self.plan = candidate_contract(proposal, self.historical_chain_hash(), self.expected['predecessorIncidentRef'])
        self.execution_root = self.root / ('semantic-registry-recovery-' + self.plan['logicalOperationRef'])
        self.execution_root.mkdir(mode=0o700)
        self.boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        self.expected['creationRequestHash'] = c.digest(request)
        # Expensive disposable setup precedes the finite signed recovery.
        self.now = int(time.time())
        # The borrowed signature fixture starts with a controllable unit clock;
        # actual native execution must continue to enforce the current window.
        self.clock = lambda: int(time.time())
        self.verifier.clock = self.clock
        raw = {'schema': 'ouf.semantic-cutover-execution-authority.v2',
            **{k: v for k, v in self.expected.items() if k != 'intakeHash'},
            'issuedAt': self.now, 'expiresAt': self.now + 300, 'deploymentProfile': PROFILE,
            'executionProfileHash': self.profile.sha256, 'newDistinctLeaseWorkerRequired': False,
            'phaseIntentHashes': {phase: 'a' * 64 for phase in PHASES},
            'semanticRegistryRecovery': a.scope(self.plan),
            'semanticRegistryPostbootBootstrap': bootstrap_scope(self.plan, request, self.profile, self.boot),
            'semanticRegistryRecoveryReads': read_scope(self.plan, self.execution_root),
            'semanticRegistryRecoveryGateway': gateway_scope(SimpleNamespace(plan=self.plan),
                self.gateway_pin, self.gateway_profile, self.routes, self.nid)}
        self.extra_scopes(raw)
        self.authority = c.encoded(raw)
        self.approval.update(schema='ouf.semantic-cutover-human-mandate.v2', **self.expected,
            executionAuthorityHash=signed.sha(self.authority), deploymentProfile=PROFILE,
            executionProfileHash=self.profile.sha256, expiresAt=self.now + 360)
        self.write(self.mandate, c.encoded(self.approval))
        self.approved = signed.sha(self.mandate.read_bytes())
        for role in self.grant['roles']:
            self.sign(role)
        self.current_authority = CutoverAuthority(self.verifier, self.binding(self.mandate), self.approved,
            self.context, self.expected, self.clock, execution_profile=self.profile)
        self.scope = a.AuthorityScope(self.current_authority, self.authority, self.plan, request)
        self.store = c.Store(self.execution_root, self.plan['logicalOperationRef'])
        wall, mono = time.time(), time.monotonic()
        self.store.initialize(c.initial(self.plan, authority_hash=self.scope.hash, expires_unix=wall + 240,
            expires_monotonic=mono + 240, boot_id=self.boot,
            predecessor_history_hash=self.expected['predecessorHistoryHash'], created_unix=wall, created_monotonic=mono))
        self.budget = ReadBudget.initialize(self.store, self.scope, self.plan)
        self.lifecycle = l.Lifecycle(self.engine, self.scope, self.store, self.plan, request, self.baseline, proposal)
        self.gateway = CurrentGateway(self.lifecycle, self.gateway_pin, self.gateway_profile, self.routes, self.nid, self.budget)
        self.ports = BootstrapPorts(self.lifecycle, self.profile, self.gateway)
        self.runner = c.Runner(self.plan, self.store, self.ports, boot_id=self.boot)

    def extra_scopes(self, raw):
        """Subclass hook creates genuine signed fixture scopes before signing."""

    def advance_to_paused(self):
        deadline = time.monotonic() + 90
        while self.store.read()['nextStage'] < 4:
            self.runner.step()
            self.assertLess(time.monotonic(), deadline)
            if self.store.read()['state'] == 'IN_FLIGHT':
                time.sleep(.05)
        return self.ports.witness.observe('PREGRANT')

    def test_actual_prefix_reconciles_route_endpoint_and_stops_before_full_admission(self):
        with self.assertRaisesRegex(c.RecoveryDenied, 'PAUSE_PREFIX'):
            self.ports.witness.observe('PREGRANT')
        proof = self.advance_to_paused()
        self.assertNotEqual(proof['runtimeGeneration']['pid'], self.previous_pid)
        self.assertEqual(proof['runtimeGeneration'], self.store.read()['newGeneration'])
        self.assertTrue(self.inspect()['State']['Paused'])
        self.assertEqual(proof['processKind'], 'GATE_WAITING')
        self.assertFalse(proof['applicationReadinessProven'])
        before = self.store.read()
        with self.assertRaisesRegex(c.RecoveryDenied, 'PREFIX_ONLY_STOP'):
            self.runner.step()
        self.assertEqual(self.store.read(), before)
        effects = [e['stage'] for e in before['effects'] if e.get('nativeRequestAttempted')]
        self.assertEqual(effects, ['START_NEW_WAIT_GATE', 'PAUSE_NEW_WAIT_GATE'])
        self.assertGreater(self.budget.read()['counts']['gatewayAdminGets'], 0)

    def test_real_unowned_unpause_invalidates_pregrant_witness(self):
        self.advance_to_paused()
        self.assertEqual(self.engine.request('POST', '/v1.44/containers/' + self.cid + '/unpause')[0], 204)
        with self.assertRaisesRegex(c.RecoveryDenied, 'SAME_FENCED_POSTBOOT'):
            self.ports.witness.observe('PREGRANT')
        self.assertEqual(self.store.read()['nextStage'], 4)

    def test_actual_admin_route_drift_blocks_before_container_start(self):
        changed = copy.deepcopy(self.routes)
        changed['fixture-semantic-read']['status'] = 0
        self.route_file.write_bytes(c.encoded({'list': list(changed.values()), 'total': 1}))
        with self.assertRaisesRegex(c.RecoveryDenied, 'UNCHANGED_COMPLETE'):
            self.runner.step()
        self.assertEqual(self.inspect()['State']['Pid'], 0)
        self.assertFalse(any(e.get('nativeRequestAttempted') for e in self.store.read()['effects']))

    def test_current_signed_scope_revocation_blocks_new_start(self):
        self.approval['state'] = 'REVOKED'
        self.write(self.mandate, c.encoded(self.approval))
        with self.assertRaises(Exception):
            self.runner.step()
        self.assertEqual(self.inspect()['State']['Pid'], 0)
        self.assertEqual(self.store.read()['effects'], [])


class NativePostbootOwnerQualified(NativePostbootQualified):
    """Real TLS owner composition; only legacy host-systemd state is synthetic.

    The issuer, confidential client, CA, HUMAN mandate and Alpine process are
    disposable. This does not qualify production IAM, Java, the full OCI/frame
    observer, policy refresh, the service GET or target recovery.
    """
    test_actual_prefix_reconciles_route_endpoint_and_stops_before_full_admission = None
    test_real_unowned_unpause_invalidates_pregrant_witness = None
    test_actual_admin_route_drift_blocks_before_container_start = None
    test_current_signed_scope_revocation_blocks_new_start = None

    def make_iam(self, tls_root):
        return iam_fixture.Fixture(tls_root)

    def extra_scopes(self, raw):
        tls_root = self.root / 'iam'
        tls_root.mkdir(mode=0o700)
        self.iam = self.make_iam(tls_root)
        self.addCleanup(self.iam.close)
        self.owner_clock = lambda: (time.time(), time.monotonic())
        self.transport = PinnedIamOpener(self.iam.profile, self.owner_clock, self.iam.context())
        credential = self.root / 'owner-credential'
        credential.write_text('DISPOSABLE_FIXTURE_SECRET')
        credential.chmod(0o400)
        self.owner_binding = Binding(self.iam.profile.token_endpoint, self.iam.profile.client_id,
            'authorization.bundle.read', str(self.token_root), 'token.jwt', 10001)
        self.owner_context = make_context(self.root / 'owner-history', self.owner_binding, self.iam.profile,
            self.transport.trust_digest(), credential,
            {'planHash': c.digest(self.plan), 'logicalOperationRef': self.plan['logicalOperationRef'],
             'registryId': self.cid, 'bootId': self.boot}, self.expected['sourceClosureHash'],
            budget={'maximumGrantAttempts': 1, 'maximumSeconds': 240,
                    'attemptTimeoutSeconds': 30, 'intervalSeconds': 60})
        self.owner_scope = owner_contract.compile_scope(self.owner_context)
        raw[owner_contract.SCOPE] = self.owner_scope
        # CI has no deployed legacy systemd units. This is the sole owner
        # boundary replaced; source, signature, file/boot/process/network and
        # invocation-lock checks all run unchanged against actual resources.
        legacy_fence = patch.object(LegacyWriterFence, 'guard', return_value=True)
        legacy_fence.start()
        self.addCleanup(legacy_fence.stop)

    def install_owner(self):
        self.advance_to_paused()
        before = {name: (Path(self.owner_context['predecessorJournalPath']) / name).read_bytes()
                  for name in owner_contract.RECORDS}
        receipt = owner_installer.install(self.owner_context, self.current_authority, self.authority,
                                         self.ports.witness, clock=self.owner_clock)
        self.assertEqual(receipt['oauthRequests'], 0)
        self.assertEqual(self.iam.calls, [])
        self.assertFalse(receipt['budgetReset'])
        self.assertEqual(receipt['predecessorGrantAttempts'], 319)
        self.assertEqual(receipt['currentSessionBootId'], self.boot)
        self.assertNotEqual(receipt['retainedFirstGrantBootId'], self.boot)
        self.assertEqual(before, {name: (Path(self.owner_context['predecessorJournalPath']) / name).read_bytes()
                                 for name in owner_contract.RECORDS})
        return receipt

    def build_worker(self):
        return postboot_owner.build_worker(self.owner_context, self.current_authority, self.authority,
            self.ports.witness, clock=self.owner_clock, transport=self.transport)

    def run_worker(self):
        worker = self.build_worker()
        coordination = threading.RLock()
        stop = threading.Event()
        settled = threading.Event()
        failures = []
        statuses = []

        def observe(status):
            statuses.append(status)
            if status['state'] in ('ACTIVE', 'BLOCKED', 'CANCELLED', 'PAUSED_EXHAUSTED', 'RECONCILE_REQUIRED'):
                settled.set()

        def run():
            try:
                worker.run(stop, observe=observe, coordination_lock=coordination)
            except BaseException as error:
                failures.append(type(error).__name__)
            finally:
                settled.set()

        thread = threading.Thread(target=run, name='disposable-postboot-owner')
        thread.start()

        def finish():
            stop.set()
            thread.join(35)
            self.assertFalse(thread.is_alive(), 'Finite owner did not release its invocation lock')
        self.addCleanup(finish)
        self.assertTrue(settled.wait(35), 'Finite TLS owner did not settle')
        self.assertEqual(failures, [])
        return worker, coordination, stop, thread, statuses

    def observer(self):
        return postboot_owner.build_observer(self.owner_context, self.current_authority, self.authority,
            self.ports.witness, clock=self.owner_clock, transport=self.transport)

    def grant_count(self):
        return sum(path.endswith('/token') for path, _ in self.iam.calls)

    def test_actual_tls_grant_current_boot_lease_and_mounted_introspection_preserve_319(self):
        self.install_owner()
        worker, coordination, _, _, statuses = self.run_worker()
        with coordination:
            self.assertEqual(statuses[-1]['state'], 'ACTIVE', statuses[-1])
            observer = self.observer()
            self.assertEqual(observer.lease(90)['controlledCumulativeGrantAttempts'], 320)
            row = worker.r.journal.read()
            self.assertEqual(row['attempts'], 1)
            self.assertEqual(row['publicationCount'], 1)
            self.assertEqual(row['bootId'], self.boot)
            self.assertNotEqual(row['retainedFirstGrantBootId'], self.boot)
            mounted = Path('/proc') / str(row['gateGeneration']['pid']) / 'root/run/fixture-token/token.jwt'
            output = self.token_root / 'token.jwt'
            self.assertEqual((mounted.stat().st_dev, mounted.stat().st_ino),
                             (output.stat().st_dev, output.stat().st_ino))
            actual_token = mounted.read_text()
            self.assertEqual(actual_token, 'FIXTURE_TOKEN')
            before = len(self.iam.calls)
            self.assertTrue(observer.admit_mounted(actual_token, 90, self.owner_binding.digest(), time.monotonic() + 10))
            self.assertTrue(any(path.endswith('/introspect') for path, _ in self.iam.calls[before:]))
            # Last permitted grant does not itself revoke the positive lease,
            # nor authorize another grant when the live worker ticks again.
            self.assertEqual(worker._tick()['state'], 'ACTIVE')
            self.assertEqual(self.grant_count(), 1)
            self.assertTrue(self.inspect()['State']['Paused'])
            self.assertEqual(self.store.read()['nextStage'], 4)

    def test_no_observer_without_actual_worker_invocation_lock(self):
        self.install_owner()
        with self.assertRaisesRegex(Exception, 'LIVE_SAME_PROCESS_POSTBOOT_WORKER_INVOCATION'):
            self.observer()
        self.assertEqual(self.iam.calls, [])

    def test_tls_issuer_rejection_consumes_one_attempt_without_publication_or_release(self):
        self.install_owner()
        self.iam.active = lambda: {'active': False}
        worker, coordination, _, thread, statuses = self.run_worker()
        thread.join(5)
        self.assertFalse(thread.is_alive())
        with coordination:
            row = worker.r.journal.read()
            self.assertEqual(statuses[-1]['state'], 'BLOCKED')
            self.assertEqual(row['attempts'], 1)
            self.assertEqual(row['controlledCumulativeGrantAttempts'], 320)
            self.assertEqual(row['publicationCount'], 0)
            self.assertEqual(self.grant_count(), 1)
            self.assertEqual((self.token_root / 'token.jwt').read_text(), 'DISPOSABLE_NOT_CURRENTLY_ADMITTED')
            self.assertTrue(self.inspect()['State']['Paused'])
            self.assertEqual(self.store.read()['nextStage'], 4)

    def test_stopped_worker_cannot_be_replayed_or_installation_reinitialized(self):
        self.install_owner()
        worker, coordination, stop, thread, statuses = self.run_worker()
        self.assertEqual(statuses[-1]['state'], 'ACTIVE', statuses[-1])
        stop.set(); thread.join(35)
        self.assertFalse(thread.is_alive())
        before = self.grant_count()
        with coordination:
            with self.assertRaises(Exception):
                self.observer()
            with self.assertRaises(Exception):
                owner_installer.install(self.owner_context, self.current_authority, self.authority,
                                        self.ports.witness, clock=self.owner_clock)
        new_worker, _, _, new_thread, new_statuses = self.run_worker()
        new_thread.join(5)
        self.assertFalse(new_thread.is_alive())
        self.assertIn(new_statuses[-1]['state'], ('BLOCKED', 'CANCELLED', 'RECONCILE_REQUIRED'))
        self.assertEqual(self.grant_count(), before)
        self.assertEqual(new_worker.r.journal.read()['controlledCumulativeGrantAttempts'], 320)


if __name__ == '__main__':
    unittest.main()
