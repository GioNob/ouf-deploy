"""Whole disposable Registry recovery composition, with no native owner mocks.

The production JVM is built from the pinned Registry source. A derived fixture
image imports one disposable TLS CA before its image/independent rootfs audit.
Docker 29.8.1 runs in an owned isolated daemon; expected OCI comes from the
checked-in independent baseline, never from this candidate's observed OCI.
The IAM/HUMAN credentials, APISIX-shaped forwarding proxy, seeded read data and
legacy-systemd fence are fixtures. This cannot establish VPS health, production
issuer/target-image approval, real APISIX plugins or release acceptance.
"""
import copy
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import native_postbootqualified as prefix_fixture
import jvm_fixture_inputs as inputs
import jvm_fixture_servers as servers
from cryptography.hazmat.primitives.asymmetric import rsa
from engine_creation import Engine
from file_only_frame_inputs import compile_inputs, ENGINE, BASELINE_SHA256
from file_only_preparation import file_source
from image_custody import archive, loaded, native_identity
from tools.semantic_provider_node_observation import rootfs_seal
from tools.semantic_provider_deployment_signing import ExistingEd25519Signer
from tools.semantic_registry_recovery_execution import core as c
from tools.semantic_registry_recovery_execution.node_owner import node_scope
from tools.semantic_registry_recovery_execution.database import database_scope
from tools.semantic_registry_recovery_execution.factory import factory_scope
from tools.semantic_registry_recovery_execution.semantic_request import request_scope
from tools.semantic_registry_recovery_execution.postboot_factory import build_on_bootstrap
from tools.semantic_registry_recovery_execution.postboot_controller import ColdStartWait
from tools.semantic_policy_token_owner.iam_admission import IamProfile

ROOT = prefix_fixture.ROOT
SOURCE = inputs.REGISTRY_SOURCE.rsplit('@', 1)[1]
LIMITS = {'maxEntries': 100000, 'maxBytes': 8589934592, 'maxDepth': 64}


class Budget:
    def __init__(self, seconds=180):
        self.until = time.monotonic() + seconds

    def check(self):
        if time.monotonic() >= self.until:
            raise AssertionError('Disposable independent image seal deadline')


def checked(*args, timeout=60, data=None):
    return subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          check=True, timeout=timeout).stdout


class NativeJvmPostboot(prefix_fixture.NativePostbootOwnerQualified):
    # Keep exactly one expensive full-composition case; the eight smaller
    # refusal/crypto/TLS tests run independently in their own CI job.
    test_actual_tls_grant_current_boot_lease_and_mounted_introspection_preserve_319 = None
    test_no_observer_without_actual_worker_invocation_lock = None
    test_tls_issuer_rejection_consumes_one_attempt_without_publication_or_release = None
    test_stopped_worker_cannot_be_replayed_or_installation_reinitialized = None

    def historical_chain_hash(self):
        return c.digest({'disposableHistoricalFixture': True})

    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true':
            raise AssertionError('Only an owned disposable root GitHub runner is permitted')
        cls.daemon_root = Path(tempfile.mkdtemp(prefix='postboot-engine-', dir=ROOT))
        cls.daemon_root.chmod(0o700)
        cls.addClassCleanup(shutil.rmtree, cls.daemon_root)
        cls.engine_socket = str(cls.daemon_root / 'docker.sock')
        config = cls.daemon_root / 'daemon.json'
        config.write_text(json.dumps({'features': {'containerd-snapshotter': True},
                                     'exec-opts': ['native.cgroupdriver=systemd']}))
        cls.engine_log = (cls.daemon_root / 'daemon.log').open('wb')
        cls.addClassCleanup(cls.engine_log.close)
        cls.daemon = subprocess.Popen([shutil.which('dockerd'), '--config-file', str(config),
            '--data-root', str(cls.daemon_root / 'data'), '--exec-root', str(cls.daemon_root / 'exec'),
            '--pidfile', str(cls.daemon_root / 'pid'), '-H', 'unix://' + cls.engine_socket,
            '--bridge', 'none', '--iptables=false', '--ip6tables=false', '--storage-driver', 'overlayfs'],
            stdout=cls.engine_log, stderr=cls.engine_log)

        def stop():
            if cls.daemon.poll() is None:
                cls.daemon.terminate()
                try:
                    cls.daemon.wait(timeout=25)
                except subprocess.TimeoutExpired:
                    cls.daemon.kill(); cls.daemon.wait(timeout=5)
        cls.addClassCleanup(stop)

        def docker(*args, timeout=120):
            return checked(shutil.which('docker'), '--host', 'unix://' + cls.engine_socket,
                           *args, timeout=timeout)
        cls.docker = staticmethod(docker)
        deadline = time.monotonic() + 60
        while True:
            try:
                info = json.loads(docker('info', '--format', '{{json .}}'))
                break
            except subprocess.CalledProcessError:
                if cls.daemon.poll() is not None or time.monotonic() >= deadline:
                    raise AssertionError('Owned Docker daemon did not become ready') from None
                time.sleep(.2)
        if {key: info.get(native) for key, native in (('serverVersion', 'ServerVersion'),
                ('storageDriver', 'Driver'), ('cgroupDriver', 'CgroupDriver'))} != {
                key: ENGINE[key] for key in ('serverVersion', 'storageDriver', 'cgroupDriver')}:
            raise AssertionError('Independent Docker baseline engine profile changed')
        source_archive = Path(os.environ['OUF_JVM_FIXTURE_IMAGE_ARCHIVE']).resolve(strict=True)
        cls.docker('load', '--input', str(source_archive), timeout=180)
        cls.base_image = os.environ['OUF_JVM_FIXTURE_IMAGE']
        for label, image in (('alpine_image', 'alpine:3.21'),
                             ('postgres_image', 'postgres:17-alpine'),
                             ('gateway_image', 'python:3.12-alpine')):
            cls.docker('pull', image)
            setattr(cls, label, json.loads(cls.docker('image', 'inspect', image))[0]['Id'])
        cls.image = cls.base_image

    def sql(self, sql):
        return checked(shutil.which('docker'), '--host', 'unix://' + self.engine_socket,
            'exec', '-i', self.pg_id, 'psql', '-X', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1',
            '-U', 'ouf_fixture', '-d', 'ouf_semantic', data=sql.encode(), timeout=20).decode().strip()

    def registry_request(self, request, configtree):
        tls_root = self.root / 'tls'; tls_root.mkdir(mode=0o700)
        self.ca, self.tls_key = prefix_fixture.iam_fixture.certificate(tls_root)
        self.iam_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.iam_app = servers.IamApplication('https://iam.fixture.test:443/realms/fixture',
            signing_key=self.iam_key, client_secret='DISPOSABLE_FIXTURE_SECRET')
        listener = servers.make_tls_server(('0.0.0.0', 443), self.ca, self.tls_key, self.iam_app)
        self.iam_running = servers.running(listener)
        self.iam_running.__enter__()
        self.addCleanup(self.iam_running.__exit__, None, None, None)
        # Production factories use the ordinary verified default SSLContext.
        # Only this isolated CI process gets an additional disposable CA bundle.
        trust = tls_root / 'trust.pem'
        trust.write_bytes(Path(ssl.get_default_verify_paths().cafile).read_bytes() + b'\n' + self.ca.read_bytes())
        old_trust = os.environ.get('SSL_CERT_FILE')
        os.environ['SSL_CERT_FILE'] = str(trust)
        self.addCleanup(lambda: os.environ.pop('SSL_CERT_FILE', None) if old_trust is None
                        else os.environ.__setitem__('SSL_CERT_FILE', old_trust))
        derived = self.root / 'derived-image'; derived.mkdir(mode=0o700)
        shutil.copyfile(self.ca, derived / 'fixture-ca.pem')
        (derived / 'Dockerfile').write_text('FROM ' + self.base_image + '\nUSER 0:0\n'
            'COPY fixture-ca.pem /tmp/fixture-ca.pem\n'
            'RUN keytool -importcert -noprompt -alias ouf-disposable-fixture '
            '-file /tmp/fixture-ca.pem -cacerts -storepass changeit && rm /tmp/fixture-ca.pem\n'
            'USER 10001:10001\n')
        image_tag = 'ouf-postboot-ca-' + uuid.uuid4().hex
        self.docker('build', '--network', 'none', '--label', 'org.opencontainers.image.revision=' + SOURCE,
                    '--tag', image_tag, str(derived), timeout=120)
        native_image = json.loads(self.docker('image', 'inspect', image_tag))[0]
        self.image = native_image['Id']
        image_tar = self.root / 'image.tar'
        self.docker('save', '--output', str(image_tar), image_tag, timeout=120)
        with tarfile.open(image_tar) as saved:
            manifest = json.load(saved.extractfile('manifest.json'))
            config_bytes = saved.extractfile(manifest[0]['Config']).read()
        config_id = 'sha256:' + hashlib.sha256(config_bytes).hexdigest()
        with image_tar.open('rb') as saved:
            audit = archive(saved, hashlib.file_digest(saved, 'sha256').hexdigest(), config_id, SOURCE)
        if native_image['Id'] != audit['imageId']:
            audit['nativeIdentity'] = native_identity(audit)
        loaded(audit, native_image)
        self.image_audit = audit
        self.pg_address = str(self.subnet.network_address + 4)
        pg_request = {'Image': self.postgres_image,
            'Env': ['POSTGRES_DB=ouf_semantic', 'POSTGRES_USER=ouf_fixture',
                    'POSTGRES_PASSWORD=DISPOSABLE_DATABASE_FIXTURE'],
            'HostConfig': {'NetworkMode': self.network_name, 'RestartPolicy': {'Name': 'no'}},
            'NetworkingConfig': {'EndpointsConfig': {self.network_name: {'NetworkID': self.nid,
                'IPAMConfig': {'IPv4Address': self.pg_address}}}}}
        self.pg_id = self.create_container(pg_request, 'ouf-postboot-pg-')
        self.assertEqual(self.engine.request('POST', '/v1.44/containers/' + self.pg_id + '/start')[0], 204)
        deadline = time.monotonic() + 45
        while True:
            try:
                self.assertEqual(self.sql('SELECT 1;'), '1')
                break
            except subprocess.CalledProcessError:
                self.assertLess(time.monotonic(), deadline)
                time.sleep(.2)
        request['Image'] = self.image
        image_environment = dict(row.split('=', 1) for row in native_image['Config']['Env'])
        image_environment.update(dict(row.split('=', 1) for row in request['Env']))
        image_environment.update(OUF_SEM_DB_URL='jdbc:postgresql://' + self.pg_address + ':5432/ouf_semantic',
            OUF_SEM_DB_USER='ouf_fixture', OUF_IAM_ENABLED='true', OUF_IAM_ISSUER=self.iam_app.issuer,
            OUF_IAM_AUDIENCE=inputs.AUDIENCE, OUF_IAM_ACTOR_TYPE_CLAIM='ouf_actor_type',
            OUF_AUTHORIZATION_REGISTRY_URL='https://iam.fixture.test:443' + self.iam_app.active_path,
            OUF_AUTHORIZATION_REGISTRY_TOKEN_FILE='/run/fixture-token/token.jwt',
            OUF_AUTHORIZATION_REFRESH_SECONDS='2', OUF_AUTHORIZATION_MAX_STALENESS_SECONDS='120',
            OUF_SEMANTIC_DELEGATION_KEY_FILE='/run/ouf/delegation.key',
            OUF_SEMANTIC_DELEGATION_WORKLOAD='disposable-ingestion',
            OUF_SEMANTIC_PROPOSAL_RECEIPT_KEY_FILE='/run/ouf/proposal.key',
            OUF_SEMANTIC_PROPOSAL_RECEIPT_ISSUER='disposable-gateway',
            OUF_SEMANTIC_PROPOSAL_RECEIPT_AUDIENCE='disposable-semantic',
            OUF_SEMANTIC_PROPOSAL_RECEIPT_WORKLOAD='disposable-ingestion',
            OUF_AUTHORIZATION_THS_PUBLIC_ORIGIN='https://fixture.invalid')
        request['Env'] = [key + '=' + value for key, value in sorted(image_environment.items())]
        request['WorkingDir'] = '/app'
        request['HostConfig'].update(ReadonlyRootfs=False, SecurityOpt=['no-new-privileges:true'],
            Memory=536870912, MemorySwap=536870912, PidsLimit=256, NanoCpus=1000000000,
            ExtraHosts=['iam.fixture.test:' + str(self.subnet.network_address + 1)])
        request['NetworkingConfig']['EndpointsConfig'][self.network_name]['MacAddress'] = '02:42:ab:cd:ef:02'
        self.delegation = self.source_file('delegation.key', '/run/ouf/delegation.key', b'a' * 64, 10001, 10001, 0o400)
        self.proposal_key = self.source_file('proposal.key', '/run/ouf/proposal.key', b'b' * 64, 0, 10001, 0o440)
        self.proposal_key['metadataHash'] = file_source(self.proposal_key)
        request['HostConfig']['Binds'] = [self.delegation['source'] + ':' + self.delegation['target'] + ':ro',
            self.proposal_key['source'] + ':' + self.proposal_key['target'] + ':ro', *request['HostConfig']['Binds']]
        self.tree = copy.deepcopy(configtree)
        # Migrations run through a separate actual JVM before the historical
        # stopped recovery candidate exists. No fabricated Flyway history.
        prepare = copy.deepcopy(request)
        prepare['Entrypoint'], prepare['Cmd'] = request['Cmd'], []
        prepare['NetworkingConfig']['EndpointsConfig'][self.network_name]['IPAMConfig']['IPv4Address'] = str(self.subnet.network_address + 5)
        prepare['NetworkingConfig']['EndpointsConfig'][self.network_name]['MacAddress'] = '02:42:ab:cd:ef:05'
        migration_id = self.create_container(prepare, 'ouf-postboot-migration-')
        self.assertEqual(self.engine.request('POST', '/v1.44/containers/' + migration_id + '/start')[0], 204)
        deadline = time.monotonic() + 90
        while True:
            try:
                history = json.loads(self.sql("SELECT json_agg(json_build_object('version',version,'type',type,'script',script,'checksum',checksum,'success',success) ORDER BY installed_rank) FROM ouf_sem.flyway_schema_history;"))
                if history and any(row['version'] == '10' and row['success'] for row in history):
                    self.history = history
                    break
            except (subprocess.CalledProcessError, json.JSONDecodeError):
                pass
            self.assertTrue(self.inspect(migration_id)['State']['Running'], 'Disposable migration JVM exited')
            self.assertLess(time.monotonic(), deadline, 'Real Flyway migrations did not finish')
            time.sleep(.3)
        self.cleanup_container(migration_id)
        self.sql(inputs.seed_sql())
        self.database_oid = int(self.sql('SELECT oid FROM pg_database WHERE datname=current_database();'))
        # Independent same-image reference gate. Its OCI is never copied or
        # accepted; only the complete pre-Java image-rootfs bytes are sealed.
        reference = copy.deepcopy(request)
        reference.pop('NetworkingConfig')
        reference['HostConfig']['NetworkMode'] = 'none'
        reference['HostConfig'].pop('ExtraHosts')
        seal_id = self.create_container(reference, 'ouf-independent-seal-')
        self.assertEqual(self.engine.request('POST', '/v1.44/containers/' + seal_id + '/start')[0], 204)
        self.assertEqual(self.engine.request('POST', '/v1.44/containers/' + seal_id + '/pause')[0], 204)
        self.expected_seal = rootfs_seal(self.daemon_root / 'data/rootfs/overlayfs' / seal_id, LIMITS, Budget())
        self.cleanup_container(seal_id)
        return request

    def source_file(self, name, target, raw, uid, gid, mode):
        path = self.root / name; path.write_bytes(raw); path.chmod(mode); os.chown(path, uid, gid)
        return {'source': str(path), 'target': target, 'readOnly': True, 'uid': uid, 'gid': gid,
                'mode': mode, 'maxBytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

    def prior_gate_observed(self, actual):
        # Read only independently declared NIC/daemon identity slots, never OCI.
        sandbox = actual['NetworkSettings']['SandboxKey']
        self.docker_context = {'schema': 'ouf.semantic-docker-frame-context.v1',
            'bundleParent': str(self.daemon_root / 'exec/containerd/daemon/io.containerd.runtime.v2.task/moby'),
            'metadataParent': str(self.daemon_root / 'data/containers'),
            'networkNamespaceParent': str(Path(sandbox).parent), 'cgroupDriver': 'systemd',
            'storageParent': str(self.daemon_root / 'data'), 'rootfsLayout': 'docker-containerd-overlayfs-v1'}
        self.native_network = {'interface': 'eth0', 'bridge': 'br-' + self.nid[:12],
            'mac': '02:42:ab:cd:ef:02', 'ipv4': self.registry_address,
            'workloadRef': 'ouf-semantic', 'bindingRef': 'ouf-semantic-file-native'}

    def gateway_request(self, request):
        fixture = self.root / 'proxy'; fixture.mkdir(mode=0o755)
        for name in ('jvm_fixture_servers.py', 'jvm_fixture_inputs.py'):
            shutil.copyfile(Path(__file__).with_name(name), fixture / name)
            (fixture / name).chmod(0o444)
        (fixture / 'admin-key').write_text('DISPOSABLE_ADMIN_FIXTURE_KEY')
        (fixture / 'admin-key').chmod(0o440); os.chown(fixture / 'admin-key', 0, 10001)
        (fixture / 'config.json').write_bytes(c.encoded({'upstream_origin': 'http://' + self.registry_address + ':8080',
            'routes': self.routes, 'admin_key_file': '/fixture/admin-key', 'timeout': 2}))
        (fixture / 'config.json').chmod(0o444)
        request.update(Image=self.gateway_image, Entrypoint=['python3'],
                       Cmd=['/fixture/jvm_fixture_servers.py', 'gateway', '--config', '/fixture/config.json'])
        request['HostConfig']['Binds'].append(str(fixture) + ':/fixture:ro')
        return request

    def make_iam(self, tls_root):
        application = self.iam_app
        profile = IamProfile(**application.profile_values(('127.0.0.1',)))
        first_call = len(application.calls)
        class CurrentIam:
            # Preserve all earlier setup calls; expose the post-setup suffix to
            # the shared fixture's zero-IAM-during-installation assertion.
            @property
            def calls(self):
                return [(path, None) for _, path, _ in application.calls[first_call:]]
            def close(self):
                pass
            def context(self):
                return ssl.create_default_context()
        value = CurrentIam(); value.profile = profile
        return value

    def extra_scopes(self, raw):
        super().extra_scopes(raw)
        token_info = self.token_root.stat()
        token = {'source': str(self.token_root), 'target': '/run/fixture-token', 'fileName': 'token.jwt',
            'gid': 10001, 'directoryDevice': token_info.st_dev, 'directoryInode': token_info.st_ino,
            'ownerBindingHash': self.owner_binding.digest(), 'maxBytes': 16384, 'minimumRemainingSeconds': 90}
        baseline = (ROOT / 'tools/semantic_frame_compiler/containerd-overlayfs-southbound.json').read_bytes()
        self.assertEqual(hashlib.sha256(baseline).hexdigest(), BASELINE_SHA256)
        template, launch = compile_inputs(baseline, self.profile.request, self.tree, token,
                                         self.delegation, self.proposal_key, ENGINE)
        native_binary = lambda name: {'path': str(Path(shutil.which(name)).resolve()),
            'sha256': hashlib.sha256(Path(shutil.which(name)).resolve().read_bytes()).hexdigest()}
        runtime_root = self.daemon_root / 'exec/runtime-runc/moby'
        frame_source = ROOT / 'tools/semantic_frame_compiler/frame-observer.py'
        self.recipe = {'schema': 'ouf.semantic-file-only-node-recipe.v1',
            'sourceClosureHash': self.expected['sourceClosureHash'], 'qualifiedPackageHash': c.digest(self.image_audit),
            'imageConfigurationHash': self.image_audit['configSha256'], 'expectedRootfsSeal': self.expected_seal,
            'template': template, 'launch': launch, 'dockerContext': self.docker_context,
            'runtimeRoot': str(runtime_root), 'observationConfiguration': {
                'runtimeBinding': native_binary('runc'), 'runtimeRootParents': [str(self.daemon_root / 'exec')],
                'bundleParents': [self.docker_context['bundleParent']],
                'commands': {name: native_binary(name) for name in ('ip', 'nsenter')},
                'candidate': {'networkBindings': [self.native_network], 'transport': [{
                    'purpose': 'IDENTITY', 'authorityRef': 'ouf-semantic-file-action', 'source': self.registry_address,
                    'destination': str(self.subnet.network_address + 1), 'protocol': 'tcp', 'port': 443,
                    'peerIngress': {'kind': 'HOST', 'ifindex': 0}}], 'tableName': 'ouf_postboot_fixture'},
                'rootfsLimits': LIMITS},
            'frameSourceBinding': {'path': str(frame_source), 'sha256': hashlib.sha256(frame_source.read_bytes()).hexdigest()},
            'renewableToken': token, 'delegationKeyMetadataHash': file_source(self.delegation),
            'proposalReceiptKey': self.proposal_key, 'transactionId': c.digest({'fixture': self.cid}), 'observationSeconds': 180}
        pg = self.inspect(self.pg_id)
        readiness = {'databaseContainerId': self.pg_id, 'databaseUser': 'ouf_fixture', 'database': 'ouf_semantic',
            'databaseOid': self.database_oid, 'flywaySchema': 'ouf_sem', 'flywayHistoryHash': c.digest(self.history),
            'health': {'address': self.registry_address, 'port': 8080, 'path': '/actuator/health/readiness', 'timeoutSeconds': 5}}
        database = {'readiness': readiness, 'postgres': {
            'binding': prefix_fixture.runtime_bindings.observed(pg, prefix_fixture.runtime_bindings.SORTED),
            'bindingProfile': prefix_fixture.runtime_bindings.SORTED, 'restartCount': pg['RestartCount']},
            'program': prefix_fixture.private_profile(Path(shutil.which('docker')).resolve())}
        caller_token = self.root / 'ingestion.jwt'
        caller_token.write_text(inputs.rs256_jwt(self.iam_key, inputs.service_claims(self.iam_app.issuer, int(time.time()))))
        caller_token.chmod(0o440); os.chown(caller_token, 0, 10001)
        origin = 'http://' + self.gateway_address + ':9080'
        caller = self.create_container({'Image': self.alpine_image, 'User': '10001:10001',
            'Entrypoint': ['sleep'], 'Cmd': ['600'], 'Env': ['OUF_INGESTION_ACTIVATION_GATEWAY_URL=' + origin,
                'OUF_INGESTION_ACTIVATION_TOKEN_FILE=/run/ingestion.jwt'],
            'HostConfig': {'NetworkMode': self.network_name, 'CapDrop': ['ALL'], 'SecurityOpt': ['no-new-privileges'],
                'Binds': [str(caller_token) + ':/run/ingestion.jwt:ro']}}, 'ouf-postboot-caller-')
        self.assertEqual(self.engine.request('POST', '/v1.44/containers/' + caller + '/start')[0], 204)
        actual_caller = self.inspect(caller)
        configuration = {'semanticReferenceBindings': [inputs.reference()],
                         'semanticMapping': {'semanticRefs': [inputs.SEMANTIC_ID + '@' + inputs.SEMANTIC_VERSION]}}
        config_hash = 'sha256:' + c.digest(configuration)
        version = str(uuid.uuid4())
        original = {'caller': {'binding': prefix_fixture.runtime_bindings.observed(actual_caller, prefix_fixture.runtime_bindings.SORTED),
            'bindingProfile': prefix_fixture.runtime_bindings.SORTED, 'restartCount': 0},
            'origin': origin, 'tokenTarget': '/run/ingestion.jwt', 'tokenSource': prefix_fixture.private_profile(caller_token),
            'pythonExecutable': self.gateway_profile['pythonExecutable'], 'ca': None, 'peerCertificateSha256': None,
            'references': [inputs.reference()], 'frozenConfigurationHash': config_hash, 'onboardingVersionId': version,
            'frozenConfiguration': {'onboardingVersionId': version, 'configurationHash': config_hash,
                                    'state': 'APPROVED', 'configuration': configuration}}
        proposal = {'registry': {'containerId': self.cid, 'imageId': self.image,
            'configHash': c.digest(self.baseline['Config']), 'hostConfigHash': c.digest(self.baseline['HostConfig']),
            'mountsHash': c.digest(sorted(self.baseline['Mounts'], key=lambda m: m['Destination']))},
            'requiredGates': list(prefix_fixture.GATES), 'unresolvedGateCount': 8}
        historical_binding = {'disposableHistoricalFixture': True}
        # Rebuild the candidate around the actual historical binding before
        # scopes are signed. No current OCI is included in this history.
        self.assertEqual(self.plan['stages'][0]['intent']['proposalHash'], c.digest(proposal))
        history = {'schema': 'ouf.semantic-registry-recovery-private-historical-inputs.v1',
            'kind': 'OFFLINE_COMPOSITION_INPUTS_NOT_EXECUTABLE_AUTHORITY', 'candidateContract': self.plan,
            'historicalBinding': historical_binding, 'proposal': proposal,
            'registryInputs': {'creationRequest': self.profile.request, 'configtree': self.tree,
                'nodeRecipe': self.recipe, 'readinessScope': readiness, 'imageAudit': self.image_audit,
                'directoryPlan': {'root': str(self.root / 'historical/registry')}}}
        # The prefix fixture's synthetic historical hash is replaced by this
        # independently materialized fixture history through its plan hook.
        self.assertEqual(c.digest(historical_binding), self.plan['stages'][0]['intent']['historicalChainHash'])
        history_root = self.root / 'history-inputs'; history_root.mkdir(mode=0o700)
        history_file = history_root / 'inputs.json'; self.write(history_file, c.encoded(history))
        self.native_context = {'schema': 'ouf.semantic-registry-recovery-native-context.v1',
            'retainedInputs': prefix_fixture.private_profile(history_file), 'plan': self.plan,
            'engineBinding': {'socketPath': self.engine.path, 'socketBinding': list(self.engine.binding)},
            'stoppedSnapshot': self.baseline, 'nodeRecipe': self.recipe, 'database': database,
            'gateway': {'pin': self.gateway_pin, 'profile': self.gateway_profile, 'routes': self.routes, 'networkId': self.nid},
            'originalRequest': original, 'executionRoot': str(self.execution_root)}
        self.expected['intakeHash'] = c.digest(self.native_context)
        raw['semanticRegistryRecoveryFactory'] = factory_scope(self.native_context)
        raw['semanticRegistryRecoveryNode'] = node_scope(self.plan, self.recipe, self.profile)
        raw['semanticRegistryRecoveryDatabase'] = database_scope(SimpleNamespace(plan=self.plan, engine=self.engine),
            readiness, database['postgres'], database['program'], self.image_audit)
        raw['semanticRegistryRecoveryOriginalRequest'] = request_scope(SimpleNamespace(
            lifecycle=SimpleNamespace(plan=self.plan), scope=raw['semanticRegistryRecoveryGateway']), original)
        policy = json.loads(self.policy.read_bytes()); policy['keys'][1]['publicKey'] = self.grant['publicKey']
        self.write(self.policy, c.encoded(policy)); self.verifier.policy_binding = self.binding(self.policy)
        self.node_signer = ExistingEd25519Signer(self.binding(self.key), policy['keys'][1]['keyRef'], self.verifier,
            {'role': 'CREATION_ATTESTATION', 'issuerRef': self.context['attestorRef'],
             'installationRef': self.context['installationRef'], 'entityRef': self.context['entityRef']})
        (self.execution_root / 'node').mkdir(mode=0o700)

    def test_full_native_pause_owner_oci_database_release_and_same_service_get(self):
        from tools.semantic_registry_recovery_execution.semantic_request import OriginalSemanticRequest
        initial = OriginalSemanticRequest(self.gateway, self.native_context['originalRequest'])
        failed = initial._get(inputs.reference())
        self.assertEqual(failed['status'], 502)
        self.install_owner()
        worker, coordination, _, _, statuses = self.run_worker()
        self.assertEqual(statuses[-1]['state'], 'ACTIVE')
        with coordination:
            runner = build_on_bootstrap(self.runner, self.native_context, self.owner_context,
                self.current_authority, self.authority, self.verifier, self.node_signer)
        deadline = time.monotonic() + 180
        cold_start = ColdStartWait()
        while True:
            delay = None
            with coordination:
                cold_start.before_poll(runner, self.ports.witness)
                before = runner.current()
                if before['nextStage'] == 12:
                    break
                row = runner.step()
                if row['nextStage'] == before['nextStage']:
                    delay = cold_start.defer(runner, before, row, self.ports.witness)
                self.assertLess(time.monotonic(), deadline, 'Finite whole JVM recovery did not settle')
            # A read-only observation of the durable claim may complete a
            # delayed native acknowledgement; Runner never redispatches it.
            if delay is not None:
                time.sleep(delay)
        self.assertTrue(row['originalSemanticGetSucceeded'])
        self.assertEqual(self.iam_app.grant_count, 1)
        self.assertTrue(any(path == self.iam_app.active_path and code == 200
                            for _, path, code in self.iam_app.calls))
        self.assertEqual(worker.r.journal.read()['controlledCumulativeGrantAttempts'], 320)
        attempts = [effect['stage'] for effect in row['effects'] if effect.get('nativeRequestAttempted')]
        self.assertEqual(attempts, ['START_NEW_WAIT_GATE', 'PAUSE_NEW_WAIT_GATE',
                                    'UNPAUSE_ATTESTED_GENERATION', 'RELEASE_SAME_GENERATION_SIGUSR1'])
        self.assertEqual(row['effects'][-1]['nativeEvidence']['httpStatus'], 200)
        self.assertFalse(row['effects'][-1]['nativeEvidence']['releaseAcceptance'])


if __name__ == '__main__':
    unittest.main()
