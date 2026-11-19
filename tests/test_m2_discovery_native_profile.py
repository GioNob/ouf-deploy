"""Independent synthetic proposals; no target OCI, secret or authority evidence."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'tools/semantic_application_cutover')]
from tools.m2_discovery_installation_profile.native_profile import DiscoveryProfile, JAVA, ENTRY, FILE_ROLES, digest
from tools.m2_discovery_installation_profile.frame import compile_policy, compilation_receipt
from tools.semantic_application_cutover.file_only_profile import FileOnlyProfile
from tools.semantic_application_cutover.transition_journal import PHASES


def fixture():
    names = ('read.key', 'proposal.key', 'provider.secret', 'discovery.key', 'trust.p12')
    fs = {role: {'source': '/fixture/' + name, 'target': '/run/owned/' + name, 'readOnly': True,
        'uid': 10001 if i == 0 else 0, 'gid': 10001, 'mode': 0o400 if i == 0 else 0o440,
        'maxBytes': 64 if i in (0, 1, 3) else 4096, 'sha256': str(i + 1) * 64,
        'metadataHash': 'a' * 64} for i, (role, name) in enumerate(zip(FILE_ROLES, names))}
    tree = {'source': '/fixture/db', 'target': '/run/db', 'readOnly': True, 'uid': 10001, 'gid': 10001,
        'directoryMode': 0o500, 'fileName': 'OUF_SEM_DB_PASSWORD', 'fileMode': 0o400,
        'maxBytes': 4096, 'sha256': '6' * 64}
    token = {'source': '/fixture/policy', 'target': '/run/policy', 'fileName': 'token', 'gid': 10001,
        'directoryDevice': 1, 'directoryInode': 2, 'ownerBindingHash': '7' * 64,
        'maxBytes': 8192, 'minimumRemainingSeconds': 30}
    refs = {'OUF_IAM_ISSUER': 'https://iam.fixture.invalid/realms/test', 'OUF_IAM_AUDIENCE': 'fixture-gateway',
        'OUF_SCHEMA_GOV_CLIENT_ID': 'fixture-semantic', 'OUF_SCHEMA_GOV_TOKEN_ENDPOINT': 'https://iam.fixture.invalid/token',
        'OUF_SCHEMA_GOV_WORKLOAD_SCOPE': 'gateway.southbound.invoke',
        'OUF_SCHEMA_GOV_GATEWAY_BASE_URL': 'https://provider.fixture.invalid:10443',
        'OUF_SCHEMA_GOV_SEARCH_PATH': '/internal/providers/schema-gov/search',
        'OUF_SCHEMA_GOV_FETCH_PATH': '/internal/providers/schema-gov/fetch',
        'OUF_SEMANTIC_DISCOVERY_DELEGATION_WORKLOAD': 'fixture-mcp'}
    old = ['PATH=/usr/bin:/bin', 'OUF_SCHEMA_GOV_ENABLED=false', 'OUF_DISCOVERY_WORKER_ENABLED=false',
        'OUF_SEMANTIC_DELEGATION_WORKLOAD=fixture-mcp', 'OUF_SEMANTIC_PROPOSAL_RECEIPT_WORKLOAD=fixture-mcp',
        'OUF_AUTHORIZATION_REGISTRY_URL=https://policy.fixture.invalid/active',
        'OUF_SEM_DB_URL=jdbc:postgresql://db.fixture.invalid/semantic', 'OUF_SEM_DB_USER=fixture-semantic']
    values = dict(row.split('=', 1) for row in old)
    values.update(refs)
    values.update(OUF_SCHEMA_GOV_ENABLED='true', OUF_DISCOVERY_WORKER_ENABLED='true', OUF_IAM_ENABLED='true',
        OUF_SCHEMA_GOV_GATEWAY_AUTH_ENABLED='true', OUF_SEMANTIC_DELEGATION_KEY_FILE='/run/owned/read.key',
        OUF_SEMANTIC_PROPOSAL_RECEIPT_KEY_FILE='/run/owned/proposal.key', OUF_SCHEMA_GOV_CLIENT_SECRET_FILE='/run/owned/provider.secret',
        OUF_SEMANTIC_DISCOVERY_DELEGATION_KEY_FILE='/run/owned/discovery.key',
        SPRING_CONFIG_IMPORT='configtree:/run/db/', OUF_AUTHORIZATION_REGISTRY_TOKEN_FILE='/run/policy/token',
        JAVA_TOOL_OPTIONS='-Djavax.net.ssl.trustStore=/run/owned/trust.p12 -Djavax.net.ssl.trustStoreType=PKCS12 -Djavax.net.ssl.trustStorePassword=changeit')
    bindings = [{'source': f['source'], 'target': f['target'], 'readOnly': True} for f in fs.values()]
    bindings += [{'source': tree['source'], 'target': tree['target'], 'readOnly': True},
        {'source': token['source'], 'target': token['target'], 'readOnly': True}]
    request = {'Image': 'sha256:' + 'b' * 64, 'User': '10001:10001', 'Entrypoint': copy.deepcopy(ENTRY),
        'Cmd': list(JAVA), 'Env': [k + '=' + v for k, v in values.items()], 'WorkingDir': '/app',
        'HostConfig': {'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0}, 'CapDrop': ['ALL'],
            'SecurityOpt': ['no-new-privileges:true'], 'NetworkMode': 'fixture-private', 'Memory': 2147483648,
            'MemorySwap': 2147483648, 'NanoCpus': 2000000000, 'PidsLimit': 512, 'ReadonlyRootfs': False,
            'Mounts': [{'Type': 'bind', 'Source': b['source'], 'Target': b['target'], 'ReadOnly': True} for b in bindings]},
        'NetworkingConfig': {'EndpointsConfig': {'fixture-private': {'NetworkID': 'f' * 64}}}}
    selection = {'preserved_environment': old, 'references': refs, 'files': fs, 'configtree': tree,
        'renewable_token': token, 'mcp_workload': 'fixture-mcp'}
    startup = {'uid': 10001, 'gid': 10001, 'umask': None, 'cwd': '/app', 'args': ENTRY + JAVA,
        'env': request['Env'] + ['HOSTNAME=$OUF_HOSTNAME']}
    launch = {'schema': 'ouf.semantic-creation-frame-launch.v1', 'startup': startup,
        'sources': [{k: v for k, v in f.items() if k != 'metadataHash'} for f in fs.values()],
        'manifest': {'user': '10001:10001', 'readOnlyRoot': False, 'memoryBytes': 2147483648,
            'pidsLimit': 512, 'mounts': bindings}}
    mounts = [{'type': 'bind', 'source': b['source'], 'destination': b['target'], 'options': ['rbind', 'rprivate', 'ro']} for b in bindings]
    mounts += [{'type': 'bind', 'source': source, 'destination': target, 'options': ['rbind', 'rprivate', 'ro']}
        for source, target in (('$OUF_HOSTS', '/etc/hosts'), ('$OUF_HOSTNAME_FILE', '/etc/hostname'), ('$OUF_RESOLV', '/etc/resolv.conf'))]
    template = {'schema': 'ouf.semantic-creation-frame-template.v1', 'approvedHooks': {}, 'expectedOci': {
        'hostname': '$OUF_HOSTNAME', 'root': {'path': '$OUF_ROOTFS', 'readonly': False},
        'process': {'user': {'uid': 10001, 'gid': 10001}, 'args': ENTRY + JAVA, 'cwd': '/app',
            'env': copy.deepcopy(startup['env']), 'noNewPrivileges': True, 'capabilities': {}},
        'mounts': mounts, 'linux': {'cgroupsPath': '$OUF_CGROUPS', 'namespaces': [{'type': 'network', 'path': '$OUF_NETWORK_NAMESPACE'}],
            'resources': {'memory': {'limit': 2147483648, 'swap': 2147483648}, 'pids': {'limit': 512},
                'cpu': {'period': 100000, 'quota': 200000}}}}}
    context = {'schema': 'ouf.semantic-docker-frame-context.v1', 'containerId': 'c' * 64,
        'bundleParent': '/run/fixture/bundles', 'metadataParent': '/var/lib/fixture/containers',
        'networkNamespaceParent': '/run/fixture/netns', 'networkNamespaceName': None, 'cgroupDriver': 'systemd',
        'rootfsPath': '/var/lib/fixture/overlay/merged', 'storageParent': '/var/lib/fixture'}
    return request, selection, template, launch, context


def change_env(request, key, value):
    values = dict(row.split('=', 1) for row in request['Env']); values[key] = value
    request['Env'] = [k + '=' + v for k, v in values.items()]


class DiscoveryNativeProfile(unittest.TestCase):
    def test_complete_proposal_retains_full_transport_and_renewal_phases_without_authority(self):
        r, s, t, l, c = fixture(); before = copy.deepcopy((r, s, t, l, c))
        p = DiscoveryProfile(r, **s); result = compile_policy(t, l, c, execution_profile=p)
        self.assertEqual((r, s, t, l, c), before)
        self.assertEqual(p.compiled['phaseOrder'], list(PHASES))
        self.assertIn('INSTALL_AUTHENTICATED_TRANSPORT', PHASES)
        self.assertIn('START_DISTINCT_LEASE_WORKER', PHASES)
        self.assertEqual(len(result['manifest']['mounts']), 7); self.assertEqual(len(result['sources']), 5)
        self.assertEqual(result['fileBindings'], s['files'])
        self.assertEqual(result['expectedOci']['process']['args'], ENTRY + JAVA)
        self.assertEqual(result['executionProfileHash'], p.sha256)
        receipt = compilation_receipt(t, l, c, result)
        for k in ('observedOciUsed', 'inputsAuthenticated', 'credentialCustodyProven', 'providerAdmissionProven',
                  'nativeExecutorIntegrated', 'startAuthorized', 'runtimeAuthorityIssued', 'targetApplyAuthorized'):
            self.assertIs(receipt[k], False)
        self.assertNotIn('/fixture/', str(receipt)); self.assertNotIn('OUF_SEM_DB_URL', str(receipt))

    def test_file_only_profile_rejects_discovery_and_new_compiler_rejects_old_type(self):
        r, s, t, l, c = fixture()
        with self.assertRaisesRegex(ValueError, 'DISCOVERY_MUST_BE_EXPLICITLY_DISABLED'):
            FileOnlyProfile(r, s['configtree'])
        with self.assertRaisesRegex(ValueError, 'EXACT_TYPED_DISCOVERY'):
            compile_policy(t, l, c, execution_profile=object())

    def test_missing_native_custody_references_cannot_be_replaced_by_success_booleans(self):
        for role in FILE_ROLES:
            r, s, *_ = fixture(); s['files'][role].pop('metadataHash'); s['files'][role]['custodyProven'] = True
            with self.subTest(role=role), self.assertRaises(ValueError): DiscoveryProfile(r, **s)
        r, s, *_ = fixture(); s['renewable_token'].pop('directoryInode'); s['renewable_token']['directoryCustodyScopeHash'] = 'd' * 64
        with self.assertRaises(ValueError): DiscoveryProfile(r, **s)

    def test_same_key_bytes_at_distinct_paths_and_credential_reuse_are_denied(self):
        for other in ('consultationKey', 'proposalReceiptKey', 'providerCredential'):
            r, s, *_ = fixture(); s['files']['discoveryReceiptKey']['sha256'] = s['files'][other]['sha256']
            with self.subTest(other=other), self.assertRaisesRegex(ValueError, 'CONTENT_IDENTITIES'): DiscoveryProfile(r, **s)

    def test_unrelated_old_settings_cannot_be_removed_changed_or_overridden(self):
        for value in ('jdbc:postgresql://other.invalid/db', ''):
            r, s, *_ = fixture(); change_env(r, 'OUF_SEM_DB_URL', value)
            with self.assertRaisesRegex(ValueError, 'PRESERVE_UNRELATED'): DiscoveryProfile(r, **s)
        for name in ('SPRING_APPLICATION_JSON', 'SPRING_CONFIG_LOCATION', 'JDK_JAVA_OPTIONS', 'JAVA_OPTS',
                     'OUF_SEMANTIC_PROVIDERS_SCHEMA_GOV_ENABLED'):
            r, s, *_ = fixture(); s['preserved_environment'].append(name + '=override'); r['Env'].append(name + '=override')
            with self.subTest(name=name), self.assertRaises(ValueError): DiscoveryProfile(r, **s)

    def test_flags_issuer_workload_and_tls_are_explicit_and_bound(self):
        for key, value in [('OUF_IAM_ENABLED', 'false'), ('OUF_SCHEMA_GOV_GATEWAY_AUTH_ENABLED', 'false'),
                           ('OUF_DISCOVERY_WORKER_ENABLED', 'false'), ('JAVA_TOOL_OPTIONS', '-Doverride=true')]:
            r, s, *_ = fixture(); change_env(r, key, value)
            with self.subTest(key=key), self.assertRaises(ValueError): DiscoveryProfile(r, **s)
        r, s, *_ = fixture(); s['mcp_workload'] = 'other-mcp'
        with self.assertRaisesRegex(ValueError, 'MUST_AGREE'): DiscoveryProfile(r, **s)
        for value in ('http://provider.invalid', 'https://user:pass@provider.invalid', 'https://provider.invalid/?token=bad'):
            r, s, *_ = fixture(); s['references']['OUF_SCHEMA_GOV_GATEWAY_BASE_URL'] = value
            with self.assertRaises(ValueError): DiscoveryProfile(r, **s)

    def test_native_mount_custody_modes_and_shadowing_are_closed(self):
        for role in FILE_ROLES:
            for field, value in [('readOnly', False), ('mode', 0o444), ('gid', 0)]:
                r, s, *_ = fixture(); s['files'][role][field] = value
                with self.subTest(role=role, field=field), self.assertRaises(ValueError): DiscoveryProfile(r, **s)
        for target in ('/run/db/secret', '/run/policy/secret', '/run/owned/read.key'):
            r, s, *_ = fixture(); s['files']['discoveryReceiptKey']['target'] = target
            change_env(r, 'OUF_SEMANTIC_DISCOVERY_DELEGATION_KEY_FILE', target)
            with self.assertRaisesRegex(ValueError, 'NONSHADOWING'): DiscoveryProfile(r, **s)

    def test_bare_flag_flip_auto_restart_and_direct_java_start_are_denied(self):
        r, s, *_ = fixture(); r['Entrypoint'] = list(JAVA); r['Cmd'] = []
        with self.assertRaisesRegex(ValueError, 'PREAPPLICATION_GATE'): DiscoveryProfile(r, **s)
        for key, value in [('RestartPolicy', {'Name': 'always', 'MaximumRetryCount': 0}), ('NetworkMode', 'host'),
                           ('CapAdd', ['SYS_ADMIN']), ('PortBindings', {'8080/tcp': [{'HostPort': '8080'}]}),
                           ('CpuQuota', 999), ('Mounts', [])]:
            r, s, *_ = fixture(); r['HostConfig'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): DiscoveryProfile(r, **s)

    def test_profile_or_selection_drift_never_reuses_prepared_hash(self):
        r, s, *_ = fixture(); p = DiscoveryProfile(r, **s)
        p.selection['files']['discoveryReceiptKey']['metadataHash'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'PROFILE_OR_REQUEST_DRIFT'): p.verify(r)
        p = DiscoveryProfile(r, **s); p.compiled['targetApplyAuthorized'] = True
        with self.assertRaisesRegex(ValueError, 'PROFILE_OR_REQUEST_DRIFT'): p.verify(r)

    def test_native_process_environment_and_cpu_limits_match_signed_launch(self):
        for case in ('env', 'cpu', 'capabilities', 'gate', 'readonly'):
            r, s, t, l, c = fixture(); p = DiscoveryProfile(r, **s)
            if case == 'env': l['startup']['env'] = l['startup']['env'] + ['EXTRA=unreviewed']
            if case == 'cpu': t['expectedOci']['linux']['resources']['cpu']['quota'] += 1
            if case == 'capabilities': t['expectedOci']['process']['capabilities'] = {'bounding': ['CAP_SYS_ADMIN']}
            if case == 'gate': t['expectedOci']['process']['args'] = ['unreviewed']
            if case == 'readonly': l['manifest']['readOnlyRoot'] = True
            with self.subTest(case=case), self.assertRaises(ValueError): compile_policy(t, l, c, execution_profile=p)

    def test_missing_extra_shared_and_rw_oci_mounts_cannot_pass(self):
        for case in ('missing', 'extra', 'shared', 'rw', 'source', 'duplicate'):
            r, s, t, l, c = fixture(); p = DiscoveryProfile(r, **s); mounts = t['expectedOci']['mounts']
            if case == 'missing': mounts.pop(2)
            if case == 'extra': mounts.append({'type': 'bind', 'source': '/var/run/docker.sock', 'destination': '/run/docker.sock', 'options': ['ro']})
            if case == 'shared': mounts[2]['options'] += ['rshared']
            if case == 'rw': mounts[2]['options'] += ['rw']
            if case == 'source': mounts[2]['source'] = '/fixture/other'
            if case == 'duplicate': mounts.append(copy.deepcopy(mounts[2]))
            with self.subTest(case=case), self.assertRaises(ValueError): compile_policy(t, l, c, execution_profile=p)

    def test_oci_cannot_be_its_own_template_and_context_cannot_supply_observation(self):
        r, s, t, l, c = fixture(); p = DiscoveryProfile(r, **s)
        result = compile_policy(t, l, c, execution_profile=p)
        t['expectedOci'] = result['expectedOci']
        with self.assertRaises(ValueError): compile_policy(t, l, c, execution_profile=p)
        r, s, t, l, c = fixture(); c['observedOci'] = t['expectedOci']
        with self.assertRaises(ValueError): compile_policy(t, l, c, execution_profile=DiscoveryProfile(r, **s))

    def test_gate_slot_exemption_does_not_extend_to_environment_or_restored_directories(self):
        r, s, t, l, c = fixture(); r['Env'].append('OUF_REVIEWED_SENTINEL=$OUF_ROOTFS'); s['preserved_environment'].append('OUF_REVIEWED_SENTINEL=$OUF_ROOTFS')
        p = DiscoveryProfile(r, **s); l['startup']['env'].append('OUF_REVIEWED_SENTINEL=$OUF_ROOTFS'); t['expectedOci']['process']['env'].append('OUF_REVIEWED_SENTINEL=$OUF_ROOTFS')
        with self.assertRaises(ValueError): compile_policy(t, l, c, execution_profile=p)

    def test_compilation_has_no_io_or_authority_side_effect(self):
        r, s, t, l, c = fixture()
        with patch('builtins.open', side_effect=AssertionError('IO denied')):
            p = DiscoveryProfile(r, **s); result = compile_policy(t, l, c, execution_profile=p)
        self.assertIs(p.compiled['externalProviderCallsAllowed'], False)
        self.assertIs(p.compiled['nativeExecutorIntegrated'], False)
        self.assertEqual(result['startup']['args'], ENTRY + JAVA)

    def test_pinned_engine_baseline_compiles_full_discovery_without_observed_oci(self):
        sys.path.insert(0,str(ROOT/'tools/semantic_frame_compiler'))
        from tools.m2_discovery_installation_profile.frame_inputs import compile_inputs,ENGINE
        r,s,_,_,c=fixture();p=DiscoveryProfile(r,**s)
        raw=(ROOT/'tools/semantic_frame_compiler/containerd-overlayfs-southbound.json').read_bytes()
        t,l=compile_inputs(raw,r,execution_profile=p,engine_profile=ENGINE)
        policy=compile_policy(t,l,c,execution_profile=p)
        self.assertEqual(len(policy['sources']),5)
        self.assertEqual(len(policy['manifest']['mounts']),7)
        self.assertEqual(policy['startup']['args'],ENTRY+JAVA)
        with self.assertRaisesRegex(ValueError,'BASELINE_REQUIRED'):
            compile_inputs(raw+b' ',r,execution_profile=p,engine_profile=ENGINE)


if __name__ == '__main__': unittest.main()
