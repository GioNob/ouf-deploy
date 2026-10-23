"""Actual configured DNS/TLS and the three unchanged HTTP endpoint contracts."""
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import copy
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT), str(ROOT / 'tests'), str(Path(__file__).resolve().parent)]
import test_current_admission as _native_fixture_paths
from tools.semantic_registry_recovery_execution import caller_lookup as lookup, original_tls, postboot_prepare as p, semantic_request
import test_caller_resolver_view as resolver_fixture


REFERENCE = {'semanticId': 'urn:fixture:lookup', 'semanticVersion': '1.0',
    'revisionId': '00000000-0000-0000-0000-000000000001',
    'publicationSetId': '00000000-0000-0000-0000-000000000002'}
FROZEN = {'sourceId': 'fixture-source', 'onboardingVersionId': '00000000-0000-0000-0000-000000000003',
          'configurationHash': 'sha256:' + 'a' * 64}


class Endpoint(resolver_fixture.Http):
    def do_GET(self):
        self.server.http_calls += 1
        self.server.tokens.append(self.headers.get('Authorization'))
        if self.path.startswith('/api/internal/v1/onboarding/ingestion-configuration?'):
            value = {**FROZEN, 'state': 'APPROVED', 'configuration': {}}
        elif self.path.startswith('/api/semantic/v1/references:resolve?'):
            value = {'semantic_id': REFERENCE['semanticId'], 'semantic_version': REFERENCE['semanticVersion'],
                'revision_id': REFERENCE['revisionId'], 'publication_set_id': REFERENCE['publicationSetId'], 'status': 'ACTIVE'}
        else:
            self.send_response(404); self.end_headers(); return
        raw = json.dumps(value).encode(); self.send_response(200)
        self.send_header('Content-Length', str(len(raw))); self.end_headers(); self.wfile.write(raw)


class LookupTransport(unittest.TestCase):
    setUpClass = classmethod(resolver_fixture.CallerResolver.setUpClass.__func__)
    def setUp(self):
        resolver_fixture.CallerResolver.setUp(self); self.server.RequestHandlerClass = Endpoint; self.server.tokens = []

    def invoke(self, source, values):
        fd = os.open('/proc/self/ns/net', os.O_RDONLY)
        try:
            return subprocess.run([sys.executable, '-I', '-B', '-S', '-c', source, str(fd)],
                input=json.dumps(values).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                pass_fds=(fd,), timeout=12, env={'LC_ALL': 'C'}, cwd='/')
        finally: os.close(fd)

    def payload(self, reference):
        return {'origin': self.origin, 'token': 'DISPOSABLE_FIXTURE_SERVICE_TOKEN', 'reference': reference,
            'ca': self.cert.read_text(), 'lookup': self.views,
            'peerCertificateSha256': hashlib.sha256(ssl_der(self.cert.read_text())).hexdigest()}

    def test_actual_tls_identity_uses_configured_dns_no_http(self):
        before = resolver_fixture.CallerResolver.host_snapshot(self)
        result = self.invoke(original_tls.TLS_CHILD_SOURCE, {'origin': self.origin,
            'ca': self.cert.read_text(), 'lookup': self.views})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['certificateChainVerified'])
        self.assertGreater(self.dns.queries, 0); self.assertEqual(self.server.http_calls, 0)
        self.assertEqual(before, resolver_fixture.CallerResolver.host_snapshot(self))

    def test_actual_frozen_get_uses_same_dns_tls_and_service_token(self):
        result = self.invoke(p.FROZEN_CHILD_SOURCE, self.payload(FROZEN))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['configurationHash'], FROZEN['configurationHash'])
        self.assertGreater(self.dns.queries, 0)
        self.assertEqual(self.server.tokens, ['Bearer DISPOSABLE_FIXTURE_SERVICE_TOKEN'])

    def test_actual_semantic_get_uses_same_dns_and_exact_active_reference(self):
        result = self.invoke(semantic_request.CHILD_SOURCE, self.payload(REFERENCE))
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value['status'], 200); self.assertTrue(value['exactActiveReferenceMatched'])
        self.assertGreater(self.dns.queries, 0)
        self.assertEqual(self.server.tokens, ['Bearer DISPOSABLE_FIXTURE_SERVICE_TOKEN'])

    def test_leaf_mismatch_prevents_bearer_on_both_http_children(self):
        for source, ref in ((p.FROZEN_CHILD_SOURCE, FROZEN), (semantic_request.CHILD_SOURCE, REFERENCE)):
            value = self.payload(ref); value['peerCertificateSha256'] = '0' * 64
            result = self.invoke(source, value)
            self.assertNotEqual(result.returncode, 0); self.assertEqual(result.stdout, b'')
        self.assertEqual(self.server.http_calls, 0); self.assertEqual(self.server.tokens, [])

    def test_unapproved_nss_prevents_dns_and_bearer(self):
        self.views['nsswitch.conf'] = 'hosts: files resolve dns\n'
        result = self.invoke(semantic_request.CHILD_SOURCE, self.payload(REFERENCE))
        self.assertNotEqual(result.returncode, 0); self.assertEqual(self.server.tokens, [])
        self.assertEqual(self.dns.queries, 0)


def ssl_der(value):
    import ssl
    return ssl.PEM_cert_to_DER_cert(value)


class Contract(unittest.TestCase):
    def test_lookup_policy_and_files_are_part_of_bound_profile(self):
        caller = {'State': {'Pid': 7}}
        views = {'resolv.conf': 'nameserver 192.0.2.1\n', 'hosts': '127.0.0.1 localhost\n', 'nsswitch.conf': 'hosts: files dns\n'}
        with patch.object(lookup, 'process_ticks', return_value=9), patch.object(lookup, '_caller_views', return_value=(views, {'pin': 1})):
            profile, _ = lookup.capture(caller)
            self.assertEqual(lookup.payload(caller, profile), {'lookup': views})
            changed = dict(profile, processTicks=10)
            with self.assertRaisesRegex(Exception, 'SAME_SIGNED_CALLER_LOOKUP'): lookup.payload(caller, changed)

    def test_recovery_case_has_stable_root_across_source_closure_updates(self):
        case = json.loads((ROOT / 'releases/semantic-registry-postboot-resolver-case-20261023.json').read_text())['preparation']
        boot = '00000000-1111-2222-3333-444444444444'
        self.assertEqual(p.prepared_root(case, {'fixture': 'sourceA'}, boot), p.prepared_root(case, {'fixture': 'sourceB'}, boot))
        p.validate_case(case)
        case['resolverRecovery']['lookupPolicy'] = {'hostResolverFallbackAllowed': True}
        with self.assertRaises(Exception): p.validate_case(case)

    def test_all_three_preparations_and_two_observations_retained_and_advance_rejected(self):
        from tools.semantic_registry_recovery_execution import resolver_reconciliation as reconcile
        case = json.loads((ROOT / 'releases/semantic-registry-postboot-resolver-case-20261023.json').read_text())['preparation']
        boot = '00000000-1111-2222-3333-444444444444'
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary, patch.object(p, 'PARENT', temporary):
            parent = Path(temporary); case['privateParent'] = temporary
            def publish(directory, name, value):
                p.publish(directory, name, value)
                return {'path': str(directory / name), 'sha256': p.digest(value)}
            for prior in case['priorPreparations']:
                directory = parent / ('semantic-registry-postboot-inputs-' + p.digest({
                    'case': prior['case'], 'closure': prior['sourceClosureHash'], 'boot': boot}))
                directory.mkdir(mode=0o700)
                publish(directory, 'claim.json', {'schema': p.SCHEMA, 'caseHash': prior['caseHash'],
                    'sourceClosureHash': prior['sourceClosureHash'], 'bootId': boot,
                    'maximumEngineGets': 12, 'maximumAdminGets': 1, 'maximumFrozenGets': 1,
                    'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False})
                for n in range(1, 7): publish(directory, 'engine-get-' + str(n) + '.json', {'requestPathHash': 'a' * 64, 'attempt': n})
                publish(directory, 'admin-get.json', {'method': 'GET', 'operation': '/apisix/admin/routes', 'maximumAttempts': 1})
            recovery = case['resolverRecovery']; original = {k: v for k, v in case.items() if k != 'resolverRecovery'}
            directory = parent / ('semantic-registry-postboot-inputs-' + p.digest({
                'case': original, 'closure': recovery['originalTlsSourceClosureHash'], 'boot': boot}))
            directory.mkdir(mode=0o700)
            tls_claim = {'schema': p.SCHEMA, 'caseHash': p.digest(original), 'sourceClosureHash': recovery['originalTlsSourceClosureHash'],
                'bootId': boot, 'maximumEngineGets': 12, 'maximumAdminGets': 1, 'maximumFrozenGets': 1,
                'maximumTlsHandshakes': 1, 'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False}
            publish(directory, 'claim.json', tls_claim)
            for n in range(1, 7): publish(directory, 'engine-get-' + str(n) + '.json', {'requestPathHash': 'a' * 64, 'attempt': n})
            publish(directory, 'admin-get.json', {'method': 'GET', 'operation': '/apisix/admin/routes', 'maximumAttempts': 1})
            origin = 'https://fixture.test'; ca = {'fixture': 'public-ca'}
            publish(directory, 'tls-handshake.json', {'originHash': p.digest(origin), 'caProfileHash': p.digest(ca),
                'maximumAttempts': 1, 'httpRequests': 0, 'bearersSent': 0})
            claim_profile = p.Files().json(str(directory / 'claim.json'))[1]
            old = parent / 'old-diagnostic'; old.mkdir(mode=0o700)
            new = parent / 'new-diagnostic'; new.mkdir(mode=0o700)
            old_claim = {'schema': 'ouf.semantic-registry-tls-diagnostic-result.v1', 'retainedClaimHash': p.digest(tls_claim),
                'bootId': boot, 'diagnosticScriptSha256': '7' * 64, 'maximumEngineGets': 2, 'maximumResolverCalls': 2,
                'maximumNewTlsHandshakes': 1, 'retainedTlsAttemptMarkers': 1, 'cumulativeTlsAttemptCeiling': 2,
                'automaticReplayAllowed': False, 'budgetReset': False}
            publish(old, 'claim.json', old_claim)
            recovery['failedObservation'] = publish(old, 'observation.json', {'oldClaim': claim_profile, 'origin': origin, 'ca': ca,
                'host': {'resolverSucceeded': True}, 'caller': {'phase': 'DNS_RESOLUTION', 'gaiCode': -3,
                    'tcpConnectAttempted': False, 'tlsHandshakeAttempted': False}})
            publish(old, 'host-dns-attempt.json', {'maximumResolverCalls': 1, 'httpRequests': 0, 'tlsHandshakes': 0})
            publish(old, 'caller-probe-attempt.json', {'maximumResolverCalls': 1, 'maximumTlsHandshakes': 1, 'httpRequests': 0, 'bearersSent': 0})
            publish(new, 'claim.json', {'schema': 'ouf.semantic-registry-caller-resolver-result.v1',
                'retainedObservationHash': recovery['failedObservation']['sha256'], 'retainedDiagnosticClaimHash': p.digest(old_claim),
                'bootId': boot, 'scriptSha256': '8' * 64, 'maximumEngineGets': 2, 'maximumResolverCalls': 1,
                'maximumTlsHandshakes': 1, 'priorEngineAttempts': 20, 'priorResolverAttempts': 2, 'priorTlsIntentMarkers': 2,
                'cumulativeEngineGetCeiling': 22, 'cumulativeResolverCallCeiling': 3, 'cumulativeTlsIntentCeiling': 3,
                'automaticReplayAllowed': False, 'budgetReset': False})
            publish(new, 'network-attempt.json', {'maximumResolverCalls': 1, 'maximumTlsHandshakes': 1, 'httpRequests': 0,
                'bearersSent': 0, 'resolverSource': 'COPIED_CALLER_FILES', 'privateMountNamespace': True})
            for diag in (old, new):
                for n in (1, 2): publish(diag, 'engine-get-' + str(n) + '.json', {'pathHash': 'a' * 64, 'attempt': n})
            result = dict(status='OBSERVED', phase='COMPLETE', **{key: True for key in ('privateLookupViewInstalled',
                'resolverSucceeded', 'tcpConnectAttempted', 'tlsHandshakeAttempted', 'certificateChainVerified', 'hostnameVerified')})
            recovery['correctedObservation'] = publish(new, 'observation.json', {'retainedObservationHash': recovery['failedObservation']['sha256'],
                'originHash': p.digest(origin), 'caProfileHash': p.digest(ca), 'callerViews': {key: {} for key in lookup.VIEWS}, 'result': result})
            # Prior TLS case identity excludes the new recovery proof.
            # References are inside that excluded field, so the claim stays exact.
            before = {file: (file.read_bytes(), file.stat()) for file in parent.rglob('*.json')}
            proof = reconcile.reconcile(case, p.Files(), boot)
            self.assertEqual(proof['priorAttemptCounts']['engineGets'], 22)
            self.assertEqual(proof['cumulativeAttemptCeilings']['engineGets'], 34)
            self.assertFalse(proof['budgetReset'])
            self.assertEqual(before, {file: (file.read_bytes(), file.stat()) for file in before})
            publish(directory, 'frozen-get.json', {'attempt': 1})
            with self.assertRaisesRegex(Exception, 'PRIOR_TLS_PREPARATION_ADVANCED'):
                reconcile.reconcile(case, p.Files(), boot)

    def test_all_three_children_share_private_lookup_setup_without_literal_endpoints(self):
        for source in (original_tls.TLS_CHILD_SOURCE, p.FROZEN_CHILD_SOURCE, semantic_request.CHILD_SOURCE):
            ast.parse(source)
            self.assertIn("v['lookup']", source); self.assertIn('os.unshare(os.CLONE_NEWNS)', source)
            self.assertNotIn('127.0.0.11', source); self.assertNotIn('CERT_NONE', source)


if __name__ == '__main__': unittest.main()
