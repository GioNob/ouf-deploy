import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import types
import unittest
from unittest.mock import patch
import uuid

SPEC = importlib.util.spec_from_file_location('block_a', Path(__file__).resolve().parents[1] / 'scripts/check-teatri-lake-block-a-20261109.py')
a = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(a)


class BlockA(unittest.TestCase):
    def setUp(self):
        a.CACHE.clear()
        a.REPORT['steps'] = []
        self.doc = {'Id': 'a' * 64, 'Name': '/fixture', 'Image': a.APPS['udp'][1], 'Config': {'Env': None}, 'State': {'Running': True, 'Pid': 123}, 'Mounts': [], 'NetworkSettings': {'Networks': {'private': {'IPAddress': '172.22.0.5'}}}}

    def test_null_environment_and_running_java_split_arguments(self):
        command = b'java\0-jar\0/app/app.jar\0--ouf.ingestion.execution.enabled\0true\0--ouf.ingestion.activation.gateway-url=https://api.ouf-lab.it\0'
        with patch.object(Path, 'read_bytes', return_value=command):
            values, env = a.settings(self.doc)
        self.assertEqual(env, {})
        self.assertEqual(a.setting(values, 'ouf.ingestion.execution.enabled'), 'true')
        self.assertEqual(a.setting(values, 'ouf.ingestion.activation.gateway-url'), 'https://api.ouf-lab.it')

    def test_spring_json_and_relaxed_names(self):
        self.doc['Config']['Env'] = ['SPRING_APPLICATION_JSON={"ouf":{"udp":{"lake":{"tenant-id":"ouf-lab"}}}}', 'OUF_UDP_IAM_ENABLED=true']
        with patch.object(Path, 'read_bytes', return_value=b'java\0-jar\0/app/app.jar\0'):
            values, _ = a.settings(self.doc)
        self.assertEqual(a.setting(values, 'ouf.udp.lake.tenant-id'), 'ouf-lab')
        self.assertEqual(a.setting(values, 'ouf.udp.iam.enabled'), 'true')

    def test_conflicting_declarations_do_not_choose_precedence(self):
        with self.assertRaisesRegex(a.Held, 'CONFLICTING'):
            a.setting({'serverport': [('8080', 'ENV'), ('8081', 'RUNNING_JAVA')]}, 'server.port')

    def test_process_not_java_is_explicit(self):
        with patch.object(Path, 'read_bytes', return_value=b'sh\0-c\0sleep 10\0'):
            with self.assertRaisesRegex(a.Held, 'RUNNING_PID_IS_NOT_JAVA'):
                a.settings(self.doc)

    def test_command_failure_does_not_emit_stderr_secrets(self):
        result = types.SimpleNamespace(returncode=17, stdout=b'', stderr=b'SECRET credential')
        with patch.object(a.subprocess, 'run', return_value=result), contextlib.redirect_stdout(io.StringIO()) as out:
            a.step('READINESS', 'udp:1234', lambda: a.command(['false']))
        value = json.loads(out.getvalue())
        self.assertEqual((value['step'], value['container'], value['reason']), ('READINESS', 'udp:1234', 'COMMAND_EXIT_17'))
        self.assertNotIn('SECRET', out.getvalue())

    def test_alias_discovery_accepts_null_aliases(self):
        peer = copy.deepcopy(self.doc)
        peer['Name'] = '/ouf-seaweedfs-stage'
        peer['NetworkSettings']['Networks']['private']['Aliases'] = None
        peer['NetworkSettings']['Networks']['private']['DNSNames'] = None
        with patch.object(a, 'command', side_effect=[b'a\n', json.dumps([peer]).encode()]):
            found, address = a.find_peer(self.doc, 'ouf-seaweedfs-stage')
        self.assertEqual(found['Id'], peer['Id'])
        self.assertEqual(address, '172.22.0.5')

    def test_ambiguous_alias_fails(self):
        peer = copy.deepcopy(self.doc)
        peer['Name'] = '/ouf-seaweedfs-stage'
        with patch.object(a, 'command', side_effect=[b'a\nb\n', json.dumps([peer, peer]).encode()]):
            with self.assertRaisesRegex(a.Held, 'PEER_ALIAS_NOT_UNIQUE'):
                a.find_peer(self.doc, 'ouf-seaweedfs-stage')

    def test_tls_uses_udp_namespace_and_strict_verification(self):
        a.CACHE['udp'] = (self.doc, {}, {})
        a.CACHE['seaweedfs'] = (self.doc, '172.22.0.5', '/proc/123/root/config/tls/ca.pem')
        with patch.object(a, 'command', return_value=b'') as cmd:
            result = a.tls()
        args = cmd.call_args.args[0]
        self.assertIn('-verify_return_error', args)
        self.assertIn('-verify_hostname', args)
        self.assertEqual(args[args.index('--target') + 1], '123')
        self.assertFalse(result['applicationJvmRequest'])

    def prepare_readback(self):
        values = {'springdatasourceurl': [('jdbc:postgresql://postgres:5432/ouf_udp', 'ENV')], 'springdatasourceusername': [('ouf_udp_app', 'ENV')]}
        env = {'AWS_PROFILE': 'default', 'AWS_SHARED_CREDENTIALS_FILE': '/credentials'}
        a.CACHE['udp'] = (self.doc, values, env)
        a.CACHE['seaweedfs'] = (self.doc, '172.22.0.5', '/ca.pem')
        rows, bodies = [], []
        for tier in ('RAW', 'NORMALIZED', 'CURATED'):
            for i in range(13):
                body = json.dumps({'row': i, 'tier': tier}).encode()
                digest = hashlib.sha256(body).hexdigest()
                rows.append({'id': str(uuid.uuid4()), 'tier': tier, 'hash': 'sha256:' + digest, 'bytes': len(body), 'locator': 'lake/ouf-lab/' + tier.lower() + '/' + digest, 'state': 'VERIFIED'})
                bodies.append(body)
        return rows, bodies

    def run_readback(self, corrupt=False, query_fail=False):
        rows, bodies = self.prepare_readback()
        calls = []
        def command(args, data=None, timeout=15):
            calls.append((args, data))
            if 'psql' in args:
                self.assertIn('BEGIN READ ONLY;', data.decode())
                self.assertIn('ROLLBACK;', data.decode())
                self.assertNotIn('INSERT', data.decode())
                self.assertNotIn('UPDATE', data.decode())
                self.assertIn('ouf_udp.lake_object_event', data.decode())
                self.assertIn('default_transaction_read_only=on', ' '.join(args))
                if query_fail:
                    raise a.Held('COMMAND_EXIT_2')
                return json.dumps(rows).encode()
            self.assertNotIn('SECRET', ' '.join(args))
            self.assertNotIn('ACCESS', ' '.join(args))
            self.assertIn('request = "GET"', data.decode())
            self.assertNotIn('PUT', data.decode())
            self.assertIn('--cacert', args)
            self.assertNotIn('--insecure', args)
            body = bodies[len(calls) - 2]
            return (b'bad' if corrupt else body) + b'\n200'
        with patch.object(a, 'find_peer', return_value=({'Id': 'b' * 64}, '172.22.0.6')), patch.object(a, 'mounted', return_value=(b'[default]\naws_access_key_id=ACCESS\naws_secret_access_key=SECRET\n', '/credentials')), patch.object(a, 'command', side_effect=command):
            result = a.readback('11111111-1111-4111-8111-111111111111', 'teatri-seaweedfs-c51745c5')
        return result, calls

    def test_39_bodies_checked_without_writes_or_secret_arguments(self):
        result, calls = self.run_readback()
        self.assertEqual(len(calls), 40)
        self.assertEqual(result['bodyMatchesByTier'], {'RAW': 13, 'NORMALIZED': 13, 'CURATED': 13})
        self.assertFalse(result['materializationProven'])

    def test_corrupt_body_reports_object_and_container(self):
        with self.assertRaisesRegex(a.Held, 'SEAWEEDFS_aaaaaaaaaaaa_OBJECT_1_BODY_HASH_OR_SIZE_MISMATCH'):
            self.run_readback(corrupt=True)

    def test_sql_failure_reports_postgres_container(self):
        with self.assertRaisesRegex(a.Held, 'POSTGRES_bbbbbbbbbbbb_CATALOG_COMMAND_EXIT_2'):
            self.run_readback(query_fail=True)

    def test_source_injection_fails_before_any_command(self):
        with patch.object(a, 'command') as cmd:
            with self.assertRaisesRegex(a.Held, 'TEATRI_SOURCE_REQUIRED'):
                a.readback('11111111-1111-4111-8111-111111111111', "teatri-seaweedfs-x'; DELETE FROM x;--")
        cmd.assert_not_called()

    def test_changed_image_fails(self):
        with patch.object(a, 'command', return_value=json.dumps([self.doc]).encode()):
            with self.assertRaisesRegex(a.Held, 'IMAGE_CHANGED'):
                a.inspect('fixture', 'sha256:different')

    def test_running_predecessor_is_named(self):
        with patch.object(a, 'command', return_value=(a.OLD_WRITERS[0] + '\n').encode()):
            with self.assertRaisesRegex(a.Held, 'PREDECESSOR_RUNNING_d69c3f763d75'):
                a.old_writers()

    def external_configuration(self, enabled='true'):
        self.doc['Mounts'] = [{'Destination': '/config', 'Source': '/etc/ouf/ingestion', 'Type': 'bind', 'RW': False}]
        direct = {a.canon('spring.config.additional-location'): [('file:/config/ingestion.properties', 'ENV')]}
        a.CACHE['ingestion'] = (self.doc, direct, {})
        root = b'spring.config.import=child.properties\nspring.datasource.password=SECRET\n'
        child = (('ouf.ingestion.execution.enabled=' + enabled + '\n') if enabled is not None else '')
        child += 'ouf.ingestion.activation.gateway-url=https://api.ouf-lab.it\nouf.ingestion.activation.token-file=/run/token\n'
        files = {'/config/ingestion.properties': root, '/config/child.properties': child.encode()}
        with patch.object(a, 'mounted', side_effect=lambda doc, path, maximum: (files[path], path)):
            observed = a.config_sources()
        self.assertNotIn('SECRET', json.dumps(observed))
        return observed

    def test_external_properties_and_relative_import_report_mount_origins(self):
        result = self.external_configuration()
        self.assertEqual(result['executionEnabled'], 'true')
        self.assertEqual(result['files'][1]['hostPath'], '/etc/ouf/ingestion/child.properties')
        self.assertEqual(a.setting(a.CACHE['ingestion'][1], 'ouf.ingestion.activation.token-file'), '/run/token')
        self.assertTrue(a.ingestion_config()['executionEnabled'])

    def test_false_execution_is_reported_without_enablement(self):
        self.external_configuration('false')
        with self.assertRaisesRegex(a.Held, 'INGESTION_EXECUTION_FALSE') as found:
            a.ingestion_config()
        self.assertEqual(found.exception.observation['configurationWrites'], 0)

    def test_absent_execution_stays_absent_not_false(self):
        result = self.external_configuration(None)
        self.assertEqual(result['executionEnabled'], 'ABSENT')
        with self.assertRaisesRegex(a.Held, 'ABSENT_IN_INSPECTED_SOURCES'):
            a.ingestion_config()

    def test_properties_escapes_continuations_and_yaml_scalars(self):
        result = a.properties(b'key\\:name = value\\\n  continued\nflag: false\n', '.properties')
        self.assertEqual(result, {'key:name': 'valuecontinued', 'flag': 'false'})
        result = a.properties(b'ouf:\n  ingestion:\n    execution.enabled: true\n', '.yml')
        self.assertEqual(result['ouf.ingestion.execution.enabled'], 'true')
        with self.assertRaisesRegex(a.Held, 'MULTIDOCUMENT'):
            a.properties(b'a=1\n#---\na=2\n', '.properties')

    def test_unsupported_config_uri_does_not_echo_credentials(self):
        a.CACHE['ingestion'] = (self.doc, {a.canon('spring.config.import'): [('https://user:SECRET@host/config', 'ENV')]}, {})
        with self.assertRaises(a.Held) as found:
            a.config_sources()
        self.assertNotIn('SECRET', json.dumps(found.exception.observation))
        self.assertIn('UNSUPPORTED', str(found.exception))

    def test_units_read_is_show_only_and_reports_loaded_cadence(self):
        service = {'LoadState': 'loaded', 'ActiveState': 'inactive', 'SubState': 'dead', 'NeedDaemonReload': 'no', 'ExecStart': '/usr/bin/python3 /opt/ouf/ops/refresh-policy-token.py SECRET', 'Result': 'success', 'ExecMainStatus': '0'}
        timer = {'LoadState': 'loaded', 'ActiveState': 'active', 'Unit': 'ouf-policy-token@udp.service', 'NeedDaemonReload': 'no', 'TimersMonotonic': '{ OnUnitActiveUSec=1min 30s ; next_elapse=2min }', 'NextElapseUSecMonotonic': '2min', 'AccuracyUSec': '1s', 'RandomizedDelayUSec': '0'}
        seen = []
        def command(args):
            seen.append(args)
            self.assertEqual(args[:2], ['/usr/bin/systemctl', 'show'])
            row = service if args[2].endswith('.service') else timer
            return ('\n'.join(k + '=' + v for k, v in row.items()) + '\n').encode()
        with patch.object(a, 'command', side_effect=command), patch.object(a.time, 'monotonic', return_value=100):
            result = a.udp_renewal_units()
        self.assertEqual(result['intervalsSeconds']['OnUnitActiveUSec'], 90)
        self.assertEqual(result['nextTriggerInSeconds'], 20)
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertEqual(len(seen), 2)

    def test_natural_renewal_observed_in_mount_without_starting_service(self):
        self.doc['Mounts'] = [{'Destination': '/run', 'Source': '/var/lib/ouf/udp', 'Type': 'bind', 'RW': False}]
        a.CACHE['udp'] = (self.doc, {a.canon('ouf.authorization.registry-token-file'): [('/run/token', 'ENV')]}, {})
        initial = {'nextTriggerInSeconds': 10, 'schedulingSlackSeconds': 1, 'timer': {'LastTriggerUSec': 'before'}}
        a.CACHE['udpRenewalUnits'] = initial
        clock, samples = [0], [0]
        def sample(role, field):
            samples[0] += 1
            a.CACHE['udpTokenSample'] = {'exp': 1000 if samples[0] == 1 else 1300, 'fingerprint': str(samples[0])}
            return {'secondsRemaining': 290}
        after = {'nextTriggerInSeconds': 90, 'schedulingSlackSeconds': 1, 'timer': {'LastTriggerUSec': 'after'}, 'service': {'ActiveState': 'inactive', 'Result': 'success', 'ExecMainStatus': '0'}}
        with patch.object(a, 'token_metadata', side_effect=sample), patch.object(a, 'udp_renewal_units', return_value=after), patch.object(a.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(a.time, 'sleep', side_effect=lambda n: clock.__setitem__(0, clock[0] + n)):
            result = a.udp_renewal_observation()
        self.assertTrue(result['automaticRenewalObserved'])
        self.assertEqual(result['hostTokenPath'], '/var/lib/ouf/udp/token')
        self.assertEqual(result['tokenGrantRequestsByReader'], 0)

    def test_timer_after_token_expiry_is_not_accepted(self):
        a.CACHE['udpRenewalUnits'] = {'nextTriggerInSeconds': 300, 'schedulingSlackSeconds': 1}
        a.CACHE['udpTokenSample'] = {'exp': 1000, 'fingerprint': 'private'}
        with patch.object(a, 'token_metadata', return_value={'secondsRemaining': 264}), patch.object(a.time, 'sleep') as sleep:
            with self.assertRaisesRegex(a.Held, 'NEXT_UDP_RENEWAL_NOT_BEFORE_TOKEN_EXPIRY'):
                a.udp_renewal_observation()
        sleep.assert_not_called()


if __name__ == '__main__':
    unittest.main()
