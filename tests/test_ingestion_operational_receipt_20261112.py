"""Synthetic unit guards, no Docker/VPS/network/installation secrets."""
import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('receipt', ROOT / 'scripts/apply-ingestion-operational-receipt-20261112.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
# Windows checkout uses CRLF for historical files. Production must verify exact
# delivered LF bytes; unit tests load the pure source without weakening that pin.
mac_spec = importlib.util.spec_from_file_location('unit_mac', ROOT / 'tools/acquisition_read_native/retained_mac.py')
mac = importlib.util.module_from_spec(mac_spec)
mac_spec.loader.exec_module(mac)
OLD_IMAGE, NEW_IMAGE = 'sha256:' + '1' * 64, 'sha256:' + '2' * 64
OLD_REV = 'a' * 40


def fixture():
    args = SimpleNamespace(plan=True, apply=False, plan_sha256=None, container='fixture',
                           candidate_image=NEW_IMAGE, expected_current_image=OLD_IMAGE,
                           expected_current_revision=OLD_REV, properties_target='/run/summary.properties',
                           journal_root=Path('/private'), docker_socket='/run/docker.sock', nsenter_bin='/usr/bin/nsenter',
                           readiness_port=8080, readiness_path='/actuator/health/readiness', readiness_timeout=5, stop_timeout=5)
    command = ['java', '-jar', '/app/app.jar', '--spring.flyway.enabled=false',
               '--ouf.ingestion.startup.schema-mode=VALIDATE_ONLY']
    old = {'Id': '3' * 64, 'Name': '/fixture', 'Image': OLD_IMAGE, 'Created': 'generation',
           'Config': {'Image': 'historical-tag', 'Env': ['PRIVATE_SYNTHETIC=never-print-me', 'SPRING_FLYWAY_ENABLED=false',
                       'SPRING_CONFIG_ADDITIONAL_LOCATION=file:/run/summary.properties'],
                      'Entrypoint': m.ENTRY, 'Cmd': command, 'MacAddress': '02:42:ac:53:01:11',
                      'User': '10002:10002', 'WorkingDir': '/app', 'Labels': {m.REVISION: OLD_REV}},
           'HostConfig': {'NetworkMode': 'backend', 'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0},
                          'Binds': ['/synthetic/props:/run/summary.properties:ro', '/synthetic/key:/run/receipt.key:ro'],
                          'Memory': 536870912, 'OomKillDisable': None},
           'Path': m.ENTRY[0], 'Args': m.ENTRY[1:] + command,
           'Mounts': [{'Type': 'bind', 'Source': '/synthetic/props', 'Destination': '/run/summary.properties', 'RW': False},
                      {'Type': 'bind', 'Source': '/synthetic/key', 'Destination': '/run/receipt.key', 'RW': False}],
           'NetworkSettings': {'Networks': {'backend': {'IPAddress': '172.30.0.2', 'MacAddress': '02:42:ac:53:01:11',
                                                        'IPAMConfig': None, 'Aliases': ['fixture', '333333333333']}}},
           'State': {'Running': True, 'Pid': 42, 'StartedAt': 'started', 'Paused': False, 'Restarting': False, 'OOMKilled': False}}
    props = ('\n'.join(k + '=' + ('/run/receipt.key' if i == 0 else 'synthetic-identity')
                       for i, k in enumerate(m.KEYS)) + '\n').encode()
    return args, old, props


def image(i, rev):
    return {'Id': i, 'Architecture': 'amd64', 'Os': 'linux', 'Config': {'Labels': {m.REVISION: rev}}}


def identity(old, props):
    return m.identity(old, '/run/summary.properties', lambda p, maximum=1048576: props if str(p).endswith('props') else b'ab' * 32)


def plan(args, old, props):
    return m.compile_plan(old, image(NEW_IMAGE, m.SOURCE), image(OLD_IMAGE, OLD_REV), args,
                          identity(old, props), mac, True, old['Config']['Cmd'])


class Guards(unittest.TestCase):
    def setUp(self):
        self.args, self.old, self.props = fixture()

    def test_exact_delta_and_public_redaction(self):
        p = plan(self.args, self.old, self.props)
        req = p['request']
        config = {k: v for k, v in req.items() if k not in ('HostConfig', 'NetworkingConfig')}
        expected = copy.deepcopy(self.old['Config'])
        expected['Image'] = NEW_IMAGE
        expected['Env'].append(m.ENABLE)
        self.assertEqual(config, expected)
        self.assertEqual(req['HostConfig'], self.old['HostConfig'])
        text = json.dumps(m.public_plan(p))
        for secret in ('never-print-me', 'synthetic-identity', '/synthetic/', '/run/receipt.key', 'ab' * 32):
            self.assertNotIn(secret, text)
        self.assertEqual(m.digest(p), m.digest(plan(self.args, self.old, self.props)))
        altered = copy.deepcopy(self.old)
        altered['State']['Health'] = {'FailingStreak': 100, 'Log': ['volatile']}
        self.assertEqual(m.digest(p), m.digest(plan(self.args, altered, self.props)))

    def test_unexpected_deltas_held(self):
        req = m.request(self.old, NEW_IMAGE, mac)
        for field, value in [('User', 'root'), ('Cmd', ['other']), ('MacAddress', None),
                             ('Labels', {}), ('Env', self.old['Config']['Env']), ('Image', OLD_IMAGE),
                             ('HostConfig', {}), ('NetworkingConfig', {})]:
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, 'UNEXPECTED_CREATE_DELTA'):
                bad = copy.deepcopy(req)
                bad[field] = value
                m.delta_guard(self.old, bad, NEW_IMAGE, mac)

    def test_missing_each_property(self):
        for key in m.KEYS:
            with self.subTest(key=key), self.assertRaises(m.IdentityHeld) as ctx:
                identity(self.old, b'\n'.join(line for line in self.props.splitlines() if not line.startswith(key.encode() + b'=')))
            self.assertFalse(ctx.exception.checks[key])

    def test_invalid_keys_and_unmounted_path(self):
        for key in (b'', b'a' * 63, b'a' * 65, b'g' * 64, b'ab\n' * 32):
            with self.subTest(length=len(key)), self.assertRaisesRegex(RuntimeError, 'SUMMARY_KEY_NOT_64_HEX'):
                m.identity(self.old, self.args.properties_target,
                           lambda p, maximum=1048576: self.props if str(p).endswith('props') else key)
        with self.assertRaisesRegex(RuntimeError, 'UNAMBIGUOUS_MOUNT_REQUIRED'):
            identity(self.old, self.props.replace(b'/run/receipt.key', b'/unmounted/key'))
        for value in (b'${SECRET}', b''):
            with self.assertRaisesRegex(RuntimeError, 'SUMMARY_PROPERTIES_UNRESOLVED_OR_EMPTY'):
                identity(self.old, self.props.replace(b'synthetic-identity', value))

    def test_properties_java_syntax(self):
        self.assertEqual(m.properties(b'! comment\na\\:b : c\\u0031\nlong = ab\\\n  cd\n'), {'a:b': 'c1', 'long': 'abcd'})
        with self.assertRaisesRegex(RuntimeError, 'DUPLICATE_PROPERTY_KEY'):
            m.properties(b'a=x\na:y\n')

    def test_image_defaults_cannot_silently_expand_delta(self):
        p = plan(self.args, self.old, self.props)
        for config in ({'Env': ['NEW_DEFAULT=synthetic']}, {'Labels': {'new-label': 'synthetic'}},
                       {'Volumes': {'/new-volume': {}}}, {'ExposedPorts': {'9999/tcp': {}}},
                       {'Healthcheck': {'Test': ['CMD', 'false']}}):
            with self.subTest(config=config), self.assertRaises(RuntimeError):
                m.image_defaults_guard(p['request'], {'Config': config})

    def test_summary_overrides_and_flyway_conflicts_held(self):
        for extra in ('OUF_SUMMARY_ENABLED=false', 'OUF_SUMMARY_ISSUER=synthetic', 'SPRING_APPLICATION_JSON={}'):
            old = copy.deepcopy(self.old)
            old['Config']['Env'].append(extra)
            with self.subTest(extra=extra), self.assertRaises(RuntimeError):
                plan(self.args, old, self.props)
        old = copy.deepcopy(self.old)
        old['Config']['Cmd'].append('--spring.flyway.enabled=true')
        with self.assertRaisesRegex(RuntimeError, 'VALIDATE_ONLY_FLYWAY_DISABLED_REQUIRED'):
            plan(self.args, old, self.props)

    def test_post_apply_exact_frame_negative_matrix(self):
        req = m.request(self.old, NEW_IMAGE, mac)
        current = copy.deepcopy(self.old)
        current.update(Id='4' * 64, Image=NEW_IMAGE)
        current['Config'] = {k: v for k, v in req.items() if k not in ('HostConfig', 'NetworkingConfig')}
        ep = copy.deepcopy(req['NetworkingConfig']['EndpointsConfig']['backend'])
        ep.update(IPAddress=ep['IPAMConfig']['IPv4Address'])
        ep['Aliases'].append(current['Id'][:12])
        current['NetworkSettings']['Networks']['backend'] = ep
        m.verify_replacement(self.old, req, current, True)
        for section, key, value in [('Config', 'Env', []), ('Config', 'MacAddress', ''), ('Config', 'Labels', {}),
                                     ('Config', 'Cmd', []), ('HostConfig', 'Memory', 1), ('State', 'Running', False)]:
            bad = copy.deepcopy(current)
            bad[section][key] = value
            with self.subTest(section=section, key=key), self.assertRaises(RuntimeError):
                m.verify_replacement(self.old, req, bad, True)
        bad = copy.deepcopy(current)
        bad['Mounts'] = []
        with self.assertRaises(RuntimeError):
            m.verify_replacement(self.old, req, bad, True)
        for key, value in [('IPAddress', '172.30.0.3'), ('MacAddress', '02:00:00:00:00:01'), ('Aliases', [])]:
            bad = copy.deepcopy(current)
            bad['NetworkSettings']['Networks']['backend'][key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                m.verify_replacement(self.old, req, bad, True)

    def test_current_candidate_images_revision_readiness_and_arguments_held(self):
        for target in ('current', 'candidate', 'revision', 'platform', 'not-ready', 'args'):
            with self.subTest(target=target), self.assertRaises(RuntimeError):
                old, candidate, predecessor = copy.deepcopy(self.old), image(NEW_IMAGE, m.SOURCE), image(OLD_IMAGE, OLD_REV)
                if target == 'current':
                    old['Image'] = NEW_IMAGE
                if target == 'candidate':
                    candidate['Id'] = OLD_IMAGE
                if target == 'revision':
                    candidate['Config']['Labels'][m.REVISION] = OLD_REV
                if target == 'platform':
                    candidate['Architecture'] = 'arm64'
                m.compile_plan(old, candidate, predecessor, self.args, identity(self.old, self.props), mac,
                               target != 'not-ready', ['wrong'] if target == 'args' else old['Config']['Cmd'])

    def test_plan_reads_only_and_rejects_wrong_target_before_identity(self):
        old, args, props = self.old, self.args, self.props
        reads = []

        class ReadOnly:
            def inspect(self, name):
                reads.append(('inspect', name))
                return old

            def image(self, i):
                reads.append(('image', i))
                return image(i, m.SOURCE if i == NEW_IMAGE else OLD_REV)

        reader = lambda p, maximum=1048576: props if str(p).endswith('props') else b'ab' * 32
        p = m.collect(ReadOnly(), args, mac, reader=reader, ready=lambda *a: True, proc=lambda *a: old['Config']['Cmd'])
        self.assertEqual(p['request']['Image'], NEW_IMAGE)
        self.assertEqual([x[0] for x in reads], ['inspect', 'image', 'image', 'inspect'])
        args.expected_current_image = NEW_IMAGE
        with patch.object(m, 'identity') as opened, self.assertRaises(RuntimeError):
            m.collect(ReadOnly(), args, mac, ready=lambda *a: True)
        opened.assert_not_called()

    def test_full_apply_order_and_retained_old(self):
        p = plan(self.args, self.old, self.props)
        original, documents, effects, saved = self.old, {self.old['Id']: copy.deepcopy(self.old)}, [], {}
        new_id = '4' * 64

        class Synthetic:
            released = False

            def inspect(self, cid):
                return copy.deepcopy(documents[cid])

            def image(self, i):
                return image(i, m.SOURCE)

            def api(self, method, path, body=None):
                if method == 'GET':
                    return [{'Names': ['/fixture']}]
                effects.append(path)
                old = documents[original['Id']]
                if '/stop?' in path:
                    old['State'].update(Running=False, Pid=0)
                elif path.endswith('/disconnect'):
                    old['NetworkSettings']['Networks'] = {}
                    del old['Config']['MacAddress']
                elif '/rename?' in path:
                    old['Name'] = '/' + path.split('name=')[1]
                elif path.startswith('/containers/create?'):
                    current = copy.deepcopy(original)
                    current.update(Id=new_id, Image=NEW_IMAGE)
                    current['Config'] = {k: v for k, v in body.items() if k not in ('HostConfig', 'NetworkingConfig')}
                    current['State'].update(Running=False, Pid=0)
                    ep = copy.deepcopy(body['NetworkingConfig']['EndpointsConfig']['backend'])
                    ep['Aliases'].append(new_id[:12])
                    ep['IPAddress'] = ep['IPAMConfig']['IPv4Address']
                    current['NetworkSettings']['Networks']['backend'] = ep
                    documents[new_id] = current
                    return {'Id': new_id}
                elif path.endswith('/start'):
                    documents[new_id]['State'].update(Running=True, Pid=99)
                elif path.endswith('/kill?signal=USR1'):
                    self.released = True
                else:
                    raise AssertionError(path)

        engine, report = Synthetic(), {'runtimeChanged': False}
        proc = lambda doc: original['Config']['Cmd'] if engine.released else m.ENTRY + original['Config']['Cmd']
        with patch.object(m, 'begin_attempt', return_value=Path('/private/attempt')), \
                patch.object(m, 'record', side_effect=lambda w, n, v: saved.setdefault(n, copy.deepcopy(v))), \
                patch.object(m, 'identity', return_value=p['identity']), patch.object(m, 'gate_armed', return_value=True):
            m.apply_plan(p, m.digest(p), engine, self.args, mac, report, recollect=lambda *a: p,
                         ready=lambda *a: True, proc=proc)
        self.assertEqual(report['status'], 'INGESTION_OPERATIONAL_RECEIPT_READY')
        self.assertTrue(report['runtimeChanged'])
        self.assertEqual(len(effects), 6)
        self.assertIn('/stop?', effects[0])
        self.assertTrue(effects[1].endswith('/disconnect'))
        self.assertIn('/rename?', effects[2])
        self.assertTrue(effects[3].startswith('/containers/create?'))
        self.assertTrue(effects[4].endswith('/start'))
        self.assertTrue(effects[5].endswith('/kill?signal=USR1'))
        self.assertFalse(documents[original['Id']]['State']['Running'])
        self.assertIn('complete.private.json', saved)

    def test_wrong_hash_and_existing_journal_before_effects(self):
        p = plan(self.args, self.old, self.props)
        with self.assertRaisesRegex(RuntimeError, 'FRESH_PLAN_HASH_MISMATCH'), patch.object(m, 'begin_attempt') as begin:
            m.apply_plan(p, '0' * 64, None, self.args, mac, {})
        begin.assert_not_called()
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            (root / ('apply-' + m.digest(p))).mkdir()
            # Portable Windows test: native CI tests assert actual POSIX ownership/modes.
            with patch.object(m.Path, 'lstat', return_value=SimpleNamespace(st_mode=0o40700, st_uid=0)):
                with self.assertRaisesRegex(RuntimeError, 'EXISTING_ATTEMPT_DO_NOT_REPLAY'):
                    m.begin_attempt(root, m.digest(p))

    def test_negative_mac_origins_and_detached_matrix(self):
        for value in ('ABSENT', None, '', 'malformed', '01:00:00:00:00:01', '00:00:00:00:00:00', '02:00:00:00:00:02'):
            bad = copy.deepcopy(self.old)
            if value == 'ABSENT':
                del bad['Config']['MacAddress']
            else:
                bad['Config']['MacAddress'] = value
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                m.request(bad, NEW_IMAGE, mac)
        detached = copy.deepcopy(self.old)
        detached['State'].update(Running=False, Pid=0)
        detached['NetworkSettings']['Networks'] = {}
        del detached['Config']['MacAddress']
        m.detached(mac, self.old, detached, self.old['Name'])
        for section, key, value in [('Config', 'MacAddress', None), ('Config', 'MacAddress', ''), ('Config', 'User', 'root'),
                                     ('Config', 'Hostname', 'new'), ('Config', 'Env', []), ('HostConfig', 'Memory', 1),
                                     ('State', 'Running', True), ('State', 'StartedAt', 'new')]:
            bad = copy.deepcopy(detached)
            bad[section][key] = value
            with self.subTest(section=section, key=key), self.assertRaises(RuntimeError):
                m.detached(mac, self.old, bad, self.old['Name'])
        for key, value in [('Id', 'other'), ('Image', NEW_IMAGE), ('Mounts', []), ('Args', [])]:
            bad = copy.deepcopy(detached)
            bad[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                m.detached(mac, self.old, bad, self.old['Name'])

    def test_failure_after_stop_never_rolls_back_or_replays(self):
        p = plan(self.args, self.old, self.props)
        events, report = [], {'runtimeChanged': False}

        class Broken:
            def api(self, method, path, body=None):
                events.append(path)
                if method == 'GET':
                    return [{'Names': ['/fixture']}]
                raise OSError('uncertain stop response')

        with patch.object(m, 'begin_attempt', return_value=Path('/private/attempt')), patch.object(m, 'record'):
            with self.assertRaises(OSError):
                m.apply_plan(p, m.digest(p), Broken(), self.args, mac, report, recollect=lambda *a: p)
        self.assertIsNone(report['runtimeChanged'])
        self.assertTrue(report['oldStopDispatched'])
        self.assertEqual(len(events), 2)
        self.assertIn('/stop?', events[-1])


if __name__ == '__main__':
    unittest.main(verbosity=2)
