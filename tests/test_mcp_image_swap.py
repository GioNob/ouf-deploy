"""R-033 protocol tests. No Docker, network, PostgreSQL, or deployment credentials."""
import copy
import gzip
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('swap', ROOT / 'scripts/swap-mcp-image.py')
swap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(swap)
OLD, NEW, PG, NET = (x * 64 for x in 'abcd')
OLD_IMAGE = 'sha256:' + 'e' * 64
MAC = '02:42:ac:44:01:07'
DEFAULTS = {'User': '10005:10005', 'WorkingDir': '/app', 'Entrypoint': swap.APP[:1], 'Cmd': swap.APP[1:]}


def bundle(path, broken_sums=False):
    entries = {}

    def blob(value):
        body = json.dumps(value).encode()
        ident = swap.sha(body)
        entries['blobs/sha256/' + ident] = body
        return {'digest': 'sha256:' + ident, 'size': len(body)}

    cfg = blob({'os': 'linux', 'architecture': 'amd64', 'config': DEFAULTS})
    layer = blob('fixture layer')
    descriptor = blob({'config': cfg, 'layers': [layer]})
    entries['index.json'] = json.dumps({'manifests': [descriptor]}).encode()
    entries['manifest.json'] = json.dumps([{'Config': 'blobs/sha256/' + cfg['digest'][7:],
        'Layers': ['blobs/sha256/' + layer['digest'][7:]], 'RepoTags': ['ouf-mcp:ci']}]).encode()
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode='w') as tar:
        for name, body in entries.items():
            item = tarfile.TarInfo(name)
            item.size = len(body)
            tar.addfile(item, io.BytesIO(body))
    archive = gzip.compress(data.getvalue())
    commit = 'f' * 40
    files = {'image.tar.gz': archive, 'image-id.txt': cfg['digest'].encode(), 'source-commit.txt': commit.encode(),
             'capabilities.json': b'{}', 'image-config.json': json.dumps([{'Id': cfg['digest'], 'Config': DEFAULTS}]).encode()}
    with zipfile.ZipFile(path, 'w') as z:
        for name, body in files.items():
            z.writestr(name, body)
        z.writestr('SHA256SUMS', '' if broken_sums else ''.join(
            swap.sha(body) + '  ' + name + '\n' for name, body in files.items()))
    return {'runId': 100, 'artifactId': 101, 'sourceCommit': commit, 'publisherCommit': commit,
            'sourceTree': 'a' * 40, 'publisherTree': 'a' * 40, 'zipSha256': swap.sha(path.read_bytes()),
            'archiveSha256': swap.sha(archive), 'binarySha256': '1' * 64, 'capabilitiesSha256': swap.sha(b'{}'),
            'imageId': descriptor['digest']}


class Docker:
    def __init__(self, c):
        self.c = c
        ep = {'IPAddress': '172.30.1.3', 'MacAddress': MAC, 'Aliases': ['mcp', OLD[:12]], 'NetworkID': NET,
              'IPAMConfig': {'IPv4Address': '172.30.1.3'}}
        self.docs = {OLD: {'Id': OLD, 'Name': '/ouf-mcp', 'Image': OLD_IMAGE, 'RestartCount': 0,
            'State': dict(Running=True, Pid=11, StartedAt='t0', Paused=False, Restarting=False),
            'Config': dict(DEFAULTS, Image=OLD_IMAGE, MacAddress=MAC, Entrypoint=swap.ENTRY, Cmd=swap.APP,
                           Labels={'test': 'keep'}, Env=['EXAMPLE=private']),
            'Path': swap.ENTRY[0], 'Args': swap.ENTRY[1:] + swap.APP, 'Mounts': [],
            'HostConfig': {'NetworkMode': 'backend', 'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0},
                           'OomKillDisable': None}, 'NetworkSettings': {'Networks': {'backend': ep}}}}
        self.tags = {'ouf-mcp:ci': OLD_IMAGE}
        self.defaults = copy.deepcopy(DEFAULTS)
        self.history = [[i, '2' * 64, 't'] for i in range(1, 15)]
        self.unready = self.drift_on_load = False
        self.gated = set()
        self.effects = []

    def inspect(self, target):
        if target == 'ouf-mcp':
            target, = [cid for cid, doc in self.docs.items() if doc['Name'] == '/ouf-mcp']
        return copy.deepcopy(self.docs[target])

    def process(self, doc, gated):
        assert (doc['Id'] in self.gated) == gated
        return ('0' * 64 if doc['Id'] == OLD else self.c['binarySha256'], '3' * 64)

    def database(self, doc, pgid):
        assert pgid == PG
        return {'databaseOid': 42, 'tables': True, 'history': self.history}

    def ready(self, doc):
        return doc['Id'] not in self.gated and not (doc['Id'] == NEW and self.unready)

    def load(self, archive):
        assert swap.sha(archive) == self.c['archiveSha256']
        self.effects.append('load')
        self.tags['ouf-mcp:ci'] = self.c['imageId']
        if self.drift_on_load:
            self.docs[OLD]['Config']['Env'].append('DRIFT=1')

    def api(self, method, path, body=None):
        if method == 'GET':
            if path == '/containers/json?all=1':
                return [{'Names': [d['Name']]} for d in self.docs.values()]
            if path == '/images/json?all=1':
                return [{'RepoTags': list(self.tags)}]
            ref = path.split('/')[2]
            return {'Id': self.tags.get(ref, ref), 'Config': self.defaults}
        self.effects.append(path)
        if path.startswith('/images/'):
            self.tags['ouf-mcp-r033-custody:' + OLD] = OLD_IMAGE
        elif path.startswith('/networks/'):
            assert path.split('/')[2] == NET
            doc = self.docs[body['Container']]
            nets = doc['NetworkSettings']['Networks']
            if path.endswith('/disconnect'):
                assert not doc['State']['Running']
                nets.clear()
                doc['Config'].pop('MacAddress')
            else:
                ep = copy.deepcopy(body['EndpointConfig'])
                nets['backend'] = dict(ep, NetworkID=NET, IPAddress=ep['IPAMConfig']['IPv4Address'])
        elif path.startswith('/containers/create?'):
            req = copy.deepcopy(body)
            doc = self.docs[NEW] = self.inspect(OLD)
            doc['HostConfig'] = req.pop('HostConfig')
            ep = req.pop('NetworkingConfig')['EndpointsConfig']['backend']
            ep['Aliases'].append(NEW[:12])
            doc['NetworkSettings']['Networks']['backend'] = dict(ep, NetworkID=NET, IPAddress=ep['IPAMConfig']['IPv4Address'])
            doc.update(Id=NEW, Config=req, Image=req['Image'], Name='/ouf-mcp')
            return {'Id': NEW}
        else:
            _, _, cid, action = path.split('/')
            doc = self.docs[cid]
            if action.startswith('stop?'):
                doc['State'].update(Running=False, Pid=0)
            elif action.startswith('rename?'):
                doc['Name'] = '/' + action.split('=')[1]
            elif action == 'start':
                doc['State'].update(Running=True, Pid=12, StartedAt='t1')
                if cid == NEW:
                    doc['Config']['MacAddress'] = doc['NetworkSettings']['Networks']['backend']['MacAddress']
                doc['HostConfig']['OomKillDisable'] = None
                self.gated.add(cid)
            else:
                assert action == 'kill?signal=USR1'
                self.gated.remove(cid)


def check_restored_rejections(case, controller, old, restored):
    """Change one field on a copy of the restored inspect, including in hosted qualification."""
    net, endpoint = next(iter(old['NetworkSettings']['Networks'].items()))
    binding = ('NetworkSettings', 'Networks', net)
    # Flip a bit in the last octet to keep the negative case valid and unicast.
    other_mac = endpoint['MacAddress'][:-2] + format(int(endpoint['MacAddress'][-2:], 16) ^ 1, '02x')
    case.assertNotIn('MacAddress', restored['Config'])
    for path, value in [
        (('Config', 'MacAddress'), None), (('Config', 'MacAddress'), ''),
        (('Config', 'MacAddress'), other_mac), (('Config', 'MacAddress'), old['Config']['MacAddress']),
        (binding + ('MacAddress',), other_mac), (binding + ('IPAddress',), '192.0.2.99'),
        (binding + ('Aliases',), []), (binding + ('NetworkID',), '0' * 64),
        (('NetworkSettings', 'Networks'), {}), (('Config', 'Env'), []), (('Config', 'Labels'), None),
        (('Id',), '1' * 64), (('Image',), 'sha256:' + '2' * 64), (('Name',), '/changed'),
        (('Path',), '/changed'), (('Args',), []), (('HostConfig', 'NetworkMode'), 'none'),
        (('Mounts',), [{'Destination': '/changed'}]),
    ]:
        with case.subTest(field=path[-1], value_type=type(value).__name__):
            changed = copy.deepcopy(restored)
            target = changed
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with case.assertRaisesRegex(controller.RestoredFrameChanged, '^RESTORED_FRAME_CHANGED$') as held:
                controller.verify_restored_frame(old, changed, reconnected=True)
            endpoint_matches = path not in (binding + ('MacAddress',), ('NetworkSettings', 'Networks'))
            case.assertEqual(held.exception.differences['NetworkSettings.MacAddress'],
                             {'matchesOriginal': endpoint_matches})
            case.assertNotIn(endpoint['MacAddress'], json.dumps(held.exception.differences))
            case.assertNotIn(other_mac, json.dumps(held.exception.differences))


class Swap(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.state = Path(work.name)
        self.zip = self.state / 'ci.zip'
        self.c = bundle(self.zip)
        self.archive, self.defaults = swap.package(self.zip, self.c, 'containerd')
        self.rt = Docker(self.c)
        self.inputs = {'candidate': self.c, 'snapshot': swap.observe(self.rt, PG)[1], 'expectedOldImageId': OLD_IMAGE}
        self.body = swap.plan(self.rt, self.inputs, self.defaults)[2]
        self.approved = swap.digest(self.body)
        self.journal = self.state / ('attempt-' + OLD)

    def apply(self):
        return swap.apply(self.rt, self.state, self.inputs, self.archive, self.defaults, self.approved)

    def test_plan_denials_have_no_effects(self):
        self.assertEqual([], self.rt.effects)
        for put, undo, reason in [
            (lambda: self.rt.history.pop(), lambda: self.rt.history.append([14, '2' * 64, 't']), 'SCHEMA_14'),
            (lambda: self.rt.docs[OLD]['Config']['Env'].append('changed'),
             lambda: self.rt.docs[OLD]['Config']['Env'].pop(), 'SNAPSHOT_CHANGED'),
            (lambda: self.inputs['snapshot'].update(imageId=self.c['imageId']),
             lambda: self.inputs['snapshot'].update(imageId=OLD_IMAGE), 'SNAPSHOT_CHANGED'),
            (lambda: self.inputs.update(expectedOldImageId=self.c['imageId']),
             lambda: self.inputs.update(expectedOldImageId=OLD_IMAGE), 'UNEXPECTED_PREDECESSOR_IMAGE'),
            (lambda: self.defaults.update(Volumes={'/extra': {}}), lambda: self.defaults.pop('Volumes'), 'DEFAULT_CHANGE'),
        ]:
            put()
            with self.assertRaisesRegex(RuntimeError, reason):
                swap.plan(self.rt, self.inputs, self.defaults)
            undo()
        self.assertEqual([], self.rt.effects)

    def test_wrong_approval_or_checksums(self):
        self.approved = '0' * 64
        with self.assertRaisesRegex(RuntimeError, 'PLAN_CHANGED'):
            self.apply()
        self.assertFalse(self.journal.exists())
        c = bundle(self.zip, broken_sums=True)
        with self.assertRaisesRegex(RuntimeError, 'PUBLISHER_CHECKSUMS'):
            swap.package(self.zip, c, 'containerd')
        with self.assertRaisesRegex(RuntimeError, 'ARCHIVED_ID_CHANGED'):
            c = bundle(self.zip)
            swap.package(self.zip, c, 'classic')

    def test_drift_during_load_prevents_stop(self):
        self.rt.drift_on_load = True
        with self.assertRaisesRegex(RuntimeError, 'PRE_STOP_FRAME_CHANGED'):
            self.apply()
        self.assertFalse((self.journal / 'stop.intent').exists())

    def test_changed_timestamp_or_endpoint_denied(self):
        self.rt.history[3][2] = 'another time'
        with self.assertRaisesRegex(RuntimeError, 'SNAPSHOT_CHANGED'):
            self.apply()
        self.rt.history[3][2] = 't'
        self.apply()
        self.rt.docs[NEW]['NetworkSettings']['Networks']['backend']['MacAddress'] = '02:42:ac:44:01:08'
        with self.assertRaisesRegex(RuntimeError, 'ENDPOINT_CHANGED'):
            swap.rollback(self.rt, self.journal, self.approved)
        self.assertFalse((self.journal / 'rollback').exists())

    def test_lost_create_response_requires_reconciliation(self):
        original = self.rt.api
        def response_lost(method, path, body=None):
            result = original(method, path, body)
            if path.startswith('/containers/create?'):
                raise TimeoutError()
            return result
        with patch.object(self.rt, 'api', side_effect=response_lost), self.assertRaises(TimeoutError):
            self.apply()
        with self.assertRaisesRegex(RuntimeError, 'RECONCILE_CREATE_OUTCOME'):
            swap.rollback(self.rt, self.journal, self.approved)
        self.assertEqual(NEW, self.rt.inspect('ouf-mcp')['Id'])

    def test_retag_and_mac_preservation(self):
        result = self.apply()
        self.assertEqual('READY', result['status'])
        self.assertEqual(self.c['imageId'], self.rt.tags['ouf-mcp:ci'])
        self.assertEqual(OLD_IMAGE, self.rt.tags[self.body['custodyTag']])
        self.assertNotIn('MacAddress', self.rt.docs[OLD]['Config'])
        self.assertEqual({}, self.rt.docs[OLD]['NetworkSettings']['Networks'])
        self.assertEqual(MAC, self.rt.docs[NEW]['NetworkSettings']['Networks']['backend']['MacAddress'])
        self.assertNotIn('private', json.dumps(result))
        self.assertEqual('ROLLED_BACK', swap.rollback(self.rt, self.journal, self.approved)['status'])
        self.assertEqual(OLD, self.rt.inspect('ouf-mcp')['Id'])

    def test_readiness_failure_then_explicit_rollback(self):
        self.rt.unready = True
        with patch.object(swap.time, 'sleep'), self.assertRaisesRegex(RuntimeError, 'READINESS_TIMEOUT'):
            self.apply()
        self.assertFalse((self.journal / 'receipt.json').exists())
        result = swap.rollback(self.rt, self.journal, self.approved)
        self.assertEqual((OLD, OLD_IMAGE, '0' * 64, 204),
                         (result['cid'], result['imageId'], result['binarySha256'], result['readyHttp']))
        self.assertFalse(self.rt.docs[NEW]['State']['Running'])
        self.assertEqual({}, self.rt.docs[NEW]['NetworkSettings']['Networks'])
        restored = self.rt.inspect('ouf-mcp')
        self.assertNotIn('MacAddress', restored['Config'])
        self.assertEqual(MAC, restored['NetworkSettings']['Networks']['backend']['MacAddress'])

    def test_restored_predecessor_matrix(self):
        old = self.rt.inspect(OLD)
        self.apply()
        swap.rollback(self.rt, self.journal, self.approved)
        check_restored_rejections(self, swap, old, self.rt.inspect(OLD))

    def test_invalid_original_legacy_cannot_qualify_a_transition(self):
        old = self.rt.inspect(OLD)
        restored = copy.deepcopy(old)
        del restored['Config']['MacAddress']
        for value in (None, '', 'invalid', '01:00:00:00:00:01', '00:00:00:00:00:00', '02:00:00:00:00:01'):
            old['Config']['MacAddress'] = value
            with self.subTest(value=value), self.assertRaises(swap.RestoredFrameChanged):
                swap.verify_restored_frame(old, restored, reconnected=True)

    def test_absent_original_requires_exact_config(self):
        old = self.rt.inspect(OLD)
        del old['Config']['MacAddress']
        restored = copy.deepcopy(old)
        swap.verify_restored_frame(old, restored, reconnected=True)
        for key, value in [('MacAddress', None), ('MacAddress', ''), ('MacAddress', MAC), ('Env', [])]:
            changed = copy.deepcopy(restored)
            changed['Config'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(swap.RestoredFrameChanged):
                swap.verify_restored_frame(old, changed, reconnected=True)

    def test_legacy_absence_requires_predecessor_reconnect(self):
        original = self.rt.api

        def fail_before_detach(method, path, body=None):
            if path == '/networks/' + NET + '/disconnect':
                raise RuntimeError('DISCONNECT_FAILED')
            result = original(method, path, body)
            if path == '/containers/' + OLD + '/start':
                del self.rt.docs[OLD]['Config']['MacAddress']
            return result

        with patch.object(self.rt, 'api', side_effect=fail_before_detach):
            with self.assertRaisesRegex(RuntimeError, 'DISCONNECT_FAILED'):
                self.apply()
            with self.assertRaises(swap.RestoredFrameChanged):
                swap.rollback(self.rt, self.journal, self.approved)
        self.assertFalse((self.journal / 'rollback/release.intent').exists())

    def test_running_candidate_still_requires_legacy_mac(self):
        original = self.rt.api

        def omit_candidate_legacy(method, path, body=None):
            result = original(method, path, body)
            if path == '/containers/' + NEW + '/start':
                del self.rt.docs[NEW]['Config']['MacAddress']
            return result

        with patch.object(self.rt, 'api', side_effect=omit_candidate_legacy):
            with self.assertRaisesRegex(RuntimeError, 'RUNNING_LEGACY_MAC_CHANGED'):
                self.apply()
        self.assertFalse((self.journal / 'release.intent').exists())

    def test_restored_frame_diff_is_redacted_and_prevents_usr1(self):
        self.apply()
        original = self.rt.api

        def drift_at_restore(method, path, body=None):
            result = original(method, path, body)
            if path == '/containers/' + OLD + '/start':
                config = self.rt.docs[OLD]['Config']
                config['Env'] = ['FAKE_SECRET=synthetic-only']
                config['Labels']['sensitive-label-name'] = 'synthetic-only'
                self.rt.docs[OLD]['HostConfig']['Binds'] = ['/private-source:/private-target:ro']
                self.rt.docs[OLD]['HostConfig']['NetworkMode'] = NET
            return result

        with patch.object(self.rt, 'api', side_effect=drift_at_restore), self.assertRaises(swap.RestoredFrameChanged) as held:
            swap.rollback(self.rt, self.journal, self.approved)
        diff = held.exception.differences
        self.assertEqual(set(diff), {'Config.MacAddress', 'Config.Env', 'Config.Labels',
                                     'HostConfig.Binds', 'HostConfig.NetworkMode', 'NetworkSettings.MacAddress'})
        self.assertEqual(diff['NetworkSettings.MacAddress'], {'matchesOriginal': True})
        self.assertEqual(diff['Config.Env'], {'before': 'list', 'after': 'list', 'orderOnly': False})
        self.assertEqual(diff['HostConfig.Binds'], {'before': 'absent', 'after': 'list'})
        self.assertEqual(diff['Config.MacAddress']['beforeProfile']['matchingEndpointCount'], 1)
        self.assertEqual(diff['Config.MacAddress']['afterProfile']['kind'], 'ABSENT')
        self.assertTrue(diff['HostConfig.NetworkMode']['beforeMatchesName'])
        self.assertTrue(diff['HostConfig.NetworkMode']['afterMatchesId'])
        for private in ('synthetic-only', 'FAKE_SECRET', 'sensitive-label-name', 'private', MAC, NET):
            self.assertNotIn(private, json.dumps(diff))
        self.assertFalse((self.journal / 'rollback/release.intent').exists())
        self.assertFalse((self.journal / 'rollback/receipt.json').exists())

    def test_list_order_is_reported_and_still_rejected(self):
        old = self.rt.inspect(OLD)
        old['HostConfig']['Binds'] = ['a', 'a', 'b']
        for binds, order_only in [(['b', 'a', 'a'], True), (['a', 'b', 'b'], False)]:
            gated = copy.deepcopy(old)
            gated['HostConfig']['Binds'] = binds
            with self.subTest(binds=binds), self.assertRaises(swap.RestoredFrameChanged) as held:
                swap.verify_restored_frame(old, gated, reconnected=False)
            self.assertEqual(held.exception.differences['HostConfig.Binds']['orderOnly'], order_only)

    def test_generation_frame_drift_after_usr1_fails_apply_and_rollback(self):
        original = self.rt.api

        def drift_after_release(method, path, body=None):
            result = original(method, path, body)
            if path.endswith('/kill?signal=USR1'):
                self.rt.docs[path.split('/')[2]]['RestartCount'] += 1
            return result

        with patch.object(self.rt, 'api', side_effect=drift_after_release):
            with self.assertRaisesRegex(RuntimeError, 'CANDIDATE_FRAME_CHANGED_AFTER_RELEASE'):
                self.apply()
            with self.assertRaisesRegex(RuntimeError, 'RESTORED_FRAME_CHANGED_AFTER_RELEASE'):
                swap.rollback(self.rt, self.journal, self.approved)
        self.assertFalse((self.journal / 'receipt.json').exists())
        self.assertFalse((self.journal / 'rollback/receipt.json').exists())


if __name__ == '__main__':
    unittest.main()
