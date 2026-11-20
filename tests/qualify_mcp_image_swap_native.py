"""Hosted-only R-033 test with the selected CI ZIP, real Docker, PostgreSQL and TLS fixture."""
import importlib.util
import json
import os
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('fixture', ROOT / 'tests/test_mcp_analysis_upgrade_native.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
swap = fixture.mod('swap', ROOT / 'scripts/swap-mcp-image.py')
protocol = fixture.mod('protocol', ROOT / 'tests/test_mcp_image_swap.py')


class NativeSwap(fixture.Native):
    schema_version = 14

    def load_image(self):
        self.candidate = json.loads((ROOT / 'r033-candidate.json').read_text())
        self.runtime = swap.Runtime()
        self.assertEqual(self.runtime.store(), os.environ['EXPECTED_STORE'])
        self.archive, self.defaults = swap.package(ROOT / 'r033.zip', self.candidate, self.runtime.store())
        self.runtime.load(self.archive)
        selected = self.runtime.api('GET', '/images/ouf-mcp:ci/json')['Id']
        self.assertEqual(selected, self.candidate['imageId'])
        # Distinct predecessor ID. Only provenance differs in its image config.
        docker = fixture.D
        fixture.cmd(*docker, 'build', '--pull=false', '--network=none', '-t', self.tag, '-',
                    input=b'FROM ouf-mcp:ci\nLABEL org.opencontainers.image.revision="fixture"\n')
        self.image = self.runtime.api('GET', '/images/' + self.tag + '/json')['Id']
        self.assertNotEqual(self.image, selected)
        fixture.cmd(*docker, 'tag', self.image, 'ouf-mcp:ci')

    def assert_live_binding(self, old, live):
        network, endpoint = next(iter(old['NetworkSettings']['Networks'].items()))
        self.assertEqual(set(live['NetworkSettings']['Networks']), {network})
        actual = live['NetworkSettings']['Networks'][network]
        for field in ('NetworkID', 'IPAddress', 'GlobalIPv6Address'):
            self.assertEqual(actual.get(field), endpoint.get(field), field)
        self.assertEqual(set(actual['Aliases']), set(endpoint['Aliases']) | {live['Id'][:12]})

    def exercise(self, explicit):
        self.assertEqual(os.environ['DOCKER_API_VERSION'], '1.44')
        old = self.create_server(explicit, 'ouf-mcp')
        _, photo = swap.observe(self.runtime, self.sql_pg_id)
        inputs = {'candidate': self.candidate, 'snapshot': photo, 'expectedOldImageId': self.image}
        _, _, plan = swap.plan(self.runtime, inputs, self.defaults)
        approved = swap.digest(plan)
        journal = self.root / ('attempt-' + old['Id'])
        try:
            receipt = swap.apply(self.runtime, self.root, inputs, self.archive, self.defaults, approved)
            self.assertEqual(receipt['readyHttp'], 204)
            self.assertEqual(receipt['imageId'], self.candidate['imageId'])
            self.assertEqual(self.runtime.inspect(old['Id'])['NetworkSettings']['Networks'], {})
            live = self.runtime.inspect(receipt['cid'])
            self.assert_live_binding(old, live)
            binary_path = ROOT / 'r033-ouf-mcp'
            fixture.cmd(*fixture.D, 'cp', live['Id'] + ':' + swap.APP[0], str(binary_path))
            self.assertEqual(swap.lifecycle.file_sha(binary_path), self.candidate['binarySha256'])
            self.assertEqual(fixture.cmd('go', 'version', '-m', str(binary_path)).splitlines()[0].split()[-1], b'go1.27.4')
            try:
                restored = swap.rollback(self.runtime, journal, approved)
            except swap.RestoredFrameChanged as exc:
                print(json.dumps({'phase': 'rollback.after-start.before-usr1',
                                  'profile': 'explicit' if explicit else 'endpoint-only',
                                  'store': os.environ['EXPECTED_STORE'],
                                  'reason': str(exc), 'differences': exc.differences}, sort_keys=True), flush=True)
                raise
            self.assertEqual((restored['cid'], restored['imageId'], restored['binarySha256'], restored['readyHttp']),
                             (old['Id'], self.image, photo['binarySha256'], 204))
            restored_frame = self.runtime.inspect(old['Id'])
            self.assert_live_binding(old, restored_frame)
            protocol.check_restored_rejections(self, swap, old, restored_frame)
            self.assertEqual(self.runtime.inspect(receipt['cid'])['NetworkSettings']['Networks'], {})
            self.assertEqual(self.calls['business'], 0)
            print(json.dumps({'profile': 'explicit' if explicit else 'endpoint-only',
                              'apply': receipt, 'rollback': restored}), flush=True)
        finally:
            if (journal / 'create.done').is_file():
                self.ids.append(swap.read(journal / 'create.done')['Id'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
