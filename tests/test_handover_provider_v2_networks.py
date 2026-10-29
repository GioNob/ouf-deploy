import copy
import unittest
import handover_provider_v2_networks as h
import pin_provider_v2_networks as p
from test_pin_provider_v2_networks import FakeAPI

def fixture():
    api = FakeAPI()
    for i, (role, (cid, name)) in enumerate(h.PREDECESSORS.items()):
        del api.rows[format(i, '064x')]
        row = copy.deepcopy(api.rows[p.CANDIDATES[role][0]])
        row['Id'] = cid; row['Name'] = '/' + name; row['HostConfig']['Runtime'] = 'runc'
        for n in row['NetworkSettings']['Networks'].values(): n['Aliases'] = [name]
        api.rows[cid] = row
    return api
class Tests(unittest.TestCase):
    def test_only_predecessor_metadata_released_and_v2_pinned(self):
        api = fixture(); before = {cid: p.immutable(api.inspect(cid)) for cid, _ in h.PREDECESSORS.values()}; writes = []
        r = h.handover(api, lambda v: writes.append(copy.deepcopy(v)))
        self.assertEqual(len(api.posts), 15); self.assertEqual(r['predecessorEndpointReleases'], 5)
        for cid, _ in h.PREDECESSORS.values():
            self.assertEqual(before[cid], p.immutable(api.inspect(cid)))
            self.assertEqual(api.inspect(cid)['NetworkSettings']['Networks'], {})
        self.assertEqual(writes[-1][-1]['state'], 'HANDOVER_COMPLETED')
    def test_running_predecessor_blocks_before_write_and_post(self):
        api = fixture(); api.rows[h.PREDECESSORS['adapter'][0]]['State']['Running'] = True
        writes = []
        with self.assertRaisesRegex(ValueError, 'PREDECESSOR_NOT_NEVER_STARTED'): h.handover(api, writes.append)
        self.assertEqual(writes, []); self.assertEqual(api.posts, [])
    def test_other_collision_still_blocks_before_release(self):
        api = fixture(); row = api.rows[format(2, '064x')]
        row['NetworkSettings']['Networks']['ouf-backend'] = {'IPAMConfig': {'IPv4Address': '172.18.0.14'}}
        with self.assertRaisesRegex(ValueError, 'NETWORK_COLLISION'): h.handover(api, lambda _: None)
        self.assertEqual(api.posts, [])
    def test_partial_failure_retains_original_endpoints_and_stops(self):
        api = fixture(); original = api.request; writes = []
        def request(method, path, value=None):
            if method == 'POST' and len(api.posts) == 1: raise ValueError('BOUNDED_DOCKER_API_FAILED')
            return original(method, path, value)
        api.request = request
        with self.assertRaisesRegex(ValueError, 'BOUNDED_DOCKER_API_FAILED'): h.handover(api, lambda v: writes.append(copy.deepcopy(v)))
        self.assertEqual(len(api.posts), 1)
        self.assertEqual(len(writes[-1][0]['predecessors'][0]['networks']), 2)
        self.assertEqual(writes[-1][-1]['state'], 'PREDECESSOR_ENDPOINT_RELEASED')
if __name__ == '__main__': unittest.main()
