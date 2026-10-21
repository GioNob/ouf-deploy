import copy
import unittest
import pin_provider_v2_networks as p

class FakeAPI:
    def __init__(self):
        self.posts = []; self.rows = {}
        for i in range(96):
            cid = format(i, '064x')
            self.rows[cid] = {'Id': cid, 'State': {'Status': 'running', 'Pid': i + 1}, 'NetworkSettings': {'Networks': {}}}
        for role, (cid, name, image) in p.CANDIDATES.items():
            nets = {}
            for net, (ip, _, _) in p.PLAN[role].items():
                nets[net] = {'NetworkID': '', 'IPAMConfig': {'IPv4Address': ip}, 'Aliases': [name],
                    'MacAddress': '', 'IPAddress': '', 'EndpointID': '', 'DriverOpts': None, 'GwPriority': 0}
            self.rows[cid] = {'Id': cid, 'Name': '/' + name, 'Image': image,
                'State': {'Status': 'created', 'Pid': 0, 'Running': False, 'Restarting': False, 'StartedAt': '0001-01-01T00:00:00Z'},
                'HostConfig': {'Runtime': 'ouf-semantic-admitted-v2', 'RestartPolicy': {'Name': 'no'}},
                'Config': {'Labels': {'ouf.semantic.provider.v2.creation': 'semantic-provider-v2-stopped-resume-k5mmsudx'}},
                'Mounts': [], 'NetworkSettings': {'Networks': nets}}
    def inspect(self, cid): return copy.deepcopy(self.rows[cid])
    def request(self, method, path, value=None):
        if path == '/containers/json?all=1': return [{'Id': cid} for cid in self.rows]
        nid = path.split('/')[2]
        name = next(n for n, x in p.NETWORKS.items() if x[0] == nid)
        if method == 'GET':
            _, bridge, internal, subnet = p.NETWORKS[name]
            return {'Id': nid, 'Name': name, 'Driver': 'bridge', 'Internal': internal, 'EnableIPv6': False,
                'Options': {'com.docker.network.bridge.name': bridge}, 'IPAM': {'Config': [{'Subnet': subnet}]}}
        self.posts.append((path, copy.deepcopy(value)))
        nets = self.rows[value['Container']]['NetworkSettings']['Networks']
        if path.endswith('/disconnect'): del nets[name]
        else: nets[name] = {**value['EndpointConfig'], 'NetworkID': '', 'IPAddress': '', 'EndpointID': ''}

class Tests(unittest.TestCase):
    def test_only_exact_five_owned_endpoints_and_never_start(self):
        api = FakeAPI(); claims = []
        report = p.apply(api, lambda value: claims.append(copy.deepcopy(value)))
        self.assertEqual(len(api.posts), 10); self.assertEqual(claims[0]['state'], 'CLAIMED')
        self.assertEqual(claims[-1]['state'], 'COMPLETED'); self.assertFalse(report['liveInterfaceBindingProven'])
        for path, value in api.posts:
            self.assertIn(value['Container'], {x[0] for x in p.CANDIDATES.values()})
            self.assertTrue(path.endswith(('/connect', '/disconnect')))
    def test_running_candidate_rejected_before_claim_and_mutation(self):
        api = FakeAPI(); api.rows[p.CANDIDATES['adapter'][0]]['State']['Running'] = True
        claims = []
        with self.assertRaisesRegex(ValueError, 'CANDIDATE_NOT_NEVER_STARTED'): p.apply(api, claims.append)
        self.assertEqual(api.posts, []); self.assertEqual(claims, [])
    def test_stopped_ip_collision_rejected(self):
        api = FakeAPI(); other = api.rows[format(0, '064x')]
        other['NetworkSettings']['Networks']['ouf-semantic-provider-internal'] = {'IPAMConfig': {'IPv4Address': '172.21.0.3'}}
        with self.assertRaisesRegex(ValueError, 'NETWORK_COLLISION'): p.apply(api, lambda _: None)
        self.assertEqual(api.posts, [])
    def test_failure_after_disconnect_retains_claim_and_does_not_continue(self):
        api = FakeAPI(); original = api.request; claims = []
        def fail(method, path, value=None):
            if method == 'POST' and path.endswith('/connect'): raise ValueError('BOUNDED_DOCKER_API_FAILED')
            return original(method, path, value)
        api.request = fail
        with self.assertRaisesRegex(ValueError, 'BOUNDED_DOCKER_API_FAILED'): p.apply(api, claims.append)
        self.assertEqual(len(api.posts), 1); self.assertEqual(claims, [{'state': 'CLAIMED', 'operationCount': 5}])
    def test_alias_drift_rejected_before_any_mutation(self):
        api = FakeAPI(); api.rows[p.CANDIDATES['southbound'][0]]['NetworkSettings']['Networks']['ouf-backend']['Aliases'].append('unexpected')
        with self.assertRaisesRegex(ValueError, 'ENDPOINT_BINDING_DRIFT'): p.apply(api, lambda _: None)
        self.assertEqual(api.posts, [])
if __name__ == '__main__': unittest.main()
