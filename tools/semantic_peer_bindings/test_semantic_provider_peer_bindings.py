import copy
import json
import unittest
from unittest.mock import patch
import semantic_provider_peer_bindings as p

NIC = {'interface': 'oufint0', 'bridge': 'oufsp-int', 'mac': '02:42:ac:15:00:02', 'ipv4': '172.21.0.2', 'workloadRef': 'southbound', 'bindingRef': 'southbound-internal'}
OCI = {'root': {'path': '/root/fixture/rootfs'}, 'process': {'args': ['sleep', '60'], 'env': ['CI_ONLY_SECRET']}}
DECL = {'containerId': 'a' * 64, 'applicationHash': p.digest(OCI), 'networkBindings': [NIC]}
FLOW = {'purpose': 'GATEWAY_ADAPTER', 'authorityRef': 'ci-infrastructure', 'source': '172.21.0.2', 'destination': '172.21.0.3', 'protocol': 'tcp', 'port': 9443,
    'peerIngress': {'kind': 'CREATED_CANDIDATE', 'containerId': 'a' * 64, 'bindingRef': 'southbound-internal'}}
class Budget:
    def check(self): pass
class Fixture:
    def __init__(self):
        self.state = {'id': 'a' * 64, 'status': 'created', 'pid': 123, 'bundle': '/root/fixture'}
        self.children = [{'ifname': 'oufint0', 'ifindex': 2, 'link_index': 20, 'address': NIC['mac'], 'addr_info': [{'family': 'inet', 'local': NIC['ipv4']}]}]
        self.hosts = [{'ifname': 'vethpeer', 'ifindex': 20, 'link_index': 2, 'master': 'oufsp-int'}]
        self.gen = {'pid': 123, 'startTicks': 100, 'namespaceInode': 900}; self.calls = []
    def run(self, binding, args, limit):
        self.calls.append(args)
        return p.encoded(self.state if args[0] == '--root' else self.children if args[0].startswith('--net=') else self.hosts)
    def collect(self, decl=DECL):
        with patch.object(p.socket, 'if_indextoname', return_value='vethpeer'):
            return p.collect(decl, '/root/runtime', {'path': '/usr/bin/runc'}, {'ip': {'path': '/usr/bin/ip'}, 'nsenter': {'path': '/usr/bin/nsenter'}}, self.run, lambda _: p.encoded(OCI), lambda _: copy.deepcopy(self.gen), Budget())
class Tests(unittest.TestCase):
    def test_symbolic_hash_stays_fixed_when_kernel_index_is_resolved(self):
        before = p.digest([FLOW]); snapshot = Fixture().collect()
        actual = p.resolve([FLOW], [DECL], {'a' * 64: snapshot}, 'b' * 64)
        self.assertEqual(actual[0]['peerIngress'], {'kind': 'BRIDGE_PORT', 'ifindex': 20})
        self.assertEqual(p.digest([FLOW]), before); self.assertNotEqual(p.digest(actual), before)
        self.assertNotIn('CI_ONLY_SECRET', json.dumps(snapshot))
    def test_full_oci_drift_is_rejected(self):
        bad = copy.deepcopy(DECL); bad['applicationHash'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'PEER_COMPLETE_OCI_DRIFT'): Fixture().collect(bad)
    def test_mac_ip_bridge_and_extra_nic_are_rejected(self):
        for field in ('mac', 'ipv4', 'bridge', 'extra'):
            f = Fixture()
            if field == 'mac': f.children[0]['address'] = '02:00:00:00:00:01'
            if field == 'ipv4': f.children[0]['addr_info'][0]['local'] = '172.21.0.8'
            if field == 'bridge': f.hosts[0]['master'] = 'wrongbridge'
            if field == 'extra': f.children.append(copy.deepcopy(f.children[0]))
            with self.subTest(field=field), self.assertRaises(ValueError): f.collect()
    def test_foreign_cid_or_binding_is_not_adopted(self):
        snapshot = Fixture().collect()
        for key, value in [('containerId', 'c' * 64), ('bindingRef', 'foreign')]:
            bad = copy.deepcopy(FLOW); bad['peerIngress'][key] = value
            with self.subTest(field=key), self.assertRaises(ValueError): p.resolve([bad], [DECL], {'a' * 64: snapshot}, 'b' * 64)
    def test_generation_changed_is_rejected(self):
        f = Fixture(); count = 0
        def gen(_):
            nonlocal count
            count += 1
            return {'pid': 123, 'startTicks': count, 'namespaceInode': 900}
        with patch.object(p.socket, 'if_indextoname', return_value='vethpeer'), self.assertRaisesRegex(ValueError, 'PEER_OBSERVATION_CHANGED'):
            p.collect(DECL, '/root/runtime', {}, {'ip': {'path': '/usr/bin/ip'}, 'nsenter': {}}, f.run, lambda _: p.encoded(OCI), gen, Budget())
    def test_legacy_numeric_peer_is_preserved(self):
        old = copy.deepcopy(FLOW); old['peerIngress'] = {'kind': 'HOST', 'ifindex': 0}
        self.assertEqual(p.resolve([old], [], {}, 'b' * 64), [old])
if __name__ == '__main__': unittest.main()
