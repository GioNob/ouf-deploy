"""Private unshare worker. No Docker, TLS, host nft, DNS or external service.

Reuse the established R3 native process/TCP helpers. Test native bridge hooks
alone, then bridge + inet through br_netfilter, with real composed role bytes.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from native_semantic_lease_kernel_v2 import Proof, CLIENT, run
import test_semantic_provider_r3_v13 as T


class IdentityProof(Proof):
    names = ('southbound', 'identity', 'third', 'semantic')
    addresses = dict(zip(names, ('172.18.0.14', '172.18.0.4', '172.18.0.99', '172.18.0.6')))
    macs = dict(zip(names, ('02:00:00:00:02:02', '02:42:ac:12:00:04',
                           '02:42:ac:12:00:63', '02:42:ac:12:00:06')))

    def configure(self):
        assert os.environ.get('OUF_R3_V13_NATIVE') == '1'
        for kind in ('net', 'mnt'):
            assert os.stat('/proc/self/ns/' + kind).st_ino != os.stat('/proc/1/ns/' + kind).st_ino
        run('mount', '--make-rprivate', '/')
        run('mount', '-t', 'tmpfs', 'tmpfs', '/run')
        Path('/run/netns').mkdir()
        self.isolated = True
        run('ip', 'link', 'set', 'lo', 'up')
        run('ip', 'link', 'add', 'br-backend', 'type', 'bridge')
        run('ip', 'link', 'set', 'br-backend', 'up')
        for ns in self.names:
            run('ip', 'netns', 'add', ns)
            run('ip', 'link', 'add', 'v-' + ns, 'type', 'veth', 'peer', 'name', 'n-' + ns)
            run('ip', 'link', 'set', 'n-' + ns, 'netns', ns)
            run('ip', 'link', 'set', 'v-' + ns, 'master', 'br-backend')
            run('ip', 'link', 'set', 'v-' + ns, 'up')
            run('ip', '-n', ns, 'link', 'set', 'lo', 'up')
            run('ip', '-n', ns, 'link', 'set', 'n-' + ns, 'name', 'eth0')
            run('ip', '-n', ns, 'link', 'set', 'eth0', 'address', self.macs[ns])
            run('ip', '-n', ns, 'addr', 'add', self.addresses[ns] + '/24', 'dev', 'eth0')
            run('ip', '-n', ns, 'link', 'set', 'eth0', 'up')
        self.server('identity', self.addresses['identity'], 443)
        self.server('identity', self.addresses['identity'], 444)
        self.server('third', self.addresses['third'], 443)
        self.server('southbound', self.addresses['southbound'], 10443)

    def tcp(self, ns, target, port, allowed):
        child = self.start(ns, CLIENT, self.addresses[ns], self.addresses[target], str(port))
        assert self.line(child) == ('CONNECTED' if allowed else 'DROP'), (ns, target, port, allowed)
        if allowed: self.echo(child, 'D-051', 'ECHO')
        child.stdin.close(); child.wait(timeout=3)
        assert child.returncode == 0

    def prove(self):
        self.configure()
        bridge_nf = Path('/proc/sys/net/bridge/bridge-nf-call-iptables')
        assert bridge_nf.exists(), 'CI must load br_netfilter; refusing a partial proof'
        # Control: listeners and all destinations actually work before filtering.
        self.tcp('southbound', 'identity', 443, True)
        self.tcp('southbound', 'identity', 444, True)
        self.tcp('southbound', 'third', 443, True)
        self.tcp('semantic', 'southbound', 10443, True)
        inputs, previous = T.fixture()
        result = T.composed(inputs, previous)
        T.load_modules(result)
        links = json.loads(run('ip', '-j', 'link', 'show'))
        index = {v['ifname']: v['ifindex'] for v in links}
        policy = T.backend_policy(result, index['v-southbound'], index['v-semantic'])
        # Real full role table: retain its unused internal/egress attachments,
        # with isolated dummy ports and bridges at those exact owned indexes.
        for a in policy['attachments']:
            if a['interface'] == 'v-southbound': continue
            run('ip', 'link', 'add', a['bridge'], 'type', 'bridge')
            run('ip', 'link', 'add', a['interface'], 'index', str(a['ifindex']), 'type', 'dummy')
            run('ip', 'link', 'set', a['interface'], 'master', a['bridge'])
            run('ip', 'link', 'set', a['interface'], 'up')
            run('ip', 'link', 'set', a['bridge'], 'up')
        rules = sys.modules['tools.materialize_semantic_shared_faces'].materialize(policy)['nftRules']
        for mode in (0, 1):
            bridge_nf.write_text(str(mode) + '\n')
            assert bridge_nf.read_text().strip() == str(mode)
            run('nft', '-f', '-', raw=rules)
            for ns in self.names: run('ip', '-n', ns, 'neigh', 'flush', 'all')
            # These positive probes require real ARP in each direction.
            self.tcp('southbound', 'identity', 443, True)
            self.tcp('semantic', 'southbound', 10443, True)
            # Pin neighbours for negative TCP probes: a DROP cannot be explained
            # by ARP failure or a missing listener (the controls passed above).
            for target in ('identity', 'third'):
                run('ip', '-n', 'southbound', 'neigh', 'replace', self.addresses[target],
                    'lladdr', self.macs[target], 'nud', 'permanent', 'dev', 'eth0')
            self.tcp('southbound', 'identity', 444, False)
            self.tcp('southbound', 'third', 443, False)
            # A new reverse connection is not an established issuer response.
            self.tcp('identity', 'southbound', 10443, False)
            families = ('bridge',) if mode == 0 else ('bridge', 'inet')
            for family in families:
                rows = json.loads(run('nft', '-j', 'list', 'table', family, policy['tableName']))['nftables']
                accepts = [v['rule'] for v in rows if 'rule' in v and v['rule']['chain'].startswith(('from_', 'to_'))
                           and any('accept' in e for e in v['rule']['expr'])]
                idp_rules = [r for r in accepts if '172.18.0.4' in json.dumps(r) and 'tcp' in json.dumps(r)]
                assert idp_rules and all(any(e.get('counter', {}).get('packets', 0) > 0 for e in r['expr'])
                                         for r in idp_rules), (family, mode, idp_rules)
            print('v13 br_netfilter=' + str(mode) + ': issuer443 PASS, issuer444 DROP, third DROP, '
                  'new reverse DROP, Semantic10443 PASS, ARP and role counters PASS', flush=True)
            for family in ('inet', 'bridge'): run('nft', 'delete', 'table', family, policy['tableName'])

    def close(self):
        # Proof.close owns child cleanup; namespace names are on our private /run.
        super().close()
        if self.isolated:
            for ns in ('identity', 'third', 'semantic'):
                subprocess.run(['ip', 'netns', 'del', ns], capture_output=True, timeout=5)


if __name__ == '__main__':
    proof = IdentityProof()
    try: proof.prove()
    finally: proof.close()
