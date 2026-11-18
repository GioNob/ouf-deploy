"""Disposable namespace packet proof, never Docker or host nft installation.

Run ONLY through test_semantic_lease_kernel_v2_native.py. Routed DNAT and direct
traffic exercise inet; same-bridge traffic with br_netfilter disabled exercises
native bridge conntrack. IPv6 is also exercised on the direct/bridge paths.
"""
import copy
import json
import os
from pathlib import Path
import select
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_semantic_lease_kernel_v2 import kernel, m, observations, refresh


def run(*args, raw=None):
    result = subprocess.run(args, input=raw, text=True, capture_output=True, timeout=15)
    if result.returncode:
        raise RuntimeError(f'{args}: {result.stdout}\n{result.stderr}')
    return result.stdout


SERVER = r'''
import socket,sys,threading
s=socket.socket(socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((sys.argv[1],int(sys.argv[2])));s.listen(16)
def echo(c):
    try:
        while True:
            data=c.recv(4096)
            if not data: break
            c.sendall(data)
    except OSError: pass
    finally: c.close()
print('READY',flush=True)
while True:
    c,_=s.accept();threading.Thread(target=echo,args=(c,),daemon=True).start()
'''
CLIENT = r'''
import json,socket,sys
s=socket.socket(socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET)
s.settimeout(1)
try:
    s.bind((sys.argv[1],0));s.connect((sys.argv[2],int(sys.argv[3])))
except TimeoutError:
    print('DROP',flush=True);sys.exit(0)
print('CONNECTED',flush=True)
for line in sys.stdin:
    data=line.strip().encode()
    try:
        s.sendall(data);reply=s.recv(4096)
        print('ECHO' if reply==data else 'BAD_REPLY',flush=True)
    except TimeoutError: print('DROP',flush=True)
    except OSError as e: print('ERROR:'+str(e),flush=True)
'''


class Proof:
    def __init__(self):
        self.children = []
        self.current = None
        self.isolated = False

    def start(self, ns, program, *args):
        child = subprocess.Popen(['ip', 'netns', 'exec', ns, sys.executable, '-I', '-B', '-u', '-c', program, *args],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.children.append(child)
        return child

    def line(self, child):
        if not select.select([child.stdout], [], [], 5)[0]:
            raise AssertionError('namespace child response timed out')
        line = child.stdout.readline().strip()
        if not line:
            child.wait(timeout=2)
            raise AssertionError('namespace child exited: ' + child.stderr.read())
        return line

    def server(self, ns, address, port):
        assert self.line(self.start(ns, SERVER, address, str(port))) == 'READY'

    def probe(self, source, destination, *, allowed, port=443, keep=False):
        child = self.start('southbound', CLIENT, source, destination, str(port))
        actual = self.line(child)
        assert actual == ('CONNECTED' if allowed else 'DROP'), (source, destination, port, actual)
        if allowed:
            self.echo(child, 'before', 'ECHO')
        if not keep:
            child.stdin.close()
            child.wait(timeout=3)
            assert child.returncode == 0
        return child

    def echo(self, child, payload, expected):
        child.stdin.write(payload + '\n'); child.stdin.flush()
        actual = self.line(child)
        assert actual == expected, (payload, expected, actual)

    def configure(self):
        # /run is a PRIVATE tmpfs before ip netns writes mounts/namespace names.
        assert os.geteuid() == 0 and os.getegid() == 0
        assert os.environ.get('OUF_LEASE_KERNEL_V2_NATIVE') == '1'
        for kind in ('net', 'mnt'):
            assert os.stat('/proc/self/ns/' + kind).st_ino != os.stat('/proc/1/ns/' + kind).st_ino
        run('mount', '--make-rprivate', '/')
        run('mount', '-t', 'tmpfs', 'tmpfs', '/run')
        Path('/run/netns').mkdir()
        self.isolated = True
        for name in ('ip_forward',):
            Path('/proc/sys/net/ipv4/' + name).write_text('1\n')
        # Explicit: newer kernels (7.0 runners) do not propagate all/forwarding to
        # default/forwarding, which interfaces created later inherit.
        for scope in ('all', 'default'):
            Path('/proc/sys/net/ipv6/conf/' + scope + '/forwarding').write_text('1\n')
        # No shared-host sysctl changes: net+mount isolation is already checked.
        for name in ('bridge-nf-call-iptables', 'bridge-nf-call-ip6tables', 'bridge-nf-call-arptables'):
            path = Path('/proc/sys/net/bridge') / name
            if path.exists():
                path.write_text('0\n')
                assert path.read_text().strip() == '0'
        run('ip', 'link', 'set', 'lo', 'up')
        for bridge, v4, v6 in (('egress', '10.64.0.1/24', 'fd64::1/64'),
                               ('servers', '10.65.0.1/24', 'fd65::1/64'),
                               ('external', '10.66.0.1/24', 'fd66::1/64')):
            run('ip', 'link', 'add', bridge, 'type', 'bridge')
            run('ip', 'addr', 'add', v4, 'dev', bridge)
            run('ip', '-6', 'addr', 'add', v6, 'dev', bridge, 'nodad')
            run('ip', 'link', 'set', bridge, 'up')
            Path('/proc/sys/net/ipv6/conf/' + bridge + '/forwarding').write_text('1\n')
        for ns, bridge, v4, v6 in (('southbound', 'egress', '10.64.0.2/24', 'fd64::2/64'),
                                    ('dnat', 'servers', '10.65.0.2/24', 'fd65::2/64'),
                                    ('direct', 'external', '10.66.0.2/24', 'fd66::2/64'),
                                    ('peer', 'egress', '10.64.0.10/24', 'fd64::10/64')):
            run('ip', 'netns', 'add', ns)
            host = 'v-' + ns
            run('ip', 'link', 'add', host, 'type', 'veth', 'peer', 'name', 'ns-' + ns)
            run('ip', 'link', 'set', 'ns-' + ns, 'netns', ns)
            run('ip', 'link', 'set', host, 'master', bridge)
            run('ip', 'link', 'set', host, 'up')
            def inside(*args): return run('ip', '-n', ns, *args)
            inside('link', 'set', 'lo', 'up')
            inside('link', 'set', 'ns-' + ns, 'name', 'eth0')
            inside('addr', 'add', v4, 'dev', 'eth0')
            inside('-6', 'addr', 'add', v6, 'dev', 'eth0', 'nodad')
            inside('link', 'set', 'eth0', 'up')
            gateway = {'egress': ('10.64.0.1', 'fd64::1'), 'servers': ('10.65.0.1', 'fd65::1'),
                       'external': ('10.66.0.1', 'fd66::1')}[bridge]
            inside('route', 'add', 'default', 'via', gateway[0])
            inside('-6', 'route', 'add', 'default', 'via', gateway[1])
        for ns, address in (('southbound', '10.64.0.3/24'), ('peer', '10.64.0.11/24')):
            run('ip', '-n', ns, 'addr', 'add', address, 'dev', 'eth0')
        run('ip', '-n', 'southbound', '-6', 'addr', 'add', 'fd64::3/64', 'dev', 'eth0', 'nodad')
        run('ip', '-n', 'peer', '-6', 'addr', 'add', 'fd64::11/64', 'dev', 'eth0', 'nodad')
        for address in ('198.51.100.10', '198.51.100.11'):
            run('ip', 'addr', 'add', address + '/32', 'dev', 'lo')
        run('nft', '-f', '-', raw='''table ip test_dnat {
 chain pre { type nat hook prerouting priority dstnat; policy accept;
  ip daddr { 198.51.100.10, 198.51.100.11 } tcp dport 443 dnat to 10.65.0.2:8443
 }
}
''')
        self.server('dnat', '10.65.0.2', 8443)
        self.server('direct', '10.66.0.2', 443)
        self.server('direct', 'fd66::2', 443)
        for address in ('10.64.0.10', '10.64.0.11', 'fd64::10', 'fd64::11'):
            self.server('peer', address, 443)

    def install(self, version):
        if self.current:
            for family in ('inet', 'bridge'):
                run('nft', 'delete', 'table', family, self.current['tableName'])
        cfg = kernel(version); cfg['staticFlows'] = []
        flow = cfg['providerFlows'][0]
        flow.update(endpoint='https://provider.invalid',
                    addresses=['198.51.100.10', '10.66.0.2', '10.64.0.10'], leaseSeconds=300)
        flow['allowedPrivateAddresses'] = list(flow['addresses'])
        v6 = copy.deepcopy(flow)
        v6.update(endpointRef='provider6', source='fd64::2', addresses=['fd66::2', 'fd64::10'],
                  allowedPrivateAddresses=['fd66::2', 'fd64::10'])
        cfg['providerFlows'].append(v6)
        # Install the ACTUAL compiler output, with empty sets as on the owner.
        rules = m.materialize(cfg, empty_provider_sets=True)['nftRules']
        run('nft', '--check', '-f', '-', raw=rules)
        run('nft', '-f', '-', raw=rules)
        plan = refresh.compile_refresh(cfg, observations(cfg, lifetime=300), 101., apply_budget_seconds=1)
        assert not plan['denyOnly']
        run('nft', '-f', '-', raw=plan['nftTransaction'])
        self.current = cfg

    def counters(self, family, index, verdict, *, direction=None):
        rows = json.loads(run('nft', '-j', 'list', 'table', family, self.current['tableName']))['nftables']
        for row in rows:
            rule = row.get('rule', {})
            expr = rule.get('expr', [])
            if rule.get('chain') != ('governed_flows' if family == 'inet' else 'governed_bridge_flows'):
                continue
            if not any(verdict in e for e in expr): continue
            encoded = json.dumps(expr)
            if index is not None and '@provider_' + str(index) not in encoded: continue
            if direction and not any(e.get('match', {}).get('left') == {'ct': {'key': 'direction'}}
                                     and e['match'].get('right') == direction for e in expr): continue
            yield from (e['counter']['packets'] for e in expr if 'counter' in e)

    def prove(self):
        self.configure()
        print('Linux', os.uname().release, 'nft:', run('nft', '--version').strip(), flush=True)
        # Positive controls for negative probes: routing, NAT, aliases/listeners
        # work before filtering. A timeout under the guard means a policy drop.
        for src, dst in (('10.64.0.2', '198.51.100.10'), ('10.64.0.2', '198.51.100.11'),
                         ('10.64.0.3', '198.51.100.10'), ('10.64.0.2', '10.66.0.2'),
                         ('10.64.0.2', '10.64.0.10'), ('10.64.0.2', '10.64.0.11'),
                         ('10.64.0.3', '10.64.0.10'), ('fd64::2', 'fd66::2'),
                         ('fd64::2', 'fd64::10'), ('fd64::2', 'fd64::11'), ('fd64::3', 'fd64::10')):
            self.probe(src, dst, allowed=True)
        for version in (1, 2):
            self.install(version)
            self.probe('10.64.0.2', '198.51.100.10', allowed=version == 2)
            self.probe('10.64.0.2', '10.66.0.2', allowed=True)
            self.probe('10.64.0.2', '10.64.0.10', allowed=True)
            self.probe('fd64::2', 'fd66::2', allowed=True)
            self.probe('fd64::2', 'fd64::10', allowed=True)
            if version == 1:
                assert sum(self.counters('inet', None, 'drop')) > 0
                print('generation 1: DNAT DROP; direct IPv4/IPv6 and bridge PASS', flush=True)
                continue
            for source, target in (('10.64.0.2', '198.51.100.11'), ('10.64.0.3', '198.51.100.10'),
                                   ('10.64.0.2', '10.64.0.11'), ('10.64.0.3', '10.64.0.10'),
                                   ('fd64::2', 'fd64::11'), ('fd64::3', 'fd64::10')):
                self.probe(source, target, allowed=False)
            # Kernel JSON readback must show both ct directions actually hit in
            # BOTH families and address families; inet-only success is not proof.
            for family in ('inet', 'bridge'):
                for index in (0, 1):
                    for direction in ('original', 'reply'):
                        assert sum(self.counters(family, index, 'accept', direction=direction)) > 0, (family, index, direction)
            live = [self.probe(source, target, allowed=True, keep=True) for source, target in (
                ('10.64.0.2', '198.51.100.10'), ('10.64.0.2', '10.66.0.2'),
                ('10.64.0.2', '10.64.0.10'), ('fd64::2', 'fd66::2'), ('fd64::2', 'fd64::10'))]
            # Invalid/missing observations produce the exact refresh flush-only
            # transaction. Keep rules/handles byte-for-byte unchanged.
            def rule_snapshot():
                return [[r['rule'] for r in json.loads(run('nft', '-j', '-a', 'list', 'table', f,
                    self.current['tableName']))['nftables'] if 'rule' in r] for f in ('inet', 'bridge')]
            def without_counts(rows):
                result = copy.deepcopy(rows)
                for family in result:
                    for rule in family:
                        for e in rule['expr']:
                            if 'counter' in e: e['counter'] = {}
                return result
            before = without_counts(rule_snapshot())
            clear = refresh.compile_refresh(self.current, [], 102., apply_budget_seconds=1)
            assert clear['denyOnly']
            run('nft', '-f', '-', raw=clear['nftTransaction'])
            for child in live: self.echo(child, 'after-flush', 'DROP')
            assert before == without_counts(rule_snapshot()), 'refresh changed rules/handles'
            print('generation 2: DNAT/direct/bridge IPv4/IPv6 PASS; original destination/source negatives DROP; '
                  'all five established sockets DROP after set flush; rule handles unchanged', flush=True)

    def close(self):
        for child in reversed(self.children):
            if child.poll() is None: child.kill()
            child.wait(timeout=3)
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream and not stream.closed: stream.close()
        # Namespace names live only in private /run, networks only in private
        # router netns. Explicit delete also closes the named netns handles.
        if self.isolated:
            for ns in ('southbound', 'dnat', 'direct', 'peer'):
                subprocess.run(['ip', 'netns', 'del', ns], capture_output=True, timeout=5)


if __name__ == '__main__':
    proof = Proof()
    try: proof.prove()
    finally: proof.close()
