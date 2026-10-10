"""Actual packet cutover in an isolated network namespace, never VPS acceptance."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'semantic_cohort_admission/cohort-draft'))
from tools.materialize_semantic_shared_faces import materialize
from peer_rebind import compile_replacement, compile_conditional_recovery, digest, footprint, structure


def main():
    assert os.geteuid() == 0
    assert os.stat('/proc/self/ns/net').st_ino != os.stat('/proc/1/ns/net').st_ino
    nft, ip = shutil.which('nft'), shutil.which('ip')
    def run(args, raw=None):
        result = subprocess.run(args, input=raw, capture_output=True, text=True, timeout=15)
        if result.returncode:
            raise AssertionError('ISOLATED_NATIVE_COMMAND_FAILED: ' + result.stderr[:2000])
        return result.stdout
    bridge = 'br-113b5f0a3c53'
    roles = ['old', 'new', 'rogue', 'back']
    spaces = {r: 'oufp-' + str(os.getpid()) + '-' + r for r in roles}
    indexes = {}
    try:
        run([ip, 'link', 'add', bridge, 'type', 'bridge'])
        run([ip, 'link', 'set', bridge, 'up'])
        for role in roles:
            ns = spaces[role]
            run([ip, 'netns', 'add', ns])
            run([ip, 'link', 'add', 'h-' + role, 'type', 'veth', 'peer', 'name', 'c-' + role])
            run([ip, 'link', 'set', 'h-' + role, 'master', bridge])
            run([ip, 'link', 'set', 'h-' + role, 'up'])
            run([ip, 'link', 'set', 'c-' + role, 'netns', ns])
            run([ip, '-n', ns, 'link', 'set', 'c-' + role, 'name', 'eth0'])
            mac = '02:42:ac:12:00:0e' if role == 'back' else 'b2:96:a1:e2:c1:8d'
            address = '172.18.0.14' if role == 'back' else '172.18.0.6'
            run([ip, '-n', ns, 'link', 'set', 'eth0', 'address', mac])
            run([ip, '-n', ns, 'addr', 'add', address + '/24', 'dev', 'eth0'])
            run([ip, '-n', ns, 'link', 'set', 'lo', 'up'])
            if role == 'back': run([ip, '-n', ns, 'link', 'set', 'eth0', 'up'])
            indexes[role] = json.loads(run([ip, '-j', 'link', 'show', 'dev', 'h-' + role]))[0]['ifindex']
        policy = {'schema': 'ouf.semantic-shared-faces.v1', 'tableName': 'ouf_peer_ci',
            'attachments': [{'workloadRef': 'southbound', 'interface': 'h-back', 'ifindex': indexes['back'],
                             'bridge': bridge, 'mac': '02:42:ac:12:00:0e', 'ipv4': '172.18.0.14', 'bindingRef': 'back'}],
            'flows': [{'purpose': 'WORKLOAD_GATEWAY', 'authorityRef': 'ci-fixture-only',
                       'source': '172.18.0.6', 'destination': '172.18.0.14', 'protocol': 'tcp', 'port': 10443,
                       'peerIngress': {'kind': 'BRIDGE_PORT', 'ifindex': indexes['old']}}]}
        run([nft, '-f', '-'], materialize(policy)['nftRules'])
        run([nft, '-f', '-'], '''table inet ouf_sem_provider {
 set provider_0 { type ipv4_addr; flags timeout; elements = { 1.1.1.1 timeout 30s }; }
 set provider_1 { type ipv4_addr; flags timeout; elements = { 8.8.8.8 timeout 30s }; }
}
table inet unrelated_ci {
 chain input { type filter hook input priority 0; policy accept; }
}
''')
        def tables():
            return {f: json.loads(run([nft, '-j', '-n', 'list', 'table', f, policy['tableName']])) for f in ('inet', 'bridge')}
        def protected():
            return {n: json.loads(run([nft, '-j', '-n', 'list', 'table', 'inet', n])) for n in ('ouf_sem_provider', 'unrelated_ci')}
        def observation(role):
            return {'containerId': ('1' if role == 'old' else '2') * 64,
                    'applicationHash': ('3' if role == 'old' else '4') * 64,
                    'generation': {'pid': 100 if role == 'old' else 200, 'startTicks': 1000, 'namespaceInode': 100 if role == 'old' else 200},
                    'bindings': [{'interface': 'eth0', 'bridge': bridge, 'mac': 'b2:96:a1:e2:c1:8d', 'ipv4': '172.18.0.6',
                                  'workloadRef': 'semantic', 'bindingRef': 'back', 'childIfindex': 2,
                                  'hostIfindex': indexes[role], 'hostInterface': 'h-' + role}]}
        original, other = tables(), protected()
        args = [policy, original, digest(structure(original)), digest(footprint(original)), observation('old'), observation('new'), materialize]
        plan = compile_replacement(*args)
        assert not plan['installed'] and not plan['authorityProven'] and not plan['leaseTableTouched']
        negative = 0
        for field, value in [('ipv4', '172.18.0.9'), ('mac', '02:42:ac:12:00:06'), ('bridge', 'foreign'), ('hostIfindex', True)]:
            modified = copy.deepcopy(args); modified[5]['bindings'][0][field] = value
            try: compile_replacement(*modified)
            except ValueError: negative += 1
            else: raise AssertionError('unapproved replacement scope accepted')
        for field in ('expected_structure', 'expected_footprint'):
            modified = list(args); modified[2 if field == 'expected_structure' else 3] = '0' * 64
            try: compile_replacement(*modified)
            except ValueError: negative += 1
            else: raise AssertionError('native drift accepted')
        def probe(role):
            for r in ('old', 'new', 'rogue'):
                run([ip, '-n', spaces[r], 'link', 'set', 'eth0', 'up' if r == role else 'down'])
            run([ip, '-n', spaces['back'], 'neigh', 'flush', 'dev', 'eth0'])
            script = 'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("172.18.0.14",10443)); s.listen(); print("READY",flush=True); c,a=s.accept(); c.sendall(b"OK"); c.close()'
            server = subprocess.Popen([ip, 'netns', 'exec', spaces['back'], sys.executable, '-u', '-c', script], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            try:
                assert server.stdout.readline().strip() == 'READY'
                client = 'import socket; s=socket.create_connection(("172.18.0.14",10443),1); s.settimeout(1); assert s.recv(2)==b"OK"'
                result = subprocess.run([ip, 'netns', 'exec', spaces[role], sys.executable, '-c', client], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
                return result.returncode == 0
            finally:
                server.terminate(); server.wait(timeout=3)
        assert probe('old') and not probe('new') and not probe('rogue')
        run([nft, '-f', '-'], plan['nativeTransaction'])
        following = tables()
        assert digest(footprint(following)) == plan['followingFootprintHash']
        assert digest(structure(protected())) == digest(structure(other))
        assert not probe('old') and probe('new') and not probe('rogue')
        # Reverse only after exact new native readback; this is isolated test recovery.
        assert digest(footprint(tables())) == plan['followingFootprintHash']
        recovery_negative = 0
        for which in ('old', 'new'):
            old_observation, new_observation = observation('old'), observation('new')
            changed = old_observation if which == 'old' else new_observation
            changed['generation']['startTicks'] += 1
            try: compile_conditional_recovery(plan, digest(plan), tables(), old_observation, new_observation)
            except ValueError: recovery_negative += 1
            else: raise AssertionError('changed generation accepted for inverse')
        try: compile_conditional_recovery(plan, digest(plan), original, observation('old'), observation('new'))
        except ValueError: recovery_negative += 1
        else: raise AssertionError('foreign native state accepted for inverse')
        reverse = compile_conditional_recovery(plan, digest(plan), tables(), observation('old'), observation('new'))
        run([nft, '-f', '-'], reverse)
        assert digest(footprint(tables())) == digest(footprint(original))
        assert probe('old') and not probe('new')
        assert digest(structure(protected())) == digest(structure(other))
        # Simulate lifecycle loss of the old reciprocal link. The retained
        # generation must not authorize an inverse after this actual deletion.
        run([nft, '-f', '-'], plan['nativeTransaction'])
        run([ip, 'link', 'del', 'h-old'])
        gone = subprocess.run([ip, '-j', 'link', 'show', 'dev', 'h-old'],capture_output=True)
        assert gone.returncode != 0
        try: compile_conditional_recovery(plan, digest(plan), tables(), None, observation('new'))
        except ValueError as error:
            assert str(error) == 'OLD_PEER_GENERATION_CHANGED_REAUTHORIZE'
            recovery_negative += 1
        else: raise AssertionError('absent old reciprocal link accepted for inverse')
        # Do not call probe: it toggles the deleted old link. Inspect new link
        # and unchanged native ownership instead; prior probes covered traffic.
        assert digest(footprint(tables())) == plan['followingFootprintHash']
        assert digest(structure(protected())) == digest(structure(other))
        print('SEMANTIC_PEER_PLAN_NATIVE=' + json.dumps({'status': 'PASS', 'actualNft': True,
            'actualPacketProbes': 8, 'negativeScopeCases': negative, 'negativeRecoveryCases': recovery_negative, 'deletedOldPeerInverseDenied': True, 'oneIngressRuleChanged': True,
            'leaseAndUnrelatedTablesUnchanged': True, 'conditionalRecoveryProvenInFixture': True,
            'peerIdentityInputs': 'CI_FIXTURE_NOT_TARGET_ATTESTATIONS', 'targetAcceptance': False}))
    finally:
        for ns in spaces.values():
            subprocess.run([ip, 'netns', 'del', ns], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
