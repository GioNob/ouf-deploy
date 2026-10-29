"""Disposable hosted-CI proof: real runc created PID and reciprocal NIC links.

No application start. No target keys, namespaces, containers or host service
configuration. Own named networks and runc state are removed in finally.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import semantic_provider_peer_bindings as p

class Budget:
    def __init__(self): self.end = time.monotonic() + 15
    def check(self): p.require(time.monotonic() < self.end, 'CI_OBSERVATION_DEADLINE')
def generation(pid):
    path = Path('/proc') / str(pid)
    before = (path / 'stat').read_text(); inode = (path / 'ns/net').stat().st_ino; after = (path / 'stat').read_text()
    def ticks(value): return int(value.rsplit(')', 1)[1].split()[19])
    p.require(ticks(before) == ticks(after), 'CI_GENERATION_CHANGED')
    return {'pid': pid, 'startTicks': ticks(after), 'namespaceInode': inode}
def main():
    p.require(os.geteuid() == 0, 'HOSTED_CI_ROOT_REQUIRED')
    suffix = uuid.uuid4().hex[:7]; namespace = 'pnc_' + suffix; cid = hashlib.sha256(namespace.encode()).hexdigest()
    commands = {k: str(Path(shutil.which(k)).resolve()) for k in ('ip', 'nsenter', 'runc', 'sysctl')}
    def cmd(*args, check=True):
        # The created init retains stdio until FIFO release; pipes would wait
        # for EOF even when the runc create command has already exited.
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            value = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=15)
            out.seek(0); err.seek(0)
            result = subprocess.CompletedProcess(args, value.returncode, out.read(1048577), err.read(1048577))
        p.require(len(result.stdout) <= 1048576 and len(result.stderr) <= 1048576, 'CI_COMMAND_OUTPUT_UNBOUNDED')
        if check and result.returncode: raise RuntimeError('CI_COMMAND_FAILED:' + str(args[:2]) + ':' + result.stderr.decode()[:1200])
        return result
    bridges = []; hosts = []; runtime_created = False
    with tempfile.TemporaryDirectory(prefix='ouf-peer-native-', dir='/root') as directory:
        root = Path(directory); runtime = root / 'runtime'; runtime.mkdir(mode=0o700)
        bundle = root / 'bundle'; bundle.mkdir(mode=0o700)
        rootfs = bundle / 'rootfs'; (rootfs / 'bin').mkdir(parents=True)
        shutil.copyfile(shutil.which('busybox'), rootfs / 'bin/busybox'); (rootfs / 'bin/busybox').chmod(0o755)
        try:
            cmd(commands['ip'], 'netns', 'add', namespace)
            for setting in ('net.ipv6.conf.all.disable_ipv6=1', 'net.ipv6.conf.default.disable_ipv6=1'):
                cmd(commands['ip'], 'netns', 'exec', namespace, commands['sysctl'], '-q', '-w', setting)
            bindings = []
            for index in range(2):
                bridge = 'pb' + str(index) + suffix; host = 'ph' + str(index) + suffix; child = 'pc' + str(index) + suffix
                bridges.append(bridge); hosts.append(host)
                mac = '02:42:c6:13:' + format(250 + index, '02x') + ':02'; address = '198.19.' + str(250 + index) + '.2'; interface = 'oufnet' + str(index)
                cmd(commands['ip'], 'link', 'add', bridge, 'type', 'bridge')
                cmd(commands['ip'], 'link', 'set', bridge, 'up')
                cmd(commands['ip'], 'link', 'add', host, 'type', 'veth', 'peer', 'name', child)
                cmd(commands['ip'], 'link', 'set', host, 'master', bridge); cmd(commands['ip'], 'link', 'set', host, 'up')
                cmd(commands['ip'], 'link', 'set', child, 'netns', namespace)
                cmd(commands['ip'], '-n', namespace, 'link', 'set', child, 'name', interface)
                cmd(commands['ip'], '-n', namespace, 'link', 'set', interface, 'address', mac)
                cmd(commands['ip'], '-n', namespace, 'addr', 'add', address + '/24', 'dev', interface)
                cmd(commands['ip'], '-n', namespace, 'link', 'set', interface, 'up')
                bindings.append({'interface': interface, 'bridge': bridge, 'mac': mac, 'ipv4': address, 'bindingRef': 'ci-peer-' + str(index), 'workloadRef': 'ci-peer'})
            cmd(commands['ip'], '-n', namespace, 'link', 'set', 'lo', 'up')
            result = subprocess.run([commands['runc'], 'spec'], cwd=bundle, capture_output=True, timeout=15)
            p.require(result.returncode == 0, 'CI_SPEC_FAILED')
            path = bundle / 'config.json'; oci = json.loads(path.read_bytes())
            oci['process']['terminal'] = False; oci['process']['args'] = ['/bin/busybox', 'sleep', '60']
            oci['process']['user'] = {'uid': 10006, 'gid': 10006}; oci['process']['cwd'] = '/'
            oci['root']['path'] = str(rootfs); oci['root']['readonly'] = True
            oci['linux']['cgroupsPath'] = '/ouf_peer_' + suffix
            for item in oci['linux']['namespaces']:
                if item['type'] == 'network': item['path'] = '/run/netns/' + namespace
            path.write_bytes(p.encoded(oci)); path.chmod(0o600)
            expected = {'containerId': cid, 'applicationHash': p.digest(oci), 'networkBindings': bindings}
            # Expected OCI and NIC declarations exist before runc create.
            runtime_created = True
            cmd(commands['runc'], '--root', str(runtime), 'create', '--bundle', str(bundle), cid)
            runtime_binding = {'path': commands['runc'], 'sha256': hashlib.sha256(Path(commands['runc']).read_bytes()).hexdigest()}
            io = {k: {'path': commands[k], 'sha256': hashlib.sha256(Path(commands[k]).read_bytes()).hexdigest()} for k in ('ip', 'nsenter')}
            def run(binding, args, limit):
                raw = Path(binding['path']).read_bytes(); p.require(hashlib.sha256(raw).hexdigest() == binding['sha256'], 'CI_EXECUTABLE_CHANGED')
                result = cmd(binding['path'], *args)
                p.require(len(result.stdout) <= limit, 'CI_OUTPUT_UNBOUNDED'); return result.stdout
            def read_bundle(name):
                p.require(name == str(path), 'CI_BUNDLE_REBIND'); return path.read_bytes()
            snapshot = p.collect(expected, str(runtime), runtime_binding, io, run, read_bundle, generation, Budget())
            for index in range(2):
                flow = {'purpose': 'GATEWAY_ADAPTER', 'authorityRef': 'ci-infrastructure', 'source': bindings[index]['ipv4'],
                    'destination': '198.19.' + str(250 + index) + '.3', 'protocol': 'tcp', 'port': 9443,
                    'peerIngress': {'kind': 'CREATED_CANDIDATE', 'declaration': expected, 'bindingRef': bindings[index]['bindingRef']}}
                sealed = p.digest([flow]); actual = p.resolve([flow], [expected], {cid: snapshot}, 'f' * 64)
                p.require(actual[0]['peerIngress']['ifindex'] == snapshot['bindings'][index]['hostIfindex'] and p.digest([flow]) == sealed, 'CI_PEER_RESOLUTION_FAILED')
            for mutate in ('mac', 'applicationHash'):
                bad = copy.deepcopy(expected)
                if mutate == 'mac': bad['networkBindings'][0]['mac'] = '02:42:00:00:00:01'
                else: bad['applicationHash'] = '0' * 64
                try: p.collect(bad, str(runtime), runtime_binding, io, run, read_bundle, generation, Budget())
                except ValueError: pass
                else: raise RuntimeError('CI_BAD_PEER_ACCEPTED')
            # An unexpected third NIC must not be adopted.
            cmd(commands['ip'], '-n', namespace, 'link', 'add', 'foreign0', 'type', 'dummy')
            try: p.collect(expected, str(runtime), runtime_binding, io, run, read_bundle, generation, Budget())
            except ValueError as e: p.require(str(e) == 'UNAPPROVED_PEER_INTERFACE', 'CI_WRONG_EXTRA_NIC_GATE')
            else: raise RuntimeError('CI_EXTRA_NIC_ACCEPTED')
            state = json.loads(cmd(commands['runc'], '--root', str(runtime), 'state', cid).stdout)
            p.require(state['status'] == 'created', 'CI_APPLICATION_WAS_STARTED')
            print('PEER_BINDINGS_NATIVE=PASS REAL_RUNC_CREATED_PID=true REAL_RECIPROCAL_LINKS=true EXPECTED_OCI_BEFORE_CREATE=true MAC_OCI_EXTRA_NIC_REJECTED=true DECLARATION_HASH_UNCHANGED=true APPLICATION_NOT_STARTED=true TARGET_INTEGRATION_PROVEN=false TARGET_START_AUTHORIZED=false')
        finally:
            if runtime_created: cmd(commands['runc'], '--root', str(runtime), 'delete', '--force', cid, check=False)
            for host in hosts: cmd(commands['ip'], 'link', 'delete', host, check=False)
            for bridge in bridges: cmd(commands['ip'], 'link', 'delete', bridge, check=False)
            cmd(commands['ip'], 'netns', 'delete', namespace, check=False)
if __name__ == '__main__': main()
