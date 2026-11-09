#!/usr/bin/env python3
"""Compile retained pre-CREATE intent, then read the exact current peer twice.

No credentials/mount contents, requests to the application, lifecycle effects,
signatures or authorization. Fresh private evidence is the sole local write.
"""
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
CID = 'ef35ea78dc8f5116255ce1c12186935451af6612293c95ecacab3165e220598a'
FRAME = '1ff2ed51293a5295016c0cfe713c87dba519322543b2d0c3ccbb802f3f63c3e7'
IMAGE = 'sha256:89e84f7a6208afa74039de7057c46ad5c9981fb283b22d9b93fa014e92d1b048'
NETWORK = '113b5f0a3c53059b087a2ce997d2670cc057e88c0c17d4291b3b41a51ce26ba3'
REPAIR = Path('/var/lib/ouf-storage-migration/semantic-discovery-key-repair-20261108')
ORIGINAL = Path('/var/lib/ouf-storage-migration/semantic-application-upgrade-20261108/gated.private.json')
BUNDLE_PARENTS = ('/run/docker/containerd/daemon/io.containerd.runtime.v2.task/moby',
                  '/run/containerd/io.containerd.runtime.v2.task/moby')
RUNTIME_ROOT = '/run/docker/runtime-runc/moby'


def need(ok, code):
    if not ok: raise RuntimeError(code)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def module(name, relative, pin):
    p = ROOT / relative; raw = p.read_bytes()
    need(sha(raw) == pin, 'PINNED_DEPENDENCY_CHANGED')
    m = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name, p))
    exec(compile(raw, str(p), 'exec'), m.__dict__)
    return m


def dependencies():
    return (
        module('private_source', 'scripts/reconcile-discovery-placeholder-20261109.py',
               '94649eefceddc348c92172872bf0cb180c21bd057ae84f7b371d9b2aa6c6259f'),
        module('native_source', 'scripts/read-discovery-lifecycle-20261109.py',
               '4824c247ddb7c0c90b8740ebcaa1c2681dccd9efd7811666cb1c86210b322e67'),
        module('frame_source', 'scripts/read-analysis-discovery-runtime-20261107.py',
               'ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4'),
        module('rollout_source', 'scripts/upgrade-semantic-application-20261108.py',
               '2e7e7e42367b3329f6ebd441bba665f974ea43871049d863415524610138efb1'),
        module('peer_source', 'tools/semantic_cohort_admission/cohort-draft/tools/semantic_provider_peer_bindings.py',
               '4d99b60459d7122b5126d8424fb6233a9f3de15858219cd9061131b23f45af8b'),
    )


class Budget:
    def __init__(self, seconds=60): self.end = time.monotonic() + seconds
    def check(self): need(time.monotonic() < self.end, 'PEER_READ_BUDGET_EXHAUSTED')


class PeerIO:
    """Closed native reads. All executables are custody checked before/after."""
    def __init__(self, private, native, work, cid, pid, bundle, *, runc='/usr/bin/runc',
                 ip='/usr/sbin/ip', nsenter='/usr/bin/nsenter'):
        self.private, self.native, self.work = private, native.Native(work), work
        self.cid, self.pid, self.bundle = cid, pid, bundle
        self.calls = []
        self.commands = {k: {'path': self.native.binary(v)} for k, v in
                         [('runc', runc), ('ip', ip), ('nsenter', nsenter)]}

    def run(self, binding, args, maximum):
        executable = binding['path']; commands = self.commands
        allowed = (
            executable == commands['runc']['path'] and args == ['--root', RUNTIME_ROOT, 'state', self.cid]
            or executable == commands['nsenter']['path'] and args ==
                ['--net=/proc/' + str(self.pid) + '/ns/net', commands['ip']['path'], '-j', 'addr', 'show']
            or executable == commands['ip']['path'] and len(args) == 5 and args[:4] ==
                ['-j', 'link', 'show', 'dev'] and re.fullmatch('[A-Za-z0-9_.-]{1,15}', args[4])
        )
        need(allowed and len(self.calls) < 12 and 0 < maximum <= 131072, 'CLOSED_PEER_READ_COMMAND_REQUIRED')
        self.native.binary(executable)
        with tempfile.TemporaryFile(dir=self.work) as output:
            result = subprocess.run([executable, *args], stdin=subprocess.DEVNULL, stdout=output,
                                    stderr=subprocess.DEVNULL, timeout=5,
                                    env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'})
            output.seek(0); raw = output.read(maximum + 1)
        self.calls.append({'command': next(k for k, v in commands.items() if v['path'] == executable),
                           'exitCode': result.returncode})
        self.native.binary(executable)
        need(result.returncode == 0 and len(raw) <= maximum, 'NATIVE_PEER_READ_FAILED')
        return raw

    def read_bundle(self, filename):
        need(filename == self.bundle + '/config.json', 'EXACT_CURRENT_BUNDLE_REQUIRED')
        # containerd publishes config.json as root-owned 0644. That runtime
        # document has a different custody profile from our private 0600
        # receipts. Keep the private reader unchanged and forbid all writes
        # by group/other, links, oversized files and changes during this read.
        path = Path(filename); parent = self.private.open_parent(path); fd = None
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                 and stat.S_IMODE(before.st_mode) in (0o600, 0o644) and before.st_nlink == 1
                 and 0 < before.st_size <= 131072, 'ROOT_CONTROLLED_RUNTIME_BUNDLE_REQUIRED')
            with os.fdopen(os.dup(fd), 'rb') as stream: raw = stream.read(131073)
            need(len(raw) == before.st_size and self.private.identity(before) ==
                 self.private.identity(os.fstat(fd)) ==
                 self.private.identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)),
                 'RUNTIME_BUNDLE_CHANGED_DURING_READ')
            return raw
        finally:
            if fd is not None: os.close(fd)
            os.close(parent)

    def generation(self, pid):
        need(type(pid) is int and pid == self.pid and pid > 1, 'ENGINE_RUNC_PID_MUST_AGREE')
        proc = Path('/proc') / str(pid)
        before = (proc / 'stat').read_bytes(); inode = (proc / 'ns/net').stat().st_ino
        after = (proc / 'stat').read_bytes()
        need(len(before) <= 8192 and len(after) <= 8192, 'BOUNDED_PROC_STAT_REQUIRED')
        ticks = lambda raw: int(raw[raw.rfind(b')') + 2:].split()[19])
        need(ticks(before) == ticks(after), 'PROCESS_GENERATION_CHANGED')
        return {'pid': pid, 'startTicks': ticks(after), 'namespaceInode': inode}


def context_for(cid, storage, bundle_parent):
    need(bundle_parent in BUNDLE_PARENTS, 'REVIEWED_CONTAINERD_BUNDLE_LAYOUT_REQUIRED')
    return {'schema': 'ouf.semantic-docker-frame-context.v1', 'containerId': cid,
            'bundleParent': bundle_parent, 'metadataParent': storage + '/containers',
            'networkNamespaceParent': '/run/docker/netns', 'networkNamespaceName': None,
            'cgroupDriver': 'systemd', 'storageParent': storage,
            'rootfsPath': storage + '/rootfs/overlayfs/' + cid}


def declaration(request, recipe, cid, *, network_name, network_id, address, mac):
    eps = request['NetworkingConfig']['EndpointsConfig']
    need(set(eps) == {network_name}, 'EXACT_SEMANTIC_BACKEND_REQUIRED')
    ep = eps[network_name]
    need(ep.get('MacAddress') == mac and ep.get('IPAMConfig', {}).get('IPv4Address') == address
         and ep.get('IPAMConfig', {}).get('IPv6Address') in (None, '')
         and not ep.get('IPAMConfig', {}).get('LinkLocalIPs')
         and ep.get('NetworkID') in (None, '', network_id), 'PRECREATE_ENDPOINT_IDENTITY_DRIFT')
    opts = ep.get('DriverOpts') or {}
    need(set(opts) <= {'com.docker.network.endpoint.ifname'}, 'UNREVIEWED_ENDPOINT_OPTIONS')
    return {'containerId': cid, 'applicationHash': recipe['applicationHash'], 'networkBindings': [{
        'interface': opts.get('com.docker.network.endpoint.ifname', 'eth0'),
        'bridge': 'br-' + network_id[:12], 'ipv4': address, 'mac': mac,
        'workloadRef': 'ouf-semantic-registry', 'bindingRef': 'semantic-backend'}]}


def differences(expected, actual, at=''):
    if type(expected) is not type(actual): return [at or '/']
    if type(expected) is dict:
        result = []
        for k in sorted(set(expected) | set(actual)):
            p = at + '/' + k.replace('~', '~0').replace('/', '~1')
            result += [p] if k not in expected or k not in actual else differences(expected[k], actual[k], p)
        return result
    if type(expected) is list:
        if len(expected) != len(actual): return [at]
        return [p for i, (a, b) in enumerate(zip(expected, actual)) for p in differences(a, b, at + '/' + str(i))]
    return [] if expected == actual else [at]


def main():
    report = {'schema': 'ouf.retained-semantic-peer-read.v1', 'status': 'HELD', 'phase': 'INITIAL',
              'automaticReplayAllowed': False, 'snapshotAtomic': False, 'credentialFileContentsRead': 0,
              'mountSourceContentsRead': 0, 'credentialValuesEmitted': False, 'engineRequests': 0,
              'businessRequestsIssued': 0, 'providerRequests': 0, 'databaseRequests': 0,
              'dnsQueries': 0, 's3Requests': 0, 'tokenRequests': 0, 'containerCreates': 0,
              'serviceStarts': 0, 'serviceStops': 0, 'daemonReloads': 0, 'nftWrites': 0,
              'historicalJournalWrites': 0, 'signaturesProduced': 0, 'newGenerationAdmitted': False,
              'activeInstallationPointerChanged': False, 'leaseAuthorized': False,
              'startAuthorized': False, 'providerReady': False}
    private = work = None
    try:
        need(os.geteuid() == 0 and sys.flags.isolated, 'ISOLATED_ROOT_REQUIRED')
        os.umask(0o077); signal.signal(signal.SIGALRM, lambda *_: need(False, 'TOTAL_READ_TIMEOUT')); signal.alarm(90)
        private, native, h, rollout, peers = dependencies()
        sys.path.insert(0, str(ROOT))
        from tools.semantic_frame_compiler.compile_retained_semantic_peer import compile_peer, ENGINE, digest
        work = Path(tempfile.mkdtemp(prefix='semantic-peer-recipe-', dir='/var/lib/ouf-storage-migration'))
        report['privateEvidenceDirectory'] = str(work)
        record = lambda name, value: private.save(work / name, encoded(value))
        retained = {}
        def source(filename):
            raw = private.read_private(filename); retained[str(filename)] = raw
            return h.parse(raw)
        def get(resource):
            need(resource in ('/info', '/containers/' + CID + '/json', '/networks/' + NETWORK),
                 'CLOSED_ENGINE_READ_REQUIRED')
            class Local(http.client.HTTPConnection):
                def connect(self):
                    self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); self.sock.settimeout(5)
                    self.sock.connect('/run/docker.sock')
                    need(struct.unpack('3i', self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1] == 0,
                         'ROOT_ENGINE_PEER_REQUIRED')
            connection = Local('localhost', timeout=5)
            try:
                report['engineRequests'] += 1
                connection.request('GET', '/v1.44' + resource); response = connection.getresponse()
                raw = response.read(2097153)
                need(response.status == 200 and len(raw) <= 2097152, 'ENGINE_READ_FAILED')
                return h.parse(raw)
            finally: connection.close()
        report['phase'] = 'RECONSTRUCT_PRECREATE_REQUEST'
        request = source(REPAIR / 'request.private.json'); original = source(ORIGINAL)
        created = source(REPAIR / 'created.json'); complete = source(REPAIR / 'complete.json')
        marker = source(REPAIR.parent / 'semantic-discovery-current.json')
        need(created == {'containerId': CID} and marker['containerId'] == CID and marker['imageId'] == IMAGE
             and marker['evidenceDirectory'] == str(REPAIR) and complete['replacementContainerId'] == CID
             and complete['status'] == 'SEMANTIC_DISCOVERY_KEY_REPAIRED_V12_READY'
             and complete['providerEnabled'] is False and complete['workerEnabled'] is False,
             'COMPLETED_RETAINED_REPAIR_LINEAGE_REQUIRED')
        need(original['Id'] == '11d9362c7db484a2204266062fd54b5c08fbf1da7382076fb2a164bc1a9dd070',
             'EXACT_ORIGINAL_GATED_IDENTITY_REQUIRED')
        reconstructed = rollout.request(original, IMAGE)
        key = 'OUF_SEMANTIC_DISCOVERY_DELEGATION_KEY_FILE='
        old = key + '/run/secrets/semantic-discovery-owner.key'
        need(reconstructed['Env'].count(old) == 1, 'ONE_RETAINED_DISCOVERY_KEY_BINDING_REQUIRED')
        reconstructed['Env'][reconstructed['Env'].index(old)] = key + '/run/secrets/semantic-read-owner.key'
        need(request == reconstructed, 'PRECREATE_REPAIR_REQUEST_DIFFERS')
        report['phase'] = 'COMPILE_INDEPENDENT_OCI'
        info = get('/info'); actual = get('/containers/' + CID + '/json'); network = get('/networks/' + NETWORK)
        need(info['ServerVersion'] == '29.8.1' and info['Driver'] == 'overlayfs'
             and info['CgroupDriver'] == 'systemd' and info['DockerRootDir'] == '/var/lib/docker',
             'EXACT_RETAINED_ENGINE_PROFILE_REQUIRED')
        need(h.digest(h.frame(actual)) == FRAME and actual['Image'] == IMAGE and actual['State']['Running']
             and not actual['State']['Paused'] and not actual['State']['Restarting'], 'CURRENT_SEMANTIC_FRAME_CHANGED')
        rollout.verify_replacement(original, request, actual, True)
        need(network['Id'] == NETWORK and network['Name'] == 'ouf-backend' and network['Driver'] == 'bridge'
             and network.get('EnableIPv6') is False
             and (network.get('Options') or {}).get('com.docker.network.bridge.name', 'br-' + NETWORK[:12]) == 'br-' + NETWORK[:12],
             'CURRENT_BACKEND_BRIDGE_CHANGED')
        matches = [p for p in BUNDLE_PARENTS if (Path(p) / CID / 'config.json').exists()]
        need(len(matches) == 1, 'ONE_REVIEWED_CURRENT_BUNDLE_REQUIRED')
        context = context_for(CID, '/var/lib/docker', matches[0])
        baseline = (ROOT / 'tools/semantic_frame_compiler/containerd-overlayfs-southbound.json').read_bytes()
        recipe = compile_peer(baseline, request, context, engine_profile=ENGINE)
        record('independent-recipe.private.json', recipe)
        expected = declaration(request, recipe, CID, network_name='ouf-backend', network_id=NETWORK,
                               address='172.18.0.6', mac='b2:96:a1:e2:c1:8d')
        peers.declaration(expected); record('peer-declaration.private.json', expected)
        report['phase'] = 'OBSERVE_FULL_OCI_AND_RECIPROCAL_LINKS'
        io = PeerIO(private, native, work, CID, actual['State']['Pid'], matches[0] + '/' + CID)
        raw = io.read_bundle(matches[0] + '/' + CID + '/config.json'); observed = h.parse(raw)
        record('observed-oci.private.json', observed)
        diff = differences(recipe['expectedOci'], observed)
        # Values, environment names and mount sources never enter the public receipt.
        report['ociDifferencePaths'] = [p if not p.startswith('/process/env/') else '/process/env/<index>' for p in diff[:32]]
        need(not diff, 'INDEPENDENT_COMPLETE_OCI_MISMATCH')
        snapshot = peers.collect(expected, RUNTIME_ROOT, io.commands['runc'], io.commands,
                                 io.run, io.read_bundle, io.generation, Budget())
        record('peer-observation.private.json', snapshot)
        need(h.frame(get('/containers/' + CID + '/json')) == h.frame(actual)
             and get('/networks/' + NETWORK) == network, 'ENGINE_PEER_FRAME_CHANGED_DURING_READ')
        need(all(private.read_private(p) == raw for p, raw in retained.items()), 'RETAINED_INPUT_CHANGED_DURING_READ')
        need((Path('/proc') / str(actual['State']['Pid']) / 'cmdline').read_bytes().rstrip(b'\0').split(b'\0') ==
             [v.encode() for v in rollout.JAVA], 'RETAINED_JAVA_INIT_REQUIRED')
        report.update(status='SEMANTIC_PEER_RECIPE_MATCHED_NOT_AUTHORIZED', phase='COMPLETE',
                      precreateRequestReconstructed=True, fullIndependentOciMatched=True,
                      applicationHash=recipe['applicationHash'], creationRequestHash=recipe['creationRequestHash'],
                      peerDeclaration=expected, nativePeerObservation=snapshot, metadataFilesRead=len(retained),
                      sourceFilesStableDuringRead=True, observedOciUsedAsExpectation=False,
                      nativeReadCommands=len(io.calls), currentMacShape=h.mac_shape(actual),
                      providerEnabled=False, workerEnabled=False, mountContentsVerified=False,
                      expectationAuthorityIssued=False, reuseAfterSemanticReplacementAllowed=False)
        record('recipe-bindings.json', {k: sha(v) for k, v in retained.items()})
    except Exception as exc:
        message = str(exc)
        report['reason'] = message if isinstance(exc, (RuntimeError, ValueError)) and re.fullmatch('[A-Z][A-Z0-9_]{0,100}', message) else type(exc).__name__
    finally:
        signal.alarm(0)
        report['observedAt'] = datetime.now(timezone.utc).isoformat()
        if private and work: private.save(work / 'result.json', encoded(report))
        print(json.dumps(report, sort_keys=True))


if __name__ == '__main__': main()
