"""R3 Semantic declaration, live epoch and the two-family admission transaction."""
import hashlib
from contextlib import contextmanager
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import signal
import stat
import subprocess
import tempfile
import time


def semantic_check(ok, reason='R3_SEMANTIC_PROFILE_DRIFT'):
    if not ok:
        raise ValueError(reason)


def semantic_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode('ascii')).hexdigest()


def semantic_kernel(system=None, release=None):
    if system is None:
        import platform
        system, release = platform.system(), platform.release()
    match = re.fullmatch(r'(\d+)\.(\d+)(?:[.-][A-Za-z0-9.+_~-]+)?', release)
    semantic_check(system == 'Linux' and match and tuple(map(int, match.groups())) >= (6, 6),
                   'R3_MONOTONE_KERNEL_REQUIRED')


def semantic_profile(p):
    semantic_check(set(p) == {'role', 'containerName', 'image', 'configurationSha256', 'network',
                              'networkId', 'bridge', 'ipv4', 'destination', 'port', 'protocol', 'direction'})
    semantic_check(p['role'] == 'semantic' and p['direction'] == 'semantic-to-southbound'
                   and p['protocol'] == 'tcp' and type(p['port']) is int and 0 < p['port'] <= 65535)
    semantic_check(re.fullmatch('sha256:[0-9a-f]{64}', p['image'])
                   and all(re.fullmatch('[0-9a-f]{64}', p[k]) for k in ('networkId', 'configurationSha256'))
                   and all(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', p[k])
                           for k in ('containerName', 'network'))
                   and re.fullmatch('[A-Za-z][A-Za-z0-9_.-]{0,14}', p['bridge']))
    for k in ('ipv4', 'destination'):
        ip = ipaddress.IPv4Address(p[k])
        semantic_check(str(ip) == p[k] and not (ip.is_multicast or ip.is_unspecified or ip.is_loopback))
    semantic_check(p['ipv4'] != p['destination'])
    return p


def semantic_configuration(row):
    """Digest the create-time application and network configuration, never log inspect."""
    cid = row['Id']
    semantic_check(re.fullmatch('[0-9a-f]{64}', cid))
    config = dict(row['Config'])
    config.pop('MacAddress', None)  # D-057
    if config['Hostname'] == cid[:12]:
        config['Hostname'] = {'dockerDefault': True}
    networks = {}
    for name, ep in row['NetworkSettings']['Networks'].items():
        networks[name] = {k: ep.get(k) for k in ('NetworkID', 'IPAMConfig', 'IPAddress',
                          'GlobalIPv6Address', 'Links', 'DriverOpts', 'GwPriority')}
        networks[name]['Aliases'] = sorted(ep.get('Aliases') or ())
        networks[name]['DNSNames'] = sorted(n for n in ep.get('DNSNames') or () if n not in (cid, cid[:12]))
    return semantic_digest({'Config': config, 'networks': networks,
                            'Mounts': sorted(row['Mounts'], key=lambda m: m['Destination']),
                            **{k: row[k] for k in ('HostConfig', 'Path', 'Args')}})


_verified_tools = {}


def semantic_executable(binding):
    path = Path(binding['path'])
    semantic_check(path.is_absolute() and path.resolve() == path)
    for parent in path.parents:
        info = parent.stat()
        semantic_check(info.st_uid == 0 and not info.st_mode & 0o022)
    with path.open('rb') as stream:
        info = os.fstat(stream.fileno())
        semantic_check(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
                       and info.st_mode & 0o111 and info.st_size <= 256 * 1024 * 1024)
        def identity(value):
            return (value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        key = (str(path), binding['sha256'])
        if _verified_tools.get(key) != identity(info):
            semantic_check(hashlib.file_digest(stream, 'sha256').hexdigest() == binding['sha256'])
        semantic_check(identity(info) == identity(os.fstat(stream.fileno())) == identity(path.lstat()))
        _verified_tools[key] = identity(info)


def semantic_command(binding, argv, data=None, *, deadline=None):
    if deadline is not None:
        semantic_check(time.monotonic() < deadline, 'R3_SEMANTIC_OBSERVATION_TIMEOUT')
    semantic_executable(binding)
    timeout = 5 if deadline is None else min(5, deadline - time.monotonic())
    semantic_check(timeout > 0, 'R3_SEMANTIC_OBSERVATION_TIMEOUT')
    with tempfile.TemporaryFile() as out:
        result = subprocess.run([binding['path'], *argv], input=data or b'', stdout=out,
                                stderr=subprocess.DEVNULL, timeout=timeout,
                                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
                                     'DOCKER_API_VERSION': '1.44'})
        out.seek(0)
        raw = out.read(1048577)
    semantic_executable(binding)
    semantic_check(result.returncode == 0 and len(raw) <= 1048576, 'R3_SEMANTIC_COMMAND_UNPROVEN')
    if deadline is not None:
        semantic_check(time.monotonic() < deadline, 'R3_SEMANTIC_OBSERVATION_TIMEOUT')
    return raw


def semantic_kernel_probe(ip):
    """Sample automatic allocation in a disposable child netns on the actual boot."""
    semantic_kernel()
    semantic_executable(ip)
    child = os.fork()
    if child == 0:
        try:
            host = os.stat('/proc/self/ns/net')
            os.unshare(os.CLONE_NEWNET)
            semantic_check(not os.path.samestat(host, os.stat('/proc/self/ns/net')))
            last = 0
            for _ in range(3):
                semantic_command(ip, ['link', 'add', 'r3-sample', 'type', 'veth', 'peer', 'name', 'r3-peer'])
                indexes = [socket.if_nametoindex(n) for n in ('r3-sample', 'r3-peer')]
                semantic_check(min(indexes) > last)
                last = max(indexes)
                semantic_command(ip, ['link', 'del', 'r3-sample'])
        except BaseException:
            os._exit(1)
        os._exit(0)
    _, status = os.waitpid(child, 0)
    semantic_check(os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, 'R3_MONOTONE_KERNEL_REQUIRED')


def semantic_process(pid):
    semantic_check(type(pid) is int and pid > 1)
    proc = Path('/proc', str(pid))
    def ticks():
        return int((proc / 'stat').read_bytes().rsplit(b') ', 1)[1].split()[19])
    before = ticks()
    ns = (proc / 'ns/net').stat()
    semantic_check(before == ticks() and ns.st_ino != Path('/proc/self/ns/net').stat().st_ino)
    return dict(pid=pid, startTicks=before, namespaceDevice=ns.st_dev, namespaceInode=ns.st_ino)


def semantic_observe(p, commands, run=semantic_command, process=semantic_process, boot=None,
                     check_executable=semantic_executable):
    semantic_kernel()
    semantic_profile(p)
    base = ['--host', 'unix://' + commands['socket']]
    def docker(*args):
        row, = json.loads(run(commands['docker'], base + list(args)))
        return row
    row = docker('container', 'inspect', p['containerName'])
    state, cid = row['State'], row['Id']
    semantic_check(row['Name'] == '/' + p['containerName'] and state['Running'] is True
                   and state['Status'] == 'running' and row['Image'] == p['image']
                   and semantic_configuration(row) == p['configurationSha256'])
    net = docker('network', 'inspect', p['networkId'])
    ep = row['NetworkSettings']['Networks'][p['network']]
    semantic_check(net['Name'] == p['network'] and net['Id'] == ep['NetworkID'] == p['networkId']
                   and net['Driver'] == 'bridge' and ep['IPAddress'] == p['ipv4']
                   and (net.get('Options') or {}).get('com.docker.network.bridge.name',
                                                       'br-' + net['Id'][:12]) == p['bridge'])
    owners = [(key, v) for key, v in net['Containers'].items() if
              v['Name'] == p['containerName'] or v['IPv4Address'].split('/')[0] == p['ipv4']]
    semantic_check(len(owners) == 1 and owners[0][0] == cid and owners[0][1]['Name'] == p['containerName']
                   and owners[0][1]['IPv4Address'].split('/')[0] == p['ipv4']
                   and owners[0][1]['EndpointID'] == ep['EndpointID']
                   and re.fullmatch('[0-9a-f]{64}', ep['EndpointID']), 'R3_SEMANTIC_GENERATION_AMBIGUOUS')
    gen = process(state['Pid'])
    binding = semantic_link(p, commands, gen, run, process, check_executable)
    return {'containerId': cid, 'generation': gen, 'bootId': boot or
            Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'endpointId': ep['EndpointID'],
            'startedAt': state['StartedAt'], 'binding': binding, 'profileSha256': semantic_digest(p)}, row


def semantic_link(p, commands, gen, run, process=semantic_process, check_executable=semantic_executable):
    semantic_check(process(gen['pid']) == gen, 'R3_SEMANTIC_EPOCH_CHANGED')
    ip = commands['ip']
    check_executable(ip)
    children = json.loads(run(commands['nsenter'], ['--net=/proc/%d/ns/net' % gen['pid'],
                              ip['path'], '-j', '-d', 'addr', 'show']))
    check_executable(ip)
    child, = [c for c in children if any(a['family'] == 'inet' and a['local'] == p['ipv4']
                                          for a in c['addr_info'])]
    semantic_check([a['local'] for a in child['addr_info'] if a['family'] == 'inet'] == [p['ipv4']])
    index = child['link_index']
    semantic_check(type(index) is int and 1 < index < 2147483647)
    name = socket.if_indextoname(index)
    host, = json.loads(run(ip, ['-j', '-d', 'link', 'show', 'dev', name]))
    semantic_check(host['linkinfo']['info_kind'] == child['linkinfo']['info_kind'] == 'veth'
                   and host['ifname'] == name and host['ifindex'] == index and host['link_index'] == child['ifindex']
                   and host['master'] == p['bridge'] and process(gen['pid']) == gen)
    return {'bridge': p['bridge'], 'ipv4': p['ipv4'], 'hostIfindex': index,
            'childIfindex': child['ifindex'], 'hostInterface': host['ifname']}


class SemanticGate:
    """Called under the common lock. Empty named sets are the preexec template."""
    def __init__(self, table, profile, nft, observe):
        semantic_check(re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,31}', table))
        self.table, self.profile, self.nft, self.observe = table, semantic_profile(profile), nft, observe
        self.epoch = None
        self.last_verified = None
        self.refresh_at = 0

    def write(self, port=None, enabled=False):
        lines = []
        address = self.profile['ipv4'] if enabled else None
        members = [('bridge', 'semantic_open', address), ('inet', 'semantic_open', address)]
        if not enabled:
            members.append(('bridge', 'semantic_port', port))
        for family, name, member in members:
            target = f'{family} {self.table} {name}'
            lines.append('flush set ' + target)
            if member is not None:
                if name == 'semantic_port':
                    semantic_check(type(member) is int and 1 < member < 2147483647)
                lines.append(f'add element {target} {{ {member} }}')
        self.nft(['-f', '-'], ('\n'.join(lines) + '\n').encode())

    def read(self, footprint):
        # Compare the *entire* isolated preexec template after extracting only
        # these three named sets. All other elements, rules and hooks remain exact.
        tables, values = {}, {}
        for family in ('bridge', 'inet'):
            table = json.loads(self.nft(['-j', '-n', 'list', 'table', family, self.table]))
            rows = []
            for entry in table['nftables']:
                if 'metainfo' in entry:
                    continue
                obj = entry.get('set', {})
                name = obj.get('name')
                if name in ('semantic_port', 'semantic_open'):
                    key = family, name
                    semantic_check(key not in values and obj['family'] == family and obj['table'] == self.table)
                    values[key] = obj.pop('elem', [])
                    if name == 'semantic_open':
                        semantic_check(not obj.get('flags') and 'timeout' not in obj
                                       and values[key] in ([], [self.profile['ipv4']]),
                                       'R3_SEMANTIC_TABLE_DRIFT')
                rows.append(entry)
            tables[family] = {'nftables': rows}
        def clean(value):
            if isinstance(value, list):
                return [clean(v) for v in value]
            if isinstance(value, dict):
                return {k: clean(v) for k, v in value.items() if k not in ('handle', 'packets', 'bytes')}
            return value
        semantic_check(semantic_digest(clean(tables)) == footprint, 'R3_SEMANTIC_TABLE_DRIFT')
        port = values.pop(('bridge', 'semantic_port'))
        if len(port) == 1 and isinstance(port[0], str):
            port = [socket.if_nametoindex(port[0])]
        return port, values.pop(('bridge', 'semantic_open')), values.pop(('inet', 'semantic_open'))

    def close(self):
        self.epoch = None
        self.write()

    def reconcile(self, footprint, *, link, refresh, clock):
        # The lock owner provides a separate deadline for recovery on any error.
        addr = [self.profile['ipv4']]
        closed = False
        if self.epoch is not None and clock() < self.refresh_at:
            old = self.epoch
            port = old['binding']['hostIfindex']
            try:
                unchanged = link(old) == old['binding']
            except (ValueError, OSError):
                unchanged = False
            if unchanged and self.read(footprint) == ([port], addr, addr):
                semantic_check(link(old) == old['binding'], 'R3_SEMANTIC_EPOCH_CHANGED')
                return old
            self.close()
            semantic_check(self.read(footprint) == ([], [], []))
            closed = True
        first = self.observe()
        port = first['binding']['hostIfindex']
        if self.last_verified and self.last_verified != first and self.last_verified['bootId'] == first['bootId']:
            semantic_check(port > self.last_verified['binding']['hostIfindex'], 'R3_NONMONOTONE_PORT')
        restage = self.epoch != first or self.read(footprint) != ([port], addr, addr)
        if restage and not closed:
            self.close()
            semantic_check(self.read(footprint) == ([], [], []))
        semantic_check(self.observe() == first, 'R3_SEMANTIC_EPOCH_CHANGED')
        if restage:
            self.write(port)
            semantic_check(self.read(footprint) == ([port], [], []) and self.observe() == first)
            self.write(port, True)
        semantic_check(self.read(footprint) == ([port], addr, addr) and self.observe() == first)
        self.epoch = self.last_verified = first
        self.refresh_at = clock() + refresh
        return first


class SemanticDeadline(BaseException):
    """Cross nested guards that translate ordinary exceptions into scope failures."""


@contextmanager
def semantic_phase(end, clock):
    # The Linux supervisor runs on the main thread and owns ITIMER_REAL.
    # This also bounds signed journal/authority reads which have no timeout API.
    def expired(*_):
        raise SemanticDeadline()
    remaining = end - clock()
    if remaining <= 0:
        expired()
    previous = signal.signal(signal.SIGALRM, expired)
    try:
        remaining = end - clock()
        if remaining <= 0:
            expired()
        signal.setitimer(signal.ITIMER_REAL, remaining)
        yield
        if clock() >= end:
            expired()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def bind_semantic_gate(cfg, coordinator, guards, read_file, *, phase=semantic_phase, link_observer=semantic_link):
    ingress = cfg['semanticIngress']
    renewal = cfg['leaseRenewal']
    budget = renewal['semanticTickBudgetSeconds']
    reserve = renewal['semanticCloseReserveSeconds']
    cadence = renewal['semanticFullObservationSeconds']
    clock = time.monotonic
    deadline = None
    def inspect(binding, argv):
        return semantic_command(binding, argv, deadline=deadline)
    def nft(argv, data=None):
        return semantic_command(cfg['coordinator']['nftBinding'], argv, data, deadline=deadline)
    gate = SemanticGate(ingress['table'], ingress['profile'], nft,
                        lambda: semantic_observe(ingress['profile'], ingress['commands'], inspect)[0])
    def link(epoch):
        return link_observer(gate.profile, ingress['commands'], epoch['generation'], inspect)
    verified_at = None
    coordinator.semantic_epoch = lambda: semantic_digest(gate.epoch) if gate.epoch is not None else None
    coordinator.semantic_verified_age_ms = lambda: None if verified_at is None else int((clock() - verified_at) * 1000)
    coordinator.semantic_result = None

    def close_locked(*, quiescing=False):
        gate.epoch = None
        if quiescing:
            tables = json.loads(nft(['-j', 'list', 'tables']))['nftables']
            present = {r['table']['family'] for r in tables if 'table' in r
                       and r['table']['name'] == ingress['table']} & {'bridge', 'inet'}
            if not present:
                return  # Both role tables may be absent during service startup.
            semantic_check(present == {'bridge', 'inet'}, 'PARTIAL_TABLE_PAIR')
        gate.close()
        for family, name in (('bridge', 'semantic_port'), ('bridge', 'semantic_open'), ('inet', 'semantic_open')):
            rows = json.loads(nft(['-j', 'list', 'set', family, gate.table, name]))['nftables']
            obj, = [v['set'] for v in rows if 'set' in v]
            semantic_check(obj['family'] == family and obj['table'] == gate.table
                           and obj['name'] == name and not obj.get('elem'))

    # The owner has already revoked its finite lease when it publishes QUIESCED.
    # Close the role tables under that same lock before acknowledging quiescence.
    publish = coordinator.publish
    def publish_with_ingress(previous, following):
        if following['state'] == 'QUIESCED':
            close_locked(quiescing=True)
        return publish(previous, following)
    coordinator.publish = publish_with_ingress

    def check_time():
        if clock() >= deadline:
            raise SemanticDeadline()

    def driver_footprint():
        check_time()
        snap = guards.scope_guard()['southbound']
        cid = ingress['containerId']
        semantic_check(snap['containerId'] == cid)
        check_time()
        row = guards.current(cfg['registryRoot'], cid)
        semantic_check(row['epoch'] == snap['epoch'] and row['generation'] == snap['generation']
                       and row['state'] == 'STARTED' and re.fullmatch('[0-9a-f]{64}', row['driverHash']))
        path = Path(cfg['registryRoot']) / cid / 'epochs' / str(row['epoch']) / 'driver.json'
        check_time()
        profile = json.loads(read_file(path, row['driverHash']))['profile']
        matches = [f['peerIngress']['declaration'] for f in profile['policy']['flows']
                   if f['peerIngress']['kind'] == 'SEMANTIC_PROFILE']
        semantic_check(profile['policy']['tableName'] == gate.table and matches == [gate.profile])
        return profile['expectedFootprint']

    def tick_ingress(wake, lease_end, expected):
        nonlocal deadline, verified_at
        started = clock()
        ordinary_end = started + budget
        outcome = 'DEFERRED'
        acquired = False
        try:
            if lease_end is None or min(wake, lease_end) < started + coordinator.semantic_horizon:
                return
            with coordinator.hold_until(ordinary_end):
                acquired = True
                footprint = None
                try:
                    deadline = ordinary_end
                    with phase(deadline, clock):
                        lease = coordinator.journal()
                        semantic_check(lease == expected and lease['state'] == 'LEASE_READY'
                                       and lease['leaseAuthorized'] is True)
                        footprint = driver_footprint()
                        check_time()
                        gate.reconcile(footprint, link=link, refresh=cadence, clock=clock)
                    verified_at = clock()
                    outcome = 'VERIFIED'
                    return
                except (SemanticDeadline, Exception) as error:
                    gate.epoch = None
                    timeout = isinstance(error, SemanticDeadline) or clock() >= ordinary_end
                    fatal = footprint is None and not timeout
                    if str(error) == 'R3_SEMANTIC_TABLE_DRIFT':
                        fatal = True
                    deadline = min(clock(), ordinary_end) + reserve
                    try:
                        with phase(deadline, clock):
                            if footprint is None:
                                close_locked()
                            else:
                                gate.close()
                                semantic_check(gate.read(footprint) == ([], [], []))
                    except (SemanticDeadline, Exception):
                        outcome = 'R3_SEMANTIC_CLOSE_UNVERIFIED'
                    else:
                        outcome = 'CLOSED'
                        if fatal:
                            raise
            if outcome == 'R3_SEMANTIC_CLOSE_UNVERIFIED':
                guards.deny(outcome, outcome)
        except Exception as error:
            if not acquired and getattr(error, 'code', None) == 'COMMON_LOCK_TIMEOUT':
                return
            raise
        finally:
            deadline = None
            coordinator.semantic_result = {'outcome': outcome, 'durationMs': int((clock() - started) * 1000)}

    coordinator.semantic_tick = tick_ingress
