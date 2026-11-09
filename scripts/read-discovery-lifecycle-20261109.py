#!/usr/bin/env python3
"""Observe the two retained provider lifecycles, without invoking their runtime.

Native commands are closed to runc list, ctr metadata reads and nft list. Old
admission/rollback code is data only. No cleanup, authority reuse or startup.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

STARTUP = 'read-discovery-startup-20261109.py'
STARTUP_SHA = '0df0567b786f6d5317951c838062e166a4d5037a07d95a3c145b578949372a89'
HELPER = 'read-analysis-discovery-runtime-20261107.py'
HELPER_SHA = 'ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4'
WRAPPER_SHA = '55de41662098c1059a03d06ffb77bc965e5b033b9c3529dcfc7143808324efdd'
CONFIG_SHA = '7462e41e6b40a3bb1ac23760f223a34a958bcd34151ce165f6f4625d942740c5'
ROLES = ('adapter', 'southbound')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}


def need(ok, code):
    if not ok:
        raise RuntimeError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def code(exc):
    return str(exc) if type(exc) is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}', str(exc)) else type(exc).__name__


def parse(raw):
    def unique(pairs):
        result = {}
        for k, v in pairs:
            need(k not in result, 'DUPLICATE_JSON_KEY')
            result[k] = v
        return result
    return json.loads(raw, object_pairs_hook=unique)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'


def runtime_binding(cfg, cid):
    # Same per-candidate projection as semantic_provider_docker_runtime.binding;
    # the journal does NOT contain the hash of the whole configuration file.
    value = {**{k: v for k, v in cfg.items() if k != 'candidates'}, 'candidate': cfg['candidates'][cid]}
    return sha(encoded(value).removesuffix(b'\n'))


def module(name, digest):
    path = Path(__file__).with_name(name)
    raw = path.read_bytes()
    need(sha(raw) == digest, 'PINNED_READER_HASH_MISMATCH')
    m = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name, path))
    exec(compile(raw, str(path), 'exec'), m.__dict__)
    return m


def file_presence(path):
    try:
        info = Path(path).lstat()
    except FileNotFoundError:
        return {'present': False}
    return {'present': True, 'symlink': stat.S_ISLNK(info.st_mode), 'directory': stat.S_ISDIR(info.st_mode), 'inode': info.st_ino}


def generation(expected):
    need(type(expected) is dict and set(expected) == {'pid', 'startTicks', 'namespaceInode'}, 'RECORDED_GENERATION_REQUIRED')
    need(all(type(expected[k]) is int and expected[k] > 0 for k in expected) and expected['pid'] > 1, 'VALID_GENERATION_REQUIRED')
    proc = Path('/proc') / str(expected['pid'])
    try:
        before = (proc / 'stat').read_bytes()
        inode = (proc / 'ns/net').stat().st_ino
        after = (proc / 'stat').read_bytes()
    except FileNotFoundError:
        # A missing namespace on a still-present PID is not proof of absence.
        need(not proc.exists(), 'PROCESS_GENERATION_READ_INCOMPLETE')
        return {'recordedPidPresent': False, 'recordedGenerationAlive': False}
    ticks = lambda raw: int(raw[raw.rfind(b')') + 2:].split()[19])
    need(ticks(before) == ticks(after), 'PROCESS_GENERATION_CHANGED')
    same = ticks(after) == expected['startTicks']
    return {'recordedPidPresent': True, 'sameStartTicks': same,
            'sameNetworkNamespace': inode == expected['namespaceInode'],
            'recordedGenerationAlive': same, 'namespaceDrift': same and inode != expected['namespaceInode']}


def runc_rows(raw, cids):
    values = parse(raw)
    if values is None:  # runc emits null for a genuinely empty inventory.
        values = []
    need(type(values) is list and len(values) <= 1024, 'RUNC_LIST_FORMAT_UNPROVEN')
    result = {cid: {'present': False} for cid in cids}
    for row in values:
        need(type(row) is dict and type(row.get('id')) is str, 'RUNC_ROW_FORMAT_UNPROVEN')
        cid = row['id']
        if cid in result:
            need(not result[cid]['present'], 'DUPLICATE_RUNC_ID')
            need(row.get('status') in ('creating', 'created', 'running', 'stopped') and type(row.get('pid')) is int, 'RUNC_STATUS_UNPROVEN')
            result[cid] = {'present': True, 'status': row['status'], 'pid': row['pid']}
    return result


def task_rows(raw, cids):
    lines = raw.decode('utf-8').splitlines()
    need(bool(lines) and lines[0].split() == ['TASK', 'PID', 'STATUS'] and len(lines) <= 1025, 'CTR_TASK_HEADER_UNPROVEN')
    result = {cid: {'present': False} for cid in cids}
    for line in lines[1:]:
        fields = line.split()
        need(len(fields) == 3 and fields[1].isdigit(), 'CTR_TASK_ROW_UNPROVEN')
        cid, pid, state = fields
        if cid in result:
            need(not result[cid]['present'], 'DUPLICATE_CTR_TASK')
            need(state in ('RUNNING', 'CREATED', 'STOPPED', 'PAUSED', 'PAUSING', 'UNKNOWN'), 'CTR_TASK_STATE_UNPROVEN')
            result[cid] = {'present': True, 'pid': int(pid), 'status': state}
    return result


def container_ids(raw, cids):
    lines = raw.decode('utf-8').splitlines()
    need(len(lines) <= 1024 and len(set(lines)) == len(lines) and
         all(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', v) for v in lines), 'CTR_CONTAINER_LIST_UNPROVEN')
    return {cid: cid in lines for cid in cids}


def nft_families(raw, table):
    value = parse(raw)
    need(type(value.get('nftables')) is list, 'NFT_LIST_FORMAT_UNPROVEN')
    tables = [v['table'] for v in value['nftables'] if type(v) is dict and 'table' in v]
    need(all(type(v) is dict and type(v.get('name')) is str and type(v.get('family')) is str for v in tables), 'NFT_TABLE_ENTRY_UNPROVEN')
    return sorted({v['family'] for v in tables if v['name'] == table and v['family'] in ('inet', 'bridge')})


class Native:
    """No arbitrary command passthrough; all methods below are reads."""
    def __init__(self, work):
        self.work = work
        self.calls = []
        self.bindings = {}

    def binary(self, path, expected=None):
        p = Path(path)
        need(p.is_absolute() and '..' not in p.parts, 'ABSOLUTE_BINARY_REQUIRED')
        p = p.resolve(strict=True)
        need(any(p.is_relative_to(root) for root in ('/usr/bin', '/usr/sbin', '/usr/local/bin', '/usr/local/sbin', '/opt')), 'NATIVE_BINARY_ROOT_REQUIRED')
        for parent in p.parents:
            info = parent.stat()
            need(info.st_uid == 0 and not info.st_mode & 0o022, 'ROOT_OWNED_BINARY_ANCESTRY_REQUIRED')
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022 and info.st_mode & 0o111 and 0 < info.st_size <= 134217728, 'TRUSTED_NATIVE_EXECUTABLE_REQUIRED')
            with os.fdopen(os.dup(fd), 'rb') as stream:
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_uid', 'st_gid')
            identity = tuple(getattr(info, k) for k in fields)
            need(identity == tuple(getattr(os.fstat(fd), k) for k in fields) == tuple(getattr(p.stat(), k) for k in fields), 'EXECUTABLE_CHANGED_DURING_READ')
        finally:
            os.close(fd)
        need(expected is None or digest == expected, 'NATIVE_EXECUTABLE_HASH_MISMATCH')
        record = {'sha256': digest, 'identity': identity}
        need(str(p) not in self.bindings or self.bindings[str(p)] == record, 'NATIVE_EXECUTABLE_CHANGED')
        self.bindings[str(p)] = record
        return str(p)

    def read(self, kind, path, args, expected=None):
        allowed = ((kind == 'runc' and len(args) == 5 and args[0] == '--root' and args[2:] == ['list', '--format', 'json']) or
                   (kind == 'ctr' and args[:4] == ['--address', '/run/containerd/containerd.sock', '--namespace', 'moby'] and
                    (args[4:] in (['tasks', 'list'], ['containers', 'list', '--quiet'], ['version']) or
                     len(args) == 7 and args[4:6] == ['containers', 'info'] and re.fullmatch('[a-f0-9]{64}', args[6]))) or
                   (kind == 'nft' and (args == ['-j', '-n', 'list', 'tables'] or
                    len(args) == 6 and args[:4] == ['-j', '-n', 'list', 'table'] and args[4] in ('inet', 'bridge') and re.fullmatch('[A-Za-z][A-Za-z0-9_]{0,63}', args[5]))))
        need(allowed and len(self.calls) < 24, 'READ_ONLY_NATIVE_COMMAND_REQUIRED')
        executable = self.binary(path, expected)
        with tempfile.TemporaryFile(dir=self.work) as output:
            result = subprocess.run([executable, *args], stdin=subprocess.DEVNULL, stdout=output,
                                    stderr=subprocess.DEVNULL, timeout=5, env=ENV)
            output.seek(0)
            raw = output.read(2097153)
        self.calls.append({'kind': kind, 'exitCode': result.returncode})
        self.binary(path, expected)
        need(result.returncode == 0, 'NATIVE_READ_FAILED')
        need(len(raw) <= 2097152, 'NATIVE_OUTPUT_LIMIT')
        return raw


def process_bindings(cids):
    """Only dockerd and exact provider shims: no host command-line dump."""
    result = {'dockerEndpoints': [], 'shims': {cid: [] for cid in cids}}
    entries = list(Path('/proc').iterdir())
    need(len(entries) <= 16384, 'PROC_ENTRY_LIMIT')
    for proc in entries:
        if not proc.name.isdecimal():
            continue
        try:
            exe = os.readlink(proc / 'exe')
            name = Path(exe).name
            if name not in ('dockerd', 'containerd-shim-runc-v2'):
                continue
            raw = (proc / 'cmdline').read_bytes()
            need(len(raw) <= 65536, 'PROCESS_ARGUMENT_LIMIT')
            args = raw.rstrip(b'\0').split(b'\0')
            if name == 'dockerd':
                for i, arg in enumerate(args):
                    if arg.startswith(b'--containerd='):
                        result['dockerEndpoints'].append(arg.split(b'=', 1)[1].decode())
                    elif arg == b'--containerd':
                        result['dockerEndpoints'].append(args[i + 1].decode())
                continue
            if b'-id' not in args:
                continue
            cid = args[args.index(b'-id') + 1].decode()
            if cid not in cids:
                continue
            before = (proc / 'stat').read_bytes()
            cwd = os.readlink(proc / 'cwd')
            after = (proc / 'stat').read_bytes()
            ticks = lambda v: int(v[v.rfind(b')') + 2:].split()[19])
            need(ticks(before) == ticks(after) and (proc / 'cmdline').read_bytes() == raw, 'SHIM_GENERATION_CHANGED')
            expected = '/run/containerd/io.containerd.runtime.v2.task/moby/' + cid
            result['shims'][cid].append({'pid': int(proc.name), 'startTicks': ticks(after), 'argvSha256': sha(raw),
                'namespaceMatches': b'-namespace' in args and args[args.index(b'-namespace') + 1] == b'moby',
                'bundlePathMatches': str(Path(cwd).resolve()) == str(Path(expected).resolve())})
        except (FileNotFoundError, ProcessLookupError):
            continue
    return result


def journal(reader, path, schema):
    try:
        value = parse(reader.read(path, 'runtimeJournal'))
    except FileNotFoundError:
        return None
    need(value.get('schema') == schema, 'KNOWN_JOURNAL_SCHEMA_REQUIRED')
    return value


def classify(row):
    if row['runc']['present'] or any(v['recordedGenerationAlive'] for v in row['generations'].values()):
        return 'NATIVE_RUNTIME_OR_PROCESS_PRESENT'
    if row['runcDirectory']['present']:
        return 'NATIVE_RUNTIME_DIRECTORY_REMAINS'
    if row['containerdTask']['present']:
        return 'CONTAINERD_TASK_REMAINS'
    if row['shimCount']:
        return 'SHIM_REMAINS'
    if row['ownedTableFamilies'] or row['namespaceHandle']['present']:
        return 'GUARD_OR_NAMESPACE_HANDLE_REMAINS'
    return 'NO_NATIVE_RESIDUE_OBSERVED'


def collect(report, h, s, reader, native, work):
    docs = {role: h.inspect(s.PINS[role][0]) for role in ROLES}
    for role, doc in docs.items():
        need(h.digest(h.frame(doc)) == s.PINS[role][1], 'RETAINED_PROVIDER_FRAME_CHANGED')
        need(not doc['State']['Running'] and doc['State']['Pid'] == 0, 'STOPPED_PROVIDER_REQUIRED')
    info = s.engine_info()
    names = {doc['HostConfig']['Runtime'] for doc in docs.values()}
    need(len(names) == 1, 'SAME_CUSTOM_RUNTIME_REQUIRED')
    wrapper = s.exact_path(info['Runtimes'][names.pop()]['path'])
    raw = reader.read(wrapper, 'runtimeMetadata')
    need(sha(raw) == WRAPPER_SHA, 'RETAINED_RUNTIME_WRAPPER_CHANGED')
    match = re.fullmatch(rb'#!/bin/sh\nexec (/[A-Za-z0-9_./-]+) -I -B (/[A-Za-z0-9_./-]+/scripts/semantic_provider_docker_runtime.py) --configuration (/[A-Za-z0-9_./-]+) "\$@"\n', raw)
    need(match is not None, 'RUNTIME_WRAPPER_SHAPE_UNRECOGNIZED')
    cfg_raw = reader.read(s.exact_path(match[3].decode()), 'runtimeMetadata')
    need(sha(cfg_raw) == CONFIG_SHA, 'RETAINED_RUNTIME_CONFIGURATION_CHANGED')
    cfg = parse(cfg_raw)
    need(cfg['schema'] == 'ouf.semantic-docker-runtime-adapter.v4', 'CURRENT_RUNTIME_V4_REQUIRED')
    need(sha(reader.read(s.exact_path(match[2].decode()), 'runtimeSource')) == cfg['sourceHash'], 'RUNTIME_SOURCE_HASH_MISMATCH')
    registry = s.exact_path(cfg['registryRoot'])
    cids = [docs[role]['Id'] for role in ROLES]
    report['components'] = {}
    records = {}; coordination_binding = None
    for role in ROLES:
        cid = docs[role]['Id']; root = registry / cid
        adapter = journal(reader, root / 'adapter.json', 'ouf.semantic-docker-runtime-journal.v1')
        need(adapter is not None and adapter['containerId'] == cid and adapter['configurationHash'] == runtime_binding(cfg, cid), 'BOUND_RUNTIME_JOURNAL_REQUIRED')
        need(adapter['state'] in ('DELETED', 'DELETING'), 'RETAINED_TERMINAL_PHASE_REQUIRED')
        runtime_root = s.exact_path(adapter['runtimeRoot'])
        need(runtime_root.is_relative_to('/run') and runtime_root != Path('/run'), 'BOUNDED_NATIVE_RUNTIME_ROOT_REQUIRED')
        broker_raw = reader.read(root / 'broker.json', 'runtimeMetadata')
        need(sha(broker_raw) == cfg['candidates'][cid]['admissionConfigurationHash'], 'BOUND_BROKER_REQUIRED')
        broker = parse(broker_raw)
        need(broker['candidateRoot'] == str(root), 'BROKER_CANDIDATE_ROOT_MISMATCH')
        driver_raw = reader.read(root / 'driver.json', 'runtimeMetadata')
        need(sha(driver_raw) == adapter['driverHash'], 'BOUND_DRIVER_REQUIRED')
        driver = parse(driver_raw)
        need(driver['profile']['containerId'] == cid and driver['runtimeBinding'] == {'path': cfg['runtimePath'], 'sha256': cfg['runtimeSha256'], 'root': str(runtime_root)}, 'DRIVER_RUNTIME_BINDING_MISMATCH')
        entries = {key: journal(reader, root / name, schema) for key, name, schema in (
            ('broker', 'broker-state.json', 'ouf.semantic-deployment-broker-journal.v1'),
            ('admission', 'admission.json', 'ouf.semantic-admission-journal.v1'),
            ('preexec', 'preexec.json', 'ouf.semantic-preexec-journal.v1'))}
        need(all(v is not None for v in entries.values()), 'CLEANUP_JOURNALS_REQUIRED')
        need(all(v['transactionId'] == driver['profile']['transactionId'] for v in entries.values()), 'JOURNAL_TRANSACTION_MISMATCH')
        template_ref = broker['preparerTemplate']
        template_raw = reader.read(s.exact_path(template_ref['path']), 'runtimeMetadata')
        need(sha(template_raw) == template_ref['sha256'], 'BOUND_PREPARER_TEMPLATE_REQUIRED')
        template = parse(template_raw)
        need(template['commands']['nft'] == driver['commands']['nft'], 'NFT_COMMAND_BINDING_MISMATCH')
        table = driver['profile']['policy']['tableName']
        need(re.fullmatch('[A-Za-z][A-Za-z0-9_]{0,63}', table), 'OWNED_TABLE_NAME_REQUIRED')
        current_coordination = (driver['coordinationJournal'], driver['kernel']['tableName'], driver['commands']['nft'], template['commandHashes']['nft'])
        need(coordination_binding is None or coordination_binding == current_coordination, 'SHARED_COORDINATION_BINDING_MISMATCH')
        coordination_binding = current_coordination
        entries['adapter'] = adapter
        generations = {key: generation(v['containerGeneration']) for key, v in entries.items() if v.get('containerGeneration') is not None}
        handle = file_presence(root / 'netns')
        handle['matchesRecordedInode'] = handle.get('inode') == entries['admission'].get('namespaceInode') if handle['present'] else None
        row = {'journalStates': {k: v['state'] for k, v in entries.items()}, 'generations': generations,
               'namespaceHandle': handle, 'runcDirectory': file_presence(runtime_root / cid)}
        report['components'][role] = row
        records[role] = {'root': runtime_root, 'table': table, 'nft': driver['commands']['nft'], 'nftHash': template['commandHashes']['nft']}
    coordinate = journal(reader, s.exact_path(coordination_binding[0]), 'ouf.semantic-lease-coordination.v1')
    need(coordinate is not None and coordinate['state'] in ('QUIESCED', 'LEASE_READY', 'LEASE_UPDATING', 'QUIESCING', 'BLOCKED') and type(coordinate['leaseAuthorized']) is bool, 'COORDINATION_STATE_REQUIRED')
    report['coordination'] = {'state': coordinate['state'], 'leaseAuthorized': coordinate['leaseAuthorized'], 'lockAcquired': False}
    # Native absence is established only by successful reads, never stderr matching.
    processes = process_bindings(cids)
    need(processes['dockerEndpoints'] == ['/run/containerd/containerd.sock'], 'EXPLICIT_DOCKER_CONTAINERD_ENDPOINT_REQUIRED')
    report['containerdEndpointSource'] = 'CURRENT_DOCKER_ARGUMENT'
    ctr_args = ['--address', '/run/containerd/containerd.sock', '--namespace', 'moby']
    tasks = task_rows(native.read('ctr', '/usr/bin/ctr', ctr_args + ['tasks', 'list']), cids)
    containers = container_ids(native.read('ctr', '/usr/bin/ctr', ctr_args + ['containers', 'list', '--quiet']), cids)
    native_records = {}
    for role, binding in records.items():
        cid = docs[role]['Id']; row = report['components'][role]
        raw = native.read('runc', cfg['runtimePath'], ['--root', str(binding['root']), 'list', '--format', 'json'], cfg['runtimeSha256'])
        row['runc'] = runc_rows(raw, cids)[cid]
        row['containerdTask'] = dict(tasks[cid])
        if tasks[cid]['present']:
            row['containerdTask']['pidPresent'] = file_presence('/proc/' + str(tasks[cid]['pid']))['present'] if tasks[cid]['pid'] > 0 else False
        row['shimCount'] = len(processes['shims'][cid])
        row['shims'] = processes['shims'][cid]
        meta = None
        if containers[cid]:
            meta = parse(native.read('ctr', '/usr/bin/ctr', ctr_args + ['containers', 'info', cid]))
            need(meta.get('ID') == cid, 'CONTAINERD_CONTAINER_ID_MISMATCH')
        row['containerdMetadataPresent'] = containers[cid]
        families = nft_families(native.read('nft', binding['nft'], ['-j', '-n', 'list', 'tables'], binding['nftHash']), binding['table'])
        row['ownedTableFamilies'] = families
        table_raws = {f: parse(native.read('nft', binding['nft'], ['-j', '-n', 'list', 'table', f, binding['table']], binding['nftHash'])) for f in families}
        native_records[role] = {'containerdMetadata': meta, 'runc': row['runc'], 'tables': table_raws, 'shims': row['shims']}
        row['classification'] = classify(row)
    table = coordination_binding[1]
    need(re.fullmatch('[A-Za-z][A-Za-z0-9_]{0,63}', table), 'LEASE_TABLE_NAME_REQUIRED')
    lease_tables = {}
    families = nft_families(native.read('nft', coordination_binding[2], ['-j', '-n', 'list', 'tables'], coordination_binding[3]), table)
    report['coordination']['tableFamiliesPresent'] = families
    for family in families:
        value = parse(native.read('nft', coordination_binding[2], ['-j', '-n', 'list', 'table', family, table], coordination_binding[3]))
        need(type(value.get('nftables')) is list, 'LEASE_TABLE_FORMAT_UNPROVEN')
        sets = [v['set'] for v in value['nftables'] if type(v) is dict and 'set' in v]
        need(bool(sets) and all(type(v.get('elem', [])) is list for v in sets), 'LEASE_SETS_UNPROVEN')
        report['coordination'][family] = {'setCount': len(sets), 'elementCount': sum(len(v.get('elem', [])) for v in sets)}
        lease_tables[family] = value
    native_records['leaseTables'] = lease_tables
    (work / 'native-selected.private.json').write_bytes(encoded(native_records))
    # Preserve exact MAC/config views. This reader performs no STOP or DETACH.
    for role, doc in docs.items():
        need(h.frame(h.inspect(doc['Id'])) == h.frame(doc), 'PROVIDER_CHANGED_DURING_READ')
    after_info = s.engine_info()
    need(all(info.get(k) == after_info.get(k) for k in ('ID', 'ServerVersion', 'Driver', 'Runtimes')), 'RUNTIME_REGISTRATION_CHANGED')
    for path in list(reader.seals):
        reader.read(path, 'stabilityRecheck')
    # A second native inventory detects concurrent task/runtime changes. Snapshots
    # remain sequential observations, not a lock or permission to clean anything.
    need(task_rows(native.read('ctr', '/usr/bin/ctr', ctr_args + ['tasks', 'list']), cids) == tasks, 'CONTAINERD_TASKS_CHANGED')
    need(container_ids(native.read('ctr', '/usr/bin/ctr', ctr_args + ['containers', 'list', '--quiet']), cids) == containers, 'CONTAINERD_METADATA_SET_CHANGED')
    for role, binding in records.items():
        cid = docs[role]['Id']
        raw = native.read('runc', cfg['runtimePath'], ['--root', str(binding['root']), 'list', '--format', 'json'], cfg['runtimeSha256'])
        need(runc_rows(raw, cids)[cid] == report['components'][role]['runc'], 'NATIVE_RUNTIME_CHANGED')
        if containers[cid]:
            need(parse(native.read('ctr', '/usr/bin/ctr', ctr_args + ['containers', 'info', cid])) == native_records[role]['containerdMetadata'], 'CONTAINERD_METADATA_CHANGED')
    need(process_bindings(cids) == processes, 'PROVIDER_PROCESS_BINDINGS_CHANGED')
    report.update(status='DISCOVERY_LIFECYCLE_READ_COMPLETE', containerFramesAndJournalsUnchanged=True,
                  snapshotAtomic=False, cleanupQualified=False, startQualified=False)


def main():
    report = {'schema': 'ouf.discovery-lifecycle-read.v1', 'status': 'READ_INCOMPLETE',
              'observedAt': datetime.now(timezone.utc).isoformat(), 'serviceConfigurationChanged': False,
              'serviceStartDispatched': False, 'serviceStops': 0, 'nativeLifecycleWrites': 0,
              'runtimeWrapperInvoked': False, 'historicalAuthorityReused': False, 'credentialFileContentsRead': 0,
              'credentialValuesEmitted': False, 'rawLogsEmitted': False, 'journalWrites': 0,
              'databaseRequests': 0, 'providerRequests': 0, 'tokenRequests': 0, 's3Requests': 0, 'businessRequestsIssued': 0}
    reader = None; native = None; work = None
    def deadline(*_):
        raise RuntimeError('LIFECYCLE_READ_DEADLINE')
    signal.signal(signal.SIGALRM, deadline); signal.alarm(120)
    try:
        need(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode, 'ISOLATED_ROOT_READER_REQUIRED')
        os.umask(0o077)
        s = module(STARTUP, STARTUP_SHA); h = module(HELPER, HELPER_SHA)
        root = Path('/var/lib/ouf-storage-migration')
        need(root.is_dir(), 'EXISTING_EVIDENCE_ROOT_REQUIRED')
        work = Path(tempfile.mkdtemp(prefix='discovery-lifecycle-', dir=root))
        report['privateEvidenceDirectory'] = str(work)
        reader = s.Reader(); native = Native(work)
        collect(report, h, s, reader, native, work)
    except Exception as exc:
        report.update(status='READ_INCOMPLETE', reason=code(exc))
    finally:
        signal.alarm(0)
        if native is not None:
            report['nativeReadCommands'] = native.calls
        if work is not None:
            if reader is not None:
                (work / 'source-bindings.private.json').write_bytes(encoded(reader.seals))
            if native is not None:
                (work / 'native-bindings.private.json').write_bytes(encoded(native.bindings))
            (work / 'result.json').write_bytes(encoded(report))
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == 'DISCOVERY_LIFECYCLE_READ_COMPLETE' else 1


if __name__ == '__main__':
    sys.exit(main())
