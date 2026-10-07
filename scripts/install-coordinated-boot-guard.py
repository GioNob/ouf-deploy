#!/usr/bin/env python3
"""One-time sealed EMPTY_ONLY-to-coordinated boot command installation.

No daemon, container, nft, DNS, credential, sudoers or provider operations.
Only the two known systemd commands and the bounded read-only helper change.
"""
import argparse
import hashlib
import importlib.util
from importlib.machinery import SourceFileLoader
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import uuid

SNAPSHOTS = Path('/etc/ouf/deploy-snapshots')
STAGE = SNAPSHOTS/'semantic-runtime-transition-stage-20261003-160211/prepared'
STAGE_HASH = 'ab4476f03d11f6325227b43b786be4a2e4d222b0ec8be29d4f119f354332402f'
PACKAGE = SNAPSHOTS/'semantic-coordinated-owner-package-p0mxeups'
PACKAGE_CONFIG_HASH = '994e8b58222f5ddfdb33edb376b7da1f6349153228c55c26b9329fda78fd2a35'
PACKAGE_JOURNAL_HASH = '520a58e1292404da4b403e6b01399ad542d3b93fbd49545365a1612be9eec342'
SOURCE_COMMIT = 'df103735c1fe75a31e6d4c752360e9368e6aa52d'
HELPER = Path('/usr/local/sbin/ouf-discovery-preflight')
BACKUP = Path('/usr/local/sbin/ouf-discovery-preflight-v2')
POINTER = Path('/etc/ouf/coordinated-boot-installation.json')
HELPER_V2_HASH = 'a46d0900ca20ed13115572c9ab9b436105c820e81f066d6e67c2a5333292e893'
HELPER_V3_HASH = '65c8caa661005a7bf4bfe7eb1c5f45932a32c3e024095db861882f6c52998618'
EXPECTED = {'configurationHash': '24968cf990a32b87f3169b9226fe63d224c93a403540afec197011fbd670b0bb',
            'journalHash': '4ccb05b0a28b6e7e823de3d9af81f29255d60b38271d0a74a00f64e2e5828a74',
            'leaseStructureHash': '26f6f80af9d1e4898c1a6fe6dc8721cd6f67f1ceed05c7eea35e3b9f4a040e54'}
UNIT_PATHS = {'guard.service': Path('/etc/systemd/system/ouf-semantic-boot-guard.service'),
              'docker-drop-in.conf': Path('/etc/systemd/system/docker.service.d/90-ouf-semantic-boot-guard.conf')}
UNIT_HASHES = {'guard.service': '0f0791f9e12f4326d811bb2e2c61f6c9c142138056b21632034d72457a026541',
               'docker-drop-in.conf': '413d5143ffe75da96ba2101c8c545f5dfb8393053058ef89cebc6221f0d2750d'}
OWNER_HASHES = {
    'scripts/run_semantic_coordinated_lease_owner.py': 'c2937a39578311018d47c0d414e6687278ce8b6b103de62c422cfe7b760b6889',
    'tools/materialize_southbound_kernel.py': '98e3004300226fecd509a46c009585df14021927f20d4e5c82d8ff7a8a8180de',
    'tools/materialize_southbound_lease_refresh.py': '1c0d7f1243752fe216ef62eefbc2e3253b8f2503b518fafe11277e4d7721a084',
    'tools/semantic_provider_coordinated_supervisor.py': '25a952c9f6d1385ce7759ef61666d25c7ec24a5735d3d0d27c36ade8e1614dad',
    'tools/semantic_provider_dns.py': 'c466172113d1ffe850bf2c69762113b55fbc65d9091c96dca98a74548fddf930',
    'tools/semantic_provider_lease_coordination.py': 'e267e0f86637191b9830895930daa35afc10fec733b6957f427ab8a0ccddf587',
    'tools/semantic_provider_lease_nft.py': '7a5f2b21c096228a3e4d298674e380f667c3004dd6d8ec19934a2302844c0f93',
    'tools/semantic_provider_lease_owner.py': '92736eebeccf344e565186bce94d29c65ffe1d50638d57eae81486e7b26e884d'}
BOOT_HASHES = {'scripts/run_semantic_coordinated_boot_guard.py': 'ff8d1e483496f9201f9663f58cc3f942c4b6c2ef9041743d52419050fe8134c6',
               'tools/semantic_provider_boot_coordination.py': '518ad91e209d379bc06ce7e209052230d327ce2fa86014d214f32a62b2985431'}
INSTALL_STAGE = 'INPUT_VALIDATION'
INSTALL_SNAPSHOT = None


def encoded(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
def digest(raw): return hashlib.sha256(raw).hexdigest()


def parents(path):
    if not path.is_absolute() or '..' in path.parts: raise ValueError('unsafe path')
    for p in (path.parent, *path.parent.parents):
        info = p.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('unsafe ancestor')


def read(path, mode=0o600, protected=True):
    if protected: parents(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 2_000_000:
            raise ValueError('unsafe file')
        if protected and (info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != mode):
            raise ValueError('unsafe ownership')
        raw = os.read(fd, 2_000_001)
        if len(raw) != info.st_size: raise ValueError('read drift')
        return raw
    finally: os.close(fd)


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value: raise ValueError('duplicate key')
        value[key] = item
    return value


def parsed(raw): return json.loads(raw, object_pairs_hook=unique)


def sealed(path, expected, mode=0o600, protected=True):
    raw = read(path, mode, protected)
    if digest(raw) != expected: raise ValueError('sealed file drift')
    return raw


def module(path, raw):
    name = 'sealed_'+path.stem
    spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
    value = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


def synced_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def write_new(path, raw, mode=0o600):
    parents(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(os.dup(fd), 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    finally: os.close(fd)
    synced_directory(path.parent)


def replace(path, previous, raw, mode=0o600):
    if read(path, mode) != previous: raise ValueError('foreign file preserved')
    temp = path.parent/('.ouf-coordinated-'+uuid.uuid4().hex)
    try:
        write_new(temp, raw, mode)
        if read(path, mode) != previous: raise ValueError('file changed before publication')
        os.replace(temp, path); synced_directory(path.parent)
    finally:
        if temp.exists(): temp.unlink()


def rewrite_command(raw, directive, command):
    lines = raw.decode().splitlines(keepends=True)
    indices = [i for i, line in enumerate(lines) if line.startswith(directive+'=')]
    if len(indices) != 1 or any(line.startswith(directive+'=') and line.strip() == directive+'=' for line in lines):
        raise ValueError('ambiguous service command')
    lines[indices[0]] = directive+'='+command+'\n'
    return ''.join(lines).encode()


def transaction(entries, reload_units, verify_new, verify_old, journal):
    """Publish only owned bytes; rollback only bytes still owned by this attempt."""
    changed = []
    journal('INSTALLING')
    try:
        for entry in entries:
            # Record the attempt before rename: fsync can fail AFTER publication.
            changed.append(entry)
            replace(entry['path'], entry['old'], entry['new'], entry.get('mode', 0o600))
        reload_units()
        verify_new()
        journal('INSTALLED')
    except Exception:
        journal('ROLLBACK_REQUIRED')
        blocked = False
        for entry in reversed(changed):
            try:
                mode = entry.get('mode', 0o600)
                current = read(entry['path'], mode)
                if current == entry['new']: replace(entry['path'], entry['new'], entry['old'], mode)
                elif current != entry['old']: blocked = True
            except Exception: blocked = True
        try: reload_units(); verify_old()
        except Exception: blocked = True
        if blocked:
            journal('ROLLBACK_BLOCKED')
            raise RuntimeError('partial transition retained; no replay') from None
        journal('ROLLED_BACK')
        raise RuntimeError('transition rolled back; no replay') from None


def original(legacy):
    raw, receipt = legacy.private_receipt_data(STAGE/'runtime-stage-receipt.json')
    if digest(raw) != STAGE_HASH: raise ValueError('original selected receipt drift')
    args = SimpleNamespace(stage_root=STAGE, stage_source_commit=receipt['sourceCommit'],
                           installer_sha256=receipt['sourceHashes']['transition_semantic_runtime_guard.py'])
    installer = legacy.runtime_installer(args)
    return args, installer, installer.stage(args)


def observe_once(receipt, legacy):
    if receipt.get('schema') != 'ouf.semantic-coordinated-boot-installation.v1' \
            or receipt.get('state') != 'INSTALLED' or receipt.get('startAuthorized') is not False \
            or receipt.get('sourceCommit') != SOURCE_COMMIT or receipt.get('sourceHashes') != {**OWNER_HASHES, **BOOT_HASHES} \
            or receipt.get('oldRuntimeHashes') != EXPECTED:
        raise ValueError('installed receipt binding')
    root = Path(receipt['directory'])
    if root.parent != SNAPSHOTS or not root.name.startswith('semantic-coordinated-boot-install-'):
        raise ValueError('selected root required')
    sealed(root/'transition-source.py', receipt['observerHash'])
    sealed(HELPER, HELPER_V3_HASH, 0o755)
    sealed(BACKUP, HELPER_V2_HASH, 0o755)
    args, installer, cohort = original(legacy)
    g, old_receipt, artifacts, conf, intent, roots, old_install, gu, unit, drop, _ = cohort
    if {'guard.service': unit, 'docker-drop-in.conf': drop} != UNIT_PATHS:
        raise ValueError('unit path drift')
    journal_raw = g.private(Path(conf['journalFile']))
    if digest(journal_raw) != EXPECTED['journalHash'] or old_receipt['configurationHash'] != EXPECTED['configurationHash']:
        raise ValueError('original journal/configuration changed')
    installer.independent(g, old_receipt, intent, roots, old_install, conf)
    tables = g.tables(conf)
    if not g.sets_empty(tables) or g.footprint(tables) != conf['expectedFootprint'] \
            or digest(g.encoded(g.stable(tables, True))) != EXPECTED['leaseStructureHash']:
        raise ValueError('owned native structure changed')
    for name, expected in receipt['sourceHashes'].items(): sealed(root/'source'/name, expected)
    for package in ('scripts', 'tools'):
        if os.path.lexists(root/'source'/package/'__init__.py'): raise ValueError('unsealed initializer')
    owner = parsed(sealed(root/'coordinated-configuration.json', receipt['configurationHash']))
    boot = parsed(sealed(root/'boot-profile.json', receipt['bootProfileHash']))
    if owner['sourceHashes'] != OWNER_HASHES or owner['kernel'] != conf['kernel'] \
            or owner['commonLockFile'] != conf['lockFile'] or owner['expectedStructureHash'] != EXPECTED['leaseStructureHash'] \
            or owner['journalFile'] != str(root/'coordination-journal.json') \
            or boot['sourceHashes'] != BOOT_HASHES \
            or boot['coordinatedConfiguration'] != str(root/'coordinated-configuration.json') \
            or boot['coordinatedConfigurationHash'] != receipt['configurationHash'] \
            or boot['bootConfiguration'] != str(STAGE/'runtime-configuration.json') \
            or boot['bootConfigurationHash'] != EXPECTED['configurationHash'] \
            or boot['bootGuardFile'] != str(STAGE.parent/'source/scripts/restore_semantic_runtime_boot_guard.py') \
            or boot['bootGuardHash'] != old_receipt['sourceHashes']['restore_semantic_runtime_boot_guard.py']:
        raise ValueError('coordinated profile drift')
    coord = parsed(read(root/'coordination-journal.json'))
    if set(coord) != {'schema', *owner['binding'], 'state', 'leaseAuthorized', 'startAuthorized', 'leaseAddresses'} \
            or coord['schema'] != 'ouf.semantic-lease-coordination.v1' \
            or any(coord.get(k) != v for k, v in owner['binding'].items()) \
            or coord['state'] != 'QUIESCED' or coord['leaseAuthorized'] is not False \
            or coord['startAuthorized'] is not False \
            or coord['leaseAddresses'] != [[] for _ in conf['kernel']['providerFlows']]:
        raise ValueError('quiescent coordination receipt required')
    changed_artifacts = dict(artifacts)
    for name, path in UNIT_PATHS.items():
        content = sealed(root/'prepared'/name, receipt['artifactHashes'][name])
        if read(path) != content: raise ValueError('installed command drift')
        if digest(read(root/'previous'/name)) != UNIT_HASHES[name]: raise ValueError('previous artifact drift')
        changed_artifacts[name] = content
    installer.loaded(g, old_receipt, changed_artifacts, old_install, gu, unit, drop)
    result = {'schema': 'ouf.semantic-runtime-readiness.v2', 'runtimeState': 'RUNTIME_COORDINATED_EMPTY',
        'guardProfile': 'COORDINATED_EMPTY_RESTORE', 'runtimeCustodyVerified': True,
        'configurationHash': EXPECTED['configurationHash'], 'journalHash': EXPECTED['journalHash'],
        'leaseStructureHash': EXPECTED['leaseStructureHash'], 'coordinatedConfigurationHash': receipt['configurationHash'],
        'coordinatedJournalHash': digest(encoded(coord)), 'providerSetsEmpty': True, 'candidateCount': 2,
        'candidatesNeverStarted': True, 'startupReady': False, 'startAuthorized': False, 'leaseAuthorized': False,
        'activeLeaseLifecycleReady': False, 'realRebootProven': False, 'atomicSnapshotProven': False,
        'readOnly': True, 'providerCalls': 0, 'dnsCalls': 0, 'notReleaseAcceptance': True, 'noSecretsPrinted': True,
        'unprovenGates': ['INFRASTRUCTURE_AUTHORITY', 'SHARED_FACE_SOURCE_ENFORCEMENT', 'LIVE_NAMESPACE_ADDRESS_BINDING',
            'PACKET_SPOOF_BYPASS_IPV6', 'OIDC_PURPOSE_TLS_REVOCATION_ADMISSION', 'ACTIVE_LEASE_GUARD_COORDINATION', 'REAL_REBOOT']}
    return result


def observe(receipt, legacy):
    _, _, cohort = original(legacy)
    g, conf = cohort[0], cohort[3]
    fd = g.lock(Path(conf['lockFile']))
    try:
        first = observe_once(receipt, legacy); second = observe_once(receipt, legacy)
        if first != second: raise ValueError('unstable installed observation')
        first['stableAcrossReads'] = True
        return first
    finally: os.close(fd)


def install(source_directory, installer_raw):
    global INSTALL_STAGE, INSTALL_SNAPSHOT
    INSTALL_STAGE = 'INPUT_VALIDATION'; INSTALL_SNAPSHOT = None
    if os.geteuid() != 0: raise ValueError('root required')
    os.umask(0o077)
    if os.path.lexists(POINTER): raise ValueError('existing installation; no replay')
    helper_old = sealed(HELPER, HELPER_V2_HASH, 0o755)
    INSTALL_STAGE = 'LEGACY_READER_LOAD'
    legacy = module(HELPER, helper_old)
    INSTALL_STAGE = 'ORIGINAL_NATIVE_READBACK'
    readiness = legacy.selected_runtime_readiness()
    if any(readiness.get(k) != v for k, v in EXPECTED.items()) \
            or readiness.get('runtimeCustodyVerified') is not True:
        raise ValueError('original native cohort changed')
    INSTALL_STAGE = 'OWNER_PACKAGE_VALIDATION'
    old_config = parsed(sealed(PACKAGE/'coordinated-configuration.json', PACKAGE_CONFIG_HASH))
    old_journal = parsed(sealed(PACKAGE/'coordination-journal.json', PACKAGE_JOURNAL_HASH))
    if old_journal['state'] != 'QUIESCED' or old_journal['leaseAuthorized'] is not False \
            or old_journal['startAuthorized'] is not False or old_config['sourceHashes'] != OWNER_HASHES:
        raise ValueError('staged owner changed')
    sources = {name: sealed(PACKAGE/'source'/name, expected) for name, expected in OWNER_HASHES.items()}
    sources.update({name: sealed(source_directory/name, expected, protected=False) for name, expected in BOOT_HASHES.items()})
    helper_new = sealed(source_directory/'privileged-discovery-preflight-v3.py', HELPER_V3_HASH, protected=False)
    if not isinstance(installer_raw, bytes) or not installer_raw: raise ValueError('verified execution bytes required')
    INSTALL_STAGE = 'ORIGINAL_UNIT_BINDING'
    args, installer, cohort = original(legacy)
    g, r, a, c, intent, roots, old_install, gu, unit, drop, _ = cohort
    if {'guard.service': unit, 'docker-drop-in.conf': drop} != UNIT_PATHS: raise ValueError('unit binding drift')
    for name, path in UNIT_PATHS.items():
        if sealed(path, UNIT_HASHES[name]) != a[name]: raise ValueError('installed file drift')
    parents(POINTER); parents(SNAPSHOTS/'unused')
    if os.path.lexists(BACKUP): sealed(BACKUP, HELPER_V2_HASH, 0o755)
    else: write_new(BACKUP, helper_old, 0o755)
    INSTALL_STAGE = 'PRIVATE_PACKAGE_PREPARATION'
    root = Path(tempfile.mkdtemp(prefix='semantic-coordinated-boot-install-', dir=SNAPSHOTS)); root.chmod(0o700)
    INSTALL_SNAPSHOT = root
    for directory in ('source', 'source/scripts', 'source/tools', 'prepared', 'previous'):
        (root/directory).mkdir(mode=0o700)
    for name, raw in sources.items(): write_new(root/'source'/name, raw)
    write_new(root/'transition-source.py', installer_raw)
    owner = dict(old_config); owner['journalFile'] = str(root/'coordination-journal.json')
    owner.pop('binding')
    owner['binding'] = {'transactionId': digest(os.urandom(32)), 'configurationHash': digest(encoded(owner)),
                        'leaseStructureHash': EXPECTED['leaseStructureHash']}
    write_new(root/'coordinated-configuration.json', encoded(owner)); owner_hash = digest(encoded(owner))
    coord_journal = {'schema': 'ouf.semantic-lease-coordination.v1', **owner['binding'], 'state': 'QUIESCED',
                    'leaseAuthorized': False, 'startAuthorized': False,
                    'leaseAddresses': [[] for _ in owner['kernel']['providerFlows']]}
    write_new(root/'coordination-journal.json', encoded(coord_journal))
    profile = {'schema': 'ouf.semantic-coordinated-boot-profile.v1', 'sourceHashes': BOOT_HASHES,
        'coordinatedConfiguration': str(root/'coordinated-configuration.json'), 'coordinatedConfigurationHash': owner_hash,
        'bootConfiguration': str(STAGE/'runtime-configuration.json'), 'bootConfigurationHash': EXPECTED['configurationHash'],
        'bootGuardFile': str(STAGE.parent/'source/scripts/restore_semantic_runtime_boot_guard.py'),
        'bootGuardHash': r['sourceHashes']['restore_semantic_runtime_boot_guard.py']}
    write_new(root/'boot-profile.json', encoded(profile)); profile_hash = digest(encoded(profile))
    command = '/usr/bin/python3 -I -B '+str(root/'source/scripts/run_semantic_coordinated_boot_guard.py') \
        +' --configuration '+str(root/'boot-profile.json')+' --configuration-sha256 '+profile_hash
    new = {'guard.service': rewrite_command(a['guard.service'], 'ExecStart', command),
           'docker-drop-in.conf': rewrite_command(a['docker-drop-in.conf'], 'ExecStartPre', command)}
    for name in new:
        write_new(root/'previous'/name, a[name]); write_new(root/'prepared'/name, new[name])
    # Check the owner through the actual isolated read-only CLI before publishing
    # units. The boot command itself revokes; it is not run during installation.
    INSTALL_STAGE = 'PRIVATE_OWNER_GUARD'
    checked = subprocess.run(['/usr/bin/python3', '-I', '-B', str(root/'source/scripts/run_semantic_coordinated_lease_owner.py'),
        '--mode', 'guard', '--configuration', str(root/'coordinated-configuration.json'), '--configuration-sha256', owner_hash],
        capture_output=True, timeout=30)
    if checked.returncode: raise ValueError('staged owner verification failed')
    receipt = {'schema': 'ouf.semantic-coordinated-boot-installation.v1', 'state': 'INSTALLED', 'directory': str(root),
        'sourceCommit': SOURCE_COMMIT, 'sourceHashes': {**OWNER_HASHES, **BOOT_HASHES}, 'oldRuntimeHashes': EXPECTED,
        'configurationHash': owner_hash, 'bootProfileHash': profile_hash,
        'artifactHashes': {name: digest(raw) for name, raw in new.items()},
        'readHelperHash': HELPER_V3_HASH, 'observerHash': digest(installer_raw), 'startAuthorized': False,
        'leaseAuthorized': False, 'daemonStarted': False, 'rulesChanged': False, 'containerLifecycleOperations': 0,
        'providerCalls': 0, 'realRebootProven': False, 'notReleaseAcceptance': True}
    write_new(root/'installation-receipt.json', encoded(receipt))
    pointer = encoded({'schema': 'ouf.semantic-coordinated-boot-pointer.v1', 'receiptFile': str(root/'installation-receipt.json'),
                       'receiptHash': digest(encoded(receipt)), 'observerFile': str(root/'transition-source.py'),
                       'observerHash': digest(installer_raw)})
    journal_path = root/'installation-journal.json'
    write_new(journal_path, encoded({'state': 'PREPARED', 'startAuthorized': False}))
    def journal(state):
        before = read(journal_path)
        replace(journal_path, before, encoded({'state': state, 'startAuthorized': False}))
    INSTALL_STAGE = 'UNIT_TRANSITION'
    fd = g.lock(Path(c['lockFile']))
    try:
        installer.independent(g, r, intent, roots, old_install, c)
        installer.loaded(g, r, a, old_install, gu, unit, drop)
        if os.path.lexists(POINTER): raise ValueError('concurrent installed pointer')
        entries = [{'path': UNIT_PATHS[name], 'old': a[name], 'new': new[name]} for name in new]
        entries.append({'path': HELPER, 'old': helper_old, 'new': helper_new, 'mode': 0o755})
        def reload_units(): g.run([r['executables']['systemctl_path'], 'daemon-reload'])
        def verify_new(): observe_once(receipt, legacy)
        def verify_old():
            installer.loaded(g, r, a, old_install, gu, unit, drop)
            installer.independent(g, r, intent, roots, old_install, c)
        transaction(entries, reload_units, verify_new, verify_old, journal)
        # Publish the active receipt only once, after the complete readback.
        # Do not expose a partially written pointer to concurrent readers.
        INSTALL_STAGE = 'ACTIVE_POINTER_PUBLICATION'
        pointer_temp = root/'active-pointer.json'; write_new(pointer_temp, pointer)
        linked = False
        try:
            os.link(pointer_temp, POINTER); linked = True
            pointer_temp.unlink(); synced_directory(root)
            synced_directory(POINTER.parent)
        except Exception:
            # The complete unit transaction must also be recovered if pointer
            # publication fails. A foreign pointer is never overwritten.
            if linked:
                if read(POINTER) != pointer: raise ValueError('foreign active pointer preserved')
                POINTER.unlink(); synced_directory(POINTER.parent)
            transaction([{'path': e['path'], 'old': e['new'], 'new': e['old'], 'mode': e.get('mode', 0o600)} for e in entries],
                        reload_units, verify_old, verify_new, journal)
            journal('ROLLED_BACK')
            raise
        finally:
            if pointer_temp.exists(): pointer_temp.unlink()
            synced_directory(root)
    finally: os.close(fd)
    INSTALL_STAGE = 'INSTALLED_BOUNDED_READBACK'
    actual = module(HELPER, sealed(HELPER, HELPER_V3_HASH, 0o755)).collect()
    if actual['runtimeReadiness'].get('runtimeCustodyVerified') is not True:
        raise ValueError('bounded installed readback denied; no replay')
    return {'status': 'INSTALLED_AND_READBACK_VERIFIED', 'snapshotDirectory': str(root), **receipt,
            'runtimeReadiness': actual['runtimeReadiness'], 'generalSudoGranted': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-directory', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = install(args.source_directory, globals().get('__ouf_verified_source__'))
        print('OUF_COORDINATED_BOOT_INSTALLATION='+json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        phase = 'NOT_CREATED'
        if INSTALL_SNAPSHOT is not None:
            try:
                value = parsed(read(INSTALL_SNAPSHOT/'installation-journal.json')).get('state')
                phase = value if value in {'PREPARED', 'INSTALLING', 'INSTALLED', 'ROLLBACK_REQUIRED', 'ROLLED_BACK', 'ROLLBACK_BLOCKED'} else 'UNAVAILABLE'
            except Exception: phase = 'UNAVAILABLE'
        print('OUF_COORDINATED_BOOT_INSTALLATION='+json.dumps({
            'status': 'BLOCKED', 'stage': INSTALL_STAGE, 'installationPhase': phase,
            'snapshotDirectory': str(INSTALL_SNAPSHOT) if INSTALL_SNAPSHOT is not None else None,
            'exceptionType': type(error).__name__ if type(error).__name__ in {'ValueError', 'AttributeError', 'RuntimeError', 'OSError', 'PermissionError', 'FileNotFoundError', 'TimeoutExpired'} else 'UNKNOWN',
            'doNotRerunApply': True, 'noRawOutput': True}, sort_keys=True))
        return 1


if __name__ == '__main__': raise SystemExit(main())
