"""Linux root adapter. Uses the existing authenticated R3 readers, never Docker writes."""
from contextlib import ExitStack
import copy
from pathlib import Path
import re
import sys

from tools.semantic_provider_r3 import install_common as I
from tools.semantic_provider_r3 import operate as O
from . import boot_dispatcher as B
from . import migration as M

ROOT = Path(__file__).resolve().parents[2]
COMPILER = ROOT / 'tools/semantic_cohort_admission/cohort-draft/tools'
UNITS = {'guard': '/etc/systemd/system/ouf-semantic-boot-guard.service',
         'docker': '/etc/systemd/system/docker.service.d/90-ouf-semantic-boot-guard.conf'}
POINTER = '/etc/ouf/coordinated-boot-installation.json'
DIRECTIVES = {'guard': 'ExecStart', 'docker': 'ExecStartPre'}
UNIT_PROPERTIES = ('FragmentPath', 'DropInPaths', 'NeedDaemonReload', 'MainPID', 'LoadState', 'ControlPID',
                   'User', 'Group', 'RootDirectory', 'RootImage', 'ProtectSystem', 'ReadWritePaths',
                   'ReadOnlyPaths', 'InaccessiblePaths', 'PrivateNetwork', 'PrivateUsers', 'ProtectHome')


def covered(path, entries):
    return any(Path(path) == Path(v.removeprefix('-')) or Path(path).is_relative_to(Path(v.removeprefix('-')))
               for v in entries.split() if v.removeprefix('-').startswith('/'))


def rewrite(raw, directive, command):
    rows = raw.decode('ascii').splitlines(keepends=True)
    found = [i for i, row in enumerate(rows) if row.startswith(directive + '=')]
    B.need(len(found) == 1 and rows[found[0]].strip() != directive + '=', 'SINGLE_BOOT_COMMAND_REQUIRED')
    rows[found[0]] = directive + '=' + command + '\n'
    return ''.join(rows).encode('ascii')


def boot_command(raw, directive):
    rows = [row.split('=', 1)[1] for row in raw.decode('ascii').splitlines() if row.startswith(directive + '=')]
    B.need(len(rows) == 1 and rows[0] and re.fullmatch(r'[A-Za-z0-9_./ =-]+', rows[0]), 'SAFE_BOOT_COMMAND_REQUIRED')
    return rows[0]


class Native:
    def __init__(self, args):
        self.args = args
        self.manifest = B.document(B.private(args.inputs, args.inputs_sha256))
        B.need(set(self.manifest) == {'schema', 'owner', 'bootProfile', 'pointer', 'units',
                                    'dispatcherPath', 'executables'}
               and self.manifest['schema'] == 'ouf.semantic-lease-kernel-migration-inputs.v1', 'EXACT_INPUT_MANIFEST_REQUIRED')
        B.need(self.manifest['pointer']['path'] == POINTER and set(self.manifest['units']) == set(UNITS)
               and all(self.manifest['units'][k]['path'] == v for k, v in UNITS.items()), 'EXACT_PUBLICATION_PATHS_REQUIRED')
        self.work = B.safe(args.migration_directory or args.output_directory)
        self.generation = B.safe(args.generation_directory)
        self.dispatcher = B.safe(self.manifest['dispatcherPath'])
        self.owner = B.document(self.bound(self.manifest['owner']))
        self.profile = B.document(self.bound(self.manifest['bootProfile']))
        B.need(self.owner.get('schema') == 'ouf.semantic-coordinated-owner-runtime.v1'
               and set(self.owner) == {'schema', 'kernel', 'dns', 'expectedStructureHash', 'nftPath', 'nftSha256',
                    'readBudgetSeconds', 'pollSeconds', 'commonLockFile', 'journalFile', 'binding', 'sourceHashes'},
               'EXACT_COORDINATOR_PROFILE_REQUIRED')
        self.boot = B.document(B.private(self.profile['bootConfiguration'], self.profile['bootConfigurationHash']))
        B.need(self.profile['coordinatedConfiguration'] == self.manifest['owner']['path']
               and self.profile['coordinatedConfigurationHash'] == self.manifest['owner']['sha256']
               and self.boot['kernel'] == self.owner['kernel']
               and self.boot['lockFile'] == self.owner['commonLockFile']
               and self.boot['nftPath'] == args.nft and self.owner['nftPath'] == args.nft
               and self.owner['nftSha256'] == args.nft_sha256, 'OWNER_BOOT_COHORT_DRIFT')
        self.nft = {'path': args.nft, 'sha256': args.nft_sha256}
        self.systemctl = {'path': args.systemctl, 'sha256': args.systemctl_sha256}
        for binding in self.manifest['executables'].values():
            B.executable(binding['path'], binding['sha256'])
        B.need(set(self.manifest['executables']) == {'python', 'unshare'}, 'EXACT_EXECUTABLE_BINDINGS_REQUIRED')
        B.need(self.manifest['executables']['python']['path'] == sys.executable, 'PINNED_PYTHON_REQUIRED')
        for path in (self.work, self.generation, self.dispatcher):
            B.ancestors(path)
        B.need(self.work != self.generation and not self.work.is_relative_to(self.generation)
               and not self.generation.is_relative_to(self.work)
               and not self.generation.is_relative_to(Path(args.install_root))
               and not self.work.is_relative_to(Path(args.install_root))
               and not self.dispatcher.is_relative_to(self.generation)
               and not self.dispatcher.is_relative_to(self.work), 'SEPARATE_GENERATION_DIRECTORIES_REQUIRED')
        self.original_sources = self.old_sources()
        B.need(B.digest(self.owner) == self.manifest['owner']['sha256'], 'CANONICAL_OWNER_REQUIRED')

    @staticmethod
    def bound(binding):
        B.need(set(binding) == {'path', 'sha256'}, 'EXACT_PATH_HASH_REQUIRED')
        return B.private(binding['path'], binding['sha256'])

    def old_sources(self):
        root = Path(self.manifest['owner']['path']).parent / 'source'
        result = {}
        for name, digest in {**self.owner['sourceHashes'], **self.profile['sourceHashes']}.items():
            B.need(not Path(name).is_absolute() and '..' not in Path(name).parts, 'SOURCE_PATH_INVALID')
            result[name] = B.private(root / name, digest)
        result['__boot_guard__'] = B.private(self.profile['bootGuardFile'], self.profile['bootGuardHash'])
        B.private(self.boot['compilerFile'], self.boot['compilerHash'])
        return result

    def delivered_sources(self):
        # Preserve every historical source byte. New modules have new names.
        result = {'source/' + k: v for k, v in self.original_sources.items() if k != '__boot_guard__'}
        result.update({
            'source/tools/materialize_southbound_kernel.py': self.original_sources['tools/materialize_southbound_kernel.py'],
            'source/tools/materialize_southbound_kernel_v2.py': (COMPILER / 'materialize_southbound_kernel_v2.py').read_bytes(),
            'source/tools/materialize_southbound_lease_refresh_v2.py': (ROOT / 'tools/semantic_lease_recovery/materialize_southbound_lease_refresh_v2.py').read_bytes(),
            'boot-runner-v2.py': (Path(__file__).parent / 'boot_runner_v2.py').read_bytes(),
        })
        return result

    def source_hashes(self):
        # Re-read delivery bytes, so a checkout drift between plan and apply denies.
        return {k: B.sha(v) for k, v in self.delivered_sources().items()} | {
            '@dispatcher': B.sha(Path(B.__file__).read_bytes()),
            '@migration': B.sha(Path(M.__file__).read_bytes()),
            '@native': B.sha(Path(__file__).read_bytes())}

    def verify_inputs(self):
        B.private(self.args.inputs, self.args.inputs_sha256)
        B.need(B.document(self.bound(self.manifest['owner'])) == self.owner
               and B.document(self.bound(self.manifest['bootProfile'])) == self.profile
               and B.document(B.private(self.profile['bootConfiguration'], self.profile['bootConfigurationHash'])) == self.boot
               and self.old_sources() == self.original_sources, 'LEASE_KERNEL_IMMUTABLE_INPUT_DRIFT')
        for binding in self.manifest['executables'].values():
            B.executable(binding['path'], binding['sha256'])

    def paths(self):
        return {'migrationDirectory': str(self.work), 'generationDirectory': str(self.generation),
                'dispatcher': str(self.dispatcher), 'inputs': {'path': self.args.inputs, 'sha256': self.args.inputs_sha256},
                'r3': {k: getattr(self.args, k) for k in ('install_root', 'wrapper', 'wrapper_sha256', 'lock',
                       'docker', 'docker_sha256', 'docker_socket', 'systemctl', 'systemctl_sha256', 'nft', 'nft_sha256')}}

    def observe(self):
        return O.observe(self.args, output_exists=self.work.exists())

    def runtime(self):
        root = Path(self.args.install_root)
        wrapper = I.native_switch().custody(self.args.wrapper, 0o755)[0]
        code = I.wrapper_code_root(root, wrapper)
        raw = I.native_switch().custody(code / 'runtime-configuration.json', 0o600)[0]
        cfg = B.document(raw)
        version = 1 if code == root else int(code.name)
        return cfg, version

    def authorization(self, owner, phase, observation):
        # O.observe authenticates both heads with the INSTALLED runtime loader.
        # Compare the actual head payload, not a caller-provided version claim.
        cfg, version = self.runtime()
        auth = observation['authorization']
        raw = B.private(Path(self.args.install_root) / 'authorization' / (str(auth['sequence']) + '.json'), auth['sha256'])
        payload = I.A.validate(raw)
        B.need(payload['runtimeConfigurationSha256'] == observation['configurationSha256']
               and payload['lease']['ownerConfigurationSha256'] == B.digest(owner)
               and payload['lease']['leaseStructureHash'] == owner['expectedStructureHash'],
               'LEASE_KERNEL_R3_HEAD_KERNEL_MISMATCH')
        sup = B.document(self.bound(cfg['leaseQuiesce']['configuration']))
        B.need(sup['coordinator']['ownerConfiguration']['sha256'] == B.digest(owner)
               and sup['coordinator']['journalPath'] == owner['journalFile']
               and sup['coordinator']['commonLockPath'] == owner['commonLockFile'], 'LEASE_KERNEL_R3_COORDINATOR_MISMATCH')
        generation = owner['kernel'].get('generation', 1)
        step = (generation - 1, generation) if phase == 'finalize' else (generation, generation + 1)
        policy = M.POLICIES.get(step)
        B.need(policy is not None and (version >= policy['r3AfterMinVersion'] if phase == 'finalize'
               else version <= policy['r3BeforeMaxVersion']), 'LEASE_KERNEL_R3_SEQUENCE_INCOHERENT')

    def loaded(self):
        result = {}
        for key, unit in (('guard', 'ouf-semantic-boot-guard.service'), ('docker', 'docker.service')):
            names = (*UNIT_PROPERTIES, DIRECTIVES[key])
            raw = B.command(self.systemctl, ['show', unit, '--all', *('--property=' + n for n in names)])
            row = dict(line.split('=', 1) for line in raw.decode('ascii').splitlines())
            B.need(set(row) == set(names) and row['NeedDaemonReload'] == 'no' and row['MainPID'].isdigit()
                   and row['LoadState'] == 'loaded' and row['ControlPID'] == '0',
                   'SETTLED_LOADED_SYSTEMD_UNITS_REQUIRED')
            B.need((key == 'docker' and int(row['MainPID']) > 1) or (key == 'guard' and row['MainPID'] == '0'),
                   'BOOT_DAEMON_FRAME_INVALID')
            if key == 'guard':
                B.need(row['User'] in ('', 'root') and row['Group'] in ('', 'root')
                       and not row['RootDirectory'] and not row['RootImage']
                       and row['PrivateNetwork'] == row['PrivateUsers'] == 'no', 'HOST_ROOT_BOOT_UNIT_REQUIRED')
            paths = [row['FragmentPath'], *row['DropInPaths'].split()]
            B.need(all(paths) and UNITS[key] in paths, 'SYSTEMD_FRAGMENT_BINDING_DRIFT')
            # Existing vendor fragments may be 0644. The historical custody
            # reader binds their exact mode; no omitted drop-in is normalized.
            row['fileHashes'] = {}
            for path in paths:
                info = Path(path).lstat()
                raw_file = I.native_switch().custody(path, info.st_mode & 0o777)[0]
                row['fileHashes'][path] = B.sha(raw_file)
            result[key] = row
        return result

    @staticmethod
    def verify_commands(loaded, commands, expected_arrays=None):
        for key, expected in commands.items():
            raw = loaded[key][DIRECTIVES[key]]
            # systemctl's structured property contains explicit argv records.
            # Require the entire argv array, exactly one command, no substring.
            rows = re.findall(r'argv\[\]=(.*?)\s*;', raw)
            wanted = expected_arrays[key] if expected_arrays is not None else None
            B.need(rows.count(expected) == 1 and (key == 'docker' or rows == [expected])
                   and (wanted is None or rows == wanted)
                   and raw.count('{') == raw.count('}') == len(rows),
                   'LOADED_BOOT_COMMAND_DRIFT')

    def proposed_units(self, context):
        new = {key: rewrite(raw.encode('ascii'), DIRECTIVES[key], self.dispatch_command()).decode('ascii')
               for key, raw in context['units'].items()}
        guard = context['loaded']['guard']
        writable = self.generation.parent
        B.need(not covered(self.dispatcher, guard.get('InaccessiblePaths', '')), 'BOOT_DISPATCHER_PATH_INACCESSIBLE')
        if guard.get('ProtectHome') in ('yes', 'tmpfs'):
            B.need(not any(covered(path, '/root /home /run/user') for path in (self.dispatcher, writable)),
                   'BOOT_GENERATION_HOME_INACCESSIBLE')
        B.need(not covered(writable, guard.get('ReadOnlyPaths', ''))
               and not covered(writable, guard.get('InaccessiblePaths', '')), 'BOOT_GENERATION_PATH_INACCESSIBLE')
        if guard.get('ProtectSystem') == 'strict' and not covered(writable, guard['ReadWritePaths']):
            # First conversion grants the stable root of future generations.
            # Subsequent migrations MUST retain the exact unit bytes.
            B.need('--pointer ' not in context['units']['guard'], 'BOOT_GENERATION_ROOT_CHANGED')
            B.need(new['guard'].count('[Service]') == 1, 'ONE_SERVICE_SECTION_REQUIRED')
            new['guard'] = new['guard'].replace('[Service]', '[Service]\nReadWritePaths=' + str(writable), 1)
        return new

    def context(self):
        self.verify_inputs()
        B.need(not self.work.exists() and not self.generation.exists(), 'LEASE_KERNEL_APPLY_ALREADY_CLAIMED')
        pointer_raw = self.bound(self.manifest['pointer'])
        pointer, receipt = B.sealed_receipt(POINTER)
        B.need(B.canonical(pointer) == pointer_raw and receipt.get('configurationHash') == self.manifest['owner']['sha256']
               and receipt.get('bootProfileHash') == self.manifest['bootProfile']['sha256'], 'BOOT_POINTER_OWNER_DRIFT')
        units = {k: self.bound(v).decode('ascii') for k, v in self.manifest['units'].items()}
        commands = {k: boot_command(v.encode('ascii'), DIRECTIVES[k]) for k, v in units.items()}
        loaded = self.loaded()
        self.verify_commands(loaded, commands)
        # Validate boot sandbox compatibility during plan, before any mutation.
        self.proposed_units({'units': units, 'loaded': loaded})
        if self.dispatcher.exists():
            B.need(B.private(self.dispatcher) == Path(B.__file__).read_bytes(), 'DISPATCHER_VERSION_DRIFT')
        if set(commands.values()) == {self.dispatch_command()}:
            B.need(self.dispatcher.exists(), 'DISPATCHER_SOURCE_MISSING')
        else:
            # Restore retains the sealed dispatcher as evidence but restores
            # the original fixed units. A NEW claim may reuse those same bytes.
            legacy_python = commands['guard'].split()[0]
            B.need(Path(legacy_python).resolve() == Path(self.manifest['executables']['python']['path']).resolve(),
                   'LEGACY_PYTHON_BINDING_DRIFT')
            expected = (legacy_python + ' -I -B '
                + str(Path(self.manifest['owner']['path']).parent / 'source/scripts/run_semantic_coordinated_boot_guard.py')
                + ' --configuration ' + self.manifest['bootProfile']['path']
                + ' --configuration-sha256 ' + self.manifest['bootProfile']['sha256'])
            B.need(set(commands.values()) == {expected}, 'LEGACY_BOOT_COMMAND_DRIFT')
        journal = B.document(B.private(self.owner['journalFile']))
        return {'owner': self.owner, 'journal': journal, 'boot': self.boot, 'profile': self.profile,
                'pointerRaw': pointer_raw.decode('ascii'), 'units': units, 'loaded': loaded,
                'proposedUnits': self.proposed_units({'units': units, 'loaded': loaded}),
                'dispatcherCommand': self.dispatch_command(),
                'bootJournalSha256': B.sha(B.private(self.boot['journalFile'])),
                'inputHashes': {self.args.inputs: self.args.inputs_sha256, **{
                    v['path']: v['sha256'] for v in (self.manifest['owner'], self.manifest['bootProfile'],
                    self.manifest['pointer'], *self.manifest['units'].values())}}}

    def dispatch_command(self):
        return (self.manifest['executables']['python']['path'] + ' -I -B ' + str(self.dispatcher)
                + ' --pointer ' + POINTER + ' --self-sha256 ' + B.sha(Path(B.__file__).read_bytes()))

    def tables(self, kernel):
        return B.tables(self.nft, kernel['tableName'])

    def compile(self, kernel):
        # The delivery package imports the versioned compiler without its legacy
        # public alias. The installed boot loader uses the same two sealed blobs.
        import types
        package = types.ModuleType('_migration_compiler')
        package.__path__ = []
        sys.modules[package.__name__] = package
        for name in ('materialize_southbound_kernel', 'materialize_southbound_kernel_v2'):
            raw = self.delivered_sources()['source/tools/' + name + '.py']
            module = types.ModuleType(package.__name__ + '.' + name)
            module.__package__ = package.__name__
            sys.modules[module.__name__] = module
            exec(compile(raw, name + '.py', 'exec'), module.__dict__)
            setattr(package, name, module)
        return module.materialize(kernel, empty_provider_sets=True)['nftRules']

    def template(self, kernel):
        source_paths = {'materialize_southbound_kernel.py': Path(self.manifest['owner']['path']).parent
                        / 'source/tools/materialize_southbound_kernel.py',
                        'materialize_southbound_kernel_v2.py': COMPILER / 'materialize_southbound_kernel_v2.py'}
        config = {'kernel': kernel, 'nft': self.nft, 'parentNamespace': Path('/proc/self/ns/net').stat().st_ino,
                  'sources': {n: {'path': str(p), 'sha256': B.sha(p.read_bytes())} for n, p in source_paths.items()}}
        python = self.manifest['executables']['python']
        B.executable(python['path'], python['sha256'])
        try:
            return B.document(B.command(self.manifest['executables']['unshare'], ['--net',
                 python['path'], '-I', '-B', str(ROOT / 'scripts/migrate-semantic-lease-kernel.py'),
                 '--native-template'], B.canonical(config)))
        finally:
            B.executable(python['path'], python['sha256'])

    def locks(self):
        stack = ExitStack()
        try:
            cfg, version = self.runtime()
            stack.enter_context(I.operation_locks(Path(self.args.install_root), sorted(cfg['candidates'])))
            stack.enter_context(B.directory_lock(Path(self.args.install_root) / 'authorization'))
            stack.enter_context(B.lock(self.args.lock))
            # On the VPS the coordinator's common lock IS the boot guard lock
            # (/run/ouf-semantic-boot-guard/guard.lock). A second flock on a new
            # descriptor of the same inode would fail with EWOULDBLOCK: take it once.
            guard, common = Path(self.args.lock).lstat(), Path(self.owner['commonLockFile']).lstat()
            if (guard.st_dev, guard.st_ino) != (common.st_dev, common.st_ino):
                stack.enter_context(B.lock(self.owner['commonLockFile']))
            B.need(self.runtime() == (cfg, version), 'LEASE_KERNEL_R3_CHANGED_BEFORE_LOCK')
            return stack
        except BaseException:
            stack.close()
            raise

    def batch(self, raw):
        B.command(self.nft, ['-f', '-'], raw.encode('ascii'))

    def delete(self, kernel):
        # Compile first to validate the name and the whole scope.
        self.compile(kernel)
        return ''.join('delete table ' + f + ' ' + kernel['tableName'] + '\n' for f in ('inet', 'bridge'))

    def claim(self, planned):
        B.need(not self.generation.exists(), 'LEASE_KERNEL_GENERATION_DIRECTORY_EXISTS')
        self.work.mkdir(mode=0o700)
        B.sync(self.work.parent)
        self.save('plan.json', planned)

    def save(self, name, value):
        B.write_once(self.work / name, B.canonical(value))

    def load(self, name):
        return B.document(B.private(self.work / name))

    def exists(self, name):
        return (self.work / name).exists()

    def record(self, value):
        index = len(list(self.work.glob('event-*.json')))
        self.save('event-' + str(index).zfill(6) + '.json', value)

    def event_exists(self, phase, side):
        return any(row['phase'] == phase and row['side'] == side
                   for row in (B.document(B.private(p)) for p in self.work.glob('event-*.json')))

    def prepare(self, planned):
        self.generation.mkdir(mode=0o700)
        B.sync(self.generation.parent)
        B.need(self.source_hashes() == planned['sourceHashes'], 'LEASE_KERNEL_SOURCE_DRIFT')
        for name, raw in self.delivered_sources().items():
            path = self.generation / name
            missing = []
            parent = path.parent
            while not parent.exists():
                missing.append(parent)
                parent = parent.parent
            for directory in reversed(missing):
                directory.mkdir(mode=0o700)
                B.sync(directory.parent)
            B.write_once(path, raw)
        if self.dispatcher.exists():
            B.need(B.private(self.dispatcher) == Path(B.__file__).read_bytes(), 'DISPATCHER_VERSION_DRIFT')
        else:
            B.write_once(self.dispatcher, Path(B.__file__).read_bytes())

    def stage(self, planned, target):
        root = str(self.generation)
        owner = copy.deepcopy(self.owner)
        owner.update(kernel=planned['destination'], expectedStructureHash=B.digest(B.structure(target)),
                     journalFile=root + '/coordination-journal.json')
        owner['sourceHashes'] = {k.removeprefix('source/'): v for k, v in self.source_hashes().items() if k.startswith('source/')}
        owner.pop('binding')
        owner['binding'] = {'transactionId': planned['planSha256'], 'configurationHash': B.digest(owner),
                            'leaseStructureHash': owner['expectedStructureHash']}
        boot = {**self.boot, 'kernel': owner['kernel'], 'compilerFile': root + '/source/tools/materialize_southbound_kernel_v2.py',
                'compilerHash': owner['sourceHashes']['tools/materialize_southbound_kernel_v2.py'],
                'expectedFootprint': planned['expectedBootFootprint'], 'journalFile': root + '/boot-journal.json',
                'transactionId': planned['planSha256']}
        profile = {**self.profile, 'sourceHashes': owner['sourceHashes'],
                   'coordinatedConfiguration': root + '/coordinated-configuration.json', 'coordinatedConfigurationHash': B.digest(owner),
                   'bootConfiguration': root + '/boot-configuration.json', 'bootConfigurationHash': B.digest(boot),
                   'bootGuardFile': root + '/boot-runner-v2.py', 'bootGuardHash': self.source_hashes()['boot-runner-v2.py']}
        files = {'coordinated-configuration.json': owner, 'boot-configuration.json': boot, 'boot-profile.json': profile,
                 'coordination-journal.json': {'schema': 'ouf.semantic-lease-coordination.v1', **owner['binding'],
                    'state': 'QUIESCED', 'leaseAuthorized': False, 'startAuthorized': False,
                    'leaseAddresses': [[] for _ in owner['kernel']['providerFlows']]},
                 'boot-journal.json': {'schema': 'ouf.semantic-runtime-transition.v1', 'state': 'RUNTIME_EMPTY',
                    'transactionId': owner['binding']['transactionId'], 'configurationHash': B.digest(boot),
                    'leaseStructureHash': owner['expectedStructureHash'], 'startAuthorized': False}}
        # Owner is the completion marker for journal checks during recovery.
        # A crash during any earlier write leaves N authoritative and restorable.
        for name in ('coordination-journal.json', 'boot-journal.json', 'boot-configuration.json',
                     'boot-profile.json', 'coordinated-configuration.json'):
            value = files[name]
            B.write_once(self.generation / name, B.canonical(value))
        closure = {k: v for k, v in self.source_hashes().items() if not k.startswith('@')}
        closure.update({name: B.digest(files[name]) for name in
                        ('coordinated-configuration.json', 'boot-configuration.json', 'boot-profile.json')})
        receipt = {'schema': 'ouf.semantic-lease-kernel-generation.v1', 'directory': root,
                   'generation': planned['destination']['generation'], 'closure': closure, 'runner': 'boot-runner-v2.py',
                   'configurationHash': B.digest(owner), 'bootProfileHash': B.digest(profile),
                   'bootProfile': {'path': root + '/boot-profile.json', 'sha256': B.digest(profile)},
                   'predecessorTableName': self.owner['kernel']['tableName'], 'migrationPlanSha256': planned['planSha256']}
        B.write_once(self.generation / 'generation-receipt.json', B.canonical(receipt))
        pointer = {'schema': 'ouf.semantic-coordinated-boot-pointer.v1',
                   'receiptFile': str(self.generation / 'generation-receipt.json'), 'receiptHash': B.digest(receipt),
                   'observerFile': str(self.dispatcher), 'observerHash': B.sha(Path(B.__file__).read_bytes())}
        entries = []
        new_units = self.proposed_units(planned['context'])
        for key, binding in self.manifest['units'].items():
            before = planned['context']['units'][key]
            after = new_units[key]
            entries.append({'path': binding['path'], 'old': before, 'new': after})
        entries.append({'path': POINTER, 'old': planned['context']['pointerRaw'], 'new': B.canonical(pointer).decode('ascii')})
        return entries

    def publication_state(self, entries):
        if entries:
            plan = self.load('plan.json')
            expected_old = {UNITS[k]: v for k, v in plan['context']['units'].items()}
            expected_old[POINTER] = plan['context']['pointerRaw']
            B.need(len(entries) == len(expected_old) and {e['path'] for e in entries} == set(expected_old),
                   'EXACT_PUBLICATION_ENTRIES_REQUIRED')
            for entry in entries:
                B.need(entry['old'] == expected_old[entry['path']], 'PUBLICATION_OLD_BYTES_DRIFT')
                if entry['path'] != POINTER:
                    key = next(k for k, v in UNITS.items() if v == entry['path'])
                    expected_new = self.proposed_units(plan['context'])[key]
                else:
                    expected_new = B.canonical({'schema': 'ouf.semantic-coordinated-boot-pointer.v1',
                        'receiptFile': str(self.generation / 'generation-receipt.json'),
                        'receiptHash': B.sha(B.private(self.generation / 'generation-receipt.json')),
                        'observerFile': str(self.dispatcher), 'observerHash': B.sha(Path(B.__file__).read_bytes())}).decode('ascii')
                B.need(entry['new'] == expected_new, 'PUBLICATION_NEW_BYTES_DRIFT')
        result = []
        for entry in entries:
            raw = B.private(entry['path']).decode('ascii')
            B.need(raw in (entry['old'], entry['new']), 'FOREIGN_PUBLICATION_PRESERVED')
            result.append({'path': entry['path'], 'sha256': B.sha(raw.encode('ascii')),
                           'state': 'new' if raw == entry['new'] else 'old'})
        return result

    def publish(self, entries, restore):
        self.publication_state(entries)
        if not entries:
            # No publication intent: prove the exact old bytes, even when the
            # crash happened before publication.json could be written.
            plan = self.load('plan.json')
            for binding in (self.manifest['pointer'], *self.manifest['units'].values()):
                self.bound(binding)
            B.need(self.loaded() == plan['context']['loaded'], 'LOADED_BOOT_COMMAND_DRIFT')
            return
        for entry in reversed(entries) if restore else entries:
            before, after = (entry['new'], entry['old']) if restore else (entry['old'], entry['new'])
            current = B.private(entry['path']).decode('ascii')
            if current != after:
                B.cas(entry['path'], before.encode('ascii'), after.encode('ascii'))
        B.command(self.systemctl, ['daemon-reload'])
        loaded = self.loaded()
        old = self.load('plan.json')['context']['loaded']
        for key in old:
            B.need(all(loaded[key][k] == old[key][k] for k in ('MainPID', 'FragmentPath', 'DropInPaths')),
                   'BOOT_DAEMON_OR_UNIT_FRAME_CHANGED')
            for path, digest in old[key]['fileHashes'].items():
                if path != UNITS[key]:
                    B.need(loaded[key]['fileHashes'][path] == digest, 'OTHER_DROPIN_CHANGED')
            for name in UNIT_PROPERTIES:
                if name in old[key] and name != 'ReadWritePaths':
                    B.need(loaded[key][name] == old[key][name], 'BOOT_UNIT_PROPERTY_DRIFT')
            expected_writable = old[key].get('ReadWritePaths')
            if key == 'guard' and not restore and old[key].get('ProtectSystem') == 'strict' \
                    and not covered(self.generation.parent, expected_writable):
                expected_writable = ' '.join(sorted(set(expected_writable.split()) | {str(self.generation.parent)}))
            if expected_writable is not None:
                B.need(set(loaded[key]['ReadWritePaths'].split()) == set(expected_writable.split()), 'BOOT_WRITE_SCOPE_CHANGED')
        commands = {key: boot_command(B.private(path), DIRECTIVES[key]) for key, path in UNITS.items()}
        arrays = {key: [commands[key] if value == boot_command(self.load('plan.json')['context']['units'][key].encode('ascii'),
                       DIRECTIVES[key]) else value for value in re.findall(r'argv\[\]=(.*?)\s*;', old[key][DIRECTIVES[key]])]
                  for key in old}
        self.verify_commands(loaded, commands, arrays)

    def new_owner(self):
        return B.document(B.private(self.generation / 'coordinated-configuration.json'))

    def check_journals(self, planned):
        self.verify_inputs()
        M.quiesced(self.owner, B.document(B.private(self.owner['journalFile'])))
        B.need(B.sha(B.private(self.boot['journalFile'])) == planned['context']['bootJournalSha256'], 'OLD_BOOT_JOURNAL_CHANGED')
        path = self.generation / 'coordinated-configuration.json'
        # Before publication.json is durable the new owner is never selected.
        # Incomplete preparatory files (including a short owner/journal write)
        # must not prevent recovery of N. Publication itself preflights the
        # original pointer/unit bytes before any removal of target tables.
        if path.exists() and self.exists('publication.json'):
            owner = self.new_owner()
            B.need(owner['kernel'] == planned['destination']
                   and owner['expectedStructureHash'] == self.load('native-after.json')['seals']['structure']
                   and owner['commonLockFile'] == self.owner['commonLockFile'], 'NEW_OWNER_BINDING_DRIFT')
            receipt_path = self.generation / 'generation-receipt.json'
            if receipt_path.exists():
                receipt = B.document(B.private(receipt_path))
                B.need(receipt['configurationHash'] == B.digest(owner)
                       and receipt['migrationPlanSha256'] == planned['planSha256'], 'GENERATION_RECEIPT_DRIFT')
                for name, expected in receipt['closure'].items():
                    B.need(not Path(name).is_absolute() and '..' not in Path(name).parts, 'CLOSURE_PATH_INVALID')
                    B.private(self.generation / name, expected)
            M.quiesced(owner, B.document(B.private(owner['journalFile'])))

    def finalize_claim(self, planned):
        output = B.safe(self.args.output_directory)
        B.need(output != self.work and not output.is_relative_to(self.work), 'SEPARATE_FINALIZE_OUTPUT_REQUIRED')
        if output.exists():
            B.need(B.private(output / 'finalize-plan.json') == B.canonical(planned), 'FINALIZE_CLAIM_CHANGED')
            return
        output.mkdir(mode=0o700)
        B.sync(output.parent)
        B.write_once(output / 'finalize-plan.json', B.canonical(planned))


def native_template():
    # Private internal subprocess, useful only after unshare. No host mutations.
    B.need(Path('/proc/self/ns/net').stat().st_ino != Path('/proc/1/ns/net').stat().st_ino,
           'DISPOSABLE_NETNS_REQUIRED')
    config = B.document(sys.stdin.buffer.read(131073))
    B.need(Path('/proc/self/ns/net').stat().st_ino != config['parentNamespace'], 'NEW_NETNS_REQUIRED')
    inventory = B.document(B.command(config['nft'], ['-j', 'list', 'tables']))
    B.need(not any('table' in r for r in inventory['nftables']), 'EMPTY_NETNS_REQUIRED')
    import types
    package = types.ModuleType('_template_compiler')
    package.__path__ = []
    sys.modules[package.__name__] = package
    for name in ('materialize_southbound_kernel', 'materialize_southbound_kernel_v2'):
        binding = config['sources'][name + '.py']
        raw = B.private(binding['path'], binding['sha256'])
        module = types.ModuleType(package.__name__ + '.' + name)
        module.__package__ = package.__name__
        sys.modules[module.__name__] = module
        exec(compile(raw, name + '.py', 'exec'), module.__dict__)
        setattr(package, name, module)
    raw = module.materialize(config['kernel'], empty_provider_sets=True)['nftRules']
    B.command(config['nft'], ['-f', '-'], raw.encode('ascii'))
    print(B.canonical(B.tables(config['nft'], config['kernel']['tableName'])).decode('ascii'))
