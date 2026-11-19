#!/usr/bin/env python3
"""Bind the verified successor to boot; never start Docker or old providers.

The existing v3 pointer reader dispatches this sealed observer. The old runtime
configuration remains historical and blocked until a fresh provider generation.
"""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import traceback
import types
from datetime import datetime, timezone

STAGE_SCRIPT = 'stage-discovery-coordinator-successor-20261109.py'
STAGE_SHA = '8e9cfe1e8073d33423e11f51e0a790530ec14e3cedbc6a5620a0ecff962e815d'
STAGED = Path('/etc/ouf/deploy-snapshots/discovery-coordinator-successor-20261109-uz9gw5ny')
RESULT = Path('/var/lib/ouf-storage-migration/discovery-coordination-stage-5lxy439w/result.json')
RESULT_SHA = '855e637ce5585269c4eae33b13b23b4b3e1a92c3b305c1d1ba3a6cabfc4ca45f'
HELD_RESULT = Path('/var/lib/ouf-storage-migration/discovery-boot-activation-a2tzafec/result.json')
HELD_RESULT_SHA = '865ee49a11d64aba5e2e72858cf757511c199e04ffb84948c33fd515ae7c2466'
PREPARATION_SHA = '3c693988ded91ecaa29c491c7bf5b537adf78a93c1e2511eada28f7af0f40b21'
OWNER_SHA = '5deb74791d7d3e20b1f91285320a5d48a15b7d99af2d14f03c063bdd970dd8df'
PROFILE_SHA = '8135b9839e8ba5dc2e98068c0dd6f631d56f1fd7b91e2e4d456ea3f5d1a35fb7'
CLAIM = Path('/var/lib/ouf-storage-migration/discovery-coordinator-boot-activation-20261109')
POINTER = Path('/etc/ouf/coordinated-boot-installation.json')
UNITS = {'guard.service': Path('/etc/systemd/system/ouf-semantic-boot-guard.service'),
         'docker-drop-in.conf': Path('/etc/systemd/system/docker.service.d/90-ouf-semantic-boot-guard.conf')}
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}


def need(ok, reason):
    if not ok: raise RuntimeError(reason)


def sha(raw): return hashlib.sha256(raw).hexdigest()
def encoded(value): return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def dependency():
    root = Path(__file__).parent
    if Path(__file__).name == 'transition-source.py': root /= 'helpers'
    path = root / STAGE_SCRIPT; raw = path.read_bytes()
    need(sha(raw) == STAGE_SHA, 'PINNED_STAGE_HELPER_CHANGED')
    ns = {'__name__': 'staged_boot_dependency', '__file__': str(path)}
    exec(compile(raw, str(path), 'exec'), ns)
    m = types.SimpleNamespace(**ns); d = m.load_drift(); q = d.load_quiesce()
    p = q.load_helper('reconcile-discovery-placeholder-20261109.py')
    l = q.load_helper('read-discovery-lifecycle-20261109.py')
    s = l.module(l.STARTUP, l.STARTUP_SHA); h = l.module(l.HELPER, l.HELPER_SHA)
    return types.SimpleNamespace(m=m, d=d, q=q, p=p, l=l, s=s, h=h, core=q.load_core())


def helper_pins(c):
    return {STAGE_SCRIPT:STAGE_SHA, c.m.DRIFT:c.m.DRIFT_SHA, c.d.QUIESCE:c.d.QUIESCE_SHA,
            **c.q.HELPERS, c.l.STARTUP:c.l.STARTUP_SHA, c.l.HELPER:c.l.HELPER_SHA,
            **{'core/'+k+'.py':v for k,v in c.q.CORE.items()}}


def sealed(c, path, expected):
    raw = c.p.read_private(path)
    need(sha(raw) == expected, 'SEALED_BOOT_INPUT_CHANGED')
    return raw


def verify_receipt(raw):
    need(sha(raw) == RESULT_SHA, 'EXACT_STAGED_RECEIPT_REQUIRED')


def verify_prepublication_hold(raw):
    need(sha(raw) == HELD_RESULT_SHA, 'EXACT_PREPUBLICATION_HOLD_REQUIRED')
    held = json.loads(raw)
    need(held['reason'] == 'SETTLED_LOADED_SYSTEMD_UNITS_REQUIRED'
         and held['operationIntentPresent'] is False and held['publicationAttempted'] is False
         and held['activeInstallationPointerChanged'] is False, 'PREPUBLICATION_HOLD_REQUIRED')


def context(c, old_pointer):
    verify_receipt(c.p.read_private(RESULT))
    need(c.p.read_private(c.m.CLAIM / 'complete.json') == c.p.read_private(RESULT), 'STAGING_COMPLETION_CHANGED')
    prep = c.l.parse(sealed(c, STAGED / 'preparation-receipt.json', PREPARATION_SHA))
    need(prep['status'] == 'STAGED_NOT_ACTIVE' and prep['directory'] == str(STAGED)
         and prep['previousActivePointerSha256'] == sha(old_pointer)
         and prep['configurationHash'] == OWNER_SHA and prep['bootProfileHash'] == PROFILE_SHA,
         'EXACT_COMPLETED_SUCCESSOR_BINDING_REQUIRED')
    files = {name: c.l.parse(sealed(c, STAGED / name, digest)) for name, digest in prep['fileHashes'].items()}
    need(set(files) == {'coordinated-configuration.json','boot-configuration.json','boot-profile.json',
                       'coordination-journal.json','boot-journal.json'}, 'CLOSED_STAGED_PROFILE_SET_REQUIRED')
    owner, boot, profile = [files[name] for name in ('coordinated-configuration.json','boot-configuration.json','boot-profile.json')]
    expected = {'tools/' + k + '.py': v for k, v in c.q.CORE.items()}; expected.update(c.m.EXTRA_SOURCE)
    need(prep['sourceHashes'] == expected, 'CLOSED_ORIGINAL_STAGE_SOURCES_REQUIRED')
    for name, digest in expected.items(): sealed(c, STAGED / 'source' / name, digest)
    for package in ('scripts','tools'):
        need(not os.path.lexists(STAGED / 'source' / package / '__init__.py'), 'UNSEALED_INITIALIZER_REFUSED')
    need(profile['coordinatedConfiguration'] == str(STAGED / 'coordinated-configuration.json')
         and profile['coordinatedConfigurationHash'] == OWNER_SHA
         and profile['bootConfiguration'] == str(STAGED / 'boot-configuration.json')
         and profile['bootConfigurationHash'] == sha(encoded(boot)), 'STAGED_INTERNAL_BINDINGS_CHANGED')
    for name, digest in ((boot['compilerFile'], boot['compilerHash']), (profile['bootGuardFile'], profile['bootGuardHash'])):
        sealed(c, c.s.exact_path(name), digest)
    bindings = c.l.parse(c.p.read_private(c.q.RECEIPT.parent / 'source-bindings.private.json'))
    paths = [k for k, v in bindings.items() if v['sha256'] == c.l.CONFIG_SHA]
    need(len(paths) == 1, 'ONE_RETAINED_RUNTIME_CONFIGURATION_REQUIRED')
    cfg = c.l.parse(sealed(c, c.s.exact_path(paths[0]), c.l.CONFIG_SHA)); registry = c.s.exact_path(cfg['registryRoot'])
    driver = c.l.parse(sealed(c, registry / c.s.PINS['southbound'][0] / 'driver.json', prep['previousDriverSha256']))
    pointer = c.l.parse(old_pointer); oldroot = c.s.exact_path(pointer['receiptFile']).parent
    old_owner = c.l.parse(sealed(c, oldroot / 'coordinated-configuration.json', prep['previousOwnerSha256']))
    old_journal = c.p.read_private(c.s.exact_path(old_owner['journalFile']))
    j = c.l.parse(old_journal)
    need(j['state'] == 'BLOCKED' and not j['leaseAuthorized'] and not j['startAuthorized'], 'HISTORICAL_OWNER_MUST_REMAIN_BLOCKED')
    return types.SimpleNamespace(prep=prep, files=files, owner=owner, boot=boot, profile=profile,
        registry=registry, driver=driver, oldroot=oldroot, old_owner=old_owner, old_journal=old_journal,
        old_pointer=old_pointer, cfg_path=paths[0])


def locks(c, ctx):
    stack = contextlib.ExitStack()
    try:
        for role in ('southbound','adapter'):
            stack.enter_context(c.p.existing_lock(ctx.registry / c.s.PINS[role][0] / 'operation.lock'))
        stack.enter_context(c.p.existing_lock(ctx.registry, directory=True))
        stack.enter_context(c.p.existing_lock(c.s.exact_path(ctx.owner['commonLockFile'])))
        return stack
    except Exception:
        stack.close(); raise


def native_guard(c, ctx, work, terminal=True):
    native = c.l.Native(work)
    if terminal:
        current = {}; reader = c.s.Reader(); c.l.collect(current, c.h, c.s, reader, native, work); c.q.check_terminal(current)
    baseline = c.d.boot_baseline(lambda path: ctx.old_pointer if Path(path) == POINTER else c.p.read_private(path),
                                 c.l.parse, c.s.exact_path, ctx.driver)
    need(baseline['allOwnerBindingsMatchDriver'] and baseline['expectedFootprintSha256'] == c.m.BOOT_FOOTPRINT,
         'HISTORICAL_BOOT_PROVENANCE_CHANGED')
    nft = c.d.ReadOnlyNft({'path':ctx.owner['nftPath'],'sha256':ctx.owner['nftSha256']},
                         ctx.owner['kernel']['tableName'], native.binary, work, c.l.parse)
    c.m.qualify_tables(c.core, c.d, ctx.owner, ctx.boot, nft.tables('default'), c.m.CURRENT_STRUCTURE, c.m.BOOT_FOOTPRINT)
    c.m.verify_staged_owner(c.q, c.core, ctx.owner, native, work)
    need(c.p.read_private(c.s.exact_path(ctx.old_owner['journalFile'])) == ctx.old_journal, 'HISTORICAL_JOURNAL_CHANGED')
    for role in ('adapter','southbound'):
        need(c.h.digest(c.h.frame(c.h.inspect(c.s.PINS[role][0]))) == c.s.PINS[role][1], 'OLD_PROVIDER_FRAME_CHANGED')
    return {'runtimeCustodyVerified': True, 'bootCoordinatorVerified': True, 'activeCoordinationState':'QUIESCED',
            'providerSetsEmpty':True,'oldRuntimeGenerationPreserved':True,'providerGenerationReady':False,
            'startupReady':False,'leaseAuthorized':False,'startAuthorized':False,'readOnly':True,
            'providerCalls':0,'realRebootProven':False,'notReleaseAcceptance':True}


def systemctl(arguments):
    need(arguments == ['daemon-reload'] or (len(arguments) == 4 and arguments[0] == 'show'
         and arguments[1] in ('docker.service','ouf-semantic-boot-guard.service')
         and arguments[2].startswith('--property=') and arguments[3] == '--no-pager'), 'BOUNDED_SYSTEMD_COMMAND_REQUIRED')
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(['/usr/bin/systemctl', *arguments], stdin=subprocess.DEVNULL,
            stdout=output, stderr=subprocess.DEVNULL, timeout=15, env=ENV)
        output.seek(0); raw = output.read(65537)
    need(result.returncode == 0 and len(raw) <= 65536, 'SYSTEMD_COMMAND_FAILED')
    return raw.decode('utf-8')


PROPERTIES = ('LoadState','ActiveState','SubState','MainPID','ControlPID','NeedDaemonReload','FragmentPath',
              'DropInPaths','ExecStart','ExecStartPre','User','Group','RootDirectory','RootImage','ProtectSystem',
              'ReadWritePaths','ReadOnlyPaths','InaccessiblePaths','PrivateNetwork','PrivateUsers')


def empty_guard_prestart():
    """Prove an empty command array; systemctl may omit empty structured values."""
    args = ['/usr/bin/busctl', '--system', '--no-pager', 'get-property',
            'org.freedesktop.systemd1',
            '/org/freedesktop/systemd1/unit/ouf_2dsemantic_2dboot_2dguard_2eservice',
            'org.freedesktop.systemd1.Service', 'ExecStartPre']
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=output,
                                stderr=subprocess.DEVNULL, timeout=15, env=ENV)
        output.seek(0); raw = output.read(65537)
    need(result.returncode == 0 and raw == b'a(sasbttttuii) 0\n',
         'EMPTY_GUARD_PRESTART_NOT_PROVEN')


def loaded(command, run=systemctl, prove_empty=empty_guard_prestart):
    result = {}
    for unit, prop in (('ouf-semantic-boot-guard.service','ExecStart'), ('docker.service','ExecStartPre')):
        raw = run(['show',unit,'--property='+','.join(PROPERTIES),'--no-pager'])
        rows = {}
        for line in raw.splitlines():
            key, sep, value = line.partition('='); need(sep and key not in rows, 'TYPED_SYSTEMD_METADATA_REQUIRED'); rows[key] = value
        # Only the observed guard omission has a typed fallback. Never default
        # unknown/missing fields, or Docker's required pre-start command, to empty.
        if unit == 'ouf-semantic-boot-guard.service' and set(PROPERTIES)-set(rows) == {'ExecStartPre'}:
            prove_empty()
            rows['ExecStartPre'] = ''
        need(set(rows) == set(PROPERTIES) and rows['LoadState'] == 'loaded'
             and rows['NeedDaemonReload'] == 'no' and rows['ControlPID'] == '0', 'SETTLED_LOADED_SYSTEMD_UNITS_REQUIRED')
        commands = re.findall(r'argv\[\]=(.*?) ;', rows[prop])
        need(commands.count(command) == 1 and (unit == 'docker.service' or commands == [command]), 'EXACT_LOADED_BOOT_COMMAND_REQUIRED')
        need(not any('run_semantic_coordinated_boot_guard.py' in value and value != command for value in commands), 'MIXED_BOOT_COMMANDS_REFUSED')
        if unit == 'docker.service':
            need(rows['ActiveState'] == 'active' and rows['SubState'] == 'running' and int(rows['MainPID']) > 1, 'DOCKER_MUST_REMAIN_RUNNING')
        else:
            need(rows['FragmentPath'] == str(UNITS['guard.service']) and rows['MainPID'] == '0'
                 and rows['User'] in ('','root') and rows['Group'] in ('','root')
                 and not rows['RootDirectory'] and not rows['RootImage']
                 and rows['PrivateNetwork'] == 'no' and rows['PrivateUsers'] == 'no', 'HOST_ROOT_BOOT_UNIT_REQUIRED')
        result[unit] = rows
    need(str(UNITS['docker-drop-in.conf']) in result['docker.service']['DropInPaths'].split(), 'SELECTED_DOCKER_DROPIN_NOT_LOADED')
    return result


def command_for(root, profile_hash):
    return '/usr/bin/python3 -I -B '+str(root / 'source/scripts/run_semantic_coordinated_boot_guard.py')+' --configuration '+str(root / 'boot-profile.json')+' --configuration-sha256 '+profile_hash


def rewrite(raw, directive, before, after):
    lines = raw.decode('utf-8').splitlines(keepends=True)
    positions = [i for i, line in enumerate(lines) if line.startswith(directive+'=')]
    need(len(positions) == 1 and lines[positions[0]].strip() == directive+'='+before, 'EXACT_PREVIOUS_UNIT_COMMAND_REQUIRED')
    lines[positions[0]] = directive+'='+after+'\n'
    return ''.join(lines).encode()


def path_covered(path, entries):
    return any(Path(path) == Path(v.removeprefix('-')) or Path(path).is_relative_to(Path(v.removeprefix('-')))
               for v in entries.split() if v.removeprefix('-').startswith('/'))


def unit_plan(old, old_command, new_command, metadata, stage=STAGED):
    new = {name:rewrite(raw, 'ExecStart' if name == 'guard.service' else 'ExecStartPre', old_command, new_command) for name,raw in old.items()}
    guard = metadata['ouf-semantic-boot-guard.service']
    need(not path_covered(stage, guard['InaccessiblePaths']) and not path_covered(stage, guard['ReadOnlyPaths']), 'STAGED_BOOT_PATH_INACCESSIBLE')
    permission_added = guard['ProtectSystem'] == 'strict' and not path_covered(stage, guard['ReadWritePaths'])
    if permission_added:
        # One exact private directory, scoped to this unit's existing Service section.
        raw = new['guard.service'].decode(); need(raw.count('[Service]') == 1, 'ONE_SERVICE_SECTION_REQUIRED')
        raw = raw.replace('[Service]', '[Service]\nReadWritePaths='+str(stage), 1); new['guard.service'] = raw.encode()
    return new, permission_added


def same_process(before, after):
    return before['docker.service']['MainPID'] == after['docker.service']['MainPID']


def verify_loaded_delta(before, after, command, permission_added):
    need(same_process(before, after), 'DOCKER_PID_CHANGED')
    for unit in before:
        allowed = {'ExecStart'} if unit.startswith('ouf-') else {'ExecStartPre'}
        if unit.startswith('ouf-') and permission_added:
            allowed.add('ReadWritePaths')
            need(set(after[unit]['ReadWritePaths'].split()) == set(before[unit]['ReadWritePaths'].split()) | {str(STAGED)}, 'BOOT_WRITE_SCOPE_CHANGED')
        need(all(before[unit][k] == after[unit][k] for k in PROPERTIES if k not in allowed), 'UNRELATED_LOADED_UNIT_METADATA_CHANGED')


def replace(c, path, before, after):
    need(c.p.read_private(path) == before, 'FOREIGN_PUBLICATION_FILE_PRESERVED')
    fd, temporary = tempfile.mkstemp(prefix='.ouf-boot-', dir=path.parent); temp = Path(temporary)
    try:
        with os.fdopen(fd, 'wb') as stream: stream.write(after); stream.flush(); os.fsync(stream.fileno())
        need(c.p.read_private(path) == before, 'PUBLICATION_FILE_CHANGED_BEFORE_RENAME')
        os.replace(temp, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if temp.exists(): temp.unlink()


def publish(c, entries, reload, verify):
    for e in entries: need(c.p.read_private(e['path']) == e['old'], 'PUBLICATION_INPUT_CHANGED')
    for e in entries: replace(c, e['path'], e['old'], e['new'])
    reload(); verify()


def observe(receipt, legacy=None):
    """Read-only observer invoked by the unchanged pointer-aware v3 reader."""
    c = dependency(); root = c.s.exact_path(receipt['directory'])
    need(root.parent == c.m.SNAPSHOTS and root.name.startswith('semantic-coordinated-boot-install-successor-')
         and receipt['schema'] == 'ouf.discovery-successor-boot-installation.v1'
         and receipt['state'] == 'INSTALLED' and receipt['stagePreparationSha256'] == PREPARATION_SHA,
         'EXACT_SUCCESSOR_BOOT_INSTALLATION_REQUIRED')
    sealed(c, root / 'transition-source.py', receipt['observerHash'])
    old = sealed(c, root / 'previous/active-pointer.json', receipt['previousPointerSha256']); ctx = context(c, old)
    for name, path in UNITS.items(): sealed(c, path, receipt['artifactHashes'][name])
    need(receipt['guardCommand'] == command_for(STAGED, PROFILE_SHA), 'SUCCESSOR_COMMAND_CHANGED')
    loaded(receipt['guardCommand'])
    with tempfile.TemporaryDirectory(prefix='discovery-boot-observe-', dir=CLAIM.parent) as tmp, locks(c, ctx):
        readiness = native_guard(c, ctx, Path(tmp))
    readiness.update(schema='ouf.semantic-runtime-readiness.v4', runtimeState='SUCCESSOR_BOOT_BOUND_OLD_PROVIDERS_STOPPED')
    return readiness


def main():
    report = {'schema':'ouf.discovery-successor-boot-activation.v1','status':'HELD','observedAt':datetime.now(timezone.utc).isoformat(),
        'serviceStartDispatched':False,'serviceStops':0,'dockerRestartDispatched':False,'nftWrites':0,
        'databaseRequests':0,'s3Requests':0,'providerRequests':0,'tokenRequests':0,'dnsQueries':0,'businessRequestsIssued':0,
        'credentialFileContentsRead':0,'credentialValuesEmitted':False,'oldRuntimeJournalWrites':0,
        'oldRuntimeConfigurationChanged':False,'newGenerationAdmitted':False,'providerReady':False,
        'leaseAuthorized':False,'startAuthorized':False,'automaticReplayAllowed':False,'automaticRollback':False,
        'publicationAttempted':False,'activeInstallationPointerChanged':False,'operationIntentPresent':False}
    work = None
    def deadline(*_): raise RuntimeError('BOOT_ACTIVATION_DEADLINE')
    signal.signal(signal.SIGALRM, deadline); signal.alarm(180)
    try:
        need(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode, 'ISOLATED_ROOT_REQUIRED')
        os.umask(0o077); c = dependency(); report['phase'] = 'VERIFY_COMPLETED_SUCCESSOR'
        need(not os.path.lexists(CLAIM), 'EXISTING_ACTIVATION_INTENT_PRESERVED')
        verify_prepublication_hold(c.p.read_private(HELD_RESULT))
        report['reconciledPrepublicationHold'] = True
        old_pointer = c.p.read_private(POINTER); ctx = context(c, old_pointer)
        work = Path(tempfile.mkdtemp(prefix='discovery-boot-activation-', dir=CLAIM.parent)); report['privateEvidenceDirectory'] = str(work)
        with locks(c, ctx):
            report['phase'] = 'VERIFY_NATIVE_AND_LOADED_BOOT_BINDINGS'; native_guard(c, ctx, work)
            pointer = c.l.parse(old_pointer)
            prior = c.l.parse(sealed(c, c.s.exact_path(pointer['receiptFile']), pointer['receiptHash']))
            old = {name:sealed(c, path, prior['artifactHashes'][name]) for name,path in UNITS.items()}
            old_command = command_for(ctx.oldroot, sha(c.p.read_private(ctx.oldroot / 'boot-profile.json')))
            before = loaded(old_command); new_command = command_for(STAGED, PROFILE_SHA)
            new, permission_added = unit_plan(old, old_command, new_command, before)
            helper = Path('/usr/local/sbin/ouf-discovery-preflight')
            # v3 already dispatches a sealed observer through this exact pointer schema.
            helper_raw = helper.read_bytes()
            need(sha(helper_raw) == '65c8caa661005a7bf4bfe7eb1c5f45932a32c3e024095db861882f6c52998618', 'UNCHANGED_V3_POINTER_READER_REQUIRED')
            self_raw = Path(__file__).read_bytes()
            report['phase'] = 'PREPARE_EXACT_BOOT_PUBLICATION'
            os.mkdir(CLAIM, 0o700); report['operationIntentPresent'] = True
            c.p.save(CLAIM / 'intent.json', encoded({'stagePreparationSha256':PREPARATION_SHA,'providerStartAllowed':False,'evidenceDirectory':str(work)}))
            root = Path(tempfile.mkdtemp(prefix='semantic-coordinated-boot-install-successor-', dir=c.m.SNAPSHOTS))
            report['installationDirectory'] = str(root)
            for folder in ('previous','prepared','helpers','helpers/core'): (root / folder).mkdir(mode=0o700)
            c.p.save(root / 'transition-source.py', self_raw)
            helpers = helper_pins(c)
            for name, digest in helpers.items():
                raw = Path(__file__).with_name(name).read_bytes() if '/' not in name else (Path(__file__).parent / name).read_bytes()
                need(sha(raw) == digest, 'DELIVERY_HELPER_CHANGED'); c.p.save(root / 'helpers' / name, raw)
            for name in UNITS: c.p.save(root / 'previous' / name, old[name]); c.p.save(root / 'prepared' / name, new[name])
            c.p.save(root / 'previous/active-pointer.json', old_pointer)
            c.p.save(work / 'loaded-before.private.json', encoded(before))
            receipt = {'schema':'ouf.discovery-successor-boot-installation.v1','state':'INSTALLED','directory':str(root),
                'stageDirectory':str(STAGED),'stagePreparationSha256':PREPARATION_SHA,'configurationHash':OWNER_SHA,
                'bootProfileHash':PROFILE_SHA,'guardCommand':new_command,'observerHash':sha(self_raw),
                'artifactHashes':{k:sha(v) for k,v in new.items()},'previousPointerSha256':sha(old_pointer),
                'leaseAuthorized':False,'startAuthorized':False,'providerGenerationReady':False}
            c.p.save(root / 'installation-receipt.json', encoded(receipt))
            proposed_pointer = encoded({'schema':'ouf.semantic-coordinated-boot-pointer.v1','receiptFile':str(root / 'installation-receipt.json'),
                'receiptHash':sha(encoded(receipt)),'observerFile':str(root / 'transition-source.py'),'observerHash':sha(self_raw)})
            report['phase'] = 'PUBLISH_BOOT_COMMANDS'; report['publicationAttempted'] = True
            c.p.save(CLAIM / 'publication-intent.json', encoded({'installationDirectory':str(root),'previousPointerSha256':sha(old_pointer)}))
            entries = [{'path':UNITS[k],'old':old[k],'new':new[k]} for k in UNITS]
            def verify(): verify_loaded_delta(before, loaded(new_command), new_command, permission_added)
            publish(c, entries, lambda:systemctl(['daemon-reload']), verify)
            report['serviceConfigurationChanged'] = True; report['daemonReloadDispatched'] = True
            context(c, old_pointer); native_guard(c, ctx, work, terminal=False)
            need(helper.read_bytes() == helper_raw, 'POINTER_READER_CHANGED')
            report['phase'] = 'PUBLISH_ACTIVE_BOOT_POINTER'
            report['activeInstallationPointerChangeAttempted'] = True
            report['activeInstallationPointerChanged'] = None
            replace(c, POINTER, old_pointer, proposed_pointer); report['activeInstallationPointerChanged'] = True
            need(c.p.read_private(POINTER) == proposed_pointer, 'POINTER_READBACK_FAILED')
            for name,path in UNITS.items(): need(c.p.read_private(path) == new[name], 'UNIT_READBACK_FAILED')
        report['phase'] = 'VERIFY_INSTALLED_OBSERVER'
        observer_raw = sealed(c, root / 'transition-source.py', sha(self_raw))
        ns = {'__name__':'installed_successor_boot_observer','__file__':str(root / 'transition-source.py')}
        exec(compile(observer_raw, ns['__file__'], 'exec'), ns)
        readiness = ns['observe'](receipt)
        need(readiness['bootCoordinatorVerified'] and c.p.read_private(POINTER) == proposed_pointer, 'INSTALLED_OBSERVER_READBACK_FAILED')
        verify_loaded_delta(before, loaded(new_command), new_command, permission_added)
        report.update(status='DISCOVERY_SUCCESSOR_BOOT_BOUND',phase='COMPLETE',activeCoordinationState='QUIESCED',
            loadedBootCommandsVerified=True,dockerPidUnchanged=True,containerFramesUnchanged=True,
            stagedContextUnchanged=True,historicalContextsPreserved=True,bootWriteDirectoryAdded=permission_added,
            installedObserverPassed=True,v3ReaderUnchanged=True,providerGenerationActivationPending=True)
        c.p.save(CLAIM / 'complete.json', encoded(report)+b'\n')
    except Exception as exc:
        reason = str(exc) if type(exc) is RuntimeError and re.fullmatch('[A-Z][A-Z0-9_]{0,100}', str(exc)) else type(exc).__name__
        report.update(reason=reason,errorLocation=[{'file':Path(f.filename).name,'function':f.name,'line':f.lineno} for f in traceback.extract_tb(exc.__traceback__)[-3:]])
        if report['publicationAttempted']:
            report['publicationOutcome'] = 'INCOMPLETE_RECONCILIATION_REQUIRED'
    finally:
        signal.alarm(0)
        if work is not None: c.p.save(work / 'result.json', encoded(report)+b'\n')
    print(json.dumps(report,sort_keys=True)); return 0 if report['status'] == 'DISCOVERY_SUCCESSOR_BOOT_BOUND' else 1


if __name__ == '__main__': sys.exit(main())
