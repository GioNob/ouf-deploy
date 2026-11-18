"""Read the selected, authenticated R3 closure under the retained locks."""
from contextlib import ExitStack, contextmanager
from pathlib import Path
import types

from tools.semantic_provider_routes import custody as C, publication as P
from tools.semantic_provider_routes.routes import canonical, decode, require, sha


RUNTIME_PINS = ('r3_wrapper_sha256', 'r3_runtime_sha256', 'r3_configuration_sha256', 'r3_head_sha256')


@contextmanager
def fenced():
    with ExitStack() as stack:
        for cid in sorted(P.CIDS.values()):
            stack.enter_context(C.locked(P.INSTALL / 'registry' / cid / 'operation.lock'))
        stack.enter_context(C.locked(P.GUARD))
        stack.enter_context(C.locked(P.AUTHORIZATION, is_directory=True))
        yield


def observe_r3(pins):
    version = pins.r3_version
    require(type(version) is int and version >= 1, 'R3_INSTALLATION_VERSION_INVALID')
    code = P.INSTALL if version == 1 else P.INSTALL / 'versions' / str(version)
    C.directory(code, private=True)
    configuration = code / 'runtime-configuration.json'
    cfg_raw = C.read(configuration, pins.r3_configuration_sha256)
    cfg = decode(cfg_raw)
    runtime_path = code / 'source' / P.RUNTIME
    wrapper = (f'#!/bin/sh\nexec {cfg["pythonPath"]} -I -B {runtime_path} '
               f'--configuration {configuration} "$@"\n').encode('ascii')
    require(C.read(P.WRAPPER, pins.r3_wrapper_sha256, metadata=(0, 0, 0o755)) == wrapper,
            'R3_INSTALLED_WRAPPER_UNPROVEN')
    raw = C.read(runtime_path, pins.r3_runtime_sha256)
    runtime = types.ModuleType('_config_publish_installed_runtime')
    runtime.__file__ = str(runtime_path)
    exec(compile(raw, str(runtime_path), 'exec'), vars(runtime))
    cfg, loaded = runtime.load_configuration(configuration)
    require(loaded == cfg_raw, 'R3_CONFIGURATION_CHANGED')
    op = cfg['operation']
    settings = decode(C.read(P.ROOT / 'ops/vps/r3-settings.json', P.SETTINGS_SHA))
    require(cfg['registryRoot'] == str(P.INSTALL / 'registry')
            and op['authorizationRoot'] == str(P.AUTHORIZATION)
            and {item['role']: cid for cid, item in cfg['candidates'].items()} == P.CIDS
            and cfg['opensslBinding'] == settings['opensslBinding']
            and all(op[key] == settings[key] for key in ('anchorBinding', 'mandateRoot', 'installationRef',
                                                         'issuerRef', 'entityRef')), 'R3_CONFIGURATION_UNPROVEN')
    # The pinned configuration pins the version-specific authorization, epoch
    # and mandate modules. verify_files checks these before loading any of them.
    runtime.verify_files(cfg)
    authorization, epochs = runtime.operation_modules(cfg)
    heads = [runtime.authorization_head(cfg, cfg_raw, cid, authorization) for cid in sorted(P.CIDS.values())]
    head = heads[0]
    require(head == heads[1] and head['decision'] == 'OPERATE' and head['sequence'] == version
            and head['sha256'] == pins.r3_head_sha256, 'R3_OPERATE_HEAD_UNPROVEN')
    historical = {}
    for role, cid in P.CIDS.items():
        current = epochs.current(cfg['registryRoot'], cid)
        require(current is None or current['state'] in epochs.TERMINAL, 'R3_EPOCH_NOT_TERMINAL')
        historical[role] = sha(canonical(current))
    supervisor = decode(runtime.bound_bytes(cfg['leaseQuiesce']['configuration']))
    lease = supervisor['coordinator']
    owner = decode(runtime.bound_bytes(lease['ownerConfiguration']))
    require(lease['journalPath'] == owner['journalFile']
            and lease['commonLockPath'] == owner['commonLockFile'] == str(P.GUARD),
            'R3_COORDINATOR_BINDING_UNPROVEN')
    journal_raw = C.read(lease['journalPath'])
    journal = decode(journal_raw)
    require(journal['state'] == 'QUIESCED' and journal['leaseAuthorized'] is False
            and journal['startAuthorized'] is False and
            all(journal.get(key) == owner['binding'][key] for key in
                ('transactionId', 'configurationHash', 'leaseStructureHash')), 'R3_LEASE_NOT_QUIESCED')
    require(C.read(P.WRAPPER, pins.r3_wrapper_sha256, metadata=(0, 0, 0o755)) == wrapper,
            'R3_INSTALLED_WRAPPER_CHANGED')
    return {'version': version, 'configurationSha256': pins.r3_configuration_sha256,
            'wrapperSha256': pins.r3_wrapper_sha256, 'runtimeSha256': pins.r3_runtime_sha256,
            'epochHashes': historical,
            'authorization': {key: head[key] for key in ('sequence', 'sha256', 'decision')},
            'lease': {'state': journal['state'], 'sha256': sha(journal_raw)}}


def safety(docker, pins, entry):
    authority = observe_r3(pins)
    inventory, rows = C.mount_scan(docker, P.CIDS, entry.source)
    require(all(row['HostConfig']['RestartPolicy']['Name'] == 'no' for row in rows.values()),
            'PROVIDER_AUTO_RESTART_CONFIGURED')
    mounts = rows[P.CIDS[entry.role]]['Mounts']
    matches = [mount for mount in mounts if mount['Destination'] == entry.target]
    require(len(matches) == 1 and matches[0]['Type'] == 'bind'
            and matches[0]['Source'] == str(entry.source) and matches[0]['RW'] is False,
            'CONFIGURATION_MOUNT_UNPROVEN')
    return {'r3': authority, 'docker': inventory, 'dockerBinary': P.binding(C.DOCKER, C.DOCKER_SHA),
            'providerFrameHashes': {role: sha(canonical(rows[cid])) for role, cid in P.CIDS.items()}}, rows
