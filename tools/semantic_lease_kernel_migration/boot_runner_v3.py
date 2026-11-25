"""G3 runner. dispatch() executes this file without a package, under common flock."""
import ctypes
import os
from pathlib import Path
import sys
import types
from uuid import uuid4


def _journal_module(receipt, api):
    # No sys.path additions: every executable byte is read with its closure pin.
    package = types.ModuleType('_sealed_lease_g3')
    package.__path__ = []
    sys.modules[package.__name__] = package
    package.boot_dispatcher = api
    sys.modules[package.__name__ + '.boot_dispatcher'] = api
    for name in ('g3_contract', 'g3_journal'):
        relative = 'source/tools/' + name + '.py'
        path = Path(receipt['directory']) / relative
        raw = api.private(path, receipt['closure'][relative])
        module = types.ModuleType(package.__name__ + '.' + name)
        module.__file__, module.__package__ = str(path), package.__name__
        sys.modules[module.__name__] = module
        exec(compile(raw, str(path), 'exec'), module.__dict__)
        setattr(package, name, module)
    return package.g3_journal


def _replay_current(state, receipt):
    api = state.api
    tables = state.tables()
    api.need(tables is not None, 'G3_SEAL_DRIFT')
    if state.journal['state'] == 'QUIESCED':
        seal_raw = api.private(state.seal_path)
        state.verify(api.document(seal_raw), tables)
        # First activation on the boot of the 2->3 migration.
        if not os.path.lexists(state.directory):
            initial = receipt['initialSeal']
            api.need(api.sha(seal_raw) == receipt['closure'][initial], 'G3_BINDING')
            return
        guard = state.guard(tables)
        state.verify_completion(guard, seal_raw)
    else:
        state.guard(tables)


def _rename_exclusive(source, target):
    """Publish a staged file or directory without replacing an existing receipt."""
    if os.name == 'nt':
        os.rename(source, target)  # Windows rename fails if the target exists.
        return
    rename = ctypes.CDLL(None, use_errno=True).renameat2
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    at_fdcwd, rename_noreplace = -100, 1  # Linux ABI; both paths are absolute.
    if rename(at_fdcwd, os.fsencode(source), at_fdcwd, os.fsencode(target), rename_noreplace) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), target)


def run(receipt, api):
    journal = _journal_module(receipt, api)
    state = journal.BootState(receipt, api)
    journal.cohort_empty(state.owner, api)
    if state.journal['bootId'] == state.boot_id:
        _replay_current(state, receipt)
        state.confirm_journal()
        return

    directory = state.directory
    if not os.path.lexists(directory):
        staged = directory.parent / ('.boot-' + uuid4().hex)
        api.need(journal.make_directory(api, staged), 'G3_BINDING')
        api.write_once(staged / 'previous.json', state.raw)
        tables = state.tables()
        instance = None
        if tables is not None:
            instance = state.seal(tables)
            state.verify(instance, tables)
        claim = {'bootId': state.boot_id, 'previousSha256': api.sha(state.raw),
                 'mode': 'rebuild' if tables is None else 'present', 'instance': instance}
        api.write_once(staged / 'claim.json', api.canonical(claim))
        _rename_exclusive(staged, directory)
    else:
        tables = state.tables()
    # Also finish a prior rename interrupted before the parent directory sync.
    api.sync(directory.parent)
    api.need(state.previous() == state.raw, 'G3_BINDING')
    claim = api.document(api.private(directory / 'claim.json'))
    api.need(claim['bootId'] == state.boot_id and claim['previousSha256'] == api.sha(state.raw),
             'G3_BINDING')

    guard_path = directory / 'guard.json'
    if journal.optional(api, guard_path) is None:
        if claim['mode'] == 'present':
            state.verify(claim['instance'], tables)
        else:
            api.need(claim['mode'] == 'rebuild' and claim['instance'] is None, 'G3_BINDING')
            if tables is None:
                sources = {k[7:]: v for k, v in receipt['closure'].items() if k.startswith('source/')}
                compiler = api.compiler(Path(receipt['directory']) / 'source', sources)
                rules = compiler.materialize(state.owner['kernel'], empty_provider_sets=True)['nftRules']
                api.command(state.nft, ['-f', '-'], rules.encode('ascii'))
                tables = state.tables()
        instance = state.seal(tables)
        state.verify(instance, tables)
        guard = {'claimSha256': api.digest(claim), 'instance': instance}
        staged = directory / ('.guard-' + uuid4().hex)
        api.write_once(staged, api.canonical(guard))
        _rename_exclusive(staged, guard_path)
    # A prior guard may have died just after rename and before directory fsync.
    api.sync(directory)
    state.block_previous(tables)
