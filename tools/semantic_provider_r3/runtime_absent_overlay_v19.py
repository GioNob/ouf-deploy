"""Preserve runc's stale-task protocol after a terminal epoch is cleaned."""
from tools.semantic_provider_operation.authorization import require

from .driver_denial_overlay_v16 import RUNTIME


FORWARD = '''def forward_absent_cleanup(config, argv):
    # Keep Docker's argv (including its log options) and runc's exit status.
    # Bound the diagnostic relayed to containerd, as for the state probes.
    with tempfile.TemporaryFile() as errors:
        result = subprocess.run([config['runtimePath'], *argv], stderr=errors, env=ENV, timeout=10)
        errors.seek(0)
        sys.stderr.buffer.write(errors.read(16384))
    return result.returncode


'''


def sources_v19(sources, source_map):
    """Apply only to the emitted runtime, before the final composition seal."""
    path = source_map[RUNTIME]
    raw = sources[path]

    # Keep the source's own line endings (a CRLF working tree must not change the anchors).
    eol = b'\r\n' if b'\r\n' in raw else b'\n'

    def edit(old, new):
        nonlocal raw
        before = old.encode('utf-8').replace(b'\n', eol)
        require(raw.count(before) == 1, 'R3_V19_SOURCE_CONTRACT_DRIFT')
        raw = raw.replace(before, new.encode('utf-8').replace(b'\n', eol))

    edit("""def inactive(config, cid, operation, root, argv):
    require(operation in ('state','delete'), 'RUNTIME_PHASE_INACTIVE')
""", FORWARD + """def inactive(config, cid, operation, root, argv, *, deleted_cleanup=False):
    require(deleted_cleanup or operation in ('state','delete'), 'RUNTIME_PHASE_INACTIVE')
""")
    edit("""    require(result.returncode == 1 and missing, 'INACTIVE_RUNTIME_ABSENCE_UNPROVEN')
    return subprocess.run""", """    require(result.returncode == 1 and missing, 'INACTIVE_RUNTIME_ABSENCE_UNPROVEN')
    if deleted_cleanup:
        verify_files(config)
        return forward_absent_cleanup(config, argv)
    return subprocess.run""")
    edit("""        if not failed and operation in ('state', 'delete')""", """        if (record is not None and record['state'] == 'DELETED' and record['bootId'] == boot
                and operation in ('kill', 'delete')):
            require(record['runtimeRoot'] == str(root), 'EPOCH_RUNTIME_ROOT_DRIFT')
            return inactive(config, cid, operation, root, argv, deleted_cleanup=True)
        if not failed and operation in ('state', 'delete')""")
    edit("""                    require(receipt is None or state is None, 'FAILED_EPOCH_CONTAINER_AFTER_CLEANUP')
                    if state is None:""", """                    require(receipt is None or state is None, 'FAILED_EPOCH_CONTAINER_AFTER_CLEANUP')
                    if receipt is not None and state is None and operation in ('kill', 'delete'):
                        stable_files()
                        return forward_absent_cleanup(config, argv)
                    if state is None:""")
    return {**sources, path: raw}
