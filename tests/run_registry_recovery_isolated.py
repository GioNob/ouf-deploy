"""Run unchanged recovery modules in fresh, explicitly isolated interpreters.

The sealed native loaders reject already loaded application modules. Discovery
must therefore happen in each child, never in the orchestration process.
"""
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUITES = {
    'components': ('tools/semantic_registry_recovery_execution/tests', 'test*.py'),
    'paused-binding': ('tests', 'test_paused_workload_binding.py'),
    'retained-checkpoint': ('tests', 'test_file_only_retained_checkpoint.py'),
    'compiler': ('tests', 'test_file_only_frame_compiler.py'),
    'acceptance': ('tests', 'test_paused_node_acceptance_native.py'),
    'mount': ('tests', 'test_renewable_token_mount.py'),
}

if __name__ == '__main__':
    assert sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
    directory, pattern = SUITES[sys.argv[1]]
    if len(sys.argv) == 2:
        files = sorted((ROOT / directory).glob(pattern))
        assert files, 'No regression modules selected'
        failed = []
        for path in files:
            outcome = subprocess.run([sys.executable, '-I', '-B', '-S', __file__,
                                      sys.argv[1], path.name], check=False)
            if outcome.returncode:
                failed.append(path.name)
        print('MODULE_PROCESS_ISOLATION', len(files), 'FAILED', failed, flush=True)
        raise SystemExit(bool(failed))
    assert len(sys.argv) == 3 and Path(sys.argv[2]).name == sys.argv[2]
    assert (ROOT / directory / sys.argv[2]) in (ROOT / directory).glob(pattern)
    # Ubuntu's root-managed apt dependency is exposed explicitly for crypto test
    # fixtures; site initialization, user packages and startup hooks stay off.
    sys.path.extend([str(ROOT), '/usr/lib/python3/dist-packages'])
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.discover(str(ROOT / directory), pattern=sys.argv[2]))
    raise SystemExit(not result.wasSuccessful())
