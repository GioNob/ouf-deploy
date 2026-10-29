"""Run existing registry regression suites with the runtime's isolation flags."""
import sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
SUITES={'components':('tools/semantic_registry_recovery_execution/tests','test*.py'),
    'paused-binding':('tests','test_paused_workload_binding.py'),
    'retained-checkpoint':('tests','test_file_only_retained_checkpoint.py'),
    'compiler':('tests','test_file_only_frame_compiler.py'),
    'acceptance':('tests','test_paused_node_acceptance_native.py'),
    'mount':('tests','test_renewable_token_mount.py')}
if __name__=='__main__':
    assert sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
    directory,pattern=SUITES[sys.argv[1]]
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.discover(str(ROOT/directory),pattern=pattern))
    raise SystemExit(not result.wasSuccessful())
