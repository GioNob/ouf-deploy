"""Reuse real database/object archive + isolated restore qualification with v4."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


v4 = load('cold_v4', 'scripts/storage-cold-backup-v4.py')
suite = load('cold_restore_suite', 'tests/qualify_storage_cold_backup_native.py')
class BoundDefinitions:
    def __init__(self, namespace):
        self.__dict__ = namespace


suite.b = BoundDefinitions(v4.definitions((ROOT / 'scripts/storage-cold-backup.py').read_bytes()))
if __name__ == '__main__': suite.main()
