"""Repository inputs of the deployed v27 delivery, independent of checkout EOL."""
from contextlib import contextmanager
from functools import cache, partial
from pathlib import Path
import subprocess
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
REVISION = '685b62527b02e4c278d9b3c96631d791243645a9'


@cache
def sealed_blob(path):
    path = Path(path)
    if path.is_absolute():
        path = path.relative_to(ROOT)
    return subprocess.check_output(['git', 'cat-file', 'blob', f'{REVISION}:{path.as_posix()}'], cwd=ROOT)


@contextmanager
def sealed_legacy_inputs(v12):
    """Bind both readers before v11 creates the authorization used by the migration."""
    base = partial(v12.F.fixture, read_blob=sealed_blob)
    with patch.object(v12.F, 'fixture', base), patch.object(v12, 'blob', sealed_blob):
        yield
