"""Epoch file metadata and allowlisted journal fields."""
from datetime import datetime, timezone
import runpy
import sys
from pathlib import Path

globals().update({k: v for k, v in runpy.run_path(str(Path(__file__).with_name('r3_common.py'))).items() if not k.startswith('__')})


def main():
    role, epoch = arguments(sys.argv[1:], (*ROLES, 'both'), epoch=True)
    cfg = configuration()
    for r, cid in candidates(cfg).items():
        if role not in (r, 'both'):
            continue
        base = epoch_base(cfg, cid, epoch)
        if not base.is_dir():
            emit(role=r, epoch=epoch, code='EPOCH_ABSENT')
            continue
        for path in sorted(base.rglob('*')):
            if not path.is_file() or path.is_symlink():
                continue
            row = {}
            if path.suffix == '.json':
                try:
                    adapter = path == base / 'adapter.json'
                    value = adapter_journal(read(path), cid, epoch) if adapter else document(path)
                    if isinstance(value, dict):
                        row = fields(value, ('state', 'failure', 'reason', 'code', 'mode', 'schema'))
                        if adapter:
                            row.update(driver_denial_fields(value))
                        elif isinstance(value.get('failure'), dict):
                            row['failure'] = fields(value['failure'], ('code', 'reason'))
                except (ValueError, OSError):
                    row = {'code': 'UNREADABLE_JSON'}
            emit(role=r, epoch=epoch, file=str(path.relative_to(base)),
                 mtimeUTC=datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(), **row)
    return 0


if __name__ == '__main__':
    raise SystemExit(entry(main))
