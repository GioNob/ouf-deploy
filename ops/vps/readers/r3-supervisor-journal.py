"""Bounded journal view with the diagnostic line-redaction filter."""
import runpy
import sys
from pathlib import Path

globals().update({k: v for k, v in runpy.run_path(str(Path(__file__).with_name('r3_common.py'))).items() if not k.startswith('__')})


def main():
    if len(sys.argv) != 1:
        raise ValueError('NO_ARGUMENTS')
    text = command(['/usr/bin/journalctl', '-u', 'ouf-semantic-lease-supervisor-v2',
                    '-q', '--no-pager', '-o', 'short-iso', '-n', '200'])
    for line in text.splitlines()[-200:]:
        if not SENSITIVE.search(line):
            print(line[:300])
    return 0


if __name__ == '__main__':
    raise SystemExit(entry(main))
