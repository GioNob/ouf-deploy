"""CI-only runc facade reproducing a partially published sibling creation.

All runtime commands delegate to real runc. Only list visibility during the
source-owned CREATING phase is delayed; state, namespaces and start stay real.
"""
import json
from pathlib import Path
import subprocess
import sys
import time

configuration = json.loads(Path(__file__).with_suffix('.json').read_bytes())
args = sys.argv[1:]
marker = Path(configuration['marker'])
seen = Path(configuration['seen'])
real = configuration['realRuntime']
cid = configuration['candidate']
if 'create' in args and args[-1] == cid:
    marker.touch(mode=0o600)
    try:
        result = subprocess.run([real, *args])
        if result.returncode == 0:
            time.sleep(1.2)
        sys.exit(result.returncode)
    finally:
        marker.unlink(missing_ok=True)
elif 'list' in args and marker.exists():
    result = subprocess.run([real, *args], stdout=subprocess.PIPE)
    if result.returncode == 0:
        rows = json.loads(result.stdout)
        for row in rows:
            if row.get('id') == cid:
                row['status'] = 'stopped'
                row['pid'] = 0
                seen.touch(mode=0o600)
        sys.stdout.write(json.dumps(rows))
    else:
        sys.stdout.buffer.write(result.stdout)
    sys.exit(result.returncode)
else:
    sys.exit(subprocess.run([real, *args]).returncode)
