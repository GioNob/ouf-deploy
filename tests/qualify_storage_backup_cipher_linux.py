#!/usr/bin/env python3
"""Exercise the new installer/probe with a disposable key, never production data."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

script = Path(__file__).resolve().parents[1] / 'scripts/prepare-storage-backup-cipher-linux.py'
spec = importlib.util.spec_from_file_location('cipher', script)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
root = Path('/var/lib/ouf-cipher-native-fixture')
root.mkdir(mode=0o700)
key = root / 'synthetic-ed25519'
subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True, timeout=15)
public = ' '.join((root / 'synthetic-ed25519.pub').read_text().split()[:2])
recipient_hash = m.digest((public + '\n').encode())
archive = Path(sys.argv[1])
area = root / 'preparation'
age = root / 'age'
original_key_hash = m.digest(key.read_bytes())
try:
    m.prepare(archive, public, '0' * 64, area, age)
    raise AssertionError('Wrong recipient accepted')
except ValueError as e:
    assert str(e) == 'RECIPIENT_DIGEST_MISMATCH'
assert not area.exists() and not age.exists()
try:
    m.binary_from_archive(b'not the pinned archive')
    raise AssertionError('Bad archive accepted')
except ValueError as e:
    assert str(e) == 'PINNED_ARCHIVE_MISMATCH'
result = m.prepare(archive, public, recipient_hash, area, age)
decoded = subprocess.run([str(age), '-d', '-i', str(key), str(area / 'probe.bin.age')],
                         capture_output=True, check=True, timeout=15).stdout
assert len(decoded) == 512 and m.digest(decoded) == result['probeSha256']
assert m.digest(key.read_bytes()) == original_key_hash
assert (area / 'recipient.pub').stat().st_mode & 0o777 == 0o600
assert age.stat().st_mode & 0o777 == 0o755
assert m.digest(age.read_bytes()) == result['ageBinarySha256']
for existing_area, existing_age in [(area, age), (root / 'not-created', age)]:
    try:
        m.prepare(archive, public, recipient_hash, existing_area, existing_age)
        raise AssertionError('Replay/overwrite accepted')
    except ValueError as e:
        assert str(e) == 'EXISTING_PATH_PRESERVED_NO_REPLAY'
assert not (root / 'not-created').exists()
report = {
    'schema': 'ouf.storage-backup-linux-cipher-native.v1', 'status': 'PASS',
    'sourceSha256': hashlib.sha256(script.read_bytes()).hexdigest(),
    'ageArchiveSha256': m.ARCHIVE_SHA, 'ageBinarySha256': result['ageBinarySha256'],
    'linuxLocalDecryptVerified': True, 'wrongRecipientDeniedBeforeWrites': True,
    'wrongArchiveDenied': True, 'replayAndExistingBinaryDenied': True,
    'privateKeyUnchanged': True, 'rootPrivateRecipientVerified': True,
    'targetOperations': 0, 'crossPlatformDecryptProven': False,
    'acceptanceCreditAdded': 0,
}
Path('cipher-native-result.json').write_text(json.dumps(report, sort_keys=True) + '\n')
print(json.dumps(report, sort_keys=True))
