#!/usr/bin/env python3
"""Finite nonroot transfer of the two immutable original CI ZIPs."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

SOURCES = {
    'onboarding': ('GioNob/ouf-source-onboarding', '31792893900eb1e9dda314feef9cd4599ee8832a', 212914450,
                   '704bf88695423695777a39910f2b0826e58172ee0085c07f912bb71cfb1201dd', 9),
    'mcp': ('GioNob/ouf-mcp-server', '0e9341af101b705625d556744b9f097837ad29a5', 9619180,
            'dbc4c918f71d0b3bf089c1b4a868ebf11ff9d3c9b1de44530cb6cd3df0cb71d7', 1)}


def validate(role, receipt):
    repository, commit, size, checksum, count = SOURCES[role]
    assert receipt['role'] == role and receipt['repository'] == repository and receipt['deliveryCommit'] == commit
    assert receipt['artifactZipBytes'] == size and receipt['artifactZipSha256'] == checksum and len(receipt['parts']) == count
    assert sum(part['bytes'] for part in receipt['parts']) == size
    for i, part in enumerate(receipt['parts']):
        assert part['name'] == 'candidate.zip.part%02d' % i and type(part['bytes']) is int and 0 < part['bytes'] <= 25165824
        assert re.fullmatch('[a-f0-9]{64}', part['sha256'])
    return repository, commit


def download(folder):
    assert os.geteuid() != 0 and folder.is_absolute() and folder.resolve() == folder
    started = time.monotonic()
    for role in ('onboarding', 'mcp'):
        receipt = json.loads((folder/(role+'-custody.json')).read_bytes()); repository, commit = validate(role, receipt)
        checksum = hashlib.sha256(); size = 0
        with (folder/(role+'.zip')).open('xb') as output:
            os.fchmod(output.fileno(), 0o600)
            for part in receipt['parts']:
                remaining = 720-(time.monotonic()-started); assert remaining > 5
                path = folder/(role+'-'+part['name']); url = 'https://raw.githubusercontent.com/'+repository+'/'+commit+'/image/'+part['name']
                subprocess.run(['curl', '--fail', '--silent', '--show-error', '--location', '--proto', '=https', '--proto-redir', '=https',
                                '--max-redirs', '3', '--connect-timeout', '15', '--max-time', str(min(120, int(remaining))),
                                '--max-filesize', str(part['bytes']), url, '-o', str(path)], check=True, timeout=min(125, remaining))
                raw = path.read_bytes(); assert len(raw) == part['bytes'] and hashlib.sha256(raw).hexdigest() == part['sha256']
                output.write(raw); checksum.update(raw); size += len(raw); path.unlink()
            output.flush(); os.fsync(output.fileno())
        assert size == receipt['artifactZipBytes'] and checksum.hexdigest() == receipt['artifactZipSha256']
        print(json.dumps({'status': 'EXACT_EXISTING_CI_ZIP_DOWNLOADED', 'role': role, 'bytes': size, 'sha256': checksum.hexdigest(),
                          'imageRebuilt': False, 'imageImported': False}), flush=True)


if __name__ == '__main__':
    assert len(sys.argv) == 2
    download(Path(sys.argv[1]))
