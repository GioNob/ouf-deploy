#!/usr/bin/env python3
"""CI-only byte readback. This script never starts an S3 server or test binary."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
assert os.environ.get('GITHUB_ACTIONS') == 'true', 'CI_ONLY'
OUT = ROOT / 'copy-readback'
OUT.mkdir()


class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        u = urllib.parse.urlsplit(newurl)
        assert u.scheme == 'https' and u.username is None and u.hostname and (u.hostname.endswith('.blob.core.windows.net') or u.hostname.endswith('.actions.githubusercontent.com') or u.hostname.endswith('.amazonaws.com') or u.hostname == 'api.github.com'), 'ALLOWLISTED_HTTPS_REDIRECT_REQUIRED'
        r = super().redirect_request(req, fp, code, msg, headers, newurl)
        if r is not None:
            r.remove_header('Authorization')
        return r


request = urllib.request.Request('https://api.github.com/repos/GioNob/ouf-deploy/actions/artifacts/13168889944/zip')
request.add_unredirected_header('Authorization', 'Bearer ' + os.environ['GH_TOKEN'])
request.add_header('Accept', 'application/vnd.github+json')
path = OUT / 'original.zip'
with urllib.request.build_opener(Redirect()).open(request, timeout=60) as response, path.open('xb') as f:
    total = 0
    while block := response.read(1048576):
        total += len(block)
        assert total <= 4420588, 'BOUNDED_EXACT_ARTIFACT_REQUIRED'
        f.write(block)
spec = importlib.util.spec_from_file_location('verify_copy', ROOT / 'scripts/verify-storage-copy-evidence-20261102.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
result = module.verify(path)
(OUT / 'byte-readback.json').write_text(json.dumps(result, indent=2) + '\n')
with zipfile.ZipFile(path) as z:
    for name in z.namelist():
        if name != 'storage-copy-lab.test':
            (OUT / name).write_bytes(z.read(name))
    (OUT / 'omitted-member.json').write_text(json.dumps({'member': 'storage-copy-lab.test', 'sha256': result['binarySha256'], 'bytes': z.getinfo('storage-copy-lab.test').file_size, 'verifiedFromOriginalArchive': True, 'includedInThisMetadataArchive': False, 'originalArtifactId': 13168889944, 'originalArtifactSha256': result['artifactSha256']}, indent=2) + '\n')
path.unlink()
print(json.dumps(result))
