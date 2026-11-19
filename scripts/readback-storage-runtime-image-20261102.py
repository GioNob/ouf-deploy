#!/usr/bin/env python3
"""CI-only independent download, no Docker or enclosed executable execution."""
import importlib.util
import json
import os
from pathlib import Path
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
assert os.environ.get('GITHUB_ACTIONS') == 'true', 'CI_ONLY'
spec = importlib.util.spec_from_file_location('verify_runtime_image', ROOT/'scripts/verify-storage-runtime-image-20261102.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        u = urllib.parse.urlsplit(newurl)
        assert u.scheme == 'https' and u.username is None and u.hostname and (
            u.hostname.endswith('.blob.core.windows.net') or u.hostname.endswith('.actions.githubusercontent.com')
            or u.hostname.endswith('.amazonaws.com') or u.hostname == 'api.github.com'), 'ALLOWLISTED_HTTPS_REDIRECT_REQUIRED'
        r = super().redirect_request(req, fp, code, msg, headers, newurl)
        if r is not None:
            r.remove_header('Authorization')
        return r


request = urllib.request.Request(f'https://api.github.com/repos/GioNob/ouf-deploy/actions/artifacts/{m.ARTIFACT}/zip')
request.add_unredirected_header('Authorization', 'Bearer '+os.environ['GH_TOKEN'])
request.add_header('Accept', 'application/vnd.github+json')
archive = ROOT/'runtime-image-original.zip'
with urllib.request.build_opener(Redirect()).open(request, timeout=60) as response, archive.open('xb') as f:
    total = 0
    while block := response.read(1048576):
        total += len(block)
        assert total <= m.ARCHIVE_BYTES, 'BOUNDED_EXACT_ARTIFACT_REQUIRED'
        f.write(block)
print(json.dumps(m.verify(archive, ROOT/'runtime-image-readback'), indent=2))
