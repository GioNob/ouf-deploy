"""Exact retained candidate bytes on CI Engine; never a production installer.

The frozen plan and staging receipt below are genuine CI records for this
fixture, explicitly NOT a VPS plan, installation authority or HUMAN decision.
The candidate is imported and inspected/created, never started: no IAM/DB call.
"""
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import uuid
import zipfile

BASE = Path(__file__).resolve().parents[1]
SOURCE = '9a374dd07745f059de3ad39757c68f02db6d29c3'
IMAGE = 'sha256:ffc78ca5e7fc1a1941cd4c4347d43e061df97d06c9fca44df0e8a5c47b5b839d'
ZIP_HASH = '6c31a1b5698942ddbb47b96ec1b49860c690c44aac8106beb1ca4b1ed7bba56a'
ARCHIVE_HASH = '19fd036f973e52734d209d20671240f8973cd55d7183968ce605254b94cbd5bb'
CAPABILITIES_HASH = 'f2a6f20ff15969c068b87cbd15cf8485e5680f63123d60e90b58c7a09b7b37ae'
MEMBERS = {'image.tar.gz', 'image-id.txt', 'image-config.json', 'source-commit.txt', 'SHA256SUMS', 'capabilities.json'}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def cli(*args):
    return subprocess.check_output(['docker', *args], stderr=subprocess.PIPE, text=True, timeout=90).strip()


def qualify(download, root, backend):
    assert backend in ('classic', 'containerd') and os.geteuid() == 0
    assert not root.exists()
    root.mkdir(mode=0o700)
    info = json.loads(cli('info', '--format', '{{json .}}'))
    assert info['ServerVersion'] == '29.8.1'
    actual_containerd = ['driver-type', 'io.containerd.snapshotter.v1'] in (info.get('DriverStatus') or [])
    assert actual_containerd == (backend == 'containerd'), 'ACTUAL_ENGINE_STORE_MUST_MATCH_MATRIX'
    assert download.stat().st_size == 9617218 and sha(download.read_bytes()) == ZIP_HASH
    files = {}
    with zipfile.ZipFile(download) as z:
        rows = z.infolist()
        assert len(rows) == len(MEMBERS) and {r.filename for r in rows} == MEMBERS
        for row in rows:
            assert not row.is_dir() and stat.S_IFMT(row.external_attr >> 16) in (0, stat.S_IFREG)
            assert 0 < row.file_size <= (16*1024*1024 if row.filename == 'image.tar.gz' else 2*1024*1024)
            raw = z.read(row)
            assert len(raw) == row.file_size
            files[row.filename] = sha(raw)
            (root/row.filename).write_bytes(raw)
            (root/row.filename).chmod(0o400)
    checksum_rows = (root/'SHA256SUMS').read_text().splitlines()
    expected = dict(line.split('  ')[::-1] for line in checksum_rows)
    assert len(expected) == len(checksum_rows) and set(expected) == MEMBERS-{'SHA256SUMS'}
    assert all(files[name] == value for name, value in expected.items())
    assert files['image.tar.gz'] == ARCHIVE_HASH and files['capabilities.json'] == CAPABILITIES_HASH
    assert (root/'source-commit.txt').read_text().strip() == SOURCE
    assert (root/'image-id.txt').read_text().strip() == IMAGE
    # Staging and fixture plan actually written before their byte hashes bind the
    # archive. These artifacts never masquerade as the target's frozen plan.
    staging = {'schema': 'ouf.synthetic-mcp-candidate-staging-ci.v1', 'sourceCommit': SOURCE,
               'workflowRun': 40284011851, 'artifactId': 12633545900,
               'zipSha256': ZIP_HASH, 'files': files, 'productionRuntimeAccess': False}
    (root/'staged-receipt.json').write_bytes(encoded(staging))
    plan = {'schema': 'ouf.synthetic-mcp-native-plan-ci.v1', 'backend': backend,
            'sourceCommit': SOURCE, 'configurationImageId': IMAGE, 'stagedReceiptHash': sha(encoded(staging)),
            'operations': ['IMPORT_EXACT_NATIVE_IMAGE', 'INSPECT_NATIVE_IMAGE', 'CREATE_UNSTARTED_FIXTURE'],
            'productionRuntimeAccess': False, 'targetUpdateAuthorized': False}
    (root/'frozen-ci-plan.json').write_bytes(encoded(plan))
    spec = importlib.util.spec_from_file_location('custody', BASE/'tools/acquisition_read_native/image_custody.py')
    custody = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(custody)
    source_binding = {'schema': 'ouf.acquisition-image-source-by-qualified-ci-manifest.v1',
                      'sourceCommit': SOURCE, 'imageId': IMAGE, 'compressedArchiveSha256': ARCHIVE_HASH,
                      'stagedReceiptHash': sha((root/'staged-receipt.json').read_bytes()),
                      'frozenPlanHash': sha((root/'frozen-ci-plan.json').read_bytes())}
    # Bound the expanded archive independently of gzip's optional trailing size.
    with gzip.open(root/'image.tar.gz', 'rb') as source, (root/'expanded.tar').open('xb') as out:
        total = 0
        while block := source.read(65536):
            total += len(block)
            assert total <= 64*1024*1024
            out.write(block)
    with (root/'expanded.tar').open('rb') as source:
        archive_hash, _ = custody.hashed(source, 64*1024*1024)
        audit = custody.archive(source, archive_hash, IMAGE, SOURCE, ci_source_binding=source_binding)
        assert audit['imageConfig']['User'] == '10005:10005'
        assert audit['imageConfig']['Entrypoint'] == ['/usr/local/bin/ouf-mcp']
        assert audit['imageConfig']['Cmd'] == ['server']
        assert len(audit['layers']) == 4
        with (root/'native.tar').open('x+b') as out:
            derived = custody.tagless_archive(source, out, audit, containerd=actual_containerd)
    if actual_containerd:
        audit['nativeIdentity'] = custody.native_identity(audit)
    native_id = custody.runtime_image_id(audit)
    assert sha((root/'native.tar').read_bytes()) == derived['derivedArchiveSha256']
    cli('image', 'load', '--input', str(root/'native.tar'))
    observed = json.loads(cli('image', 'inspect', native_id))[0]
    proof = custody.loaded(audit, observed)
    assert not observed.get('RepoTags'), 'TAGLESS_CANDIDATE_REQUIRED'
    fixture = None
    try:
        fixture = cli('create', '--network', 'none', '--name', 'ouf-mcp-denial-native-ci-'+uuid.uuid4().hex[:12], native_id)
        actual = json.loads(cli('inspect', fixture))[0]
        assert actual['Image'] == native_id and actual['State']['Status'] == 'created'
        assert actual['State']['Running'] is False and actual['State']['Pid'] == 0
        for name in ('User', 'Entrypoint', 'Cmd'):
            assert actual['Config'][name] == audit['imageConfig'][name]
        result = {'schema': 'ouf.mcp-denial-candidate-native-ci.v1', 'complete': True, 'backend': backend,
                  'serverVersion': info['ServerVersion'], 'sourceCommit': SOURCE, 'artifactZipSha256': ZIP_HASH,
                  'configurationImageId': IMAGE, 'nativeImageId': native_id,
                  'derivedArchiveSha256': derived['derivedArchiveSha256'], 'rootfsLayerCount': proof['rootfsLayerCount'],
                  'stagedReceiptHash': source_binding['stagedReceiptHash'], 'frozenCiPlanHash': source_binding['frozenPlanHash'],
                  'imageRebuilt': False, 'imageRelabelled': False, 'unstartedContainerConfigVerified': True,
                  'candidateStarted': False, 'applicationReadinessProven': False, 'applicationE2EProven': False,
                  'oauthRequests': 0, 'sqlSessions': 0, 'productionRuntimeAccess': False, 'targetUpdateAuthorized': False}
        (root/'proof.json').write_bytes(encoded(result))
        print(json.dumps(result, sort_keys=True), flush=True)
    finally:
        if fixture:
            cli('rm', fixture)


if __name__ == '__main__':
    assert len(sys.argv) == 4
    qualify(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3])
