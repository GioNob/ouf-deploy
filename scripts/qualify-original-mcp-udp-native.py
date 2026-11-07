#!/usr/bin/env python3
"""Disposable CI: compare original and controlled Docker29 import envelopes.

Only authenticated original archives are loaded. No container is created or
started, and no runtime or application admission is issued.
"""
import hashlib, json, os, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from tools.semantic_application_cutover import image_custody as custody

DOCKER = '/opt/ouf-docker-29/docker'
REFERENCES = {'mcp': 'sha256:4dfefd95c88048b86cc13006bca1b0dbfd173feed12e0e1e32f35691f593eaeb',
    'udp': 'sha256:ae78f604ef485dda3751222ce418e03027d2db87bc49d8cb1faf8de3e2b60b52'}


def require(ok, reason):
    if not ok: raise ValueError(reason)


def docker(*args):
    return subprocess.check_output([DOCKER, *args], timeout=180)


def qualify(root):
    require(os.geteuid() == 0 and os.environ.get('GITHUB_ACTIONS') == 'true', 'DISPOSABLE_HOSTED_CI_ONLY')
    require(docker('version', '--format', '{{.Server.Version}}').strip() == b'29.8.1'
        and docker('info', '--format', '{{.Driver}}').strip() == b'overlayfs', 'EXACT_NATIVE_IMAGE_STORE_REQUIRED')
    receipt = json.loads((root/'receipt.json').read_bytes()); rows = {}
    for module in ('mcp', 'udp'):
        row = receipt['modules'][module]; folder = root/module
        package = json.loads((folder/'package-record.json').read_bytes())
        original = folder/'image.docker.tar'
        with original.open('rb') as stream:
            audit = custody.archive(stream, row['originalArchiveSha256'], row['imageId'], row['sourceCommit'])
        require(audit == row['imageAudit'], 'EXACT_PRESERVED_ORIGINAL_ARCHIVE_REQUIRED')
        docker('load', '--input', str(original))
        loaded = json.loads(docker('image', 'inspect', package['imageTag']))[0]
        require(loaded['Os'] == 'linux' and loaded['Architecture'] == 'amd64'
            and loaded['RootFS'] == {'Type': 'layers', 'Layers': [v['diffId'] for v in audit['layers']]}
            and all(loaded['Config'].get(k) == audit['imageConfig'].get(k) for k in custody.FIELDS),
            'ORIGINAL_NATIVE_LOADED_EXECUTION_OR_ROOTFS_DIFFERS')
        derived = root/(module+'-controlled-native.tar')
        with original.open('rb') as source, derived.open('x+b') as output:
            projection = custody.tagless_archive(source, output, audit, containerd=True)
        identity = custody.native_identity(audit); bound = dict(audit, nativeIdentity=identity)
        docker('load', '--input', str(derived))
        controlled = json.loads(docker('image', 'inspect', identity['nativeImageId']))[0]
        custody.loaded(bound, controlled)
        rows[module] = {'originalArchiveSha256': row['originalArchiveSha256'],
            'sourceCommit': row['sourceCommit'], 'configurationImageId': audit['imageId'],
            'originalLoadedNativeImageId': loaded['Id'], 'controlledNativeImageId': identity['nativeImageId'],
            'historicalNativeImageIdReference': REFERENCES[module],
            'originalNativeMatchesHistoricalReference': loaded['Id'] == REFERENCES[module],
            'controlledNativeMatchesHistoricalReference': identity['nativeImageId'] == REFERENCES[module],
            'bothNativeExecutionAndRootfsProjectionsMatchOriginalBytes': True,
            'originalImageAuditHash': hashlib.sha256(json.dumps(audit, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
            'controlledArchiveSha256': projection['derivedArchiveSha256'], 'imageRebuilt': False}
    proof = {'schema': 'ouf.original-archive-native-import-envelopes.v1',
        'originalCohortZipSha256': receipt['originalZipSha256'], 'docker': '29.8.1',
        'driver': 'overlayfs', 'modules': rows, 'containersCreated': 0, 'containersStarted': 0,
        'targetCalls': 0, 'candidateSelectionChanged': False, 'runtimeImageIdentityAdmitted': False,
        'runtimeAuthorityIssued': False, 'targetApplyAuthorized': False, 'releaseAcceptance': False}
    (root/'native-import-envelopes.json').write_text(json.dumps(proof, indent=2, sort_keys=True)+'\n')
    return proof


if __name__ == '__main__':
    require(len(sys.argv) == 2, 'EXACT_PRESERVED_ROOT_REQUIRED'); qualify(Path(sys.argv[1]))
