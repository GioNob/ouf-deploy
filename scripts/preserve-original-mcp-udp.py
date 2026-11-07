#!/usr/bin/env python3
"""Verify and retain the two original deliveries; no build or target access.

The complete original ZIP and original signed checksum subject remain the
provenance boundary. A subset receipt is not a new installation package.
The workflow verifies the original publisher's signature separately.
"""
import argparse, hashlib, json, os, shutil, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'tools/semantic_policy_token_owner')]
from tools.chatbot_file_cohort.package_custody import extract_cohort
from tools.semantic_application_cutover.image_custody import archive, native_identity

ZIP_SHA = '144699ab7756c8312d49783967cfbb64acc02a617015ad89f5adf51e25a10300'
PRODUCER = '8bff54a52a0ce15daccaf2aee932004f106dd178'
SOURCES = {'mcp': 'f249b3dcc58c2a96742092d90fa09fd90b705bd0',
    'udp': 'b49c0d6f50c574c11684361ce4e8040e9cbddee2'}
NATIVE = {'mcp': 'sha256:4dfefd95c88048b86cc13006bca1b0dbfd173feed12e0e1e32f35691f593eaeb',
    'udp': 'sha256:ae78f604ef485dda3751222ce418e03027d2db87bc49d8cb1faf8de3e2b60b52'}
METADATA = ('COHORT_SHA256SUMS', 'COHORT_SHA256SUMS.sigstore.json', 'cohort-manifest.json', 'source-lock.json')


def require(ok, reason):
    if not ok: raise ValueError(reason)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def preserve(source, output):
    require(os.geteuid() == 0 and not output.exists() and source.is_file() and not source.is_symlink()
        and source.stat().st_size == 1708479761, 'EXACT_ORIGINAL_COHORT_ZIP_REQUIRED')
    output.mkdir(mode=0o700)
    stage = output/'verified-original'; stage.mkdir(mode=0o700)
    # Reuse the installed cohort owner: root-private copy before parsing,
    # exact original ZIP/source lock/producer/run/whole checksum closure.
    package, manifest, origin = extract_cohort(source, ZIP_SHA, PRODUCER, 38584614991, stage)
    records = {v['module']: v for v in manifest['modules']}
    (output/'origin').mkdir(mode=0o700)
    for name in METADATA: shutil.copyfile(package/name, output/'origin'/name)
    observed = {}
    for name, commit in SOURCES.items():
        record = records[name]
        require(record['sourceCommit'] == commit and record['artifactKind'] == 'DOCKER_SAVE',
            'EXACT_ORIGINAL_MODULE_SOURCE_REQUIRED')
        folder = package/name
        package_record = json.loads((folder/'package-record.json').read_bytes())
        candidate = json.loads((folder/'candidate-manifest.json').read_bytes())
        require(candidate == {k: v for k, v in record.items() if k != 'files'}
            and package_record['schema'] == 'ouf.unsigned-offline-candidate-package.v1'
            and package_record['sourceCommit'] == commit and package_record['module'] == name
            and package_record['imageId'] == record['imageId'], 'EXACT_ORIGINAL_PRODUCER_RECORDS_REQUIRED')
        with (folder/'image.docker.tar').open('rb') as image:
            proof = archive(image, record['files']['image.docker.tar'], record['imageId'], commit)
        identity = native_identity(proof)
        shutil.copytree(folder, output/name)
        observed[name] = {'sourceCommit': commit, 'imageId': record['imageId'],
            'nativeImageId': identity['nativeImageId'], 'originalArchiveSha256': record['files']['image.docker.tar'],
            'historicalNativeImageIdReference': NATIVE[name],
            'computedNativeIdentityMatchesHistoricalReference': identity['nativeImageId'] == NATIVE[name],
            'rawPackageHash': digest(package_record), 'deliveryManifestHash': digest(candidate),
            'imageAudit': proof, 'originalFiles': record['files']}
    receipt = {'schema': 'ouf.m2-original-mcp-udp-members.v1', 'originalZipSha256': ZIP_SHA,
        'originalProducer': PRODUCER, 'originalRun': 38584614991, 'originalArtifact': 11907557440,
        'originalOwnerReceipt': origin, 'modules': observed, 'imageRebuilt': False, 'candidateSelectionChanged': False,
        'runtimeImageIdentityAdmitted': False, 'coherentPackageCompositionComplete': False,
        'allComputedNativeIdentitiesMatchHistoricalReferences': all(
            row['computedNativeIdentityMatchesHistoricalReference'] for row in observed.values()),
        'runtimeAuthorityIssued': False, 'targetApplyAuthorized': False, 'releaseAcceptance': False}
    (output/'receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True)+'\n')
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('source', type=Path); parser.add_argument('output', type=Path)
    args = parser.parse_args(); preserve(args.source, args.output)
