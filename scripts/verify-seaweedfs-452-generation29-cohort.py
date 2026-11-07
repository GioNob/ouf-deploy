#!/usr/bin/env python3
"""Bind generation29 image evidence to exactly reverified legal texts, never admission."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


readback = load('generation29_readback', 'scripts/readback-seaweedfs-452-generation29-image.py')
legal = load('legal_text_evidence', 'tools/storage_licenses/evidence.py')
require = legal.require
MANIFEST = readback.candidate.MANIFEST
MANIFEST_PATH = readback.candidate.ROOT / readback.candidate.MANIFEST_PATH
HISTORICAL_SHA = '851d65dc1ac3788178978b9effc04c257475492ad6d3e5dcc04346d033288c67'
DELTA_SHA = '7cf2b9dc596ded071c9c75f1bfeb87245f443e25984b9cddf8bf4f411791eda2'
UPSTREAM_LICENCE_SHA = 'd789d433cc11da163273d1e39be2e8fa67642f9a58ef220d3f258fa9c14ef613'
OLD_BINARY = '85fa52c68a783f3cf4d54ae6064e7b46d022982c1bef4460616dd76cdc609033'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def canonical(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def git_blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def checked_archive(path, expected_sha, expected_count=None, max_bytes=1024**3):
    require(path.is_file() and not path.is_symlink() and sha(path) == expected_sha,
            'EXACT_ARCHIVE_REQUIRED:' + path.name)
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        require(len(entries) == len({e.filename for e in entries}) <= 10000,
                'UNIQUE_BOUNDED_ARCHIVE_MEMBERS_REQUIRED')
        require(expected_count is None or len(entries) == expected_count,
                'EXACT_ARCHIVE_MEMBER_COUNT_REQUIRED')
        require(sum(e.file_size for e in entries) <= max_bytes, 'ARCHIVE_EXPANSION_BUDGET')
        for entry in entries:
            legal.safe_path(entry.filename)
            require(not entry.is_dir() and not stat.S_ISLNK(entry.external_attr >> 16),
                    'REGULAR_ARCHIVE_MEMBERS_REQUIRED')
        return {e.filename: archive.read(e) for e in entries}


def check_manifest_members(members):
    require('SHA256SUMS' in members, 'CHECKSUM_MANIFEST_REQUIRED')
    sums = readback.checksum_map(members['SHA256SUMS'].decode().splitlines())
    require(set(sums) == set(members) - {'SHA256SUMS', 'provenance.json'},
            'COMPLETE_ARCHIVE_CHECKSUM_CLOSURE_REQUIRED')
    for name, digest in sums.items():
        require(legal.sha(members[name]) == digest, 'LEGAL_ARCHIVE_CHECKSUM_CHANGED:' + name)
    return sums


def binary_modules(raw, manifest=MANIFEST):
    lines = raw.decode().splitlines()
    require(not any(x.startswith('\t=>\t') for x in lines), 'REPLACED_MODULES_NOT_SUPPORTED')
    rows = [x for x in lines if x.startswith('\tdep\t')]
    require(len(rows) == manifest['build']['binaryModuleRows']
            and legal.sha(('\n'.join(rows) + '\n').encode()) == manifest['build']['binaryModuleInventorySha256'],
            'EXACT_REVIEWED_MODULE_INVENTORY_REQUIRED')
    modules = [tuple(row.split('\t')[2:5]) for row in rows]
    require(all(len(row) == 3 and row[2].startswith('h1:') for row in modules)
            and len(modules) == len({row[0] for row in modules}), 'DISTINCT_CHECKSUM_BOUND_MODULES_REQUIRED')
    return modules


def cache_paths(cache, name, version):
    legal.validate_module_identity(name, version)
    escaped = ''.join('!' + c.lower() if 'A' <= c <= 'Z' else c for c in name)
    prefix = cache / 'cache/download' / escaped / '@v' / version
    return Path(str(prefix) + '.zip'), Path(str(prefix) + '.mod')


def verify_parent_supplement(record, archive_path, retained):
    supplement = record['provenance'].get('parentLicenceSupplement')
    require(record['name'] == 'github.com/google/flatbuffers/go' and supplement
            and supplement['commit'] == '3b8644d32c50e86872584829af4b8caf180235ab'
            and supplement['currentBranchUsed'] is False and supplement['treeTruncated'] is False,
            'EXACT_PARENT_LICENCE_SUPPLEMENT_REQUIRED')
    name = supplement['parentLicencePath'];raw = retained[name]
    require(legal.sha(raw) == supplement['parentLicenceSha256']
            and git_blob(raw) == supplement['parentLicenceGitBlob'], 'PARENT_LICENCE_BLOB_CHANGED')
    with zipfile.ZipFile(archive_path) as archive:
        prefix = record['name'] + '@' + record['version'] + '/'
        matched = supplement['moduleFilesMatchedToSameCommit']
        require(len(matched) == len(archive.infolist()), 'ALL_PARENT_MODULE_FILES_REQUIRED')
        for item in matched:
            require(item['path'].startswith('go/'), 'EXACT_PARENT_MODULE_SUBDIRECTORY_REQUIRED')
            raw = archive.read(prefix + item['path'][3:])
            require(legal.sha(raw) == item['sha256'] and git_blob(raw) == item['gitBlob'],
                    'PARENT_MODULE_SOURCE_CHANGED')


def verify_legal_reuse(build_info, historical_path, delta_path, module_cache, source_root, go_root):
    historical = checked_archive(historical_path, HISTORICAL_SHA, 711)
    delta = checked_archive(delta_path, DELTA_SHA, 65)
    check_manifest_members(historical);check_manifest_members(delta)
    inventory = json.loads(historical['inventory.json'])
    prior = json.loads(delta['licence-preflight-receipt.json'])
    require(prior['binarySha256'] == OLD_BINARY and prior['patchCount'] == 15
            and prior['redistributionAccepted'] is False and prior['licenceReview'] == 'OPEN',
            'EXACT_HISTORICAL_TEXT_EVIDENCE_REQUIRED')
    old = {(r['name'], r['version']): r for r in inventory['components']}
    changed = {(r['module'], r['version']): r for r in prior['newModuleVersionEvidence']}
    modules = binary_modules(build_info)
    require(len(modules) == 262, 'EXACT_262_THIRD_PARTY_MODULES_REQUIRED')
    records = [];text_count = 0;archive_bytes = 0;parent_count = 0
    for name, version, gosum in modules:
        key = (name, version)
        require(key in changed or key in old, 'MODULE_HAS_NO_REUSABLE_LEGAL_TEXTS:' + name)
        record = changed.get(key, old.get(key));prov = record['provenance']
        require(prov['path'] == name and prov['version'] == version and prov['sum'] == gosum,
                'MODULE_IDENTITY_OR_SOURCE_SUM_CHANGED:' + name)
        archive, mod = cache_paths(module_cache, name, version)
        require(sha(archive) == prov['zipSha256'], 'MODULE_SOURCE_ZIP_CHANGED:' + name)
        texts, reproduced = legal.module_texts(name, version, archive, mod.read_bytes(), gosum, prov['goModSum'])
        require(reproduced['zipSha256'] == prov['zipSha256'], 'MODULE_ARCHIVE_PROVENANCE_CHANGED')
        retained = {};text_records = []
        for text in record['legalTexts']:
            relative = text.get('path', text.get('sourcePath'));legal.safe_path(relative)
            if key in changed:
                member = 'new-module-texts/' + name + '@' + version + '/' + relative
                raw = delta[member];origin = 'patch15-delta'
            else:
                member = 'texts/' + text['evidencePath'];raw = historical[member];origin = 'historical-corpus'
            require(legal.sha(raw) == text['sha256'] and len(raw) == text['bytes'], 'RETAINED_LEGAL_TEXT_CHANGED')
            retained[relative] = raw
            text_records.append({'path': relative, 'sha256': text['sha256'], 'bytes': len(raw),
                                 'archive': origin, 'member': member})
        if texts != retained:
            require(not texts and len(retained) == 1, 'LEGAL_TEXT_SET_CHANGED:' + name)
            verify_parent_supplement(record, archive, retained);parent_count += 1
        archive_bytes += archive.stat().st_size;text_count += len(retained)
        records.append({'module': name, 'version': version, 'sum': gosum, 'goModSum': prov['goModSum'],
                        'sourceZipSha256': prov['zipSha256'], 'legalTexts': text_records})
    require(text_count == 353 and parent_count == 1, 'EXACT_THIRD_PARTY_TEXT_SET_REQUIRED')
    mpl = json.loads(historical['mpl-source-manifest.json'])['components']
    require(mpl == prior['historicalMplSourceArchivesVerified'] and len(mpl) == 17,
            'EXACT_HISTORICAL_MPL_SOURCE_SET_REQUIRED')
    identities = {(r['module'], r['version']): r for r in records}
    for item in mpl:
        identity = identities[item['name'], item['version']]
        require(item['moduleSourcesModified'] is False and item['redistributionAccepted'] is False
                and legal.sha(historical[item['path']]) == item['sha256'] == identity['sourceZipSha256']
                and item['goSum'] == identity['sum'] and item['goModSum'] == identity['goModSum'],
                'MPL_SOURCE_BYTES_OR_IDENTITY_CHANGED')
    source_texts = []
    for item in prior['rootSourceLegalTexts']:
        raw = (source_root / item['path']).read_bytes()
        require(legal.sha(raw) == item['sha256'] and raw == delta['candidate-source-legal-texts/' + item['path']],
                'ROOT_SOURCE_LEGAL_TEXT_CHANGED:' + item['path'])
        source_texts.append(item)
    actual_paths = {f.relative_to(source_root).as_posix() for f in source_root.rglob('*')
                    if f.is_file() and not f.is_symlink() and '.git' not in f.relative_to(source_root).parts
                    and legal.legal_path(f.relative_to(source_root).as_posix())}
    require(actual_paths == {item['path'] for item in source_texts}, 'ROOT_LEGAL_TEXT_SET_CHANGED')
    require(sha(source_root / 'LICENSE') == UPSTREAM_LICENCE_SHA, 'UPSTREAM_LICENCE_CHANGED')
    stdlib = old['stdlib', 'v1.27.3']
    for item in stdlib['legalTexts']:
        raw = historical['texts/' + item['evidencePath']]
        require(legal.sha(raw) == item['sha256'] and raw == (go_root / item['sourcePath']).read_bytes(),
                'STDLIB_LEGAL_TEXT_CHANGED')
    require(len(stdlib['legalTexts']) == 39, 'EXACT_STDLIB_TEXT_COUNT_REQUIRED')
    unknown = prior['unknownClassifications']
    require(len(unknown) == 3, 'HISTORICAL_UNKNOWN_COUNT_CHANGED')
    for row in unknown:
        found = identities[row['module'], row['version']]
        require(any(t['path'] == row['path'] and t['sha256'] == row['sha256'] for t in found['legalTexts']),
                'UNKNOWN_CLASSIFICATION_TEXT_NOT_IN_GENERATION')
    return {'schema': 'ouf.generation29-legal-text-reuse.v1', 'status': 'EXACT_TEXTS_REVERIFIED_REVIEW_OPEN',
            'thirdPartyModules': 262, 'thirdPartyLegalTexts': 353, 'sourceArchivesRehashedBytes': archive_bytes,
            'moduleGoSumsIndependentlyRecomputed': True, 'moduleSourceZipHashesReverified': True,
            'parentLicenceSupplementReverified': parent_count, 'mplSourceArchivesReverified': 17,
            'rootSourceLegalTexts': source_texts, 'stdlibLegalTextsReverified': 39,
            'stdlibSourceArchiveSha256Historical': prior['stdlib']['sourceArchiveSha256'],
            'historicalCorpusSha256': HISTORICAL_SHA, 'historicalDeltaSha256': DELTA_SHA,
            'binaryModuleInventorySha256': MANIFEST['build']['binaryModuleInventorySha256'],
            'moduleEvidence': records, 'historicalUnknownClassifications': unknown,
            'classificationReusedOnlyForIdenticalTexts': True, 'newClassifierRunClaimed': False,
            'rawPriorVulnerabilityScanTransferred': False, 'rawPriorSpdxTransferred': False,
            'licenceReview': 'OPEN', 'redistributionAccepted': False, 'releaseAdmitted': False,
            'runtimeAuthorityIssued': False, 'targetOperations': 0}


def validate_lock(lock):
    require(lock['schema'] == 'ouf.storage-candidate-lock.v2' and lock['generation'] == 29
            and lock['orderedPatchCount'] == 29 and lock['status'] == 'EVIDENCE_PREPARED_NOT_ADMITTED',
            'GENERATION29_LOCK_REQUIRED')
    require(lock['buildManifest']['sha256'] == sha(MANIFEST_PATH)
            and lock['buildProfile']['binarySha256'] == MANIFEST['build']['binarySha256']
            and lock['buildManifest']['patchedSourceTree'] == MANIFEST['build']['patchedSourceTree']
            and all(lock['buildProfile'][key] == MANIFEST['build'][key] for key in ['go', 'os', 'arch', 'cgo', 'tags', 'compiledPackages'])
            and lock['image']['upstreamLicenceSha256'] == UPSTREAM_LICENCE_SHA,
            'REVIEWED_GENERATION29_BUILD_REQUIRED')
    require(re.fullmatch('[0-9a-f]{40}', lock['producerCommit'])
            and type(lock['qualification']['runId']) is int and lock['qualification']['runId'] > 0
            and type(lock['qualification']['runAttempt']) is int and lock['qualification']['runAttempt'] > 0,
            'REAL_PRODUCER_IDENTITIES_REQUIRED')
    counts = lock['qualification']['rawSeverityCounts']
    require(set(counts) == {'HIGH', 'CRITICAL', 'UNKNOWN', 'MEDIUM', 'LOW'}
            and all(type(v) is int and v >= 0 for v in counts.values()), 'COMPLETE_RAW_SEVERITY_COUNTS_REQUIRED')
    require(lock['releaseAdmitted'] is False and lock['runtimeAuthorityIssued'] is False
            and lock['targetOperations'] == 0, 'NO_ADMISSION_OR_AUTHORITY_REQUIRED')
    require(lock['qualification']['allJobsPassed'] is True
            and lock['qualification']['workflow'] == '.github/workflows/storage-452-generation29-image.yml'
            and lock['qualification']['vulnerabilitySubgate'] == 'PASS_RAW'
            and all(lock['qualification']['rawSeverityCounts'][s] == 0 for s in ['HIGH', 'CRITICAL', 'UNKNOWN']),
            'SUCCESSFUL_GENERATION29_IMAGE_QUALIFICATION_REQUIRED')
    require(lock['licenceRebinding']['path'] == 'evidence/seaweedfs-452-generation29-licence-rebinding-local-20261103.json'
            and re.fullmatch('[0-9a-f]{64}', lock['licenceRebinding']['sha256']),
            'EXACT_GENERATION29_LEGAL_REBINDING_REQUIRED')
    for field in ['producerArtifact', 'independentReadback']:
        item = lock[field]
        require(type(item['id']) is int and item['id'] > 0 and type(item['bytes']) is int and item['bytes'] > 0
                and re.fullmatch(r'sha256:[0-9a-f]{64}', item['digest']), 'EXACT_PUBLISHED_ARTIFACT_REQUIRED')


def verify(lock_path, candidate_zip, hosted_zip, historical_zip, delta_zip, cache, source_root, go_root, output):
    require(not output.exists(), 'NEW_COHORT_OUTPUT_REQUIRED')
    lock = json.loads(lock_path.read_bytes());validate_lock(lock)
    producer = lock['producerArtifact'];hosted = lock['independentReadback']
    require(candidate_zip.stat().st_size == producer['bytes'] and sha(candidate_zip) == producer['digest'][7:],
            'EXACT_GENERATION29_PRODUCER_REQUIRED')
    require(hosted_zip.stat().st_size == hosted['bytes'], 'EXACT_READBACK_ARTIFACT_SIZE_REQUIRED')
    with tempfile.TemporaryDirectory() as directory:
        reproduced_dir = Path(directory) / 'readback'
        reproduced = readback.verify(candidate_zip, reproduced_dir, producer['digest'][7:],
                                     lock['producerCommit'], lock['qualification']['runId'])
        members = checked_archive(hosted_zip, hosted['digest'][7:], 8)
        for name in ['SHA256SUMS', 'assessment.json', 'byte-readback.json', 'provenance.json',
                     'source-SHA256SUMS', 'generation-manifest.json', 'build-source.json']:
            require(members[name] == (reproduced_dir / name).read_bytes(), 'HOSTED_READBACK_DIFFERS:' + name)
        assessment = json.loads(members['assessment.json'])
        for actual, expected in [(reproduced['binarySha256'], lock['buildProfile']['binarySha256']),
                                 (reproduced['ociManifestDigest'], lock['image']['manifestDigest']),
                                 (reproduced['imageConfigDigest'], lock['image']['configDigest'])]:
            require(actual == expected, 'CANDIDATE_LOCK_IMAGE_BINDING_REQUIRED')
        require(assessment['freshScanSha256'] == lock['qualification']['scanSha256']
                and assessment['sbomSha256'] == lock['qualification']['sbomSha256']
                and assessment['rawSeverityCounts'] == lock['qualification']['rawSeverityCounts'],
                'FRESH_GENERATION29_SCAN_BINDING_REQUIRED')
        verification = json.loads(members['publisher-verification.json'])
        require(isinstance(verification, list) and len(verification) == 1, 'EXACT_PUBLISHER_VERIFICATION_REQUIRED')
        verified = verification[0]['verificationResult'];cert = verified['signature']['certificate'];statement = verified['statement']
        require(cert['sourceRepositoryDigest'] == cert['githubWorkflowSHA'] == lock['producerCommit']
                and cert['runnerEnvironment'] == 'github-hosted'
                and cert['githubWorkflowRepository'] == 'GioNob/ouf-deploy', 'PUBLISHER_IDENTITY_CHANGED')
        signer = 'https://github.com/GioNob/ouf-deploy/.github/workflows/storage-452-generation29-image.yml@refs/heads/feat/m2-discovery-complete-profile-20261029'
        require(cert['subjectAlternativeName'] == cert['buildSignerURI'] == cert['buildConfigURI'] == signer
                and cert['buildSignerDigest'] == cert['buildConfigDigest'] == lock['producerCommit'],
                'GENERATION29_SIGNER_WORKFLOW_CHANGED')
        invocation = statement['predicate']['runDetails']['metadata']['invocationId']
        expected_invocation = 'https://github.com/GioNob/ouf-deploy/actions/runs/' + str(lock['qualification']['runId']) + '/attempts/' + str(lock['qualification']['runAttempt'])
        require(invocation == cert['runInvocationURI'] == expected_invocation, 'PUBLISHER_RUN_CHANGED')
        require(statement['subject'] == [{'name': 'SHA256SUMS', 'digest': {'sha256': legal.sha(members['SHA256SUMS'])}}],
                'PUBLISHER_SUBJECT_CHANGED')
        with zipfile.ZipFile(candidate_zip) as archive:
            build_info = archive.read('build-info.txt')
        reuse = verify_legal_reuse(build_info, historical_zip, delta_zip, cache, source_root, go_root)
        reuse.update({'generation': 29, 'binarySha256': reproduced['binarySha256'],
                      'ociManifestDigest': reproduced['ociManifestDigest'], 'producerCommit': lock['producerCommit'],
                      'producerRunId': lock['qualification']['runId'], 'producerArtifactSha256': sha(candidate_zip),
                      'freshScanSha256': assessment['freshScanSha256'], 'freshSpdxSha256': assessment['sbomSha256']})
        require(legal.sha(canonical(reuse)) == lock['licenceRebinding']['sha256']
                and (ROOT / lock['licenceRebinding']['path']).read_bytes() == canonical(reuse),
                'REPRODUCED_LEGAL_REBINDING_DIFFERS')
        result = {'schema': 'ouf.seaweedfs-generation29-cohort.v1', 'status': 'TECHNICAL_COHORT_VERIFIED_NOT_ADMITTED',
                  'generation': 29, 'candidateLockSha256': sha(lock_path), 'producerArtifactSha256': sha(candidate_zip),
                  'independentReadbackSha256': sha(hosted_zip), 'binarySha256': reproduced['binarySha256'],
                  'ociManifestDigest': reproduced['ociManifestDigest'], 'readbackReproduced': True,
                  'publisherVerificationRecordBound': True, 'publisherSignatureReverifiedByThisScript': False,
                  'legalTextRebindingSha256': legal.sha(canonical(reuse)), 'licenceReview': 'OPEN',
                  'redistributionAccepted': False, 'durableImageCustody': 'OPEN', 'releaseAdmitted': False,
                  'runtimeAuthorityIssued': False, 'targetOperations': 0}
        output.mkdir(parents=True)
        (output / 'licence-rebinding.json').write_bytes(canonical(reuse))
        (output / 'cohort-receipt.json').write_bytes(canonical(result))
        (output / 'producer').mkdir()
        for name in ['SHA256SUMS', 'provenance.json']:
            (output / 'producer' / name).write_bytes(members[name])
        return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['lock', 'candidate', 'readback', 'historical', 'delta', 'cache', 'source', 'go-root', 'output']:
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(verify(a.lock, a.candidate, a.readback, a.historical, a.delta, a.cache,
                            a.source, a.go_root, a.output), indent=2))


if __name__ == '__main__':
    main()
