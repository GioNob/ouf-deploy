#!/usr/bin/env python3
"""Bind generation33 image evidence to exactly reverified legal texts, never admission."""
import argparse
import hashlib
import gzip
import io
import tarfile
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


readback = load('generation33_readback', 'scripts/readback-seaweedfs-452-generation33-image.py').engine
legal = load('legal_text_evidence', 'tools/storage_licenses/evidence.py')
require = legal.require
MANIFEST = readback.candidate.manifest
MANIFEST_REL = readback.candidate.preflight.MANIFEST
MANIFEST_PATH = ROOT / MANIFEST_REL
PROFILE_PATH = readback.candidate.preflight.PROFILE
PROFILE = readback.candidate.profile
ORIGIN_FIELDS = ('inputZipSha256', 'inputGoModSha256', 'inputZipH1', 'inputGoModH1', 'checksumsDescribeOriginalInputsOnly', 'modifiedInVendor')
MONGO_NAME = 'go.mongodb.org/mongo-driver/v2'
MONGO_VERSION = 'v2.9.2'
MONGO_DELTA = 'evidence/seaweedfs-452-generation32-mongodb-v2-legal-delta-20261104.json'
MONGO_TEXT_ROOT = 'evidence/seaweedfs-452-generation32-mongodb-v2-legal-texts'
HISTORICAL_SHA = '851d65dc1ac3788178978b9effc04c257475492ad6d3e5dcc04346d033288c67'
DELTA_SHA = '7cf2b9dc596ded071c9c75f1bfeb87245f443e25984b9cddf8bf4f411791eda2'
UPSTREAM_LICENCE_SHA = 'd789d433cc11da163273d1e39be2e8fa67642f9a58ef220d3f258fa9c14ef613'
OLD_BINARY = '85fa52c68a783f3cf4d54ae6064e7b46d022982c1bef4460616dd76cdc609033'

MODIFIED_SOURCE_MANIFEST_PATH = 'evidence/seaweedfs-source30-integrated-local-20261103/raftstore-modified-source-manifest.json'
MODIFIED_SOURCE_MANIFEST_SHA = '0b65ee710cf88f9bd2b76c0918377f10b71c6225d8937732ae6871e875569d53'
MODIFIED_SOURCE_ARCHIVE_PATH = 'evidence/seaweedfs-source30-integrated-local-20261103/raftstore-modified-source.tar.gz'
MODIFIED_SOURCE_ARCHIVE_SHA = '2767531e9510840ba159cdbb9062633dad51d4d2b5984b7d57c1aabcb38d177e'



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


def binary_modules(raw, origins):
    """Join empty vendored build metadata to authenticated original-input sums.

    Never put an original h1 into the vendored build info or raw scanner/SPDX.
    Returned h1 values describe the ORIGINAL ZIP only, not modified vendor bytes.
    """
    rows = [line for line in raw.decode().splitlines() if line.startswith('\tdep\t')]
    require(not any(line.startswith('\t=>\t') for line in raw.decode().splitlines()),
            'REPLACED_MODULES_NOT_SUPPORTED')
    require(len(rows) == MANIFEST['build']['binaryDependencyModules']
            and legal.sha(('\n'.join(rows) + '\n').encode()) == MANIFEST['build']['binaryModuleRowsSha256'],
            'EXACT_REVIEWED_MODULE_INVENTORY_REQUIRED')
    parsed = [tuple(row.split('\t')[2:]) for row in rows]
    require(all(len(row) == 3 and row[2] == '' for row in parsed)
            and len(parsed) == len({row[0] for row in parsed}), 'VENDORED_BUILD_INFO_SUMS_MUST_REMAIN_EMPTY')
    actual = readback.candidate.contract.origin_rows(origins)
    baseline = readback.candidate.contract.origin_rows(json.loads(
        readback.candidate.baseline_observation()['compiled-module-origins.json']))
    require(set(actual) == set(baseline) == {(n,v) for n,v,_ in parsed}, 'EXACT_COMPILED_ORIGINAL_MODULE_SET_REQUIRED')
    require(origins['moduleCount'] == 214 and origins['moduleCacheMutated'] is False,
            'UNMODIFIED_ORIGINAL_MODULE_CACHE_REQUIRED')
    for key, record in actual.items():
        require(all(record[field] == baseline[key][field] for field in ORIGIN_FIELDS)
                and record['checksumsDescribeOriginalInputsOnly'] is True,
                'EXACT_ORIGINAL_INPUT_CHECKSUMS_REQUIRED:' + key[0])
    require({key for key,row in actual.items() if row['modifiedInVendor']} == {('github.com/apache/iceberg-go','v0.7.0')},
            'EXACT_MODIFIED_DEPENDENCY_REQUIRED')
    return [(n,v,actual[n,v]['inputZipH1']) for n,v,_ in parsed]


def verify_vendor_dependency(module_cache, origins):
    name, version = 'github.com/apache/iceberg-go', 'v0.7.0'
    records = readback.candidate.contract.origin_rows(origins)
    record = records[name,version]
    archive, mod = cache_paths(module_cache,name,version)
    require(sha(archive) == record['inputZipSha256'] == PROFILE['upstream']['zipSha256']
            and sha(mod) == record['inputGoModSha256'], 'EXACT_ICEBERG_ORIGINAL_INPUT_REQUIRED')
    materializer = load('iceberg_materializer', 'scripts/prepare_iceberg_vendor_patch.py')
    require(sha(ROOT / 'scripts/prepare_iceberg_vendor_patch.py') == PROFILE['materializerSha256'],
            'PINNED_VENDOR_MATERIALIZER_REQUIRED')
    with zipfile.ZipFile(archive) as z:
        prefix = name + '@' + version + '/'
        original = z.read(prefix + 'config/config.go')
        patched = materializer.patched_bytes(original)
        texts = {n:z.read(prefix+n) for n in ('LICENSE','NOTICE')}
    verify_vendor_file_bytes(original, patched, texts, materializer.NOTICE)
    patch_path = MANIFEST['orderedDependencyPatches'][0]['path']
    require(sha(ROOT / patch_path) == PROFILE['patch']['sha256'], 'EXACT_ICEBERG_PATCH_REQUIRED')
    result = {'module':name,'version':version,'sourceProfilePath':PROFILE_PATH,
        'sourceProfileSha256':sha(ROOT/PROFILE_PATH),'originalZipSha256':record['inputZipSha256'],
        'originalZipH1InputOnly':record['inputZipH1'],'originalConfigSha256':legal.sha(original),
        'modifiedConfigSha256':legal.sha(patched),'patchPath':patch_path,'patchSha256':PROFILE['patch']['sha256'],
        'downstreamNoticePresent':materializer.NOTICE.encode() in patched,
        'originalLegalTexts':{n:{'sha256':legal.sha(raw),'bytes':len(raw)} for n,raw in texts.items()},
        'originalChecksumsDescribeModifiedSource':False,'canonicalScannerIdentityModified':False,
        'canonicalSpdxIdentityModified':False,'licenceReview':'OPEN','redistributionAccepted':False}
    require(result['downstreamNoticePresent'], 'DOWNSTREAM_MODIFICATION_NOTICE_REQUIRED')
    return result, {'config/config.go.original':original,'config/config.go.modified':patched,**texts,
                    'downstream.patch':(ROOT/patch_path).read_bytes()}


def verify_vendor_file_bytes(original, patched, texts, notice):
    require(legal.sha(original) == PROFILE['patch']['originalFileSha256']
            and legal.sha(patched) == PROFILE['patch']['modifiedFileSha256'], 'EXACT_ICEBERG_MODIFIED_SOURCE_REQUIRED')
    require(set(texts) == {'LICENSE','NOTICE'} and all(legal.sha(raw) == {
            'LICENSE':'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30',
            'NOTICE':'f519dc027959fc106b1b53706b70eb3bd5da2c0bac79336888c58a79d03c8f52'}[name]
            for name,raw in texts.items()), 'ICEBERG_ORIGINAL_LEGAL_TEXT_CHANGED')
    require(notice.encode() in patched and notice.startswith('// OUF downstream modification (2026-11-03):'),
            'DOWNSTREAM_MODIFICATION_NOTICE_REQUIRED')


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


def verify_modified_source(source_root):
    """Verify every changed MPL source byte against the archived source and exact checkout."""
    manifest_path = ROOT / MODIFIED_SOURCE_MANIFEST_PATH
    archive_path = ROOT / MODIFIED_SOURCE_ARCHIVE_PATH
    require(sha(manifest_path) == MODIFIED_SOURCE_MANIFEST_SHA
            and sha(archive_path) == MODIFIED_SOURCE_ARCHIVE_SHA,
            'EXACT_MODIFIED_MPL_SOURCE_ARCHIVE_REQUIRED')
    manifest = json.loads(manifest_path.read_bytes())
    require(manifest['license'] == 'MPL-2.0'
            and manifest['derivedFrom'] == 'github.com/hashicorp/raft-boltdb/v2@v2.4.2'
            and manifest['licenseDecisionOrPermissionCreated'] is False
            and manifest['gzipSha256'] == MODIFIED_SOURCE_ARCHIVE_SHA
            and manifest['gzipBytes'] == archive_path.stat().st_size <= 1024 * 1024,
            'MODIFIED_SOURCE_IDENTITY_REQUIRED')
    raw = gzip.decompress(archive_path.read_bytes())
    require(len(raw) == manifest['tarBytes'] <= 1024 * 1024
            and legal.sha(raw) == manifest['tarSha256'], 'MODIFIED_SOURCE_TAR_CHANGED')
    expected = {'weed/util/raftstore/' + name for name in
                ('LICENSE', 'UPSTREAM.md', 'bolt_store.go', 'bolt_store_test.go', 'metrics.go', 'util.go')}
    require(set(manifest['files']) == expected, 'COMPLETE_MODIFIED_MPL_SOURCE_REQUIRED')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        members = archive.getmembers()
        require(len(members) == len(expected) and {entry.name for entry in members} == expected,
                'EXACT_MODIFIED_SOURCE_TAR_MEMBERS_REQUIRED')
        for entry in members:
            legal.safe_path(entry.name)
            require(entry.isfile() and not entry.issym() and not entry.islnk(), 'REGULAR_MODIFIED_SOURCE_REQUIRED')
            content = archive.extractfile(entry).read()
            record = manifest['files'][entry.name]
            candidate_path = source_root / entry.name
            require(len(content) == record['bytes'] and legal.sha(content) == record['sha256']
                    and candidate_path.is_file() and not candidate_path.is_symlink()
                    and candidate_path.read_bytes() == content, 'MODIFIED_SOURCE_CHECKOUT_CHANGED:' + entry.name)
    return {'archivePath': MODIFIED_SOURCE_ARCHIVE_PATH, 'archiveSha256': MODIFIED_SOURCE_ARCHIVE_SHA,
            'manifestSha256': MODIFIED_SOURCE_MANIFEST_SHA, 'sourceTree': MANIFEST['rootSourceGitTree'],
            'files': manifest['files'], 'sourceFilesVerified': 6, 'licence': 'MPL-2.0',
            'derivedFrom': manifest['derivedFrom'], 'moduleSourcesModified': True,
            'legalReview': 'OPEN', 'redistributionAccepted': False,
            'licenseDecisionOrPermissionCreated': False}


def verify_mongo_delta(module_cache, source_root, gosum):
    raw = (ROOT / MONGO_DELTA).read_bytes()
    delta = json.loads(raw)
    require(delta['schema'] == 'ouf.generation32-mongo-legal-delta.v1'
            and delta['module'] == MONGO_NAME and delta['version'] == MONGO_VERSION
            and delta['licenceReview'] == 'OPEN' and delta['redistributionAccepted'] is False,
            'EXACT_MONGODB_V2_LEGAL_DELTA_REQUIRED')
    sums = legal.parse_sums((source_root / 'go.sum').read_bytes())
    modsum = sums[MONGO_NAME, MONGO_VERSION + '/go.mod']
    require(delta['sum'] == gosum == sums[MONGO_NAME, MONGO_VERSION]
            and delta['goModSum'] == modsum, 'MONGODB_V2_GO_SUM_CHANGED')
    archive, mod = cache_paths(module_cache, MONGO_NAME, MONGO_VERSION)
    texts, reproduced = legal.module_texts(MONGO_NAME, MONGO_VERSION, archive, mod.read_bytes(), gosum, modsum)
    require(reproduced['zipSha256'] == delta['sourceZipSha256'], 'MONGODB_V2_SOURCE_ZIP_CHANGED')
    require(set(texts) == set(delta['texts']) == {'LICENSE', 'THIRD-PARTY-NOTICES'},
            'EXACT_MONGODB_V2_LEGAL_TEXT_SET_REQUIRED')
    rows = []
    for name, data in sorted(texts.items()):
        member = MONGO_TEXT_ROOT + '/' + name
        require(delta['texts'][name] == {'sha256': legal.sha(data), 'bytes': len(data)}
                and (ROOT / member).read_bytes() == data, 'MONGODB_V2_LEGAL_TEXT_CHANGED:' + name)
        rows.append({'path': name, 'sha256': legal.sha(data), 'bytes': len(data),
                     'archive': 'generation33-mongodb-v2-delta', 'member': member})
    return {'module': MONGO_NAME, 'version': MONGO_VERSION, 'sum': gosum, 'goModSum': modsum,
            'sourceZipSha256': delta['sourceZipSha256'], 'legalTexts': rows}, archive.stat().st_size, legal.sha(raw)


def verify_legal_reuse(build_info, historical_path, delta_path, module_cache, source_root, go_root, origins):
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
    modules = binary_modules(build_info, origins)
    require(len(modules) == 214, 'EXACT_214_THIRD_PARTY_MODULES_REQUIRED')
    require({(n, v) for n, v, _ in modules} - old.keys() - changed.keys() == {(MONGO_NAME, MONGO_VERSION)},
            'MONGODB_V2_MUST_BE_ONLY_NEW_MODULE')
    origin_records = readback.candidate.contract.origin_rows(origins)
    for name, version, original_sum in modules:
        record=origin_records[name,version]
        archive,mod=cache_paths(module_cache,name,version)
        require(sha(archive)==record['inputZipSha256'] and sha(mod)==record['inputGoModSha256']
                and original_sum==record['inputZipH1'], 'ORIGINAL_INPUT_CACHE_CHANGED:' + name)
    records = [];text_count = 0;archive_bytes = 0;parent_count = 0
    for name, version, gosum in modules:
        key = (name, version)
        if key == (MONGO_NAME, MONGO_VERSION):
            record, size, mongo_delta_sha = verify_mongo_delta(module_cache, source_root, gosum)
            records.append(record)
            archive_bytes += size
            text_count += len(record['legalTexts'])
            continue
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
    require(text_count == 302 and parent_count == 1, 'EXACT_THIRD_PARTY_TEXT_SET_REQUIRED')
    mpl = json.loads(historical['mpl-source-manifest.json'])['components']
    require(mpl == prior['historicalMplSourceArchivesVerified'] and len(mpl) == 17,
            'EXACT_HISTORICAL_MPL_SOURCE_SET_REQUIRED')
    identities = {(r['module'], r['version']): r for r in records}
    retained_mpl = [item for item in mpl if (item['name'], item['version']) in identities]
    require(len(retained_mpl) == 7, 'EXACT_RETAINED_MPL_SOURCE_SET_REQUIRED')
    for item in retained_mpl:
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
    modified_source = verify_modified_source(source_root)
    source_texts.append({'path': 'weed/util/raftstore/LICENSE', 'sha256': modified_source['files']['weed/util/raftstore/LICENSE']['sha256'], 'bytes': modified_source['files']['weed/util/raftstore/LICENSE']['bytes'], 'source': 'modified-local-raftstore-MPL'})
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
    return {'schema': 'ouf.generation33-legal-text-reuse.v1', 'status': 'EXACT_TEXTS_REVERIFIED_REVIEW_OPEN',
            'thirdPartyModules': 214, 'thirdPartyLegalTexts': 302, 'sourceArchivesRehashedBytes': archive_bytes,
            'moduleGoSumsIndependentlyRecomputed': True, 'moduleSourceZipHashesReverified': True,
            'parentLicenceSupplementReverified': parent_count, 'mplSourceArchivesReverified': 7,
            'modifiedLocalMplSource': modified_source,
            'historicalMplModulesNotInCandidate': [item['name'] for item in mpl if item not in retained_mpl],
            'rootSourceLegalTexts': source_texts, 'stdlibLegalTextsReverified': 39,
            'stdlibSourceArchiveSha256Historical': prior['stdlib']['sourceArchiveSha256'],
            'historicalCorpusSha256': HISTORICAL_SHA, 'historicalDeltaSha256': DELTA_SHA,
            'mongoV2LegalDeltaSha256': mongo_delta_sha,
            'modifiedVendorDependency': verify_vendor_dependency(module_cache, origins)[0],
            'vendoredBuildInfoH1Fields': 'EMPTY_UNCHANGED',
            'originalInputOriginsReverified': True,
            'binaryModuleInventorySha256': MANIFEST['build']['binaryModuleRowsSha256'],
            'moduleEvidence': records, 'historicalUnknownClassifications': unknown,
            'classificationReusedOnlyForIdenticalTexts': True, 'newClassifierRunClaimed': False,
            'rawPriorVulnerabilityScanTransferred': False, 'rawPriorSpdxTransferred': False,
            'licenceReview': 'OPEN', 'redistributionAccepted': False, 'releaseAdmitted': False,
            'runtimeAuthorityIssued': False, 'targetOperations': 0}


def source_revision():
    return {'rootSourceGitTree':MANIFEST['rootSourceGitTree'], 'rootLockfilesSha256':MANIFEST['rootLockfilesSha256'],
            'vendorAfterTreeSha256':MANIFEST['vendor']['afterTreeSha256']}


def dependency_policy():
    return {'allTenArchivedCensus29ModulesAbsent':True,'allDependenciesMaintained':False}


def validate_lock(lock):
    require(lock['schema'] == 'ouf.storage-candidate-lock.v3' and lock['generation'] == 33
            and lock['orderedPatchCount'] == 33 and lock['sourcePatchCount'] == 32 and lock['dependencyPatchCount'] == 1 and lock['status'] == 'EVIDENCE_PREPARED_NOT_ADMITTED',
            'GENERATION33_LOCK_REQUIRED')
    require(lock['buildManifest']['sha256'] == sha(MANIFEST_PATH)
            and lock['buildProfile']['binarySha256'] == MANIFEST['build']['binarySha256']
            and lock['buildManifest']['rootSourceTree'] == MANIFEST['rootSourceGitTree']
            and lock['buildManifest']['vendorAfterTreeSha256'] == MANIFEST['vendor']['afterTreeSha256']
            and lock['buildManifest']['path'] == MANIFEST_REL
            and all(lock['buildProfile'][key] == MANIFEST['build'][key] for key in
                    list(MANIFEST['build']))
            and lock['image']['upstreamLicenceSha256'] == UPSTREAM_LICENCE_SHA,
            'REVIEWED_GENERATION33_BUILD_REQUIRED')
    require(re.fullmatch('[0-9a-f]{40}', lock['producerCommit'])
            and type(lock['qualification']['runId']) is int and lock['qualification']['runId'] > 0
            and type(lock['qualification']['runAttempt']) is int and lock['qualification']['runAttempt'] > 0,
            'REAL_PRODUCER_IDENTITIES_REQUIRED')
    require(lock['modifiedMplSource'] == {'archiveSha256': MODIFIED_SOURCE_ARCHIVE_SHA, 'manifestSha256': MODIFIED_SOURCE_MANIFEST_SHA},
            'EXACT_MODIFIED_MPL_SOURCE_LOCK_REQUIRED')
    require(lock['dependencyMaintenance'] == {'status': 'OPEN', 'allDependenciesMaintained': False}, 'NO_MAINTENANCE_CLOSURE_REQUIRED')
    require(lock['sourceRevision'] == source_revision()
            and lock['compiledDependencyPolicy'] == dependency_policy()
            and lock['vendorSourceProfile'] == {'path':PROFILE_PATH,'sha256':sha(ROOT/PROFILE_PATH)},
            'EXACT_GENERATION33_SOURCE_PROFILE_REQUIRED')
    require(lock['mongoV2LegalDelta'] == {'path': MONGO_DELTA, 'sha256': sha(ROOT / MONGO_DELTA)},
            'EXACT_MONGODB_V2_LEGAL_DELTA_REQUIRED')
    counts = lock['qualification']['rawSeverityCounts']
    require(set(counts) == {'HIGH', 'CRITICAL', 'UNKNOWN', 'MEDIUM', 'LOW'}
            and all(type(v) is int and v >= 0 for v in counts.values()), 'COMPLETE_RAW_SEVERITY_COUNTS_REQUIRED')
    require(lock['releaseAdmitted'] is False and lock['runtimeAuthorityIssued'] is False
            and lock['targetOperations'] == 0, 'NO_ADMISSION_OR_AUTHORITY_REQUIRED')
    require(lock['qualification']['allJobsPassed'] is True
            and lock['qualification']['workflow'] == '.github/workflows/storage-452-generation33-image.yml'
            and lock['qualification']['vulnerabilitySubgate'] == 'PASS_RAW'
            and all(lock['qualification']['rawSeverityCounts'][s] == 0 for s in ['HIGH', 'CRITICAL', 'UNKNOWN']),
            'SUCCESSFUL_GENERATION33_IMAGE_QUALIFICATION_REQUIRED')
    require(lock['licenceRebinding']['path'] == 'evidence/seaweedfs-452-generation33-licence-rebinding-local-20261104.json'
            and re.fullmatch('[0-9a-f]{64}', lock['licenceRebinding']['sha256']),
            'EXACT_GENERATION33_LEGAL_REBINDING_REQUIRED')
    for field in ['producerArtifact', 'independentReadback']:
        item = lock[field]
        require(type(item['id']) is int and item['id'] > 0 and type(item['bytes']) is int and item['bytes'] > 0
                and re.fullmatch(r'sha256:[0-9a-f]{64}', item['digest']), 'EXACT_PUBLISHED_ARTIFACT_REQUIRED')


def verify(lock_path, candidate_zip, hosted_zip, historical_zip, delta_zip, cache, source_root, go_root, output):
    require(not output.exists(), 'NEW_COHORT_OUTPUT_REQUIRED')
    lock = json.loads(lock_path.read_bytes());validate_lock(lock)
    producer = lock['producerArtifact'];hosted = lock['independentReadback']
    require(candidate_zip.stat().st_size == producer['bytes'] and sha(candidate_zip) == producer['digest'][7:],
            'EXACT_GENERATION33_PRODUCER_REQUIRED')
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
        require(all(assessment[field] == lock['image'][field] for field in
                    ['manifestDigest', 'configDigest', 'layerDigest', 'dockerArchiveSha256', 'upstreamLicenceSha256']),
                'COMPLETE_LOCK_IMAGE_LAYOUT_BINDING_REQUIRED')
        require(assessment['freshScanSha256'] == lock['qualification']['scanSha256']
                and assessment['sbomSha256'] == lock['qualification']['sbomSha256']
                and assessment['rawSeverityCounts'] == lock['qualification']['rawSeverityCounts'],
                'FRESH_GENERATION33_SCAN_BINDING_REQUIRED')
        verification = json.loads(members['publisher-verification.json'])
        require(isinstance(verification, list) and len(verification) == 1, 'EXACT_PUBLISHER_VERIFICATION_REQUIRED')
        verified = verification[0]['verificationResult'];cert = verified['signature']['certificate'];statement = verified['statement']
        require(cert['sourceRepositoryDigest'] == cert['githubWorkflowSHA'] == lock['producerCommit']
                and cert['runnerEnvironment'] == 'github-hosted'
                and cert['githubWorkflowRepository'] == 'GioNob/ouf-deploy', 'PUBLISHER_IDENTITY_CHANGED')
        signer = 'https://github.com/GioNob/ouf-deploy/.github/workflows/storage-452-generation33-image.yml@refs/heads/feat/m2-discovery-complete-profile-20261029'
        require(cert['subjectAlternativeName'] == cert['buildSignerURI'] == cert['buildConfigURI'] == signer
                and cert['buildSignerDigest'] == cert['buildConfigDigest'] == lock['producerCommit'],
                'GENERATION33_SIGNER_WORKFLOW_CHANGED')
        invocation = statement['predicate']['runDetails']['metadata']['invocationId']
        expected_invocation = 'https://github.com/GioNob/ouf-deploy/actions/runs/' + str(lock['qualification']['runId']) + '/attempts/' + str(lock['qualification']['runAttempt'])
        require(invocation == cert['runInvocationURI'] == expected_invocation, 'PUBLISHER_RUN_CHANGED')
        require(statement['subject'] == [{'name': 'SHA256SUMS', 'digest': {'sha256': legal.sha(members['SHA256SUMS'])}}],
                'PUBLISHER_SUBJECT_CHANGED')
        with zipfile.ZipFile(candidate_zip) as archive:
            build_info = archive.read('build-info.txt')
            with zipfile.ZipFile(io.BytesIO(archive.read('vendor-source-evidence.zip'))) as vendor:
                origins = json.loads(vendor.read('observation/compiled-module-origins.json'))
        reuse = verify_legal_reuse(build_info, historical_zip, delta_zip, cache, source_root, go_root, origins)
        reuse.update({'generation': 33, 'binarySha256': reproduced['binarySha256'],
                      'ociManifestDigest': reproduced['ociManifestDigest'], 'producerCommit': lock['producerCommit'],
                      'producerRunId': lock['qualification']['runId'], 'producerArtifactSha256': sha(candidate_zip),
                      'freshScanSha256': assessment['freshScanSha256'], 'freshSpdxSha256': assessment['sbomSha256']})
        require(legal.sha(canonical(reuse)) == lock['licenceRebinding']['sha256']
                and (ROOT / lock['licenceRebinding']['path']).read_bytes() == canonical(reuse),
                'REPRODUCED_LEGAL_REBINDING_DIFFERS')
        result = {'schema': 'ouf.seaweedfs-generation33-cohort.v1', 'status': 'TECHNICAL_COHORT_VERIFIED_NOT_ADMITTED',
                  'generation': 33, 'candidateLockSha256': sha(lock_path), 'producerArtifactSha256': sha(candidate_zip),
                  'independentReadbackSha256': sha(hosted_zip), 'binarySha256': reproduced['binarySha256'],
                  'ociManifestDigest': reproduced['ociManifestDigest'], 'readbackReproduced': True,
                  'publisherVerificationRecordBound': True, 'publisherSignatureReverifiedByThisScript': False,
                  'legalTextRebindingSha256': legal.sha(canonical(reuse)),
                  'mongoV2LegalDeltaSha256': reuse['mongoV2LegalDeltaSha256'],
                  'vendorSourceProfile': lock['vendorSourceProfile'],
                  'modifiedVendorDependency': reuse['modifiedVendorDependency'],
                  'sourceRevision': source_revision(),
                  'compiledDependencyPolicy': dependency_policy(),
                  'modifiedMplSourceArchiveSha256': MODIFIED_SOURCE_ARCHIVE_SHA,
                  'modifiedMplSourceManifestSha256': MODIFIED_SOURCE_MANIFEST_SHA,
                  'dependencyMaintenance': {'status': 'OPEN', 'allDependenciesMaintained': False}, 'licenceReview': 'OPEN',
                  'redistributionAccepted': False, 'durableImageCustody': 'OPEN', 'releaseAdmitted': False,
                  'runtimeAuthorityIssued': False, 'targetOperations': 0}
        output.mkdir(parents=True)
        (output / 'licence-rebinding.json').write_bytes(canonical(reuse))
        (output / 'cohort-receipt.json').write_bytes(canonical(result))
        (output / 'modified-raftstore-source.tar.gz').write_bytes((ROOT / MODIFIED_SOURCE_ARCHIVE_PATH).read_bytes())
        (output / 'modified-raftstore-source-manifest.json').write_bytes((ROOT / MODIFIED_SOURCE_MANIFEST_PATH).read_bytes())
        modified, files = verify_vendor_dependency(cache, origins)
        (output / 'modified-iceberg').mkdir()
        for name, raw in files.items():
            dest=output / 'modified-iceberg' / name; dest.parent.mkdir(parents=True, exist_ok=True); dest.write_bytes(raw)
        (output / 'modified-iceberg/manifest.json').write_bytes(canonical(modified))
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
