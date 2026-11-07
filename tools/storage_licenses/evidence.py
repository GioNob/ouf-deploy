"""Checksum-bound legal-text evidence, not a licence/redistribution decision.

Only authenticated archive bytes are read. No module source code is imported or
executed. The Go h1 implementation is cross-checked with official Go downloads
for every module by the native qualification.
"""
import base64
import hashlib
import json
from pathlib import PurePosixPath
import re
import stat
import zipfile

MAX_ARCHIVE_BYTES = 512 * 1024**2
MAX_EXPANDED_BYTES = 512 * 1024**2
MAX_TEXT_BYTES = 16 * 1024**2
MAX_TEXT_TOTAL = 64 * 1024**2
LEGAL_NAMES = ('license', 'licence', 'licenses', 'licences', 'copying', 'notice', 'authors', 'contributors',
               'copyright', 'patents', 'third_party', 'third-party', 'thirdparty')


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def safe_path(name):
    p = PurePosixPath(name.rstrip('/'))
    require(bool(name) and not p.is_absolute() and str(p) == name.rstrip('/')
            and '..' not in p.parts and '\\' not in name and '\n' not in name
            and '\r' not in name and '\x00' not in name, 'SAFE_ARCHIVE_PATH_REQUIRED')
    return p


def legal_path(name):
    p = safe_path(name)
    base = p.name.lower()
    return (any(base == n or any(base.startswith(n + sep) for sep in ('.', '-', '_'))
                for n in LEGAL_NAMES)
            or any(part.lower() in ('licenses', 'licences', 'legal') for part in p.parts[:-1]))


def licence_path(name):
    base = PurePosixPath(name).name.lower()
    return any(base == n or any(base.startswith(n + sep) for sep in ('.', '-', '_'))
               for n in ('license', 'licence', 'licenses', 'licences', 'copying'))


def h1_records(records):
    """Go dirhash.Hash1: hash sorted '<content-sha256>  <filename>\\n' records."""
    names = [name for name, _ in records]
    require(len(names) == len(set(names)), 'DUPLICATE_H1_NAME')
    combined = hashlib.sha256()
    for name, digest in sorted(records):
        require('\n' not in name and '\r' not in name and bool(name), 'SAFE_H1_NAME_REQUIRED')
        require(re.fullmatch('[0-9a-f]{64}', digest) is not None, 'SHA256_CONTENT_REQUIRED')
        combined.update((digest+'  '+name+'\n').encode())
    return 'h1:'+base64.b64encode(combined.digest()).decode()


def parse_sums(raw):
    sums = {}
    for line in raw.decode().splitlines():
        fields = line.split()
        require(len(fields) == 3 and fields[2].startswith('h1:'), 'EXACT_GO_SUM_RECORD_REQUIRED')
        key = tuple(fields[:2])
        require(key not in sums or sums[key] == fields[2], 'CONFLICTING_GO_SUM_RECORD')
        sums[key] = fields[2]
    require(bool(sums), 'NONEMPTY_GO_SUM_REQUIRED')
    return sums


def validate_module_identity(name, version):
    require(isinstance(name, str) and len(name) < 512 and '.' in name.split('/')[0]
            and not name.startswith('-') and all(re.fullmatch('[A-Za-z0-9._~-]+', p)
                                                  for p in name.split('/'))
            and '..' not in name.split('/'), 'EXACT_PUBLIC_MODULE_PATH_REQUIRED')
    require(isinstance(version, str) and re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?(?:\+incompatible)?', version),
            'EXACT_MODULE_VERSION_REQUIRED')


def module_texts(name, version, archive, mod_raw, expected_sum, expected_mod_sum):
    validate_module_identity(name, version)
    require(archive.is_file() and not archive.is_symlink()
            and 0 < archive.stat().st_size <= MAX_ARCHIVE_BYTES, 'BOUNDED_MODULE_ZIP_REQUIRED')
    actual_mod_sum = h1_records([('go.mod', sha(mod_raw))])
    require(actual_mod_sum == expected_mod_sum, 'MODULE_GO_MOD_CHECKSUM_MISMATCH')
    prefix = name+'@'+version+'/'
    records = []; texts = {}; total = 0
    with zipfile.ZipFile(archive) as z:
        infos = z.infolist()
        require(0 < len(infos) <= 100000 and len({i.filename for i in infos}) == len(infos),
                'DISTINCT_BOUNDED_MODULE_MEMBERS_REQUIRED')
        require(sum(i.file_size for i in infos) <= MAX_EXPANDED_BYTES, 'MODULE_EXPANSION_BUDGET')
        for i in infos:
            safe_path(i.filename)
            require(i.filename.startswith(prefix) and not stat.S_ISLNK(i.external_attr >> 16),
                    'EXACT_MODULE_PREFIX_NO_LINK_REQUIRED')
            relative = i.filename[len(prefix):]
            if relative:
                safe_path(relative)
            digest = hashlib.sha256()
            with z.open(i) as stream:
                while block := stream.read(1024**2):
                    digest.update(block)
            records.append((i.filename, digest.hexdigest()))
            if not i.is_dir() and relative and legal_path(relative):
                require(i.file_size <= MAX_TEXT_BYTES, 'LEGAL_TEXT_SIZE_BUDGET')
                total += i.file_size
                require(total <= MAX_TEXT_TOTAL, 'LEGAL_TEXT_TOTAL_BUDGET')
                texts[relative] = z.read(i)
    actual_sum = h1_records(records)
    require(actual_sum == expected_sum, 'MODULE_ZIP_CHECKSUM_MISMATCH')
    with archive.open('rb') as f:
        zip_sha = hashlib.file_digest(f, 'sha256').hexdigest()
    return texts, {'path': name, 'version': version, 'sum': actual_sum, 'goModSum': actual_mod_sum,
                   'zipSha256': zip_sha,
                   'archiveMembers': len(records), 'expandedBytes': sum(i.file_size for i in infos),
                   'legalTextBytes': total, 'moduleCodeExecuted': False}


def package_inventory(scan):
    require(scan.get('SchemaVersion') == 2 and scan.get('Metadata', {}).get('ImageID') ==
            'sha256:11aa43b10ef3ce7743cad1b4e0b10aeaa87cd5e55a414246b6225a50487f154d', 'EXACT_REVIEWED_IMAGE_SCAN_REQUIRED')
    results = scan.get('Results')
    require(isinstance(results, list) and len(results) == 1 and results[0].get('Type') == 'gobinary'
            and results[0].get('Target', '').lstrip('/') == 'usr/local/bin/weed', 'ONE_REVIEWED_EXECUTABLE_REQUIRED')
    packages = results[0].get('Packages')
    require(isinstance(packages, list) and len(packages) == 245, 'ALL_245_SCANNED_COMPONENTS_REQUIRED')
    keys = [(p.get('Name'), p.get('Version')) for p in packages]
    require(len(keys) == len(set(keys)), 'DISTINCT_COMPONENT_IDENTITIES_REQUIRED')
    require(('stdlib', 'v1.27.3') in keys and
            ('github.com/seaweedfs/seaweedfs', 'v0.0.0-20261025193907-153ab668c997+dirty') in keys,
            'EXACT_ROOT_AND_TOOLCHAIN_REQUIRED')
    return sorted(keys)


def retain_component(out, name, version, texts, provenance):
    component_id = sha((name+'@'+version).encode())
    records = []
    for relative, raw in sorted(texts.items()):
        safe_path(relative)
        require(0 <= len(raw) <= MAX_TEXT_BYTES, 'BOUNDED_LEGAL_TEXT_REQUIRED')
        p = out/'texts'/component_id/relative
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open('xb') as f:
            f.write(raw)
        records.append({'sourcePath': relative, 'evidencePath': str(p.relative_to(out/'texts')),
                        'sha256': sha(raw), 'bytes': len(raw), 'licenceCandidate': licence_path(relative)})
    root_licences = [r for r in records if '/' not in r['sourcePath'] and r['licenceCandidate'] and r['bytes'] > 0]
    return {'name': name, 'version': version, 'id': component_id, 'provenance': provenance,
            'legalTexts': records, 'rootLicenceCandidates': len(root_licences),
            'collectionStatus': 'ROOT_LICENCE_TEXT_RETAINED' if root_licences else 'ROOT_LICENCE_REVIEW_REQUIRED',
            'licenceExpression': 'NOASSERTION', 'obligationsAccepted': False}


def assess_classification(inventory, report, views=None):
    require(report.get('SchemaVersion') == 2 and report.get('Trivy', {}).get('Version') == '0.70.0'
            and isinstance(report.get('Results'), list) and bool(report['Results']),
            'NONEMPTY_PINNED_LICENCE_REPORT_REQUIRED')
    files = {r['evidencePath']: r for c in inventory['components'] for r in c['legalTexts']}
    require(bool(files), 'RETAINED_LEGAL_TEXTS_REQUIRED')
    paths = {p: p for p in files} if views is None else {}
    if views is not None:
        for view in views:
            safe_path(view['viewPath'])
            original = view['originalEvidencePath']
            require(original in files and view['sha256'] == files[original]['sha256']
                    and files[original]['licenceCandidate'] and view['viewPath'] not in paths,
                    'EXACT_HASH_BOUND_CLASSIFIER_VIEW_REQUIRED')
            paths[view['viewPath']] = original
    detected = {}
    for result in report['Results']:
        for finding in result.get('Licenses') or []:
            path = finding.get('FilePath', '')
            safe_path(path)
            require(path in paths and not finding.get('PkgName') and
                    isinstance(finding.get('Name'), str) and bool(finding['Name']), 'EXACT_RETAINED_FILE_CLASSIFICATION_REQUIRED')
            require(type(finding.get('Confidence')) in (int, float) and 0 <= finding['Confidence'] <= 1,
                    'VALID_CLASSIFIER_CONFIDENCE_REQUIRED')
            require(finding.get('Severity') in ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], 'KNOWN_LICENCE_SEVERITY_REQUIRED')
            original = paths[path]
            record = dict(finding, OriginalEvidencePath=original)
            detected.setdefault(original, []).append(record)
    require(bool(detected), 'ACTUAL_FILE_CLASSIFICATIONS_REQUIRED')
    components = []
    for component in inventory['components']:
        matches = [f for r in component['legalTexts'] for f in detected.get(r['evidencePath'], [])]
        root = [f for r in component['legalTexts'] if r['licenceCandidate'] and '/' not in r['sourcePath']
                for f in detected.get(r['evidencePath'], []) if f['Confidence'] >= 0.9 and f['Severity'] != 'UNKNOWN']
        components.append({'name': component['name'], 'version': component['version'],
                           'rootClassifications': root, 'allClassifications': matches,
                           'status': 'CLASSIFIED_TEXTS_REVIEW_OPEN' if root else 'UNCLASSIFIED_ROOT_REVIEW_REQUIRED',
                           'licenceExpression': 'NOASSERTION', 'obligationsAccepted': False})
    return {'schema': 'ouf.storage-licence-classification-evidence.v1',
            'status': 'EVIDENCE_COLLECTED_REVIEW_OPEN', 'components': components,
            'componentCount': len(components), 'legalTextCount': len(files),
            'classifiedFileCount': len(detected),
            'componentsWithRootClassification': sum(bool(c['rootClassifications']) for c in components),
            'componentsRequiringRootReview': [c['name']+'@'+c['version'] for c in components if not c['rootClassifications']],
            'severities': {s: sum(f['Severity'] == s for v in detected.values() for f in v)
                           for s in ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']},
            'rawSpdxModified': False, 'licenceReview': 'OPEN', 'redistributionAccepted': False,
            'releaseAdmitted': False, 'overallSwG1': 'OPEN', 'targetOperations': 0}
