#!/usr/bin/env python3
"""Preserve exact heterogeneous image origins without inventing package fields.

Original metadata stays byte exact. Public source and config/layer custody are
qualified separately from a scan, target admission or installation authority.
"""
import argparse, gzip, hashlib, importlib.util, json, shutil, stat, subprocess, sys, zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from tools.acquisition_read_native import image_custody as custody
from tools.m2_discovery_installation_profile.custody_capture import attrs

ORIGINS = ROOT/'releases/m2-current-core-artifact-origins-20261101.json'
LOCK = ROOT/'releases/m2-current-core-source-lock-20261101.json'


def require(ok, reason):
    if not ok: raise ValueError(reason)


def sha(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def entries(zipped):
    result = {}; total = 0
    for entry in zipped.infolist():
        name = entry.filename; path = PurePosixPath(name)
        require(not path.is_absolute() and '..' not in path.parts and str(path) == name
            and name not in result and len(result) < 256 and not entry.is_dir()
            and stat.S_IFMT(entry.external_attr >> 16) in (0, stat.S_IFREG)
            and 0 < entry.file_size <= 2147483648, 'BOUNDED_UNIQUE_REGULAR_ORIGIN_MEMBERS_REQUIRED')
        total += entry.file_size; require(total <= 4*1024**3, 'BOUNDED_ORIGIN_EXPANSION_REQUIRED')
        result[name] = entry
    return result


def stage(role, source, output):
    cases = json.loads(ORIGINS.read_bytes())['roles']
    require(role in cases and not output.exists(), 'EXACT_KNOWN_ORIGIN_AND_NEW_OUTPUT_REQUIRED')
    case = cases[role]
    before = source.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == case['zipBytes']
        and sha(source) == case['zipSha256'], 'EXACT_ORIGINAL_CI_ZIP_BYTES_REQUIRED')
    with zipfile.ZipFile(source) as zipped:
        members = entries(zipped); origin = output/'origin'
        require(case['imageMember'] in members and case['metadataMember'] in members,
            'EXACT_ORIGINAL_IMAGE_AND_METADATA_MEMBERS_REQUIRED')
        require(all(members[n].file_size <= 8388608 for n in members if n != case['imageMember']
            and not n.endswith(('application.jar', 'source.tar'))), 'BOUNDED_ORIGINAL_METADATA_REQUIRED')
        output.mkdir(mode=0o700); origin.mkdir(mode=0o700)
        # Preserve every original member, including its metadata/checksums and
        # source/scan payload where supplied. Never relabel an old manifest.
        for name in sorted(members):
            target = origin/name; target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with zipped.open(members[name]) as content, target.open('xb') as destination:
                shutil.copyfileobj(content, destination, 1048576)
        image = output/'image.docker.tar'
        original = origin/case['imageMember']
        if case['imageMember'].endswith('.gz'):
            require(sha(original) == case['compressedArchiveSha256'], 'EXACT_COMPRESSED_IMAGE_REQUIRED')
            with gzip.open(original, 'rb') as expanded, image.open('xb') as destination:
                count = 0
                while block := expanded.read(1048576):
                    count += len(block); require(count <= 2147483648, 'BOUNDED_IMAGE_EXPANSION_REQUIRED')
                    destination.write(block)
        else: shutil.copyfile(original, image)
        with image.open('rb') as content:
            audit = custody.archive(content, case['expandedArchiveSha256'], case['configurationImageId'],
                case['sourceCommit'], ci_source_binding=case.get('ciSourceBinding'))
        native = custody.native_identity(audit)
        require(native['nativeImageId'] == case['nativeImageId'], 'EXACT_QUALIFIED_NATIVE_IDENTITY_REQUIRED')
        metadata_raw = (origin/case['metadataMember']).read_bytes()
        if case['originalFormat'] == 'UNSIGNED_OFFLINE_IMAGE':
            metadata = json.loads(metadata_raw)
            require(metadata['schema'] == 'ouf.unsigned-offline-candidate-package.v1'
                and metadata['module'] == role and metadata['sourceCommit'] == case['sourceCommit']
                and metadata['imageId'] == case['configurationImageId']
                and metadata['runtimeUser'] == audit['imageConfig']['User'], 'EXACT_ORIGINAL_IMAGE_PACKAGE_REQUIRED')
        elif role == 'onboarding':
            metadata = json.loads(metadata_raw)
            require(metadata['schema'] == 'ouf.onboarding-tested-image.v1'
                and metadata['testedCommit'] == case['sourceCommit']
                and metadata['reviewedSourceCommit'] == case['reviewedSourceCommit']
                and metadata['testedTree'] == case['reviewedAndTestedTree']
                and metadata['imageId'] == case['configurationImageId'], 'EXACT_ORIGINAL_ONBOARDING_TESTED_IMAGE_REQUIRED')
        elif role == 'ingestion':
            metadata = json.loads(metadata_raw)
            require(metadata['schema'] == 'ouf.ingestion-readiness-workload-candidate.v1'
                and metadata['sourceCommit'] == case['sourceCommit']
                and metadata['imageId'] == case['configurationImageId'], 'EXACT_ORIGINAL_INGESTION_IMAGE_REQUIRED')
        else:
            require(role == 'mcp' and metadata_raw.decode().strip() == case['sourceCommit']
                and (origin/'image-id.txt').read_text().strip() == case['configurationImageId'],
                'EXACT_ORIGINAL_MCP_CI_SOURCE_AND_IMAGE_REQUIRED')
        require(attrs(source.lstat()) == attrs(before), 'ORIGINAL_CI_ZIP_CHANGED_DURING_READ')
        facts = {'schema': 'ouf.m2-current-core-image-origin.v1', 'role': role, 'origin': case,
            'originalMetadataSha256': hashlib.sha256(metadata_raw).hexdigest(),
            'originalFiles': {name: sha(origin/name) for name in members}, 'imageAudit': audit,
            'nativeIdentity': native, 'allConfigAndLayerBytesVerified': True, 'imageRebuilt': False,
            'originalFormatRewritten': False, 'newScanQualified': False, 'targetAdmissionProven': False,
            'candidateSelectionChanged': False, 'runtimeAuthorityIssued': False,
            'targetApplyAuthorized': False, 'releaseAcceptance': False}
        (output/'origin-facts.json').write_text(json.dumps(facts, indent=2, sort_keys=True)+'\n')
        return facts


def finalize(role, output, source_directory, scan):
    """Create new producer metadata after a fresh scan of the same image.

    This is a new unsigned envelope over preserved bytes, with original formats
    and original metadata retained. It never rewrites the old origin record.
    """
    case = json.loads(ORIGINS.read_bytes())['roles'][role]
    facts = json.loads((output/'origin-facts.json').read_bytes())
    require(facts['origin'] == case and facts['role'] == role
        and sha(output/'image.docker.tar') == case['expandedArchiveSha256'], 'EXACT_STAGED_ORIGIN_REQUIRED')
    spec = importlib.util.spec_from_file_location('original_scan_gate', ROOT/'scripts/package-semantic-proposal-candidate.py')
    producer = importlib.util.module_from_spec(spec); spec.loader.exec_module(producer)
    scan_value = json.loads(scan.read_bytes())
    producer.scan_gate(scan_value, role, case['configurationImageId'])
    def git(*args):
        return subprocess.check_output(['git', '-C', str(source_directory), *args], timeout=60)
    require(git('rev-parse', 'HEAD').decode().strip() == case['sourceCommit']
        and not git('status', '--porcelain', '--untracked-files=all').strip(), 'EXACT_CLEAN_ORIGINAL_SOURCE_REQUIRED')
    source_tree = git('rev-parse', 'HEAD^{tree}').decode().strip()
    require('reviewedAndTestedTree' not in case or source_tree == case['reviewedAndTestedTree'],
        'SAME_ONBOARDING_REVIEWED_AND_TESTED_SOURCE_TREE_REQUIRED')
    subprocess.run(['git', '-C', str(source_directory), 'archive', '--format=tar',
        '-o', str((output/'source.tar').resolve()), case['sourceCommit']], check=True, timeout=60)
    inventory = []
    for entry in git('ls-tree', '-rz', case['sourceCommit']).split(b'\0'):
        if not entry: continue
        metadata, path = entry.split(b'\t', 1); mode, kind, blob = metadata.decode().split()
        inventory.append({'path': path.decode(), 'mode': mode, 'type': kind, 'sha': blob})
    facts.update(newScanQualified=True, newScanSha256=sha(scan), sourceTree=source_tree,
        sourceArchiveSha256=sha(output/'source.tar'), sourceInventoryEntries=len(inventory))
    record = {'schema': 'ouf.unsigned-offline-candidate-package.v1', 'module': role,
        'sourceCommit': case['sourceCommit'], 'imageId': case['configurationImageId'],
        'runtimeUser': facts['imageAudit']['imageConfig']['User'],
        'artifactFormat': 'DOCKER_SAVE_OFFLINE_ARCHIVE_NOT_HOST_OCI_DECLARATION',
        'imageScanGate': 'PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED',
        'originZipSha256': case['zipSha256'], 'originMetadataSha256': facts['originalMetadataSha256'],
        'originFormat': case['originalFormat'], 'imageRebuilt': False, 'imageRelabelled': False,
        'notReleaseAcceptance': True, 'signatureIssued': False, 'runtimeAuthorityIssued': False, 'targetApplyAuthorized': False,
        'vpsOperations': 0, 'futureBuildByteReproducibilityProven': False}
    manifest = {'schema': 'ouf.chatbot-file-module-package.v1', 'module': role,
        'repository': case['sourceRepository'], 'sourceCommit': case['sourceCommit'],
        'cohortSourceLockSha256': sha(LOCK), 'artifactKind': 'DOCKER_SAVE', 'imageId': case['configurationImageId'],
        'scanGate': record['imageScanGate'], 'originFormat': case['originalFormat'],
        'originZipSha256': case['zipSha256'], 'runtimeAuthorityIssued': False,
        'signatureIssued': False, 'targetApplyAuthorized': False, 'notReleaseAcceptance': True,
        'vpsOperations': 0, 'imageRebuilt': False, 'privateRuntimeProposalRequired': True}
    for name, value in [('origin-facts.json', facts), ('package-record.json', record),
        ('source-inventory.json', {'truncated': False, 'tree': inventory}), ('candidate-manifest.json', manifest)]:
        (output/name).write_text(json.dumps(value, indent=2, sort_keys=True)+'\n')
    if scan != output/'trivy-image.json': shutil.copyfile(scan, output/'trivy-image.json')
    files = sorted(p for p in output.rglob('*') if p.is_file() and p.name != 'SHA256SUMS')
    # Preserve inner original SHA256SUMS as members of the new module checksum
    # set; only the new root checksum is omitted from its own list.
    files += sorted(p for p in (output/'origin').rglob('SHA256SUMS') if p.is_file())
    (output/'SHA256SUMS').write_text(''.join(sha(p)+'  '+p.relative_to(output).as_posix()+'\n' for p in sorted(files)))
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('role'); parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path); parser.add_argument('--source-directory', type=Path)
    parser.add_argument('--scan', type=Path); args = parser.parse_args()
    if args.scan:
        require(args.source_directory is not None, 'QUALIFIED_SCAN_AND_ORIGINAL_SOURCE_REQUIRED')
        finalize(args.role, args.output, args.source_directory, args.scan)
    else: stage(args.role, args.source, args.output)
    print(json.dumps({'role': args.role, 'configAndLayerBytesVerified': True,
        'runtimeAuthorityIssued': False, 'targetApplyAuthorized': False}))
