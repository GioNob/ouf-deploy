#!/usr/bin/env python3
"""Custody of an existing CI image, reusing the qualified Teatri image helper.

No build, import, target access, policy publication or job execution. The
caller authenticates the immutable case and downloads its exact artifact.
"""
import gzip
import hashlib
import importlib.util
import json
import re
import shutil
import signal
import stat
import sys
import tarfile
import zipfile
import zlib
from pathlib import Path


class Stop(ValueError):
    pass


def require(value, code):
    if not value:
        raise Stop(code)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def parsed(raw):
    def unique(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'UNIQUE_JSON_KEYS_REQUIRED')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: require(False, 'FINITE_JSON_REQUIRED'))


def file_hash(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            value.update(block)
    return value.hexdigest()


def split(source, folder, size=25165824):
    rows = []
    with source.open('rb') as stream:
        while block := stream.read(size):
            name = 'candidate.zip.part%02d' % len(rows)
            (folder/name).write_bytes(block)
            rows.append({'name': name, 'bytes': len(block), 'sha256': hashlib.sha256(block).hexdigest()})
    return rows


def checksum(raw):
    value = 0
    for line in raw.decode('utf-8-sig').splitlines():
        value = zlib.crc32(line.encode(), value)
    return value if value < 2**31 else value-2**32


def jar_facts(path, baseline):
    # Same byte/CRC/version fence as the installed V36 publisher, now comparing
    # ALL36 existing resources: this correction has no schema migration.
    with zipfile.ZipFile(path) as jar:
        rows = [r for r in jar.infolist() if r.filename.startswith('BOOT-INF/classes/db/migration/') and r.filename.endswith('.sql')]
        require(len(rows) == len({r.filename for r in rows}) == 36, 'EXACT_36_MIGRATION_RESOURCES_REQUIRED')
        facts = []
        for row in rows:
            match = re.fullmatch(r'BOOT-INF/classes/db/migration/V([1-9][0-9]*)__[A-Za-z0-9_]+\.sql', row.filename)
            require(match and 0 < row.file_size <= 131072, 'BOUNDED_SQL_RESOURCE_REQUIRED')
            raw = jar.read(row)
            facts.append({'version': match[1], 'script': row.filename.split('/')[-1],
                          'sha256': hashlib.sha256(raw).hexdigest(), 'flywayChecksum': checksum(raw)})
        facts.sort(key=lambda row: int(row['version']))
        require([row['version'] for row in facts] == [str(i) for i in range(1, 37)] and facts == baseline,
                'ALL_36_INSTALLED_MIGRATIONS_MUST_MATCH')
        yaml = jar.read('BOOT-INF/classes/application.yml')
        role_name = 'BOOT-INF/classes/authorization/managed-profile-recovery-role-v1.json'
        require(len(yaml) <= 131072 and jar.namelist().count(role_name) == 1, 'BOUNDED_YAML_AND_ONE_CONTROL_ROLE_REQUIRED')
        role = parsed(jar.read(role_name))
        require(role.get('assignments') in (None, []) and 'subjectId' not in role, 'UNASSIGNED_ROLE_ONLY')
    return {'jarSha256': file_hash(path), 'jarBytes': path.stat().st_size,
            'applicationYamlSha256': hashlib.sha256(yaml).hexdigest(), 'migrations': facts,
            'managedProfileRole': role, 'databaseMigrationRequired': False}


def unpack(source, work, case):
    members = {'image.tar.gz', 'manifest.json', 'SHA256SUMS'} if case['role'] == 'onboarding' else {
        'image.tar.gz', 'image-id.txt', 'image-config.json', 'source-commit.txt', 'capabilities.json', 'SHA256SUMS'}
    limits = {'image.tar.gz': case['maximumCompressedBytes']}
    with zipfile.ZipFile(source) as zipped:
        rows = zipped.infolist()
        require(len(rows) == len(members) and {r.filename for r in rows} == members, 'EXACT_CI_MEMBER_SET_REQUIRED')
        for row in rows:
            require(not row.is_dir() and stat.S_IFMT(row.external_attr >> 16) in (0, stat.S_IFREG)
                    and 0 < row.file_size <= limits.get(row.filename, 2*1024*1024), 'BOUNDED_REGULAR_CI_MEMBER_REQUIRED')
            with zipped.open(row) as stream, (work/row.filename).open('xb') as output:
                shutil.copyfileobj(stream, output, 1048576)
    checks = {}
    for line in (work/'SHA256SUMS').read_text().splitlines():
        match = re.fullmatch(r'([a-f0-9]{64})  ([A-Za-z0-9_.-]+)', line)
        require(match and match[2] not in checks, 'EXACT_UNIQUE_CI_CHECKSUM_REQUIRED')
        checks[match[2]] = match[1]
    expected = {'image.tar.gz'} if case['role'] == 'onboarding' else members-{'SHA256SUMS'}
    require(set(checks) == expected and all(file_hash(work/name) == value for name, value in checks.items()),
            'ALL_CI_MEMBER_DIGESTS_REQUIRED')
    archive = work/'image.tar.gz'
    if case['role'] == 'onboarding':
        manifest = parsed((work/'manifest.json').read_bytes())
        require(manifest['schema'] == 'ouf.onboarding-tested-image.v1'
                and manifest['repository'] == case['repository']
                and manifest['reviewedSourceCommit'] == case['sourceCommit']
                and manifest['testedCommit'] == case['testedCommit']
                and manifest['imageRevisionLabel'] == case['testedCommit']
                and manifest['workflowRunId'] == str(case['workflowRunId'])
                and manifest['imageId'] == case['configurationImageId']
                and manifest['archiveSha256'] == checks['image.tar.gz']
                and manifest['archiveBytes'] == archive.stat().st_size
                and manifest['sourceSchemaMigration'] == 'V36__managed_profile_recovery_sessions.sql'
                and all(manifest[key] is False for key in ('targetApplyAuthorized', 'humanBudgetGranted', 'releaseAcceptance')),
                'EXACT_QUALIFIED_SOURCE_MANIFEST_REQUIRED')
    else:
        manifest = {'sourceCommit': (work/'source-commit.txt').read_text().strip(),
                    'imageId': (work/'image-id.txt').read_text().strip(), 'fileHashes': checks}
        require(manifest['sourceCommit'] == case['sourceCommit'] and manifest['imageId'] == case['configurationImageId'],
                'EXACT_MCP_CI_SOURCE_REQUIRED')
        inspection = parsed((work/'image-config.json').read_bytes())
        require(type(inspection) is list and len(inspection) == 1 and inspection[0]['Id'] == case['configurationImageId'],
                'ONE_EXACT_MCP_CI_IMAGE_REQUIRED')
    return manifest, checks['image.tar.gz']


def prepare(source, destination, deploy, case):
    require(case['role'] in ('onboarding', 'mcp') and case['targetApplyAuthorized'] is False, 'CLOSED_CUSTODY_CASE_REQUIRED')
    require(source.is_file() and source.stat().st_size == case['artifactZipBytes']
            and file_hash(source) == case['artifactZipSha256'], 'EXACT_QUALIFIED_ZIP_REQUIRED')
    require(not destination.exists(), 'DELIVERY_DIRECTORY_CONSUMED')
    destination.mkdir(mode=0o700)
    work = destination/'work'; work.mkdir(mode=0o700)
    image = destination/'image'; image.mkdir(mode=0o700)
    manifest, compressed_hash = unpack(source, work, case)
    helper = deploy/'tools/acquisition_read_native/image_custody.py'
    require(file_hash(helper) == case['custodyHelperSha256'], 'PINNED_PURE_CUSTODY_HELPER_REQUIRED')
    spec = importlib.util.spec_from_file_location('existing_pure_custody', helper)
    custody = importlib.util.module_from_spec(spec); spec.loader.exec_module(custody)
    expanded = work/'expanded.tar'; total = 0
    with gzip.open(work/'image.tar.gz', 'rb') as zipped, expanded.open('xb') as output:
        while block := zipped.read(1048576):
            total += len(block)
            require(total <= case['maximumExpandedBytes'], 'BOUNDED_EXPANDED_IMAGE_REQUIRED')
            output.write(block)
    expanded_hash = file_hash(expanded)
    binding = None if case['role'] == 'onboarding' else {
        'schema': 'ouf.acquisition-image-source-by-qualified-ci-manifest.v1',
        'sourceCommit': case['sourceCommit'], 'imageId': case['configurationImageId'],
        'compressedArchiveSha256': compressed_hash, 'stagedReceiptHash': hashlib.sha256(encoded(manifest)).hexdigest(),
        'frozenPlanHash': hashlib.sha256(encoded(case)).hexdigest()}
    with expanded.open('rb') as original:
        audit = custody.archive(original, expanded_hash, case['configurationImageId'], case['testedCommit'], ci_source_binding=binding)
        require(audit['imageConfig'].get('User') == case['user'] and audit['imageConfig'].get('Entrypoint') == case['entrypoint'],
                'EXACT_QUALIFIED_LAUNCH_REQUIRED')
        with (work/'native.tar').open('x+b') as native:
            derived = custody.tagless_archive(original, native, audit, containerd=True)
    audit['nativeIdentity'] = custody.native_identity(audit)
    facts = None
    if case['role'] == 'onboarding':
        application = work/'application.jar'; found = 0
        with tarfile.open(expanded, 'r:') as outer:
            for name in audit['layerMembers']:
                with outer.extractfile(name) as stream, tarfile.open(fileobj=stream, mode='r|*') as layer:
                    for member in layer:
                        require(member.name not in ('app/.wh.application.jar', 'app/.wh..wh..opq'), 'NO_AMBIGUOUS_APPLICATION_WHITEOUT')
                        if member.name not in ('app/application.jar', './app/application.jar'):
                            continue
                        found += 1
                        require(found == 1 and member.isfile() and 0 < member.size <= 268435456, 'ONE_BOUNDED_APPLICATION_JAR_REQUIRED')
                        with layer.extractfile(member) as stream, application.open('xb') as output:
                            shutil.copyfileobj(stream, output, 1048576)
        require(found == 1, 'PACKAGED_APPLICATION_REQUIRED')
        baseline_path = deploy/'releases/onboarding-profile-recovery-image-custody-20261027.json'
        require(file_hash(baseline_path) == case['migrationBaselineSha256'], 'PINNED_INSTALLED_MIGRATION_BASELINE_REQUIRED')
        facts = jar_facts(application, parsed(baseline_path.read_bytes())['application']['migrations'])
    parts = split(source, image)
    receipt = {**case, 'schema': 'ouf.managed-profile-control-image-custody.v1', 'sourceManifest': manifest,
               'imageArchiveSha256': compressed_hash, 'imageArchiveBytes': (work/'image.tar.gz').stat().st_size,
               'expandedArchiveSha256': expanded_hash, 'expandedArchiveBytes': total,
               'nativeImageId': custody.runtime_image_id(audit), 'derivedArchiveSha256': derived['derivedArchiveSha256'],
               'nativeArchiveBytes': derived['archiveBytes'], 'imageAudit': audit, 'application': facts, 'parts': parts,
               'imageRebuilt': False, 'imageImported': False, 'imageRelabelled': False, 'runtimeAuthorityIssued': False,
               'humanBudgetGranted': False, 'applicationE2EProven': False, 'releaseAcceptance': False}
    (image/'delivery.json').write_bytes(encoded(receipt))
    (image/'SHA256SUMS').write_text(''.join(row['sha256']+'  '+row['name']+'\n' for row in parts))
    shutil.rmtree(work)
    return receipt


def main():
    try:
        require(len(sys.argv) == 5, 'CLOSED_CUSTODY_CLI_REQUIRED')
        signal.signal(signal.SIGALRM, lambda *_: require(False, 'FINITE_STAGE_DEADLINE')); signal.alarm(300)
        case = parsed(Path(sys.argv[4]).read_bytes())
        result = prepare(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), case)
        print(json.dumps({'status': 'QUALIFIED_EXISTING_IMAGE_STAGED', 'nativeImageId': result['nativeImageId'],
                          'parts': len(result['parts']), 'targetApplyAuthorized': False}), flush=True)
        return 0
    except Exception as error:
        reason = str(error) if isinstance(error, Stop) and re.fullmatch('[A-Z0-9_]{1,120}', str(error)) else 'IMAGE_CUSTODY_UNPROVEN_RECONCILE'
        print(json.dumps({'status': 'STOP_RECONCILE', 'reasonCode': reason, 'automaticReplayAllowed': False,
                          'targetApplyAuthorized': False}), flush=True)
        return 2
    finally:
        signal.alarm(0)


if __name__ == '__main__':
    raise SystemExit(main())
