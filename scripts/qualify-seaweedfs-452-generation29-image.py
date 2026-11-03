#!/usr/bin/env python3
"""Package and assess the exact patched SeaweedFS 4.52 lab candidate."""
import argparse
from collections import Counter
import importlib.util
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


image = load_module('runtime_image', 'tools/storage_security/runtime_image.py')
lifecycle = load_module('sdk_lifecycle', 'scripts/assess-storage-sdk-lifecycle.py')
MANIFEST_PATH = 'releases/seaweedfs-452-generation29-build-manifest-20261103.json'
SOURCE_FILES = (
    '.github/workflows/storage-452-generation29-image.yml',
    'scripts/qualify-seaweedfs-452-generation29-image.py',
    'scripts/readback-seaweedfs-452-generation29-image.py',
    'scripts/assess-storage-sdk-lifecycle.py',
    'tools/storage_security/runtime_image.py',
    'tests/test_seaweedfs_452_generation29_image.py',
    'tests/test_storage_runtime_image.py', MANIFEST_PATH,
)


def validate_manifest(value):
    image.require(value.get('schema') == 'ouf.seaweedfs-generation-build-manifest.v1'
                  and value.get('generation') == 29
                  and value.get('status') == 'SOURCE_REVIEWED_BUILD_PINNED_NOT_ADMITTED'
                  and value.get('upstreamCommit') == '984eac6a790be89e2a11de175a7413e1e3e32dd3',
                  'GENERATION29_MANIFEST_REQUIRED')
    patches = value.get('orderedPatches', [])
    image.require(len(patches) == 29 and len({p['path'] for p in patches}) == 29
                  and all(re.fullmatch(r'patches/seaweedfs/4[.]52-[a-z0-9-]+[.]patch', p['path'])
                          and re.fullmatch(r'[0-9a-f]{64}', p['sha256']) for p in patches),
                  'EXACT_29_PATCH_IDENTITIES_REQUIRED')
    build = value['build']
    image.require(build['go'] == '1.27.3' and build['os'] == 'linux' and build['arch'] == 'amd64'
                  and build['cgo'] is False and build['tags'] == []
                  and re.fullmatch(r'[0-9a-f]{64}', build['binarySha256'])
                  and build['binarySha256'] != '85fa52c68a783f3cf4d54ae6064e7b46d022982c1bef4460616dd76cdc609033'
                  and isinstance(build['compiledPackages'], int) and build['compiledPackages'] > 0
                  and re.fullmatch(r'[0-9a-f]{64}', build['compiledPackagesSha256'])
                  and re.fullmatch(r'[0-9a-f]{40}', build['patchedSourceTree'])
                  and build['binaryModuleRows'] > 0
                  and re.fullmatch(r'[0-9a-f]{64}', build['binaryModuleInventorySha256'])
                  and set(build['rootLockfilesSha256']) == {'go.mod', 'go.sum'}
                  and all(re.fullmatch(r'[0-9a-f]{64}', d) for d in build['rootLockfilesSha256'].values()),
                  'NEW_STANDARD_BUILD_PIN_REQUIRED')
    image.require(value['releaseAdmitted'] is False and value['runtimeAuthorityIssued'] is False
                  and value['targetOperations'] == 0, 'NO_ADMISSION_OR_AUTHORITY_REQUIRED')
    return value


MANIFEST = validate_manifest(json.loads((ROOT / MANIFEST_PATH).read_bytes()))
PROFILE = image.ImageProfile(
    binary_sha=MANIFEST['build']['binarySha256'], source_commit=MANIFEST['upstreamCommit'],
    image_tag='ouf-seaweedfs-candidate:4.52-g29-' + MANIFEST['build']['binarySha256'][:8],
    licence_sha='d789d433cc11da163273d1e39be2e8fa67642f9a58ef220d3f258fa9c14ef613',
)


def verify_patch_sources():
    for item in MANIFEST['orderedPatches']:
        path = ROOT / item['path']
        image.require(path.is_file() and not path.is_symlink()
                      and image.sha(path.read_bytes()) == item['sha256'], 'PATCH_SOURCE_CHANGED:' + item['path'])


def source_names():
    return set(SOURCE_FILES) | {item['path'] for item in MANIFEST['orderedPatches']}


def seal_sources(out):
    verify_patch_sources()
    (out / 'source-SHA256SUMS').write_text(''.join(
        image.sha((ROOT / name).read_bytes()) + '  ' + name + '\n' for name in sorted(source_names())))


DEPRECATED_MANAGER = 'github.com/aws/aws-sdk-go-v2/feature/s3/manager'
SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')


def package(build, out):
    verify_patch_sources()
    graph = (build / 'compiled-deps').read_text().splitlines()
    image.require(len(graph) == MANIFEST['build']['compiledPackages']
                  and image.sha((build / 'compiled-deps').read_bytes()) == MANIFEST['build']['compiledPackagesSha256'] and graph == sorted(set(graph))
                  and {lifecycle.WEED, lifecycle.WEED + '/s3api'} <= set(graph)
                  and not any(lifecycle.sdk_v1(p) or is_manager(p) for p in graph),
                  'EXACT_STANDARD_PACKAGE_CLOSURE_REQUIRED')
    info = (build / 'build-info.txt').read_bytes()
    lines = info.decode().splitlines()
    build_settings = {line.split('\t', 2)[2] for line in lines if line.startswith('\tbuild\t')}
    image.require(bool(lines) and lines[0].endswith(': go1.27.3')
                  and {'-trimpath=true', 'CGO_ENABLED=0', 'GOARCH=amd64', 'GOOS=linux',
                       'vcs.revision=' + PROFILE.source_commit} <= build_settings
                  and not any(setting.startswith('-tags=') for setting in build_settings),
                  'EXACT_STANDARD_BUILD_SETTINGS_REQUIRED')
    module_rows = [line for line in lines if line.startswith('\tdep\t')]
    image.require(len(module_rows) == MANIFEST['build']['binaryModuleRows']
                  and image.sha(('\n'.join(module_rows) + '\n').encode()) == MANIFEST['build']['binaryModuleInventorySha256'],
                  'EXACT_BINARY_MODULE_INVENTORY_REQUIRED')
    modules = dict(line.split('\t')[2:4] for line in lines if line.startswith('\tdep\t'))
    image.require(bool(modules) and not any(lifecycle.sdk_v1(m) or is_manager(m) for m in modules),
                  'LEGACY_BINARY_MODULE_PRESENT')
    image.require(modules.get('golang.org/x/net') == 'v0.62.0'
                  and modules.get('golang.org/x/crypto') == 'v0.58.1-0.20261009181718-2f1f834330b2',
                  'FIXED_NETWORK_AND_CRYPTO_MODULES_REQUIRED')
    image.write_image((build / 'weed').read_bytes(), (build / 'LICENSE').read_bytes(),
                      out, profile=PROFILE)
    graph_bytes = image.canonical({'packages': graph})
    (out / 'original-compiled-packages.json').write_bytes(graph_bytes)
    (out / 'original-candidate.json').write_bytes(image.canonical({
        'binarySha256': PROFILE.binary_sha,
        'declaredSource': PROFILE.source_commit,
        'compiledPackagesSha256': image.sha(graph_bytes),
        'buildInfoSha256': image.sha(info),
        'buildProfile': 'go1.27.3-linux-amd64-cgo0-no-tags',
    }))
    (out / 'build-info.txt').write_bytes(info)
    (out / 'generation-manifest.json').write_bytes((ROOT / MANIFEST_PATH).read_bytes())
    build_source = json.loads((build / 'build-source.json').read_bytes())
    image.require(build_source['upstreamCommit'] == PROFILE.source_commit
                  and build_source['patchManifestSha256'] == image.sha((ROOT / MANIFEST_PATH).read_bytes())
                  and re.fullmatch(r'[0-9a-f]{40}', build_source['patchedTree'])
                  and build_source['orderedPatchCount'] == 29,
                  'PATCHED_SOURCE_BINDING_REQUIRED')
    (out / 'build-source.json').write_bytes(image.canonical(build_source))
    for name in ('root-modules.txt', 'root-module-graph.txt'):
        data = (build / name).read_bytes()
        image.require(data and image.sha(data) == build_source['moduleEvidenceSha256'][name],
                      'MODULE_EVIDENCE_BINDING_REQUIRED')
        image.require(not re.search(rb'(^|[ \n])github[.]com/(aws/aws-sdk-go|aws/aws-sdk-go-v2/feature/s3/manager|olivere/elastic/v7|rclone/rclone)(@| |\n|$)', data),
                      'UNMAINTAINED_ROOT_MODULE_PRESENT')
        (out / name).write_bytes(data)
    verify_build_evidence(out)


def is_manager(path):
    path = path.removeprefix('vendor/').rsplit('/vendor/', 1)[-1]
    return path == DEPRECATED_MANAGER or path.startswith(DEPRECATED_MANAGER + '/')


def verify_build_evidence(out):
    manifest_bytes = (ROOT / MANIFEST_PATH).read_bytes()
    image.require((out / 'generation-manifest.json').read_bytes() == manifest_bytes,
                  'EXACT_GENERATION_MANIFEST_REQUIRED')
    original = json.loads((out / 'original-candidate.json').read_bytes())
    info = (out / 'build-info.txt').read_bytes()
    image.require(original['buildInfoSha256'] == image.sha(info), 'BUILD_INFO_BINDING_REQUIRED')
    lines = info.decode().splitlines()
    settings = {line.split('\t', 2)[2] for line in lines if line.startswith('\tbuild\t')}
    image.require(bool(lines) and lines[0].endswith(': go1.27.3')
                  and {'-trimpath=true', 'CGO_ENABLED=0', 'GOARCH=amd64', 'GOOS=linux',
                       'vcs.revision=' + PROFILE.source_commit} <= settings
                  and not any(s.startswith('-tags=') for s in settings), 'EXACT_STANDARD_BUILD_SETTINGS_REQUIRED')
    module_rows = [line for line in lines if line.startswith('\tdep\t')]
    image.require(len(module_rows) == MANIFEST['build']['binaryModuleRows']
                  and image.sha(('\n'.join(module_rows) + '\n').encode()) == MANIFEST['build']['binaryModuleInventorySha256'],
                  'EXACT_BINARY_MODULE_INVENTORY_REQUIRED')
    modules = dict(line.split('\t')[2:4] for line in lines if line.startswith('\tdep\t'))
    image.require(modules.get('golang.org/x/net') == 'v0.62.0'
                  and modules.get('golang.org/x/crypto') == 'v0.58.1-0.20261009181718-2f1f834330b2'
                  and not any(lifecycle.sdk_v1(m) or is_manager(m) for m in modules),
                  'FIXED_MAINTAINED_BINARY_MODULES_REQUIRED')
    graph = json.loads((out / 'original-compiled-packages.json').read_bytes())['packages']
    image.require(graph == sorted(set(graph)) and len(graph) == MANIFEST['build']['compiledPackages']
                  and image.sha(('\n'.join(graph) + '\n').encode()) == MANIFEST['build']['compiledPackagesSha256']
                  and not any(lifecycle.sdk_v1(p) or is_manager(p) for p in graph),
                  'EXACT_STANDARD_PACKAGE_CLOSURE_REQUIRED')
    source = json.loads((out / 'build-source.json').read_bytes())
    image.require(source['upstreamCommit'] == PROFILE.source_commit
                  and source['patchManifestSha256'] == image.sha(manifest_bytes)
                  and source['patchedTree'] == MANIFEST['build']['patchedSourceTree']
                  and source['orderedPatchCount'] == 29
                  and source['rootLockfilesSha256'] == MANIFEST['build']['rootLockfilesSha256'],
                  'PATCHED_SOURCE_BINDING_REQUIRED')
    for name in ('root-modules.txt', 'root-module-graph.txt'):
        data = (out / name).read_bytes()
        image.require(data and image.sha(data) == source['moduleEvidenceSha256'][name],
                      'MODULE_EVIDENCE_BINDING_REQUIRED')
        image.require(not re.search(rb'(^|[ \n])github[.]com/(aws/aws-sdk-go|aws/aws-sdk-go-v2/feature/s3/manager|olivere/elastic/v7|rclone/rclone)(@| |\n|$)', data),
                      'UNMAINTAINED_ROOT_MODULE_PRESENT')
    return source


def assess(out, image_id, producer, run_id):
    image.require(re.fullmatch(r'[0-9a-f]{40}', producer) and run_id > 0,
                  'GITHUB_PRODUCER_REQUIRED')
    source = verify_build_evidence(out)
    record = image.verify_layout(out, profile=PROFILE)
    image.require(image_id == record['configDigest'], 'DAEMON_IMAGE_ID_CHANGED')
    evidence = {name: (out / name).read_bytes() for name in lifecycle.INPUTS}
    sdk = lifecycle.assess(evidence)
    scan = json.loads(evidence['fresh-image-scan.json'])
    image.require(scan.get('Trivy', {}).get('Version') == '0.70.0', 'PINNED_SCANNER_REQUIRED')
    build_lines = (out / 'build-info.txt').read_text().splitlines()
    image.require(not any(line.startswith('\t=>\t') for line in build_lines),
                  'REPLACED_BINARY_MODULE_UNSUPPORTED')
    module_lines = [line.split('\t')[2:4] for line in build_lines if line.startswith(('\tdep\t', '\tmod\t'))]
    main_modules = [line.split('\t')[2:4] for line in build_lines if line.startswith('\tmod\t')]
    image.require(len(main_modules) == 1 and main_modules[0][0] == 'github.com/seaweedfs/seaweedfs'
                  and main_modules[0][1], 'EXACT_MAIN_MODULE_REQUIRED')
    expected_modules = {tuple(row) for row in module_lines} | {('stdlib', 'v' + MANIFEST['build']['go'])}
    scan_packages = scan['Results'][0]['Packages']
    image.require(len(scan_packages) == len(expected_modules)
                  and {(p['Name'], p['Version']) for p in scan_packages} == expected_modules,
                  'COMPLETE_BINARY_SCAN_INVENTORY_REQUIRED')

    findings = scan['Results'][0].get('Vulnerabilities')
    if findings is None:
        findings = []
    image.require(isinstance(findings, list)
                  and all(isinstance(f, dict) and f.get('Severity') in SEVERITIES
                          and f.get('VulnerabilityID') for f in findings),
                  'COMPLETE_SEVERITY_INVENTORY_REQUIRED')
    counts = Counter(f['Severity'] for f in findings)
    held = [f['VulnerabilityID'] for f in findings if f['Severity'] in ('HIGH', 'CRITICAL', 'UNKNOWN')]
    spdx = json.loads(evidence['image.spdx.json'])
    versioned = [(p['name'], p['versionInfo']) for p in spdx['packages'] if p.get('versionInfo')]
    descriptive = [(p['name'], p.get('primaryPackagePurpose')) for p in spdx['packages']
                   if not p.get('versionInfo')]
    image.require(len(versioned) == len(expected_modules) and set(versioned) == expected_modules,
                  'COMPLETE_SPDX_MODULE_INVENTORY_REQUIRED')
    image.require(isinstance(scan.get('ArtifactName'), str) and scan['ArtifactName']
                  and len(descriptive) == 2 and set(descriptive) == {
                      ('usr/local/bin/weed', 'APPLICATION'), (scan['ArtifactName'], 'CONTAINER')},
                  'EXACT_SPDX_DESCRIPTIVE_NODES_REQUIRED')
    manager_present = any(is_manager(p['Name']) for p in scan['Results'][0]['Packages']) or any(
        is_manager(p['name']) for p in spdx['packages'])
    licence_inventory = [{'name': p['name'], 'version': p.get('versionInfo'),
                          'declared': p.get('licenseDeclared', 'NOASSERTION'),
                          'concluded': p.get('licenseConcluded', 'NOASSERTION')}
                         for p in spdx['packages']]
    return {
        **record, 'generation': 29, 'patchedSourceTree': source['patchedTree'],
        'buildSourceSha256': image.sha((out / 'build-source.json').read_bytes()),
        'moduleEvidenceSha256': source['moduleEvidenceSha256'], 'patchManifestSha256': image.sha((ROOT / MANIFEST_PATH).read_bytes()),
        'status': 'IMAGE_EVIDENCE_PREPARED_NOT_ADMITTED',
        'producerCommit': producer, 'runId': run_id,
        'sdkLifecycle': sdk, 'deprecatedS3ManagerPresent': manager_present,
        'scanMatchesAllBinaryModules': True, 'spdxMatchesAllBinaryModules': True,
        'scannedBinaryComponents': len(expected_modules),
        'vulnerabilitySubgate': 'HELD_RAW_FINDINGS' if held else 'PASS_RAW',
        'rawSeverityCounts': {severity: counts[severity] for severity in SEVERITIES},
        'unresolvedHighCriticalUnknown': sorted(set(held)),
        'appliedApplicabilityDispositions': [],
        'freshScanSha256': image.sha(evidence['fresh-image-scan.json']),
        'sbomSha256': image.sha(evidence['image.spdx.json']),
        'spdxPackages': len(licence_inventory), 'licenceInventory': licence_inventory,
        'licenceReview': 'OPEN', 'durableReleaseCustody': 'OPEN', 'cohortQualification': 'OPEN',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    pack = commands.add_parser('package')
    pack.add_argument('build', type=Path)
    pack.add_argument('out', type=Path)
    check = commands.add_parser('assess')
    check.add_argument('out', type=Path)
    check.add_argument('producer')
    check.add_argument('run_id', type=int)
    sources = commands.add_parser('seal-sources')
    sources.add_argument('out', type=Path)
    commands.add_parser('patch-paths')
    args = parser.parse_args()
    if args.command == 'patch-paths':
        verify_patch_sources()
        print('\n'.join(p['path'] for p in MANIFEST['orderedPatches']))
        return
    if args.command == 'seal-sources':
        seal_sources(args.out)
        return
    if args.command == 'package':
        package(args.build, args.out)
        return
    result = assess(args.out, (args.out / 'daemon-image-id.txt').read_text().strip(),
                    args.producer, args.run_id)
    (args.out / 'assessment.json').write_bytes(image.canonical(result))
    print(json.dumps({k: v for k, v in result.items() if k != 'licenceInventory'}, indent=2))
    image.require(result['sdkLifecycle']['status'] == 'AWS_SDK_V1_ABSENT'
                  and not result['deprecatedS3ManagerPresent'], 'LEGACY_IMAGE_DEPENDENCY_PRESENT')
    image.require(result['vulnerabilitySubgate'] == 'PASS_RAW', 'UNRESOLVED_RAW_VULNERABILITIES')


if __name__ == '__main__':
    main()
