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
PROFILE = image.ImageProfile(
    binary_sha='85fa52c68a783f3cf4d54ae6064e7b46d022982c1bef4460616dd76cdc609033',
    source_commit='984eac6a790be89e2a11de175a7413e1e3e32dd3',
    image_tag='ouf-seaweedfs-candidate:4.52-85fa52c6',
    licence_sha='d789d433cc11da163273d1e39be2e8fa67642f9a58ef220d3f258fa9c14ef613',
)
DEPRECATED_MANAGER = 'github.com/aws/aws-sdk-go-v2/feature/s3/manager'
SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')


def package(build, out):
    graph = (build / 'compiled-deps').read_text().splitlines()
    image.require(len(graph) == 1811 and graph == sorted(set(graph))
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


def is_manager(path):
    path = path.removeprefix('vendor/').rsplit('/vendor/', 1)[-1]
    return path == DEPRECATED_MANAGER or path.startswith(DEPRECATED_MANAGER + '/')


def assess(out, image_id, producer, run_id):
    image.require(re.fullmatch(r'[0-9a-f]{40}', producer) and run_id > 0,
                  'GITHUB_PRODUCER_REQUIRED')
    record = image.verify_layout(out, profile=PROFILE)
    image.require(image_id == record['configDigest'], 'DAEMON_IMAGE_ID_CHANGED')
    evidence = {name: (out / name).read_bytes() for name in lifecycle.INPUTS}
    sdk = lifecycle.assess(evidence)
    scan = json.loads(evidence['fresh-image-scan.json'])
    image.require(scan.get('Trivy', {}).get('Version') == '0.70.0', 'PINNED_SCANNER_REQUIRED')
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
    manager_present = any(is_manager(p['Name']) for p in scan['Results'][0]['Packages']) or any(
        is_manager(p['name']) for p in spdx['packages'])
    licence_inventory = [{'name': p['name'], 'version': p.get('versionInfo'),
                          'declared': p.get('licenseDeclared', 'NOASSERTION'),
                          'concluded': p.get('licenseConcluded', 'NOASSERTION')}
                         for p in spdx['packages']]
    return {
        **record,
        'status': 'IMAGE_EVIDENCE_PREPARED_NOT_ADMITTED',
        'producerCommit': producer, 'runId': run_id,
        'sdkLifecycle': sdk, 'deprecatedS3ManagerPresent': manager_present,
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
    args = parser.parse_args()
    if args.command == 'package':
        package(args.build, args.out)
        return
    result = assess(args.out, (args.out / 'daemon-image-id.txt').read_text().strip(),
                    args.producer, args.run_id)
    (args.out / 'assessment.json').write_bytes(image.canonical(result))
    print(json.dumps({k: v for k, v in result.items() if k != 'licenceInventory'}, indent=2))
    image.require(result['sdkLifecycle']['status'] == 'AWS_SDK_V1_ABSENT'
                  and not result['deprecatedS3ManagerPresent'], 'LEGACY_IMAGE_DEPENDENCY_PRESENT')


if __name__ == '__main__':
    main()
