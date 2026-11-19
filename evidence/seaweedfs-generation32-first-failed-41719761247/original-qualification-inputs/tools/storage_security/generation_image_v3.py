#!/usr/bin/env python3
"""Package and assess the exact patched SeaweedFS 4.52 lab candidate."""
import argparse
from collections import Counter
import importlib.util
import json
from pathlib import Path
import re

ROOT = None
GENERATION = None
MANIFEST_PATH = None
SOURCE_FILES = ()
PREVIOUS = None


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module




def validate_manifest(value):
    image.require(value.get('schema') == 'ouf.seaweedfs-generation-build-manifest.v1'
                  and value.get('generation') == GENERATION
                  and value.get('status') == 'SOURCE_REVIEWED_BUILD_PINNED_NOT_ADMITTED'
                  and value.get('upstreamCommit') == '984eac6a790be89e2a11de175a7413e1e3e32dd3',
                  'GENERATION_MANIFEST_REQUIRED')
    patches = value.get('orderedPatches', [])
    image.require(len(patches) == GENERATION and len({p['path'] for p in patches}) == GENERATION
                  and all(re.fullmatch(r'patches/seaweedfs/4[.]52-[a-z0-9-]+[.]patch', p['path'])
                          and re.fullmatch(r'[0-9a-f]{64}', p['sha256']) for p in patches),
                  'EXACT_ORDERED_PATCH_IDENTITIES_REQUIRED')
    build = value['build']
    image.require(build['go'] == '1.27.3' and build['os'] == 'linux' and build['arch'] == 'amd64'
                  and build['cgo'] is False and build['tags'] == []
                  and re.fullmatch(r'[0-9a-f]{64}', build['binarySha256'])
                  and build['binarySha256'] != PREVIOUS['build']['binarySha256']
                  and isinstance(build['compiledPackages'], int) and build['compiledPackages'] > 0
                  and re.fullmatch(r'[0-9a-f]{64}', build['compiledPackagesSha256'])
                  and re.fullmatch(r'[0-9a-f]{40}', build['patchedSourceTree'])
                  and build['binaryModuleRows'] > 0
                  and re.fullmatch(r'[0-9a-f]{64}', build['binaryModuleInventorySha256'])
                  and set(build['rootLockfilesSha256']) == {'go.mod', 'go.sum'}
                  and all(re.fullmatch(r'[0-9a-f]{64}', d) for d in build['rootLockfilesSha256'].values()),
                  'NEW_STANDARD_BUILD_PIN_REQUIRED')
    image.require(value['orderedPatches'][:-1] == PREVIOUS['orderedPatches']
                  and GENERATION == PREVIOUS['generation'] + 1,
                  'EXACT_PREVIOUS_PATCH_PREFIX_REQUIRED')
    image.require(all(build[field] != PREVIOUS['build'][field] for field in
                      ('binarySha256', 'compiledPackagesSha256', 'binaryModuleInventorySha256', 'patchedSourceTree')),
                  'NEW_GENERATION_FACTS_REQUIRED')
    requirements = value.get('requiredHostedRegression', {})
    image.require(set(requirements) == {'shell'}
                  and requirements['shell'].get('status') == 'REQUIRED_HOSTED_PASS_NOT_LOCALLY_OBSERVED'
                  and requirements['shell'].get('package') == 'github.com/seaweedfs/seaweedfs/weed/shell'
                  and requirements['shell'].get('tests') == sorted(set(requirements['shell'].get('tests', [])))
                  and len(requirements['shell']['tests']) >= 10
                  and all(isinstance(name, str) and name.startswith('Test')
                          for name in requirements['shell']['tests'])
                  and re.fullmatch('[0-9a-f]{64}', requirements['shell'].get('localFailureLogSha256', '')),
                  'EXPLICIT_HOSTED_TEST_REQUIREMENTS_REQUIRED')
    regression = value['observedLocalRegression']
    image.require(set(regression) == {'packagesPassed', 'packagesSkipped', 'testsPassed', 'testsSkipped'}
                  and all(type(count) is int and count >= 0 for count in regression.values())
                  and regression['packagesPassed'] > 0 and regression['testsPassed'] > 0,
                  'OBSERVED_REGRESSION_COUNTS_REQUIRED')
    image.require(set(value['regressionProfiles']) == {'main', 'server', 'storage', 'race'}
                  and all(re.fullmatch('[0-9a-f]{64}', profile[field])
                          for profile in value['regressionProfiles'].values()
                          for field in ('terminalTestsSha256', 'terminalPackagesSha256', 'observedLogSha256')),
                  'OBSERVED_REGRESSION_IDENTITIES_REQUIRED')
    image.require(GENERATION == 32 and PREVIOUS['generation'] == 31
                  and value.get('compiledDependencyPolicy') == COMPILED_POLICY,
                  'EXACT_COMPILED_LIFECYCLE_POLICY_REQUIRED')
    image.require(value.get('sourceRevision') == {
        'kind': 'MAINTAINED_CLIENTS_AND_EXPLICIT_STORAGE_PROFILE',
        'previousGeneration': 31,
        'previousManifestSha256': '9a2a00893a07a33e432ac35f6d06da79fd27181ebf16d2fbc4b45f5f9e697719',
        'freshHostedQualificationRequired': True,
        'excludedGoogleFeatures': ['gcs-remote-storage', 'gcs-replication-sink',
                                   'google-pubsub-notification', 'google-pubsub-replication-input'],
    }, 'FRESH_PROFILE_REVISION_REQUIRED')
    image.require(value['regressionProfiles']['server'].get('environmentConditionalPackage') ==
                  'github.com/seaweedfs/seaweedfs/weed/server'
                  and value['regressionProfiles']['server'].get('environmentConditionalTests') ==
                  {name: [] for name in HOSTED_REQUIRED_SERVER_TESTS},
                  'EXACT_SERVER_TLS_CONDITIONAL_TESTS_REQUIRED')
    image.require(value['dependencyMaintenance'] == {'status': 'OPEN', 'allDependenciesMaintained': False},
                  'NO_ALL_DEPENDENCIES_MAINTAINED_CLAIM')
    image.require(value['releaseAdmitted'] is False and value['runtimeAuthorityIssued'] is False
                  and value['targetOperations'] == 0, 'NO_ADMISSION_OR_AUTHORITY_REQUIRED')
    return value


def configure(root, generation, manifest_path, source_files, previous_manifest_path, previous_manifest_sha256):
    """Initialize this freshly imported engine once; never mutate another generation."""
    global ROOT, GENERATION, MANIFEST_PATH, SOURCE_FILES, PREVIOUS, image, lifecycle, MANIFEST, PROFILE
    if ROOT is not None:
        raise ValueError('FRESH_GENERATION_ENGINE_REQUIRED')
    ROOT, GENERATION, MANIFEST_PATH = Path(root), generation, manifest_path
    SOURCE_FILES = tuple(source_files) + (previous_manifest_path,)
    image = load_module('runtime_image', 'tools/storage_security/runtime_image.py')
    lifecycle = load_module('sdk_lifecycle', 'scripts/assess-storage-sdk-lifecycle.py')
    previous_bytes = (ROOT / previous_manifest_path).read_bytes()
    image.require(image.sha(previous_bytes) == previous_manifest_sha256, 'FROZEN_PREVIOUS_MANIFEST_REQUIRED')
    PREVIOUS = json.loads(previous_bytes)
    MANIFEST = validate_manifest(json.loads((ROOT / MANIFEST_PATH).read_bytes()))
    PROFILE = image.ImageProfile(
        binary_sha=MANIFEST['build']['binarySha256'], source_commit=MANIFEST['upstreamCommit'],
        image_tag='ouf-seaweedfs-candidate:4.52-g' + str(GENERATION) + '-' + MANIFEST['build']['binarySha256'][:8],
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


# These are exclusions of the compiled standard storage profile, not of every
# optional/test module graph. The remaining YAML lifecycle review stays open.
HOSTED_REQUIRED_SERVER_TESTS = (
    'TestGuardedPeerHTTPClientUploadsOverTLS',
    'TestGuardedPeerHTTPClientRejectsHTTPSDowngrade',
)

EXCLUDED_MODULES = (
    'github.com/aws/aws-sdk-go',
    'github.com/aws/aws-sdk-go-v2/feature/s3/manager',
    'github.com/boltdb/bolt',
    'github.com/hashicorp/raft-boltdb',
    'github.com/mitchellh/mapstructure',
    'github.com/rcrowley/go-metrics',
    'github.com/Shopify/sarama',
    'github.com/facebookgo/clock',
    'github.com/facebookgo/stats',
    'go.opencensus.io',
    'github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp',
    'github.com/envoyproxy/protoc-gen-validate',
    'github.com/mitchellh/colorstring',
    'go.mongodb.org/mongo-driver',
)
COMPILED_POLICY = {
    'scope': 'COMPILED_STANDARD_PROFILE_ONLY',
    'excludedModulePaths': list(EXCLUDED_MODULES),
    'rootModuleGraphLegacyEdgesMayRemain': True,
    'allDependenciesMaintained': False,
    'yamlLifecycleStatus': 'OPEN',
    'targetFeatureBinding': 'OPEN',
    'freshQualificationRequired': True,
}


def is_excluded_dependency(path):
    path = path.removeprefix('vendor/').rsplit('/vendor/', 1)[-1]
    # MongoDB's maintained v2 is a distinct module, not a v1 subpackage.
    if path == 'go.mongodb.org/mongo-driver/v2' or path.startswith('go.mongodb.org/mongo-driver/v2/'):
        return False
    return any(path == module or path.startswith(module + '/') for module in EXCLUDED_MODULES)


DEPRECATED_MANAGER = 'github.com/aws/aws-sdk-go-v2/feature/s3/manager'
SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')


def package(build, out):
    verify_patch_sources()
    graph = (build / 'compiled-deps').read_text().splitlines()
    image.require(len(graph) == MANIFEST['build']['compiledPackages']
                  and image.sha((build / 'compiled-deps').read_bytes()) == MANIFEST['build']['compiledPackagesSha256'] and graph == sorted(set(graph))
                  and {lifecycle.WEED, lifecycle.WEED + '/s3api'} <= set(graph)
                  and not any(is_excluded_dependency(p) for p in graph),
                  'EXACT_STANDARD_PACKAGE_CLOSURE_REQUIRED')
    info = (build / 'build-info.txt').read_bytes()
    lines = info.decode().splitlines()
    build_settings = {line.split('\t', 2)[2] for line in lines if line.startswith('\tbuild\t')}
    image.require(bool(lines) and lines[0].endswith(': go1.27.3')
                  and {'-trimpath=true', 'CGO_ENABLED=0', 'GOARCH=amd64', 'GOOS=linux',
                       'vcs.revision=' + PROFILE.source_commit, 'vcs.modified=true'} <= build_settings
                  and not any(setting.startswith('-tags=') for setting in build_settings),
                  'EXACT_STANDARD_BUILD_SETTINGS_REQUIRED')
    module_rows = [line for line in lines if line.startswith('\tdep\t')]
    image.require(len(module_rows) == MANIFEST['build']['binaryModuleRows']
                  and image.sha(('\n'.join(module_rows) + '\n').encode()) == MANIFEST['build']['binaryModuleInventorySha256'],
                  'EXACT_BINARY_MODULE_INVENTORY_REQUIRED')
    modules = dict(line.split('\t')[2:4] for line in lines if line.startswith('\tdep\t'))
    image.require(bool(modules) and not any(is_excluded_dependency(m) for m in modules),
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
                  and build_source['orderedPatchCount'] == GENERATION,
                  'PATCHED_SOURCE_BINDING_REQUIRED')
    (out / 'build-source.json').write_bytes(image.canonical(build_source))
    for name in ('root-modules.txt', 'root-module-graph.txt'):
        data = (build / name).read_bytes()
        image.require(data and image.sha(data) == build_source['moduleEvidenceSha256'][name],
                      'MODULE_EVIDENCE_BINDING_REQUIRED')
        image.require(not re.search(rb'(^|[ \n])github[.]com/(aws/aws-sdk-go|aws/aws-sdk-go-v2/feature/s3/manager|olivere/elastic/v7|rclone/rclone)(@| |\n|$)', data),
                      'EXCLUDED_LEGACY_ROOT_MODULE_PRESENT')
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
                       'vcs.revision=' + PROFILE.source_commit, 'vcs.modified=true'} <= settings
                  and not any(s.startswith('-tags=') for s in settings), 'EXACT_STANDARD_BUILD_SETTINGS_REQUIRED')
    module_rows = [line for line in lines if line.startswith('\tdep\t')]
    image.require(len(module_rows) == MANIFEST['build']['binaryModuleRows']
                  and image.sha(('\n'.join(module_rows) + '\n').encode()) == MANIFEST['build']['binaryModuleInventorySha256'],
                  'EXACT_BINARY_MODULE_INVENTORY_REQUIRED')
    modules = dict(line.split('\t')[2:4] for line in lines if line.startswith('\tdep\t'))
    image.require(modules.get('golang.org/x/net') == 'v0.62.0'
                  and modules.get('golang.org/x/crypto') == 'v0.58.1-0.20261009181718-2f1f834330b2'
                  and not any(is_excluded_dependency(m) for m in modules),
                  'FIXED_NETWORK_AND_LEGACY_MODULE_BOUNDARY_REQUIRED')
    graph = json.loads((out / 'original-compiled-packages.json').read_bytes())['packages']
    image.require(graph == sorted(set(graph)) and len(graph) == MANIFEST['build']['compiledPackages']
                  and image.sha(('\n'.join(graph) + '\n').encode()) == MANIFEST['build']['compiledPackagesSha256']
                  and not any(is_excluded_dependency(p) for p in graph),
                  'EXACT_STANDARD_PACKAGE_CLOSURE_REQUIRED')
    source = json.loads((out / 'build-source.json').read_bytes())
    image.require(source['upstreamCommit'] == PROFILE.source_commit
                  and source['patchManifestSha256'] == image.sha(manifest_bytes)
                  and source['patchedTree'] == MANIFEST['build']['patchedSourceTree']
                  and source['orderedPatchCount'] == GENERATION
                  and source['rootLockfilesSha256'] == MANIFEST['build']['rootLockfilesSha256'],
                  'PATCHED_SOURCE_BINDING_REQUIRED')
    for name in ('root-modules.txt', 'root-module-graph.txt'):
        data = (out / name).read_bytes()
        image.require(data and image.sha(data) == source['moduleEvidenceSha256'][name],
                      'MODULE_EVIDENCE_BINDING_REQUIRED')
        image.require(not re.search(rb'(^|[ \n])github[.]com/(aws/aws-sdk-go|aws/aws-sdk-go-v2/feature/s3/manager|olivere/elastic/v7|rclone/rclone)(@| |\n|$)', data),
                      'EXCLUDED_LEGACY_ROOT_MODULE_PRESENT')
    image.require(source.get('nestedKafkaLockfilesSha256') == PREVIOUS['sourceRevision']['nestedKafkaLockfilesSha256'],
                  'EXACT_NESTED_KAFKA_LOCKFILES_REQUIRED')
    verify_qualification_records(source)
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
        **record, 'generation': GENERATION, 'patchedSourceTree': source['patchedTree'],
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
        'dependencyMaintenance': MANIFEST['dependencyMaintenance'],
        'compiledDependencyPolicy': MANIFEST['compiledDependencyPolicy'],
        'excludedCompiledDependenciesPresent': False,
        'releaseAdmitted': False, 'runtimeAuthorityIssued': False, 'targetOperations': 0,
    }


def verify_qualification_records(source):
    verify_hosted_record(source.get('hostedRegressionEvidence', {}))
    evidence = source['regressionEvidence']
    image.require(set(evidence) == set(MANIFEST['regressionProfiles']), 'COMPLETE_REGRESSION_PROFILES_REQUIRED')
    for name, profile in MANIFEST['regressionProfiles'].items():
        actual = evidence[name]
        expected_counts = Counter(profile['observedLocalCounts'])
        optional = profile['environmentConditionalTests']
        outcomes = actual['environmentConditionalOutcomes']
        image.require(set(outcomes) == set(optional) and all(value in ('pass', 'skip') for value in outcomes.values()),
                      'EXACT_CONDITIONAL_OUTCOMES_REQUIRED')
        if name == 'server':
            image.require(all(outcomes.get(test) == 'pass' for test in HOSTED_REQUIRED_SERVER_TESTS),
                          'HOSTED_SERVER_TLS_TESTS_MUST_PASS')
        for parent, action in outcomes.items():
            if action == 'pass':
                expected_counts['skip_tests'] -= 1
                expected_counts['pass_tests'] += 1 + len(optional[parent])
        image.require(actual['profile'] == name and Counter(actual['counts']) == expected_counts
                      and actual['terminalTestsSha256'] == profile['terminalTestsSha256']
                      and actual['terminalPackagesSha256'] == profile['terminalPackagesSha256']
                      and re.fullmatch('[0-9a-f]{64}', actual['logSha256'])
                      and actual['status'] == 'OBSERVED_TEST_IDENTITIES_VERIFIED_NOT_ACCEPTANCE'
                      and actual['targetOperations'] == 0,
                      'REGRESSION_EVIDENCE_CHANGED')
    compat = source['dbCompatibility']
    image.require(compat['schema'] == 'ouf.raftstore-local-compatibility.v1'
                  and compat['status'] == 'LOCAL_DB_FILE_COMPATIBILITY_VERIFIED_NOT_RUNTIME_ACCEPTANCE'
                  and compat['oracleContainsArchivedBoltOutsideCandidateOnly'] is True
                  and compat['testsPassed'] == [
                  'TestLocalFileReadByOldV2AndReadOnlyLocalDoesNotChangeBytes',
                  'TestLogStoreMonotonicInterfaceRemainsUnclaimed',
                  'TestOldV2FileReadAndWriteWithLocalThenReopenOldV2']
                  and compat['candidateModuleFilesUnchanged'] == MANIFEST['build']['rootLockfilesSha256']
                  and compat['candidateRequirementPinsUnchanged'] is True
                  and compat['oracle'] == 'github.com/hashicorp/raft-boltdb/v2@v2.4.2'
                  and compat['fixtureSha256'] == image.sha((ROOT / 'tests/fixtures/seaweedfs-raftstore-compat/compat_test.go').read_bytes())
                  and compat['dbFormatMigrationPerformed'] is False
                  and compat['crashOrPowerLossQualified'] is False
                  and compat['runtimeAuthorityIssued'] is False and compat['targetOperations'] == 0,
                  'EXACT_ISOLATED_DB_COMPATIBILITY_REQUIRED')


def verify_regressions(path, profile_name):
    """Bind actual terminal test identities, preserving environmental skips as skips."""
    image.require(profile_name in MANIFEST['regressionProfiles'], 'KNOWN_REGRESSION_PROFILE_REQUIRED')
    profile = MANIFEST['regressionProfiles'][profile_name]
    raw = path.read_bytes()
    image.require(0 < len(raw) <= 32 * 1024 * 1024, 'BOUNDED_REGRESSION_LOG_REQUIRED')
    records = [json.loads(line) for line in raw.splitlines()]
    terminal = [r for r in records if r.get('Action') in ('pass', 'skip', 'fail')]
    identities = [(r['Package'], r.get('Test')) for r in terminal]
    image.require(terminal and len(identities) == len(set(identities))
                  and not any(r['Action'] == 'fail' for r in terminal),
                  'COMPLETE_UNIQUE_PASS_OR_SKIP_TERMINALS_REQUIRED')
    optional = profile['environmentConditionalTests']
    optional_outcomes = {}
    optional_package = profile.get('environmentConditionalPackage')
    image.require(not optional or isinstance(optional_package, str) and optional_package, 'CONDITIONAL_PACKAGE_REQUIRED')
    for parent, children in optional.items():
        image.require(all(r['Package'] == optional_package for r in terminal
                          if r.get('Test') == parent or r.get('Test', '').startswith(parent + '/')),
                      'CONDITIONAL_TEST_PACKAGE_CHANGED')
        found = [r for r in terminal if r.get('Test') == parent]
        image.require(len(found) == 1, 'CONDITIONAL_PARENT_TERMINAL_REQUIRED')
        child_rows = [r for r in terminal if r.get('Test', '').startswith(parent + '/')]
        image.require({r['Test'] for r in child_rows} == (set(children) if found[0]['Action'] == 'pass' else set())
                      and all(r['Action'] == 'pass' for r in child_rows),
                      'CONDITIONAL_CHILDREN_MUST_PASS_WHEN_PARENT_RUNS')
        optional_outcomes[parent] = found[0]['Action']
    normalized = [r for r in terminal if not any(r.get('Test') == parent or r.get('Test', '').startswith(parent + '/')
                                               for parent in optional)]
    tests = sorted(r['Action'] + '\t' + r['Package'] + '\t' + r['Test'] + '\n'
                   for r in normalized if 'Test' in r)
    packages = sorted(r['Action'] + '\t' + r['Package'] + '\n' for r in normalized if 'Test' not in r)
    tests_sha = image.sha(''.join(tests).encode())
    packages_sha = image.sha(''.join(packages).encode())
    image.require(tests_sha == profile['terminalTestsSha256'] and packages_sha == profile['terminalPackagesSha256'],
                  'EXACT_OBSERVED_REGRESSION_TERMINALS_REQUIRED')
    counts = Counter(r['Action'] + ('_tests' if 'Test' in r else '_packages') for r in terminal)
    return {'profile': profile_name, 'counts': dict(counts), 'logSha256': image.sha(raw),
            'terminalTestsSha256': tests_sha, 'terminalPackagesSha256': packages_sha,
            'environmentConditionalOutcomes': optional_outcomes,
            'status': 'OBSERVED_TEST_IDENTITIES_VERIFIED_NOT_ACCEPTANCE', 'targetOperations': 0}


def verify_hosted_record(records):
    image.require(set(records) == set(MANIFEST['requiredHostedRegression']),
                  'COMPLETE_HOSTED_REQUIREMENTS_REQUIRED')
    for name, required in MANIFEST['requiredHostedRegression'].items():
        record = records[name]
        expected = [[required['package'], test, 'pass'] for test in required['tests']]
        image.require(record.get('status') == 'HOSTED_REQUIRED_TEST_IDENTITIES_VERIFIED_NOT_ACCEPTANCE'
                      and record.get('profile') == name
                      and record.get('testsPassed') == len(expected)
                      and record.get('packagesPassed') == 1
                      and record.get('testsFailed') == 0 and record.get('testsSkipped') == 0
                      and record.get('terminalTestsSha256') == image.sha(image.canonical(expected))
                      and re.fullmatch('[0-9a-f]{64}', record.get('logSha256', ''))
                      and record.get('localPassWasObserved') is False
                      and record.get('targetOperations') == 0,
                      'EXACT_HOSTED_REQUIRED_RESULTS_REQUIRED')


def verify_hosted_regressions(path, name):
    image.require(name in MANIFEST['requiredHostedRegression'], 'KNOWN_HOSTED_REQUIREMENT_REQUIRED')
    raw = path.read_bytes()
    image.require(0 < len(raw) <= 32 * 1024 * 1024, 'BOUNDED_HOSTED_LOG_REQUIRED')
    rows = [json.loads(line) for line in raw.splitlines()]
    required = MANIFEST['requiredHostedRegression'][name]
    terminal = [row for row in rows if row.get('Action') in ('pass', 'fail', 'skip')]
    tests = sorted([[row.get('Package'), row['Test'], row['Action']]
                    for row in terminal if 'Test' in row])
    packages = [[row.get('Package'), row['Action']] for row in terminal if 'Test' not in row]
    expected = [[required['package'], test, 'pass'] for test in required['tests']]
    image.require(tests == expected and packages == [[required['package'], 'pass']],
                  'HOSTED_REQUIRED_TESTS_MUST_ALL_PASS')
    result = {'status': 'HOSTED_REQUIRED_TEST_IDENTITIES_VERIFIED_NOT_ACCEPTANCE',
              'profile': name, 'testsPassed': len(tests), 'packagesPassed': 1,
              'testsFailed': 0, 'testsSkipped': 0,
              'terminalTestsSha256': image.sha(image.canonical(tests)),
              'logSha256': image.sha(raw), 'localPassWasObserved': False, 'targetOperations': 0}
    verify_hosted_record({name: result})
    return result


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
    regression = commands.add_parser('regressions')
    regression.add_argument('path', type=Path)
    regression.add_argument('profile', choices=('main', 'server', 'storage', 'race'))
    hosted = commands.add_parser('hosted-regressions')
    hosted.add_argument('path', type=Path)
    hosted.add_argument('profile', choices=('shell',))
    commands.add_parser('patch-paths')
    args = parser.parse_args()
    if args.command == 'hosted-regressions':
        print(json.dumps(verify_hosted_regressions(args.path, args.profile), indent=2))
        return
    if args.command == 'regressions':
        print(json.dumps(verify_regressions(args.path, args.profile), indent=2))
        return
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


