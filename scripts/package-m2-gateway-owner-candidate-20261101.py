#!/usr/bin/env python3
"""New CI-only executable delivery of the exact retained owner's declared source.

No equality with the retained executable is asserted. Source, tested JAR,
resolved base, archive, native envelope and security admission remain distinct.
"""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.acquisition_read_native import image_custody as custody

SOURCE = '81fdf7a5f9f3ef02ed930a1db911d34cab1a9415'
RETAINED = 'sha256:979de5eb0a554e0adfe924969627eb62362c4165974357afcee5bf30450f8f21'
TAG = 'ouf-m2-gateway-owner-candidate:'+SOURCE
DOCKER = '/opt/ouf-docker-29/docker'


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(path):
    with path.open('rb') as content:
        return hashlib.file_digest(content, 'sha256').hexdigest()


def run(args, timeout=180):
    return subprocess.check_output(args, timeout=timeout)


def docker(*args):
    return run([DOCKER, *args])


def helper():
    spec = importlib.util.spec_from_file_location('qualified_archive_helpers', ROOT/'scripts/prepare-m2-runtime-os-repair.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tests_passed(directory):
    reports = sorted(directory.glob('TEST-*.xml'))
    require(bool(reports), 'ACTUAL_NONEMPTY_OWNER_TEST_REPORTS_REQUIRED')
    tests = 0
    for path in reports:
        suite = ET.fromstring(path.read_bytes())
        require(suite.tag == 'testsuite' and all(int(suite.attrib.get(k, '-1')) == 0
                for k in ('failures', 'errors', 'skipped')), 'OWNER_TEST_FAILURE_ERROR_OR_SKIP_DENIED')
        tests += int(suite.attrib['tests'])
    require(tests >= 4, 'COMPLETE_ORIGINAL_OWNER_TEST_SET_REQUIRED')
    return {'suites': len(reports), 'tests': tests, 'failures': 0, 'errors': 0, 'skipped': 0}


def jar_contract(raw):
    require(0 < len(raw) <= 134217728, 'BOUNDED_OWNER_JAR_REQUIRED')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)) <= 20000, 'UNIQUE_BOUNDED_OWNER_JAR_REQUIRED')
        required = {'BOOT-INF/classes/it/comune/trieste/ouf/gateway/GatewayOperationalApplication.class',
                    'BOOT-INF/classes/it/comune/trieste/ouf/receipt/SummaryReceiptFilter.class'}
        # Actual source inventory, rather than another module's boot JAR.
        require(required <= set(names), 'ACTUAL_GATEWAY_OWNER_APPLICATION_CLASSES_REQUIRED')
        return {name: hashlib.sha256(archive.read(name)).hexdigest() for name in sorted(required)}


def build(source, output):
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and not output.exists(), 'ISOLATED_CI_NEW_CANDIDATE_ONLY')
    require(run(['git', '-C', str(source), 'rev-parse', 'HEAD']).strip().decode() == SOURCE
            and not run(['git', '-C', str(source), 'status', '--porcelain']).strip(), 'EXACT_CLEAN_OWNER_SOURCE_REQUIRED')
    require(docker('version', '--format', '{{.Server.Version}}').strip() == b'29.8.1', 'EXACT_DOCKER29_REQUIRED')
    reports = tests_passed(source/'operational-owner/target/surefire-reports')
    original_jar = source/'operational-owner/target/gateway-operational-owner-1.0.0-SNAPSHOT.jar'
    raw_jar = original_jar.read_bytes()
    classes = jar_contract(raw_jar)
    output.mkdir(mode=0o700)
    context = output/'build'
    context.mkdir(mode=0o700)
    shutil.copyfile(original_jar, context/'owner.jar')
    # A mutable selector is resolved once for a NEW candidate, then the build
    # uses and records only its exact immutable digest. No target default changes.
    docker('pull', '--platform=linux/amd64', 'eclipse-temurin:21-jre')
    base = json.loads(docker('image', 'inspect', 'eclipse-temurin:21-jre'))[0]
    refs = base.get('RepoDigests', [])
    require(len(refs) == 1 and re.fullmatch(r'eclipse-temurin@sha256:[0-9a-f]{64}', refs[0]),
            'ONE_EXACT_RESOLVED_JAVA21_BASE_REQUIRED')
    dockerfile = ('FROM '+refs[0]+'\nWORKDIR /app\n'
                  'RUN rm -f /usr/bin/pebble\nCOPY owner.jar /app/owner.jar\n'
                  'USER 10001:10001\nEXPOSE 8081\nENTRYPOINT ["java","-jar","/app/owner.jar"]\n')
    (context/'Dockerfile').write_text(dockerfile)
    docker('build', '--pull=false', '--network=none', '--label', 'org.opencontainers.image.revision='+SOURCE,
           '--label', 'org.opencontainers.image.source=https://github.com/GioNob/ouf-api-gateway',
           '-t', TAG, str(context))
    image = json.loads(docker('image', 'inspect', TAG))[0]
    require(image['Config']['User'] == '10001:10001'
            and image['Config']['Entrypoint'] == ['java', '-jar', '/app/owner.jar'], 'EXACT_ORIGINAL_OWNER_EXECUTION_CONTRACT_REQUIRED')
    docker('run', '--rm', '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
           '--pids-limit=64', '--memory=256m', '--entrypoint=java', TAG,
           '-XX:ActiveProcessorCount=2', '-XX:ParallelGCThreads=2', '-XX:ConcGCThreads=1', '-version')
    saved = output/'build-image.tar'
    docker('save', '--output', str(saved), TAG)
    with tarfile.open(saved, mode='r:') as archive:
        entries = json.loads(archive.extractfile('manifest.json').read(131073))
        require(len(entries) == 1, 'ONE_BUILT_OWNER_IMAGE_REQUIRED')
        config = archive.extractfile(entries[0]['Config']).read(2097153)
        require(len(config) <= 2097152, 'BOUNDED_OWNER_IMAGE_CONFIGURATION_REQUIRED')
    config_id = 'sha256:'+hashlib.sha256(config).hexdigest()
    with saved.open('rb') as content:
        audit = custody.archive(content, sha(saved), config_id, SOURCE)
        actual_jar = helper().effective_file(content, audit, 'app/owner.jar', 134217728)
    require(actual_jar == raw_jar, 'TESTED_AND_CONTAINER_OWNER_JAR_BYTES_MUST_MATCH')
    identity = custody.native_identity(audit)
    require(identity['nativeImageId'] != RETAINED, 'NEW_CANDIDATE_MUST_NOT_BE_PRESENTED_AS_RETAINED_IMAGE')
    with saved.open('rb') as content, (output/'image.docker.tar').open('x+b') as target:
        envelope = custody.tagless_archive(content, target, audit, containerd=True)
    with saved.open('rb') as content, (output/'scan-input.docker.tar').open('x+b') as target:
        scanner = helper().classic_scan_archive(content, target, audit)
    docker('load', '--input', str(output/'image.docker.tar'))
    custody.loaded(dict(audit, nativeIdentity=identity), json.loads(docker('image', 'inspect', identity['nativeImageId']))[0])
    run(['git', '-C', str(source), 'archive', '--format=tar', '-o', str((output/'source.tar').resolve()), SOURCE])
    inventory = []
    for entry in run(['git', '-C', str(source), 'ls-tree', '-rz', SOURCE]).split(b'\0'):
        if not entry: continue
        metadata, path = entry.split(b'\t', 1)
        mode, kind, blob = metadata.decode().split()
        inventory.append({'path': path.decode(), 'mode': mode, 'type': kind, 'sha': blob})
    (output/'source-inventory.json').write_text(json.dumps({'truncated': False, 'tree': inventory}, sort_keys=True, indent=2)+'\n')
    # Spring Boot's CycloneDX configuration places the actual generated BOM
    # under classes/META-INF/sbom, not the historical CI artifact path.
    sbom = source/'operational-owner/target/classes/META-INF/sbom/application.cdx.json'
    bom = json.loads(sbom.read_bytes())
    require(bom.get('bomFormat') == 'CycloneDX' and bom.get('components')
            and bom['metadata']['component']['name'] == 'gateway-operational-owner',
            'ACTUAL_NONEMPTY_GATEWAY_OWNER_SBOM_REQUIRED')
    shutil.copyfile(sbom, output/'bom.json')
    shutil.copyfile(context/'Dockerfile', output/'Dockerfile.resolved')
    shutil.copytree(source/'operational-owner/target/surefire-reports', output/'surefire-reports')
    proof = {'schema': 'ouf.m2-gateway-owner-distinct-candidate.v1', 'sourceRepository': 'GioNob/ouf-api-gateway',
             'sourceCommit': SOURCE, 'retainedNativeImageId': RETAINED, 'retainedImageSourceMembershipProven': False,
             'configurationImageId': config_id, 'nativeImageId': identity['nativeImageId'],
             'archiveSha256': envelope['derivedArchiveSha256'], 'scanInputSha256': sha(output/'scan-input.docker.tar'),
             'imageAudit': audit, 'scannerImageAudit': scanner, 'baseImage': refs[0],
             'applicationJarSha256': hashlib.sha256(raw_jar).hexdigest(), 'applicationClasses': classes,
             'testedAndContainerJarBytesMatch': True, 'sourceTree': run(['git', '-C', str(source), 'rev-parse', 'HEAD^{tree}']).decode().strip(),
             'sourceArchiveSha256': sha(output/'source.tar'), 'sourceInventoryEntries': len(inventory),
             'unitTestReports': reports, 'javaVersionProbePassed': True, 'imageApplicationReadinessProven': False,
             'newExecutableImageBuilt': True, 'unusedBaseSupervisorRemoved': True,
             'freshScanGatePassed': False, 'candidateSelectionChanged': False, 'targetOperations': 0,
             'targetApplyAuthorized': False, 'runtimeAuthorityIssued': False, 'releaseAcceptance': False}
    (output/'candidate.json').write_text(json.dumps(proof, sort_keys=True, indent=2)+'\n')
    return proof


def finalize(output):
    proof = json.loads((output/'candidate.json').read_bytes())
    require(sha(output/'image.docker.tar') == proof['archiveSha256']
            and sha(output/'scan-input.docker.tar') == proof['scanInputSha256'], 'EXACT_SCANNED_OWNER_BYTES_REQUIRED')
    scan = json.loads((output/'trivy-image.json').read_bytes())
    spec = importlib.util.spec_from_file_location('original_gate', ROOT/'scripts/package-semantic-proposal-candidate.py')
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    gate.scan_gate(scan, 'semantic', proof['configurationImageId'])  # same Java OS+JAR coverage; no gateway role accepted by old gate
    proof.update(freshScanGatePassed=True, scanSha256=sha(output/'trivy-image.json'))
    (output/'candidate.json').write_text(json.dumps(proof, sort_keys=True, indent=2)+'\n')
    return proof


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=('build', 'finalize'))
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    proof = build(args.source, args.output) if args.phase == 'build' else finalize(args.output)
    print(json.dumps({key: proof[key] for key in ('nativeImageId', 'freshScanGatePassed', 'retainedImageSourceMembershipProven', 'targetOperations')}, sort_keys=True))
