#!/usr/bin/env python3
"""Read one frozen laboratory artifact without executing any enclosed program."""
import ast
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = '99a6d0f00dd1fe490438cef95ce98ee98e7c3ae4'
SHA = '9714833cd2a3a0b1e26635497b1a9807752092ee41981f6bf482a956dd62578e'
SIZE = 4420588


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def verify(path):
    raw = Path(path).read_bytes()
    require(len(raw) == SIZE and digest(raw) == SHA, 'EXACT_ARTIFACT_REQUIRED')
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        require(len(names) == len(set(names)) and all('/' not in n and '\\' not in n for n in names), 'FLAT_UNIQUE_MEMBERS_REQUIRED')
        require(sum(i.file_size for i in z.infolist()) <= 64 * 1024 * 1024, 'BOUNDED_ARCHIVE_REQUIRED')
        data = {n: z.read(n) for n in names}
    rows = [line.split('  ', 1) for line in data['SHA256SUMS'].decode().splitlines()]
    sums = {n: h for h, n in rows}
    require(len(rows) == len(sums) and set(sums) == set(names) - {'SHA256SUMS', 'provenance.json'}, 'COMPLETE_CHECKSUM_CLOSURE_REQUIRED')
    for name, sha in sums.items():
        require(digest(data[name]) == sha, 'MEMBER_CHECKSUM_MISMATCH:' + name)
    q = json.loads(data['qualification.json'])
    require(q['status'] == 'PASS' and q['producerSource'] == SOURCE, 'EXACT_PASSED_PRODUCER_REQUIRED')
    require(q['twoIndependentRealS3Servers'] and not q['sourceServerIsMinio'] and not q['productionEntryPointExists'], 'SYNTHETIC_SCOPE_REQUIRED')
    require(q['syntheticObjects'] == q['bodiesVerified'] == 120 and q['syntheticLogicalBytes'] == 203743, 'FULL_SYNTHETIC_PARITY_REQUIRED')
    require(q['targetOperations'] == 0 and not q['runtimeAuthorityIssued'] and not q['migrationReady'], 'NO_TARGET_AUTHORITY_REQUIRED')
    event_files = ['unit-tests.jsonl', 'real-functional-readiness.jsonl', 'real-conditional-cas.jsonl', 'real-copy-120.jsonl', 'real-process-crashes.jsonl', 'real-ambiguous-503.jsonl', 'real-metadata-tags.jsonl', 'real-invalid-tag.jsonl', 'real-denials.jsonl']
    passes = []
    for name in event_files:
        events = [json.loads(line) for line in data[name].splitlines() if line.strip()]
        require(events and not any(e.get('Action') in ('fail', 'skip') for e in events), 'NO_FAILED_OR_SKIPPED_TESTS_REQUIRED:' + name)
        passes.extend(e['Test'] for e in events if e.get('Action') == 'pass' and 'Test' in e)
    require(len(passes) == len(set(passes)) == q['passedTestCount'] == 31 and set(passes) == set(q['passedTests']), 'EXACT_TEST_EVENT_PARITY_REQUIRED')
    require(data['storage-copy-lab.test'].startswith(b'\x7fELF'), 'ELF_TEST_BINARY_REQUIRED')
    sources = json.loads(data['source-records.json'])
    require(len(sources) == 8, 'EXACT_SOURCE_CLOSURE_REQUIRED')
    for name, sha in sources.items():
        p = ROOT / name
        require(p.resolve().is_relative_to(ROOT) and digest(p.read_bytes()) == sha, 'REPOSITORY_SOURCE_MISMATCH:' + name)
    capsule = ROOT / 'releases/seaweedfs-inventory-inputs-20261102/prepare-inputs.py'
    require(digest(capsule.read_bytes()) == 'ec5c94e074ec2efb90b77ea383ac3047416f5472cd6813b42fd739b1f49fb14b', 'FROZEN_CAPSULE_CHANGED')
    tree = ast.parse(capsule.read_text())
    manifest = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'MANIFEST' for t in n.targets))
    require(len(manifest['sources']) == 28, 'FROZEN_28_SOURCES_REQUIRED')
    for record in manifest['sources'].values():
        require(digest((ROOT / record['path']).read_bytes()) == record['sha256'], 'FROZEN_SOURCE_CHANGED:' + record['path'])
    candidate = json.loads(data['candidate.json'])
    require(candidate['binarySha256'] == 'bb9f768e5afca39c7fdc2113e5caafd9f911d4537917dd25c520ee4dbdab1f74' and candidate['inventoryBinarySha256'] == '430631fe4dfd1b844229637373ea176c2e84e81e1491919f4a25cc36c68359a8', 'ORIGINAL_EXECUTABLE_IDENTITIES_REQUIRED')
    graph = json.loads(data['compiled-packages.json'])
    require(digest(data['compiled-packages.json']) == candidate['compiledPackagesSha256'] == '67534a54978a5a157673a6a21ea26c147b0dbcb60c60d30497ce39e6ee3c435b', 'ORIGINAL_COMPILED_GRAPH_REQUIRED')
    require(len(graph['packages']) == 1738 and not graph['openpgpImported'] and not any(p == 'golang.org/x/crypto/openpgp' or p.startswith('golang.org/x/crypto/openpgp/') for p in graph['packages']), 'AFFECTED_PACKAGES_MUST_BE_ABSENT')
    modules = json.loads(data['trivy-copy-modules.json'])['Results']
    packages = {p['Name'] for r in modules for p in r.get('Packages', [])}
    require({'github.com/aws/aws-sdk-go-v2', 'github.com/aws/aws-sdk-go-v2/credentials', 'github.com/aws/aws-sdk-go-v2/service/s3'} <= packages, 'NONEMPTY_AWS_DEPENDENCY_INVENTORY_REQUIRED')
    require(not any(v['Severity'] in ('HIGH', 'CRITICAL', 'UNKNOWN') for r in modules for v in r.get('Vulnerabilities', [])), 'MODULE_SECURITY_GATE_FAILED')
    scans = json.loads(data['trivy-binary.json'])['Results']
    require({r['Target'] for r in scans} == {'weed', 'storage-inventory', 'storage-copy-lab.test'} and all(r.get('Packages') for r in scans), 'THREE_NONEMPTY_BINARY_SCANS_REQUIRED')
    findings = [(r['Target'], v['VulnerabilityID'], v['Severity']) for r in scans for v in r.get('Vulnerabilities', [])]
    require(findings == [('weed', 'GO-2026-5932', 'UNKNOWN')], 'RAW_SERVER_UNKNOWN_MUST_REMAIN_VISIBLE')
    security = json.loads(data['security-gates.json'])
    require(security['rawServerGate'] == 'HELD' and security['rawServerGatePreserved'] and not security['releaseAdmitted'], 'PRODUCTION_GATE_MUST_REMAIN_HELD')
    return {'schema': 'ouf.storage-copy-independent-readback.v1', 'status': 'PASS', 'producerSource': SOURCE, 'artifactSha256': SHA, 'artifactBytes': SIZE, 'checksumMembers': len(sums), 'testPassEventsIncludingSubtests': len(passes), 'binarySha256': digest(data['storage-copy-lab.test']), 'checksumSubjectSha256': digest(data['SHA256SUMS']), 'repositorySourceRecords': len(sources), 'priorFrozenSourcesUnchanged': 28, 'serverCompiledPackages': 1738, 'rawServerGate': 'HELD_ONE_UNKNOWN', 'publisherSignatureVerifiedByThisScript': False, 'enclosedExecutableExecuted': False, 'targetOperations': 0, 'releaseAdmitted': False}


if __name__ == '__main__':
    import sys
    print(json.dumps(verify(sys.argv[1]), indent=2))
