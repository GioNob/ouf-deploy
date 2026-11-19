#!/usr/bin/env python3
"""Apply the existing image-bound scan gate to the original retained Semantic."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
CONFIG = 'sha256:29e32c1487b5ba29d6d29ec04f7daa3baeb1e30f392a46c838eef01493d60489'
SOURCE = 'eccef11a97367f20e278db40b9ed6f45dd980c37'


def check(directory):
    raw = (directory/'trivy-image.json').read_bytes()
    report = json.loads(raw)
    proof = json.loads((directory/'semantic-origin-match.json').read_bytes())
    if proof['configurationDigest'] != CONFIG or proof['moduleSourceCommit'] != SOURCE:
        raise ValueError('EXACT_RETAINED_SEMANTIC_ORIGINAL_REQUIRED')
    spec = importlib.util.spec_from_file_location('existing_scan_gate', ROOT/'scripts/package-semantic-proposal-candidate.py')
    producer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(producer)
    counts = {}
    for row in report.get('Results', []):
        for finding in row.get('Vulnerabilities', []):
            severity = finding.get('Severity', 'UNKNOWN')
            counts[severity] = counts.get(severity, 0)+1
    result = {'schema': 'ouf.m2-retained-semantic-original-fresh-scan.v1',
        'sourceCommit': SOURCE, 'configurationDigest': CONFIG,
        'nativeManifestDigest': proof['qualifiedSchema2Envelope']['nativeImageId'],
        'originalImageArchiveSha256': proof['originalArchiveSha256'],
        'scanSha256': hashlib.sha256(raw).hexdigest(), 'allSeveritiesReported': True,
        'vulnerabilityCounts': counts, 'freshScanGatePassed': False,
        'imageRebuilt': False, 'candidateSelectionChanged': False, 'targetCalls': 0,
        'runtimeAuthorityIssued': False, 'targetApplyAuthorized': False, 'releaseAcceptance': False}
    try:
        producer.scan_gate(report, 'semantic', CONFIG)
        result['freshScanGatePassed'] = True
    finally:
        (directory/'scan-result.json').write_text(json.dumps(result, sort_keys=True, indent=2)+'\n')
        print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise ValueError('ONE_ORIGINAL_SCAN_DIRECTORY_REQUIRED')
    check(Path(sys.argv[1]))
