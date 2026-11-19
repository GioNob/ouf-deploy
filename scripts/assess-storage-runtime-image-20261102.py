#!/usr/bin/env python3
"""Fresh image scan and SPDX inventory binding; no new security disposition."""
import copy
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT/path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def assess(root, readback, evidence):
    image = load_module('runtime_image', 'tools/storage_security/runtime_image.py')
    policy = load_module('accepted', 'tools/storage_security/accepted_applicability.py')
    record = image.verify_layout(root)
    scan_bytes = (root/'fresh-image-scan.json').read_bytes()
    scan = json.loads(scan_bytes)
    image.require(scan.get('Trivy', {}).get('Version') == '0.70.0', 'PINNED_SCANNER_REQUIRED')
    image.require(scan.get('Metadata', {}).get('ImageID') == record['configDigest'], 'EXACT_IMAGE_SCAN_REQUIRED')
    results = scan.get('Results')
    image.require(isinstance(results, list) and len(results) == 1
                  and results[0].get('Target', '').lstrip('/') == 'usr/local/bin/weed'
                  and results[0].get('Class') == 'lang-pkgs'
                  and results[0].get('Type') == 'gobinary'
                  and bool(results[0].get('Packages')), 'ONE_COMPLETE_RUNTIME_BINARY_SCAN_REQUIRED')
    normalized = copy.deepcopy(scan)
    normalized['Results'][0]['Target'] = 'weed'
    decision = json.loads((evidence/'seaweedfs-g1-applicability-owner-decision-20261102.json').read_bytes())
    assessment = policy.assess(
        decision, json.loads((root/'current-advisory.json').read_bytes()),
        json.loads((readback/'candidate.json').read_bytes()),
        (readback/'compiled-packages.json').read_bytes(), normalized,
        json.loads((evidence/'seaweedfs-g1-openvex-20261102.json').read_bytes()))
    image.require(assessment['vulnerabilitySubgate'] == 'PASS_WITH_EXACT_DISPOSITION', 'IMAGE_FINDINGS_HELD')
    sbom_bytes = (root/'image.spdx.json').read_bytes()
    sbom = json.loads(sbom_bytes)
    image.require(sbom.get('spdxVersion') == 'SPDX-2.3' and bool(sbom.get('documentNamespace')),
                  'SPDX_23_REQUIRED')
    packages = sbom.get('packages')
    image.require(isinstance(packages, list) and bool(packages), 'NONEMPTY_SPDX_REQUIRED')
    scanned = {(p['Name'], p['Version']) for p in results[0]['Packages']}
    bom = {(p.get('name'), p.get('versionInfo')) for p in packages}
    image.require(scanned <= bom, 'SBOM_MUST_INCLUDE_ALL_SCANNED_PACKAGES')
    licences = [{'name': p.get('name'), 'version': p.get('versionInfo'),
                  'declared': p.get('licenseDeclared', 'NOASSERTION'),
                  'concluded': p.get('licenseConcluded', 'NOASSERTION')}
                 for p in packages]
    return {**record, 'status': 'IMAGE_SECURITY_AND_SBOM_QUALIFIED_NOT_ADMITTED',
            'freshScanSha256': image.sha(scan_bytes), 'sbomSha256': image.sha(sbom_bytes),
            'scannedPackages': len(scanned), 'spdxPackages': len(packages),
            'acceptedApplicability': assessment,
            'licenceInventory': licences, 'licenceReview': 'OPEN',
            'durableReleaseCustody': 'OPEN', 'cohortQualification': 'OPEN'}


if __name__ == '__main__':
    result = assess(ROOT/'storage-runtime-image', ROOT/'sw-readback', ROOT/'evidence')
    (ROOT/'storage-runtime-image/assessment.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'licenceInventory'}, indent=2))
