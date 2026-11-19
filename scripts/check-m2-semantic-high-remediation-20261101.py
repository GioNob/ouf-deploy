#!/usr/bin/env python3
"""Qualify an exact existing replacement without clearing the retained-image hold."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REPORT = 'evidence/artifacts/m2-retained-semantic-trivy-20261101.json.gz'
BASELINE_SHA = '1f4e4f06fbac99dd5eea9c202ec8f6c8d5d940eef82500f12858d8a4b7e1b99f'
ORIGINS = 'releases/m2-current-core-artifact-origins-20261101.json'
CONFIG = 'sha256:a6f00cda30f1c570082c94cb49d5564f40d512758441f6b6eac75e21f423d14f'
SOURCE = 'c2dae77b42f1811b704465f6ab813c91d808ade4'
FIXES = {'curl': ('CVE-2026-92392', '8.18.0-1ubuntu2.8'),
         'libcurl4t64': ('CVE-2026-92392', '8.18.0-1ubuntu2.8'),
         'libbrotli1': ('CVE-2026-111497', '1.2.0-3ubuntu0.1')}


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def gate_module():
    spec = importlib.util.spec_from_file_location('unchanged_scan_gate', ROOT/'scripts/package-semantic-proposal-candidate.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def package_versions(report):
    rows = [r for r in report['Results'] if r.get('Class') == 'os-pkgs']
    require(len(rows) == 1 and rows[0].get('Type') == 'ubuntu'
            and report.get('Metadata', {}).get('OS') == {'Family': 'ubuntu', 'Name': '26.04'},
            'EXACT_UBUNTU_SECURITY_VERSION_DOMAIN_REQUIRED')
    found = {}
    for package in rows[0].get('Packages', []):
        name = package.get('Name')
        if name not in FIXES:
            continue
        require(name not in found and package.get('Arch') == 'amd64' and package.get('AnalyzedBy') == 'dpkg',
                'UNIQUE_NATIVE_DPKG_PACKAGE_REQUIRED')
        version, release = package.get('Version', ''), package.get('Release', '')
        require(type(version) is str and re.fullmatch(r'[0-9][0-9A-Za-z.+:~\-]{0,127}', version)
                and type(release) is str and re.fullmatch(r'[0-9A-Za-z][0-9A-Za-z.+~\-]{0,127}', release),
                'COMPLETE_DEBIAN_PACKAGE_VERSION_REQUIRED')
        found[name] = version+'-'+release
    require(set(found) == set(FIXES), 'ALL_THREE_REMEDIATED_PACKAGES_MUST_BE_IN_INVENTORY')
    return found


def qualify(report, baseline, origin, scan_time=None):
    require(origin['sourceCommit'] == SOURCE and origin['configurationImageId'] == CONFIG
            and origin['qualifiedReplacementCandidateNotYetSelected'] is True
            and origin['currentRoleFromOperatorPublicReceipt'] is False,
            'EXACT_DISTINCT_UNSELECTED_REPLACEMENT_REQUIRED')
    gate_module().scan_gate(report, 'semantic', CONFIG)
    require(not any(r.get('Misconfigurations') or r.get('ModifiedFindings') for r in report['Results']),
            'FILTERED_OR_MODIFIED_FINDINGS_DENIED')
    # The workflow disables ignore inputs; also reject suppressed finding data
    # if a report containing it is passed to the offline reader.
    require(not report.get('FilteredResults') and not report.get('IgnoredFindings'), 'SUPPRESSED_FINDINGS_DENIED')
    now = scan_time or datetime.now(timezone.utc)
    created = datetime.fromisoformat(report.get('CreatedAt', '').replace('Z', '+00:00'))
    require(created.tzinfo is not None and -300 <= (now-created).total_seconds() <= 86400,
            'CURRENT_SCAN_WITHIN_24_HOURS_REQUIRED')
    before, after = package_versions(baseline), package_versions(report)
    target_ids = {row[0] for row in FIXES.values()}
    old = {(f.get('PkgName'), f.get('VulnerabilityID'), f.get('Severity'), f.get('FixedVersion'))
           for r in baseline['Results'] for f in r.get('Vulnerabilities', []) if f.get('Severity') == 'HIGH'}
    require(old == {(name, cve, 'HIGH', fixed) for name, (cve, fixed) in FIXES.items()},
            'EXACT_THREE_RETAINED_HIGH_FINDINGS_REQUIRED')
    findings = [f for r in report['Results'] for f in r.get('Vulnerabilities', [])]
    require(not any(f.get('VulnerabilityID') in target_ids for f in findings),
            'TARGET_CVE_STILL_PRESENT_AT_ANY_SEVERITY')
    rows = []
    for name, (cve, fixed) in FIXES.items():
        # Use Debian's native ordering, including epoch, revision and tilde.
        result = subprocess.run(['/usr/bin/dpkg', '--compare-versions', after[name], 'ge', fixed],
                                check=False, timeout=5, capture_output=True)
        require(result.returncode == 0, 'VENDOR_FIXED_PACKAGE_VERSION_REQUIRED')
        rows.append({'package': name, 'cve': cve, 'retainedVersion': before[name],
                     'minimumFixedVersion': fixed, 'replacementVersion': after[name],
                     'vendorFixedVersionSatisfied': True, 'cveAbsentAtEverySeverity': True})
    return {'schema': 'ouf.m2-semantic-high-remediation.v1',
            'remediationMethod': 'QUALIFIED_EXISTING_REPLACEMENT_NOT_RETAINED_IMAGE_MUTATION',
            'originalArtifactRepository': origin['repository'], 'originalArtifactId': origin['artifactId'],
            'originalZipSha256': origin['zipSha256'], 'archiveSha256': origin['expandedArchiveSha256'],
            'sourceCommit': SOURCE, 'configurationImageId': CONFIG, 'nativeImageId': origin['nativeImageId'],
            'scanCreatedAt': report['CreatedAt'], 'vulnerabilityCounts': dict(Counter(f['Severity'] for f in findings)),
            'highCriticalUnknownGate': 'PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED',
            'remediatedFindings': rows, 'threeRetainedHighFindingsRemediatedInReplacement': True,
            'retainedImageSecurityAdmission': 'HELD_HIGH_CRITICAL_UNKNOWN',
            'imageRebuilt': False, 'candidateSelectionChanged': False, 'targetImageReplaced': False,
            'targetOperations': 0, 'targetApplyAuthorized': False, 'runtimeAuthorityIssued': False,
            'releaseAcceptance': False, 'm2Acceptance': False}


def check(directory):
    raw = (ROOT/REPORT).read_bytes()
    require(sha(raw) == BASELINE_SHA, 'EXACT_RETAINED_DENIED_REPORT_REQUIRED')
    origin = json.loads((ROOT/ORIGINS).read_bytes())['roles']['semantic']
    facts_raw = (directory/'origin-facts.json').read_bytes()
    facts = json.loads(facts_raw)
    require(facts['origin'] == origin and facts['role'] == 'semantic'
            and facts['allConfigAndLayerBytesVerified'] is True and facts['imageRebuilt'] is False
            and facts['imageAudit']['archiveSha256'] == origin['expandedArchiveSha256']
            and facts['nativeIdentity']['nativeImageId'] == origin['nativeImageId'],
            'EXACT_BYTE_VERIFIED_ORIGINAL_REPLACEMENT_REQUIRED')
    report_raw = (directory/'trivy-image.json').read_bytes()
    result = qualify(json.loads(report_raw), json.loads(gzip.decompress(raw)), origin)
    result.update(scanSha256=sha(report_raw), originFactsSha256=sha(facts_raw), retainedReportGzipSha256=sha(raw))
    (directory/'remediation-result.json').write_text(json.dumps(result, sort_keys=True, indent=2)+'\n')
    print(json.dumps(result, sort_keys=True))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=Path)
    check(parser.parse_args().directory)
