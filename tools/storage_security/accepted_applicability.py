"""Pure assessment of a recorded owner disposition; never grants runtime authority.

The caller must authenticate the candidate/graph/scan provenance before calling.
Repository decision records are conversation evidence, not THS credentials.
"""
import hashlib
import json


class ApplicabilityError(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise ApplicabilityError(reason)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()


def assess(decision, advisory, candidate, graph_bytes, scan, vex):
    require(decision.get('schema') == 'ouf.security-applicability-owner-decision.v1'
            and decision.get('status') == 'ACCEPTED' and bool(decision.get('decisionRef')),
            'ACCEPTED_OWNER_DECISION_REQUIRED')
    require(decision.get('scope') == 'ONE_ADVISORY_ON_ONE_EXACT_BINARY_ONLY', 'EXACT_SCOPE_REQUIRED')
    for name in ('rawGateChanged', 'scannerIgnoreAdded', 'runtimeAuthorityIssued',
                 'targetApplyAuthorized', 'releaseAcceptance', 'migrationReady', 'thsDecisionClaimed'):
        require(decision.get(name) is False, 'DECISION_MUST_NOT_GRANT:' + name)
    require(decision.get('rawReportPreserved') is True, 'RAW_REPORT_MUST_BE_PRESERVED')
    disposition = {'status': 'not_affected', 'justification': 'vulnerable_code_not_present'}
    require(decision.get('disposition') == disposition, 'EXACT_DISPOSITION_REQUIRED')
    product = decision['product']
    expected = {'binarySha256': product['binarySha256'], 'declaredSource': product['sourceCommit'],
                'buildToolchain': product['goToolchain'], 'cgoEnabled': product['cgoEnabled'],
                'compiledPackagesSha256': product['compiledPackagesSha256']}
    require(product['cgoEnabled'] is False, 'STATIC_CGO_DISABLED_BUILD_REQUIRED')
    for name, value in expected.items():
        require(candidate.get(name) == value and type(candidate.get(name)) is type(value), 'BUILD_BINDING_CHANGED:' + name)
    require(candidate.get('dependencyPatchSha256') == product['dependencyPatchSha256'], 'DEPENDENCY_PATCH_CHANGED')
    scope = decision['advisory']
    require(advisory.get('id') == scope['id'] and hashlib.sha256(canonical(advisory)).hexdigest() == scope['canonicalSnapshotSha256'], 'ADVISORY_CHANGED_REASSESSMENT_REQUIRED')
    require(hashlib.sha256(graph_bytes).hexdigest() == product['compiledPackagesSha256'], 'COMPILED_GRAPH_CHANGED')
    graph = json.loads(graph_bytes)
    packages = graph.get('packages')
    require(isinstance(packages, list) and len(packages) == product['compiledPackageCount']
            and all(type(p) is str and bool(p) for p in packages)
            and len(set(packages)) == len(packages), 'COMPLETE_DISTINCT_COMPILED_GRAPH_REQUIRED')
    require('github.com/seaweedfs/seaweedfs/weed' in packages and graph.get('openpgpImported') is False, 'EXACT_EXECUTABLE_GRAPH_REQUIRED')
    affected = [p['path'] for a in advisory['affected'] for p in a['ecosystem_specific']['imports']]
    require(affected and all(a['package']['name'] == scope['module'] for a in advisory['affected']), 'EXACT_ADVISORY_MODULE_REQUIRED')
    require(not any(p == q or p.endswith('/vendor/' + q) or p == 'vendor/' + q
                    for p in packages for q in affected), 'VULNERABLE_CODE_PRESENT')
    statements = vex.get('statements')
    require(vex.get('@context') == 'https://openvex.dev/ns/v0.2.0'
            and bool(vex.get('@id')) and bool(vex.get('author')) and bool(vex.get('timestamp'))
            and type(vex.get('version')) is int and vex['version'] > 0
            and isinstance(statements, list) and len(statements) == 1, 'SINGLE_COMPLETE_VEX_STATEMENT_REQUIRED')
    statement = statements[0]
    require(statement.get('vulnerability', {}).get('name') == scope['id']
            and statement.get('products') == [{'hashes': {'sha-256': product['binarySha256']}}]
            and all(statement.get(k) == v for k, v in disposition.items())
            and decision['decisionRef'] in statement.get('status_notes', ''), 'VEX_SCOPE_OR_DECISION_CHANGED')
    require(scan.get('SchemaVersion') == 2 and isinstance(scan.get('Results'), list)
            and bool(scan['Results']), 'NONEMPTY_SCANNER_REPORT_REQUIRED')
    targets = [r.get('Target') for r in scan['Results']]
    require(len(set(targets)) == len(targets) and 'weed' in targets, 'UNIQUE_TARGETS_AND_WEED_REQUIRED')
    require(all(r.get('Class') == 'lang-pkgs' and r.get('Type') == 'gobinary'
                and isinstance(r.get('Packages'), list) and bool(r['Packages']) for r in scan['Results']), 'NONEMPTY_GO_PACKAGE_INVENTORIES_REQUIRED')
    weed = next(r for r in scan['Results'] if r['Target'] == 'weed')
    require(any(p.get('Name') == scope['module'] for p in weed['Packages']), 'CONTAINING_MODULE_MUST_REMAIN_PRESENT')
    raw = dict.fromkeys(('CRITICAL', 'HIGH', 'UNKNOWN', 'MEDIUM', 'LOW'), 0)
    unresolved = dict(raw)
    classified = []
    for result in scan['Results']:
        findings = result.get('Vulnerabilities') or []
        require(isinstance(findings, list), 'VALID_FINDINGS_REQUIRED')
        for v in findings:
            severity = v.get('Severity')
            require(severity in raw and bool(v.get('VulnerabilityID')) and bool(v.get('PkgName')), 'KNOWN_SEVERITY_AND_FINDING_ID_REQUIRED')
            raw[severity] += 1
            if (result['Target'] == 'weed' and v['VulnerabilityID'] == scope['id']
                    and v['PkgName'] == scope['module'] and severity == 'UNKNOWN'):
                classified.append({'target': 'weed', 'id': scope['id'], 'severity': severity, **disposition})
            else:
                unresolved[severity] += 1
    require(len(classified) == 1, 'EXACT_SINGLE_REVIEWED_FINDING_REQUIRED')
    blocked = any(unresolved[s] for s in ('CRITICAL', 'HIGH', 'UNKNOWN'))
    return {'schema': 'ouf.security-accepted-applicability-assessment.v1',
            'status': 'HELD_OTHER_FINDINGS' if blocked else 'ACCEPTED_APPLICABILITY_ONLY',
            'decisionRef': decision['decisionRef'], 'binarySha256': product['binarySha256'],
            'rawCounts': raw, 'unresolvedCounts': unresolved, 'classifiedFindings': classified,
            'rawGate': 'HELD' if any(raw[s] for s in ('CRITICAL', 'HIGH', 'UNKNOWN')) else 'PASS',
            'vulnerabilitySubgate': 'HELD' if blocked else 'PASS_WITH_EXACT_DISPOSITION',
            'overallSwG1': 'OPEN', 'allEightMigrationGatesRemainOpen': True,
            'sourceReportModified': False, 'scannerIgnoreAdded': False,
            'runtimeAuthorityIssued': False, 'targetApplyAuthorized': False,
            'releaseAcceptance': False, 'migrationReady': False}
