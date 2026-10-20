#!/usr/bin/env python3
"""Validate-only Ingestion candidate. Source-locked build only; no target authority."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

LOCK_PATH = Path(__file__).resolve().parents[1]/'releases/ingestion-validate-only-candidate-20261020.json'
LOCK = json.loads(LOCK_PATH.read_text())
SOURCES = {row['module']: (row['repository'], row['commit']) for row in LOCK['modules']}
KINDS = {row['module']: row['kind'] for row in LOCK['modules']}
JAVA_MODULES = {'semantic', 'onboarding', 'ingestion', 'udp'}
IMAGE_MODULES = JAVA_MODULES | {'mcp'}

class Denied(RuntimeError):
    pass

def require(ok, reason):
    if not ok:
        raise Denied(reason)

def run(args, *, cwd=None, timeout=30, env=None):
    result = subprocess.run(args, cwd=cwd, env=env, timeout=timeout, check=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout

def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def json_file(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True)+'\n')

def source_guard(source, module):
    expected = SOURCES[module][1]
    require(run(['git', 'rev-parse', 'HEAD'], cwd=source).decode().strip() == expected,
            'QUALIFIED_SOURCE_COMMIT_MISMATCH')
    require(not run(['git', 'status', '--porcelain', '--untracked-files=all'], cwd=source).strip(),
            'DIRTY_SOURCE_DENIED')
    return expected

def scan_gate(scan, module, image_id=None):
    require(type(scan) is dict and scan.get('SchemaVersion') == 2
            and type(scan.get('Results')) is list, 'COMPLETE_SCANNER_REPORT_REQUIRED')
    expected_classes = {'os-pkgs', 'lang-pkgs'} if module in IMAGE_MODULES else {'lang-pkgs'}
    require(bool(scan['Results']) and all(type(r) is dict and r.get('Class') in expected_classes for r in scan['Results']),
            'EXPECTED_SCANNER_COVERAGE_REQUIRED')
    if module in IMAGE_MODULES:
        require(scan.get('Metadata', {}).get('ImageID') == image_id,
                'SCANNER_IMAGE_BINDING_MISMATCH')
    coverage = {(r.get('Class'), r.get('Type')) for r in scan['Results']}
    required = {('lang-pkgs', 'jar' if module in JAVA_MODULES else 'gobinary' if module == 'mcp' else 'pip')}
    require(required <= coverage and (module not in IMAGE_MODULES or any(c == 'os-pkgs' for c, _ in coverage)), 'REQUIRED_ARTIFACT_COVERAGE_MISSING')
    findings = []
    for result in scan['Results']:
        vulnerabilities = result.get('Vulnerabilities', [])
        require(type(vulnerabilities) is list, 'SCANNER_FINDING_LIST_INVALID')
        for finding in vulnerabilities:
            require(type(finding) is dict and type(finding.get('Severity')) is str,
                    'SCANNER_SEVERITY_MISSING')
            severity = finding['Severity']
            require(severity in {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'UNKNOWN'}, 'SCANNER_SEVERITY_UNRECOGNIZED')
            if severity in {'HIGH', 'CRITICAL', 'UNKNOWN'}:
                findings.append({'id': finding.get('VulnerabilityID', 'UNSPECIFIED'), 'severity': severity})
    require(not findings, 'HIGH_CRITICAL_UNKNOWN_VULNERABILITY_GATE_BLOCKED')
    return 'PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED'

def export(source, output, module):
    commit = source_guard(source, module)
    record = None
    if module in IMAGE_MODULES:
        record = json.loads((output/'package-record.json').read_text())
        require(record.get('sourceCommit') == commit and record.get('module') == module, 'IMAGE_RECORD_SOURCE_BINDING_MISMATCH')
    scan = json.loads((output/'trivy-image.json').read_text())
    scan_gate(scan, module, record['imageId'] if record else None)
    if module in IMAGE_MODULES:
        helper = Path(__file__).with_name('package-file-loop-candidate.py')
        run(['python3', str(helper), 'export', '--source', str(source), '--commit', commit,
             '--module', module, '--output', str(output)], timeout=180)
    else:
        run(['git', 'archive', '--format=tar', '-o', str(output/'source.tar'), commit], cwd=source)
    inventory = []
    raw = run(['git', 'ls-tree', '-rz', commit], cwd=source)
    for entry in raw.split(b'\0'):
        if not entry:
            continue
        metadata, name = entry.split(b'\t', 1)
        mode, kind, sha = metadata.decode().split()
        inventory.append({'path': name.decode(), 'mode': mode, 'type': kind, 'sha': sha})
    json_file(output/'source-inventory.json', {'truncated': False, 'tree': inventory})
    manifest = {
        'schema': 'ouf.ingestion-readiness-module-package.v1', 'sourceLockSha256': digest(LOCK_PATH), 'module': module,
        'repository': 'GioNob/'+SOURCES[module][0], 'sourceCommit': commit,
        'artifactKind': KINDS[module], 'imageId': record['imageId'] if record else None,
        'scanGate': 'PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED',
        'runtimeAuthorityIssued': False, 'signatureIssued': False,
        'targetApplyAuthorized': False, 'notReleaseAcceptance': True,
        'vpsOperations': 0, 'r12Touched': False, 'budgetReset': False,
        'futureBuildByteReproducibilityProven': False,
    }
    if module == 'mcp':
        executable = output/'ouf-mcp'
        require(any(r.get('Type') == 'gobinary' and bool(r.get('Packages')) for r in scan['Results']),
                'SCANNER_EXECUTABLE_PACKAGES_MISSING')
        require(executable.is_file() and not executable.is_symlink(), 'IMAGE_EXECUTABLE_REQUIRED')
        info = run(['go', 'version', '-m', str(executable)]).decode()
        require('go1.26.9' in info and 'GOOS=linux' in info and 'GOARCH=amd64' in info and 'CGO_ENABLED=0' in info,
                'EXECUTABLE_BUILD_PLATFORM_UNPROVEN')
        manifest['executableOrigin'] = 'EXTRACTED_FROM_SCANNED_IMAGE'
        manifest['executableSha256'] = digest(executable)
    if module == 'gateway':
        requirements = source/'requirements-dev.txt'
        staged = output/'gateway-scan'/'requirements.txt'
        require(staged.is_file() and not staged.is_symlink() and digest(staged) == digest(requirements),
                'SCANNER_REQUIREMENTS_SOURCE_BINDING_MISMATCH')
        require(Path(scan.get('ArtifactName', '')).resolve() == staged.parent,
                'SCANNER_REQUIREMENTS_TARGET_MISMATCH')
        require(any(r.get('Type') == 'pip' and r.get('Target') == 'requirements.txt'
                    and bool(r.get('Packages')) for r in scan['Results']), 'SCANNER_REQUIREMENTS_PACKAGES_MISSING')
        manifest['requirementsSourcePath'] = 'requirements-dev.txt'
        manifest['requirementsSha256'] = digest(requirements)
        manifest['transitivePythonRuntimeQualificationProven'] = False
        require((output/'routes.file-loop.json').is_file(), 'MATERIALIZED_ROUTE_PACKAGE_REQUIRED')
        manifest['materializedRoutesSha256'] = digest(output/'routes.file-loop.json')
        require((output/'compiled-route-declarations.json').is_file(), 'QUALIFIED_ROUTE_DECLARATIONS_REQUIRED')
        manifest['compiledRouteDeclarationsSha256'] = digest(output/'compiled-route-declarations.json')
        manifest['routePackageTargetBound'] = False
        require((output/'route.ingestion-configuration.json').is_file(), 'ISOLATED_WORKLOAD_ROUTE_REQUIRED')
        manifest['isolatedWorkloadRouteSha256'] = digest(output/'route.ingestion-configuration.json')
    json_file(output/'candidate-manifest.json', manifest)
    files = sorted(p for p in output.rglob('*') if p.is_file() and p.name != 'SHA256SUMS')
    require(all(not p.is_symlink() for p in files), 'ARTIFACT_SYMLINK_DENIED')
    (output/'SHA256SUMS').write_text(''.join(digest(p)+'  '+p.relative_to(output).as_posix()+'\n' for p in files))
    return manifest

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=['build', 'export'])
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--module', choices=list(SOURCES), required=True)
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    phase = args.phase
    try:
        require(not output.is_relative_to(source), 'BUILD_OUTPUT_INSIDE_SOURCE_DENIED')
        commit = source_guard(source, args.module)
        output.mkdir(parents=True, exist_ok=True)
        if phase == 'export':
            manifest = export(source, output, args.module)
            print('OUF_CANDIDATE_PACKAGE='+json.dumps(manifest, sort_keys=True))
        elif args.module in IMAGE_MODULES:
            module = args.module
            helper = Path(__file__).with_name('package-file-loop-candidate.py')
            run(['python3', str(helper), 'build', '--source', str(source), '--commit', commit,
                 '--module', module, '--output', str(output)], timeout=1800)
            if module == 'semantic':
                run(['python3', str(source/'scripts/check-file-first-source-continuity.py')], cwd=source)
        else:
            run(['git', 'archive', '--format=tar', '-o', str(output/'source.tar'), commit], cwd=source)
            # Trivy recognizes requirements.txt. Preserve exact source bytes and
            # leave the qualified checkout unchanged; bind the alias at export.
            scan_dir = output/'gateway-scan'
            scan_dir.mkdir()
            (scan_dir/'requirements.txt').write_bytes((source/'requirements-dev.txt').read_bytes())
            run(['python3', str(Path(__file__).with_name('materialize-file-cohort-routes.py')), '--source', str(source), '--output', str(output/'routes.file-loop.json'), '--declarations', str(output/'compiled-route-declarations.json')], timeout=60)
            run(['python3', str(Path(__file__).with_name('materialize-ingestion-readiness-route.py')), '--source', str(source), '--output', str(output/'route.ingestion-configuration.json')], timeout=60)
    except Exception as exc:
        # Do not echo command output, private paths or arbitrary exception text.
        code = str(exc) if isinstance(exc, Denied) else ('COMMAND_TIMEOUT' if isinstance(exc, subprocess.TimeoutExpired) else 'BUILD_OR_EXPORT_FAILED')
        diagnostics = {'phase': phase, 'module': args.module, 'reason': code, 'exceptionClass': type(exc).__name__,
              'exitCode': exc.returncode if isinstance(exc, subprocess.CalledProcessError) else None,
              'command': Path(exc.cmd[0]).name if isinstance(exc, (subprocess.CalledProcessError, subprocess.TimeoutExpired)) else None,
              'stderrSha256': hashlib.sha256(exc.stderr or b'').hexdigest() if isinstance(exc, subprocess.CalledProcessError) else None,
              'evidenceLocation': 'retained candidate-package diagnostics artifact', 'automaticRetry': False,
              'targetApplyAuthorized': False, 'notReleaseAcceptance': True}
        if output.is_dir() and not output.is_relative_to(source):
            json_file(output/'diagnostics.json', diagnostics)
        print('OUF_CANDIDATE_PACKAGE_BLOCKED='+json.dumps(diagnostics, sort_keys=True))
        raise SystemExit(1)

if __name__ == '__main__':
    main()

