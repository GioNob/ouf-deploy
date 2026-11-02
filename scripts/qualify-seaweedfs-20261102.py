#!/usr/bin/env python3
"""Public CI-only SeaweedFS evaluation; never connects to an OUF target."""
import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path
import subprocess
import tarfile
import urllib.request

SOURCE = '153ab668c99731a6d29492bf6c61d0b4fa701101'
RELEASE = '4.51'
ASSET_SHA = 'c03be37416a8ee672c77766e20b22a4e1430744c3af2668599a4b6eeaec14cee'
ASSET_SIZE = 47534485
URL = 'https://github.com/seaweedfs/seaweedfs/releases/download/4.51/linux_amd64.tar.gz'


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True)+'\n')


def stage(source, out):
    require(os.environ.get('GITHUB_ACTIONS') == 'true', 'CI_ONLY')
    require(not out.exists(), 'NEW_CANDIDATE_DIRECTORY_REQUIRED')
    actual = subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()
    require(actual == SOURCE, 'EXACT_SOURCE_REQUIRED')
    require(not subprocess.check_output(['git','-C',str(source),'status','--porcelain']), 'CLEAN_SOURCE_REQUIRED')
    out.mkdir(); (out/'bin').mkdir()
    archive = out/'upstream-release.tar.gz'
    with urllib.request.urlopen(URL, timeout=60) as response, archive.open('xb') as f:
        size = 0
        while block := response.read(1024*1024):
            size += len(block)
            require(size <= ASSET_SIZE, 'OVERSIZED_ASSET')
            f.write(block)
    require(size == ASSET_SIZE and digest(archive) == ASSET_SHA, 'EXACT_RELEASE_ASSET_REQUIRED')
    with tarfile.open(archive) as t:
        matches = [m for m in t.getmembers() if m.name in ('weed','./weed')]
        require(len(matches) == 1 and matches[0].isfile() and 0 < matches[0].size < 300*1024*1024, 'UNIQUE_REGULAR_BINARY_REQUIRED')
        binary = out/'bin/weed'
        with t.extractfile(matches[0]) as f:
            binary.write_bytes(f.read())
    binary.chmod(0o500)
    # Read build info without executing the candidate.
    info = subprocess.check_output(['go','version','-m',str(binary)],text=True,timeout=60)
    (out/'go-build-info.txt').write_text(info)
    with (out/'source.tar').open('wb') as f:
        subprocess.run(['git','-C',str(source),'archive','--format=tar',SOURCE],stdout=f,check=True)
    write(out/'candidate.json', {'schema':'ouf.seaweedfs-evaluation.v1','release':RELEASE,'declaredSource':SOURCE,
        'assetSha256':ASSET_SHA,'assetBytes':size,'binarySha256':digest(binary),
        'upstreamBinaryRebuilt':False,'upstreamPublisherCryptographicallyVerified':False,
        'sourceBinaryEqualityProven':False,'targetOperations':0,'installed':False,'securityGate':'NOT_RUN'})


def rebuild(source, out):
    require(os.environ.get('GITHUB_ACTIONS') == 'true', 'CI_ONLY')
    require(subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip() == SOURCE, 'EXACT_SOURCE_REQUIRED')
    env = dict(os.environ, GOTOOLCHAIN='go1.27.3', CGO_ENABLED='0')
    def go(*args):
        return subprocess.check_output(['go',*args],cwd=source,env=env,timeout=900)
    require(go('version').decode().startswith('go version go1.27.3 '), 'EXACT_GO_TOOLCHAIN_REQUIRED')
    go('get','github.com/go-jose/go-jose/v4@v4.1.6','golang.org/x/net@v0.62.0')
    go('mod','verify')
    changed = subprocess.check_output(['git','-C',str(source),'diff','--name-only'],text=True).splitlines()
    require(set(changed) <= {'go.mod','go.sum'}, 'ONLY_DEPENDENCY_MANIFEST_PATCH_PERMITTED')
    (out/'dependency.patch').write_bytes(subprocess.check_output(['git','-C',str(source),'diff','--binary']))
    for name in ['go.mod','go.sum']:
        shutil.copyfile(source/name, out/name)
    packages = go('list','-deps','-f','{{.ImportPath}}','./weed').decode().splitlines()
    write(out/'compiled-packages.json', {'packages':packages,'openpgpImported':any(p == 'golang.org/x/crypto/openpgp' or p.startswith('golang.org/x/crypto/openpgp/') for p in packages)})
    (out/'upstream').mkdir()
    shutil.move(out/'bin/weed',out/'upstream/weed')
    go('build','-trimpath','-o',str((out/'bin/weed').resolve()),'./weed')
    (out/'patched-go-build-info.txt').write_bytes(go('version','-m',str((out/'bin/weed').resolve())))
    r = json.loads((out/'candidate.json').read_text())
    r.update(binarySha256=digest(out/'bin/weed'),upstreamBinaryRebuilt=True,
             buildToolchain='go1.27.3',cgoEnabled=False,dependencyPatchSha256=digest(out/'dependency.patch'),
             securityGate='NOT_RUN',sourceBinaryEqualityProven=False)
    r['compiledPackagesSha256'] = digest(out/'compiled-packages.json')
    write(out/'candidate.json',r)


def assess(report):
    require(isinstance(report,dict) and report.get('SchemaVersion') == 2, 'VALID_SCANNER_REPORT_REQUIRED')
    require(isinstance(report.get('Results'),list) and bool(report['Results']), 'NONEMPTY_SCAN_REQUIRED')
    require(any(r.get('Class') == 'lang-pkgs' and r.get('Type') == 'gobinary' and r.get('Packages') for r in report['Results']), 'ACTUAL_GO_PACKAGE_INVENTORY_REQUIRED')
    counts = dict.fromkeys(['UNKNOWN','LOW','MEDIUM','HIGH','CRITICAL'],0)
    for result in report['Results']:
        for v in result.get('Vulnerabilities') or []:
            severity = v.get('Severity')
            require(severity in counts, 'UNRECOGNIZED_SEVERITY')
            counts[severity] += 1
    return counts


def lab_eligible(report, graph):
    packages = graph.get('packages')
    require(isinstance(packages,list) and bool(packages) and all(isinstance(p,str) for p in packages), 'COMPLETE_PACKAGE_GRAPH_REQUIRED')
    require('github.com/seaweedfs/seaweedfs/weed' in packages, 'ACTUAL_EXECUTABLE_PACKAGE_REQUIRED')
    if any(p == 'golang.org/x/crypto/openpgp' or p.startswith('golang.org/x/crypto/openpgp/') for p in packages):return False
    findings = [v for r in report['Results'] for v in r.get('Vulnerabilities') or [] if v.get('Severity') in ['HIGH','CRITICAL','UNKNOWN']]
    return bool(findings) and all(v.get('VulnerabilityID') == 'GO-2026-5932' and v.get('PkgName') == 'golang.org/x/crypto' and v.get('Severity') == 'UNKNOWN' for v in findings)


def gate(out):
    record = json.loads((out/'candidate.json').read_text())
    require(digest(out/'bin/weed') == record['binarySha256'], 'BINARY_CHANGED')
    report = out/'trivy-binary.json'
    counts = assess(json.loads(report.read_text()))
    record.update(scanSha256=digest(report),findings=counts,
                  securityGate='HELD' if any(counts[s] for s in ['UNKNOWN','HIGH','CRITICAL']) else 'PASS')
    eligible = False
    if record.get('upstreamBinaryRebuilt') and record.get('cgoEnabled') is False:
        require(digest(out/'compiled-packages.json') == record['compiledPackagesSha256'], 'PACKAGE_GRAPH_CHANGED')
        eligible = lab_eligible(json.loads(report.read_text()),json.loads((out/'compiled-packages.json').read_text()))
    record.update(isolatedLabEligible=eligible,releaseAdmitted=False,rawGatePreserved=True)
    if eligible:
        write(out/'openpgp-applicability.json',{'advisory':'GO-2026-5932','assessment':'AFFECTED_PACKAGE_NOT_IMPORTED','binarySha256':record['binarySha256'],'compiledPackagesSha256':record['compiledPackagesSha256'],'rawSecurityGate':'HELD','allows':'synthetic loopback diagnostic tests only','allowsTargetOrRelease':False})
    write(out/'candidate.json', record)
    print(json.dumps({'securityGate':record['securityGate'],'findings':counts}))
    require(record['securityGate'] == 'PASS' or eligible,'SECURITY_GATE_HELD')


def seal(out):
    files = sorted(p for p in out.rglob('*') if p.is_file() and p.name not in ['SHA256SUMS','provenance.json'])
    (out/'SHA256SUMS').write_text(''.join(f'{digest(p)}  {p.relative_to(out)}\n' for p in files))


if __name__ == '__main__':
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['stage','rebuild','gate','seal']);p.add_argument('output',type=Path);p.add_argument('--source',type=Path)
    a=p.parse_args()
    if a.mode=='stage':stage(a.source,a.output)
    elif a.mode=='rebuild':rebuild(a.source,a.output)
    elif a.mode=='gate':gate(a.output)
    else:seal(a.output)
