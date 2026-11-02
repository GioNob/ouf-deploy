#!/usr/bin/env python3
"""Public CI-only SeaweedFS evaluation; never connects to an OUF target."""
import argparse
import hashlib
import json
import os
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


def gate(out):
    record = json.loads((out/'candidate.json').read_text())
    require(digest(out/'bin/weed') == record['binarySha256'], 'BINARY_CHANGED')
    report = out/'trivy-binary.json'
    counts = assess(json.loads(report.read_text()))
    record.update(scanSha256=digest(report),findings=counts,
                  securityGate='HELD' if any(counts[s] for s in ['UNKNOWN','HIGH','CRITICAL']) else 'PASS')
    write(out/'candidate.json', record)
    print(json.dumps({'securityGate':record['securityGate'],'findings':counts}))
    require(record['securityGate'] == 'PASS','SECURITY_GATE_HELD')


def seal(out):
    files = sorted(p for p in out.rglob('*') if p.is_file() and p.name not in ['SHA256SUMS','provenance.json'])
    (out/'SHA256SUMS').write_text(''.join(f'{digest(p)}  {p.relative_to(out)}\n' for p in files))


if __name__ == '__main__':
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['stage','gate','seal']);p.add_argument('output',type=Path);p.add_argument('--source',type=Path)
    a=p.parse_args()
    if a.mode=='stage':stage(a.source,a.output)
    elif a.mode=='gate':gate(a.output)
    else:seal(a.output)
