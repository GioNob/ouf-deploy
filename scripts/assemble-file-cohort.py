#!/usr/bin/env python3
"""One source-locked, hashed six-module delivery. No target execution or authority."""
import argparse, hashlib, json, os, re, shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT/'releases/chatbot-file-cohort-20261014.json'

def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

def require(ok, reason):
    if not ok:
        raise ValueError(reason)

def checked_members(directory):
    require(directory.is_dir() and not directory.is_symlink(), 'MODULE_DIRECTORY_REQUIRED')
    require(all(not p.is_symlink() for p in directory.rglob('*')), 'PACKAGE_SYMLINK_DENIED')
    sums = directory/'SHA256SUMS'
    require(sums.is_file(), 'MODULE_CHECKSUMS_REQUIRED')
    declared = {}
    for line in sums.read_text().splitlines():
        require(re.fullmatch(r'[0-9a-f]{64}  [A-Za-z0-9_.\-/]+', line), 'CHECKSUM_LINE_INVALID')
        digest, name = line.split('  ', 1)
        require(not Path(name).is_absolute() and '..' not in Path(name).parts and name not in declared,
                'CHECKSUM_PATH_INVALID')
        path = directory/name
        require(path.is_file() and sha(path) == digest, 'PACKAGE_MEMBER_HASH_MISMATCH')
        declared[name] = digest
    actual = {p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_file()}
    require(actual == set(declared)|{'SHA256SUMS'}, 'UNDECLARED_OR_MISSING_PACKAGE_MEMBER')
    return declared

def assemble(packages, output):
    lock = json.loads(LOCK_PATH.read_text())
    require(not output.exists(), 'OUTPUT_MUST_BE_NEW')
    expected = {row['module'] for row in lock['modules']}
    require({p.name for p in packages.iterdir()} == expected, 'EXACT_SIX_MODULE_COHORT_REQUIRED')
    records = []
    for row in lock['modules']:
        directory = packages/row['module']
        files = checked_members(directory)
        record = json.loads((directory/'candidate-manifest.json').read_text())
        require(record.get('module') == row['module'] and record.get('sourceCommit') == row['commit']
                and record.get('repository') == 'GioNob/'+row['repository']
                and record.get('artifactKind') == row['kind']
                and record.get('cohortSourceLockSha256') == sha(LOCK_PATH), 'MIXED_OR_STALE_COHORT_DENIED')
        require(record.get('scanGate') == 'PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED'
                and record.get('targetApplyAuthorized') is False and record.get('runtimeAuthorityIssued') is False,
                'SCAN_OR_AUTHORITY_BINDING_INVALID')
        required = {'source.tar', 'source-inventory.json', 'trivy-image.json', 'candidate-manifest.json'}
        if row['kind'] == 'DOCKER_SAVE':
            required |= {'image.docker.tar', 'package-record.json', 'ouf-mcp' if row['module'] == 'mcp' else 'application.jar'}
        else:
            required |= {'routes.file-loop.json', 'compiled-route-declarations.json'}
        require(required <= set(files), 'CONCRETE_MODULE_DELIVERY_MEMBERS_REQUIRED')
        if row['module'] == 'semantic':
            seal = json.loads((directory/'independent-rootfs-seal.json').read_text())
            require(seal.get('imageId') == record['imageId'] and seal.get('sourceCommit') == row['commit']
                    and seal.get('javaStarted') is False and seal.get('targetAcceptance') is False
                    and seal.get('packageRecordHash') == sha(directory/'package-record.pre-export.json'),
                    'INDEPENDENT_PREAPPLICATION_ROOTFS_SEAL_REQUIRED')
            boot = json.loads((directory/'file-first-four-mount-boot.json').read_text())
            require(boot.get('imageId') == record['imageId'] and boot.get('status') == 'DISPOSABLE_BOOT_PASSED'
                    and boot.get('mountCount') == 4 and boot.get('providerEnabled') is False
                    and boot.get('discoveryWorkerEnabled') is False, 'EXACT_FILE_FIRST_BOOT_REQUIRED')
        records.append({**record, 'files': files})
    output.mkdir()
    for row in lock['modules']:
        shutil.copytree(packages/row['module'], output/row['module'])
    shutil.copyfile(LOCK_PATH, output/'source-lock.json')
    manifest = {
        'schema':'ouf.chatbot-file-cohort-package.v1', 'cohortId':lock['cohortId'],
        'sourceLockSha256':sha(LOCK_PATH), 'modules':records,
        'producer':{'repository':'GioNob/ouf-deploy','workflow':'semantic-proposal-candidate-package.yml',
                    'sourceCommit':os.environ.get('GITHUB_SHA'),'runId':os.environ.get('GITHUB_RUN_ID'),
                    'runAttempt':os.environ.get('GITHUB_RUN_ATTEMPT')},
        'semanticRuntimeProfile':lock['semanticRuntimeProfile'],
        'composedQualification':lock['composedQualification'],
        'notReleaseAcceptance':True,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
        'vpsOperations':0,'r12Touched':False,'budgetReset':False,
        'fullChatbotProductionAcceptanceProven':False,
    }
    (output/'cohort-manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    paths = sorted(p for p in output.rglob('*') if p.is_file())
    (output/'COHORT_SHA256SUMS').write_text(''.join(sha(p)+'  '+p.relative_to(output).as_posix()+'\n' for p in paths))
    return manifest

if __name__ == '__main__':
    p=argparse.ArgumentParser();p.add_argument('--packages',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args(); result=assemble(a.packages,a.output)
    print(json.dumps({'status':'SIX_MODULE_PACKAGE_ASSEMBLED','modules':len(result['modules']),'targetApplyAuthorized':False}))
