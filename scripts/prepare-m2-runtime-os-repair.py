#!/usr/bin/env python3
"""Disposable CI candidate: repair only three APKs over the verified image.

The original JAR, migrations, source label, execution configuration and rootfs
prefix stay unchanged. No target operation or candidate selection occurs.
"""
import argparse, copy, hashlib, importlib.util, json, os, shutil, subprocess, sys, tarfile, urllib.request
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from tools.acquisition_read_native import image_custody as custody
from tools.ingestion_read_owner_preparation.audit import rootfs_jar

CASE = ROOT/'releases/m2-original-runtime-os-repair-case-20261101.json'
DOCKER = '/opt/ouf-docker-29/docker'


def require(ok, reason):
    if not ok: raise ValueError(reason)


def sha(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def docker(*args):
    return subprocess.check_output([DOCKER, '--host', 'unix:///var/run/docker.sock', *args], timeout=180)


def effective_file(stream, audit, target, maximum):
    """Read one bounded final regular member through explicit layer whiteouts."""
    parts = PurePosixPath(target).parts; whiteouts = {'.wh..wh..opq'}
    ancestors = {str(PurePosixPath(*parts[:i])) for i in range(1, len(parts))}
    for i, part in enumerate(parts):
        parent = PurePosixPath(*parts[:i])
        whiteouts.add(str(parent/('.wh.'+part)))
        if i: whiteouts.add(str(parent/'.wh..wh..opq'))
    found = None; count = 0; stream.seek(0)
    with tarfile.open(fileobj=stream, mode='r:') as outer:
        for name in audit['layerMembers']:
            with outer.extractfile(name) as raw, tarfile.open(fileobj=raw, mode='r|*') as layer:
                for entry in layer:
                    count += 1; require(count <= 250000, 'BOUNDED_IMAGE_LAYER_ENTRY_SET_REQUIRED')
                    name = entry.name.removeprefix('./').rstrip('/')
                    require(not name.startswith('/') and '..' not in PurePosixPath(name).parts,
                        'SAFE_IMAGE_LAYER_MEMBER_REQUIRED')
                    if name in whiteouts: found = None
                    if name in ancestors: require(entry.isdir(), 'IMAGE_MEMBER_ANCESTOR_LINK_OR_SPECIAL_DENIED')
                    if name == target:
                        require(entry.isfile() and not entry.islnk() and not entry.issym()
                            and 0 < entry.size <= maximum, 'EXACT_BOUNDED_REGULAR_IMAGE_MEMBER_REQUIRED')
                        with layer.extractfile(entry) as content: found = content.read(maximum+1)
                        require(len(found) == entry.size, 'COMPLETE_IMAGE_MEMBER_REQUIRED')
    require(found is not None, 'FINAL_IMAGE_MEMBER_REQUIRED'); return found


def packages(raw):
    result = {}
    for block in raw.decode().strip().split('\n\n'):
        fields = {}
        for line in block.splitlines():
            if len(line) > 2 and line[1] == ':' and line[0] in ('P', 'V'):
                require(line[0] not in fields, 'UNIQUE_APK_PACKAGE_FIELDS_REQUIRED'); fields[line[0]] = line[2:]
        require(set(fields) == {'P', 'V'} and fields['P'] not in result and len(result) < 1000,
            'BOUNDED_UNIQUE_APK_PACKAGE_DATABASE_REQUIRED')
        result[fields['P']] = fields['V']
    return result


def changed_packages(before, after, case):
    changed = {name for name in set(before)|set(after) if before.get(name) != after.get(name)}
    require(changed == set(case['allowedPackageVersionChanges'])
        and all(after.get(row['package']) == row['version'] for row in case['fixedPackages']),
        'ONLY_THREE_PINNED_SECURITY_PACKAGE_VERSIONS_MAY_CHANGE')
    return changed


def build(role, original, output):
    case = json.loads(CASE.read_bytes())
    require(os.geteuid() == 0 and os.environ.get('GITHUB_ACTIONS') == 'true'
        and role in case['roles'] and not output.exists(), 'ISOLATED_CI_UNSELECTED_REPAIR_ONLY')
    require(docker('version', '--format', '{{.Server.Version}}').strip() == b'29.8.1', 'EXACT_DOCKER_VERSION_REQUIRED')
    facts = json.loads((original/'origin-facts.json').read_bytes()); origin = facts['origin']
    require(facts['role'] == role and origin == json.loads((ROOT/case['originalRoleCaseFile']).read_bytes())['roles'][role],
        'EXACT_CURRENT_ORIGINAL_CASE_REQUIRED')
    image = original/'image.docker.tar'
    with image.open('rb') as stream:
        before = custody.archive(stream, origin['expandedArchiveSha256'], origin['configurationImageId'], origin['sourceCommit'])
        jar = rootfs_jar(stream, before)
        old_packages = packages(effective_file(stream, before, 'lib/apk/db/installed', 8388608))
    require(all(old_packages.get(name) == version for name, version in case['originalPackageVersions'].items()),
        'EXACT_ORIGINAL_VULNERABLE_PACKAGE_VERSIONS_REQUIRED')
    output.mkdir(mode=0o700); context = output/'build'; context.mkdir(mode=0o700)
    patches = context/'patches'; patches.mkdir(mode=0o700)
    for row in case['fixedPackages']:
        path = patches/row['filename']
        require(path.parent == patches and row['url'].startswith('https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/'),
            'EXACT_VENDOR_SECURITY_PACKAGE_REQUIRED')
        with urllib.request.urlopen(row['url'], timeout=30) as response: raw = response.read(8388609)
        require(len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256'],
            'EXACT_PINNED_VENDOR_APK_BYTES_REQUIRED'); path.write_bytes(raw)
    docker('load', '--input', str(image))
    original_tag = before['repositoryTags'][0]; base = 'ouf-runtime-repair-base-'+role+':'+origin['configurationImageId'][7:]
    docker('tag', original_tag, base)
    tag = 'ouf-runtime-repair-candidate-'+role+':'+sha(CASE)[:16]
    user = before['imageConfig']['User']
    require(user in ('10002:10002', '10004:10004'), 'EXACT_ORIGINAL_MODULE_USER_REQUIRED')
    # APK authenticates the local vendor packages using the original installed
    # Alpine signing keys. No allow-untrusted, repository update or network.
    (context/'Dockerfile').write_text('FROM '+base+'\nUSER 0:0\nCOPY patches/ /ouf-security-fixes/\n'
        'RUN apk add --no-cache --no-network --upgrade /ouf-security-fixes/*.apk && rm -rf /ouf-security-fixes\n'
        'USER '+user+'\n')
    docker('build', '--pull=false', '--network=none', '-t', tag, str(context))
    actual = json.loads(docker('image', 'inspect', tag))[0]
    require(all(actual['Config'].get(k) == before['imageConfig'].get(k) for k in custody.FIELDS),
        'ORIGINAL_APPLICATION_EXECUTION_CONFIGURATION_CHANGED')
    docker('run', '--rm', '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
        '--pids-limit=64', '--memory=256m', '--entrypoint=java', tag,
        '-XX:ActiveProcessorCount=2', '-XX:ParallelGCThreads=2', '-XX:ConcGCThreads=1', '-version')
    raw_save = output/'build-image.docker.tar'; docker('save', '--output', str(raw_save), tag)
    with tarfile.open(raw_save, 'r:') as saved:
        manifest = saved.extractfile('manifest.json').read(131073); entries = json.loads(manifest)
        require(len(entries) == 1, 'ONE_SECURITY_CANDIDATE_IMAGE_REQUIRED')
        config = saved.extractfile(entries[0]['Config']).read(2097153)
        require(len(config) <= 2097152, 'BOUNDED_CANDIDATE_CONFIGURATION_REQUIRED')
    config_id = 'sha256:'+hashlib.sha256(config).hexdigest()
    with raw_save.open('rb') as stream:
        after = custody.archive(stream, sha(raw_save), config_id, origin['sourceCommit'])
        new_jar = rootfs_jar(stream, after)
        new_packages = packages(effective_file(stream, after, 'lib/apk/db/installed', 8388608))
    changed = changed_packages(old_packages, new_packages, case)
    require(jar == new_jar and [v['diffId'] for v in after['layers'][:len(before['layers'])]] ==
        [v['diffId'] for v in before['layers']], 'ORIGINAL_JAR_AND_ROOTFS_PREFIX_MUST_REMAIN_BYTE_EXACT')
    candidate = output/'image.docker.tar'
    with raw_save.open('rb') as source, candidate.open('x+b') as target:
        envelope = custody.tagless_archive(source, target, after, containerd=True)
    identity = custody.native_identity(after); docker('load', '--input', str(candidate))
    custody.loaded(dict(after, nativeIdentity=identity), json.loads(docker('image', 'inspect', identity['nativeImageId']))[0])
    proof = {'schema': 'ouf.m2-original-runtime-os-repair-candidate.v1', 'role': role,
        'repairCaseSha256': sha(CASE), 'originalOriginZipSha256': origin['zipSha256'],
        'applicationSourceCommit': origin['sourceCommit'], 'originalImageAudit': before, 'candidateImageAudit': after,
        'configurationImageId': config_id, 'nativeImageId': identity['nativeImageId'],
        'candidateArchiveSha256': envelope['derivedArchiveSha256'],
        'applicationJarSha256': hashlib.sha256(jar).hexdigest(), 'applicationJarBytesUnchanged': True,
        'allApplicationMigrationsUnchanged': True, 'originalRootfsLayerPrefixUnchanged': True,
        'originalExecutionConfigurationUnchanged': True, 'changedPackageNames': sorted(changed),
        'fixedPackages': copy.deepcopy(case['fixedPackages']), 'apkVendorSignatureCheckingDisabled': False,
        'buildNetwork': 'none', 'javaVersionProbePassed': True, 'applicationMainStarted': False,
        'newRuntimeImageBuilt': True, 'applicationJarRebuilt': False,
        'applicationReadinessProven': False, 'completeCohortProven': False,
        'newScanQualified': False, 'candidateSelectionChanged': False, 'targetOperations': 0,
        'runtimeAuthorityIssued': False, 'targetApplyAuthorized': False, 'releaseAcceptance': False}
    (output/'repair-candidate.json').write_text(json.dumps(proof, indent=2, sort_keys=True)+'\n')
    return proof


def finalize(output, scan):
    proof = json.loads((output/'repair-candidate.json').read_bytes())
    require(sha(output/'image.docker.tar') == proof['candidateArchiveSha256'], 'EXACT_REPAIR_CANDIDATE_BYTES_REQUIRED')
    spec = importlib.util.spec_from_file_location('original_scan_gate', ROOT/'scripts/package-semantic-proposal-candidate.py')
    producer = importlib.util.module_from_spec(spec); spec.loader.exec_module(producer)
    producer.scan_gate(json.loads(scan.read_bytes()), proof['role'], proof['configurationImageId'])
    proof.update(newScanQualified=True, scanSha256=sha(scan))
    (output/'repair-candidate.json').write_text(json.dumps(proof, indent=2, sort_keys=True)+'\n')
    return proof


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('role'); parser.add_argument('original', type=Path)
    parser.add_argument('output', type=Path); parser.add_argument('--scan', type=Path); args = parser.parse_args()
    if args.scan: finalize(args.output, args.scan)
    else: build(args.role, args.original, args.output)
