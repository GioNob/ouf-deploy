"""Bind historical approved application intent to the exact qualified package.

Produces private review evidence only. Does not import images, open credentials,
acquire the lease lock, invoke Docker or mutate the application.
"""
import copy
import hashlib
import json
import os
import re
import stat
import sys
import tarfile
import tempfile
import types
import zipfile
from pathlib import Path

IMAGE = 'sha256:e826bd9769a72e930e356f72c1c244007f9a34d065db94ca8113b064d10d8b85'
SOURCE = '622614b0040cf11be2f6c7e3568733a488ca4ca8'
ZIP_HASH = 'a0c30bbb7d44d3e6405bae28ad80b6c5dcfc28ed2f078d387cf4e26d179e28c3'
PACKAGE = Path('/home/oufadmin/ouf-file-loop-offline-stage.LMawhAuO/semantic.zip')
DECLARATION = Path('/etc/ouf/deploy-snapshots/semantic-discovery-runtime-declaration-nfggulwg/private-runtime-declaration.json')
DECLARATION_HASH = 'b9ee536c6cb4fefa4e6357716599cfdb34a38b7e11789013cf69096e5932709c'
CONTRACT = Path('/etc/ouf/deploy-snapshots/semantic-discovery-application-contract-y4k46mc9/private-application-input-contract.json')
CONTRACT_HASH = '3883a3d2e2a6a4be044b91254092ff77a9b077e0aa0e94f6c1109fb29629b89c'
CUSTODY_HASH = 'cb9ff64684243d563da79d327eb7d7e325dbea6a3922c91a0b7791a3ceec9baf'
OLD_IMAGE = 'sha256:b1a7956a673f88b5ee65d174c2eda7b9e448153e101348c06fdd53c0640e700b'


def require(value, reason):
    if not value:
        raise ValueError(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def environment(entries):
    require(type(entries) is list and len(entries) <= 256, 'BOUNDED_ENVIRONMENT_REQUIRED')
    result = {}
    for entry in entries:
        require(type(entry) is str and len(entry) <= 65536 and '=' in entry, 'EXACT_ENVIRONMENT_ENTRY_REQUIRED')
        key, value = entry.split('=', 1)
        require(re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,127}', key) and key not in result, 'UNIQUE_ENVIRONMENT_KEYS_REQUIRED')
        result[key] = value
    return result


def package_config(path, expected_zip=ZIP_HASH, expected_image=IMAGE):
    """Read config from hash-bound Docker-save bytes inside the retained ZIP."""
    def identity(s):
        return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as raw:
        before = os.fstat(raw.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= 2147483648,
                'BOUNDED_REGULAR_PACKAGE_REQUIRED')
        require(hashlib.file_digest(raw, 'sha256').hexdigest() == expected_zip, 'EXACT_QUALIFIED_ZIP_REQUIRED')
        raw.seek(0)
        with zipfile.ZipFile(raw) as package:
            entries = package.infolist()
            names = [v.filename for v in entries]
            require(1 <= len(entries) <= 512 and len(names) == len(set(names)), 'UNIQUE_BOUNDED_ZIP_ENTRIES_REQUIRED')
            require(all(not n.startswith('/') and '..' not in Path(n).parts and '\\' not in n for n in names),
                    'PACKAGE_PATH_ESCAPE_DENIED')
            images = [v for v in entries if Path(v.filename).name == 'image.docker.tar']
            require(len(images) == 1 and 0 < images[0].file_size <= 2147483648 and not images[0].flag_bits & 1,
                    'ONE_BOUNDED_DOCKER_ARCHIVE_REQUIRED')
            # Anonymous scratch file; never extract a ZIP path onto the host.
            with tempfile.TemporaryFile() as image:
                with package.open(images[0]) as stream:
                    count = 0
                    while block := stream.read(1048576):
                        count += len(block)
                        require(count <= images[0].file_size, 'DOCKER_ARCHIVE_SIZE_DRIFT')
                        image.write(block)
                require(count == images[0].file_size, 'COMPLETE_DOCKER_ARCHIVE_REQUIRED')
                image.seek(0)
                with tarfile.open(fileobj=image, mode='r:*') as archive:
                    members = {}
                    for member in archive:
                        require(len(members) < 1024 and member.name not in members,
                                'UNIQUE_BOUNDED_DOCKER_MEMBERS_REQUIRED')
                        require(not member.name.startswith('/') and '..' not in Path(member.name).parts,
                                'DOCKER_METADATA_PATH_ESCAPE_DENIED')
                        members[member.name] = member
                    def small(name, limit):
                        member = members.get(name)
                        require(member is not None and member.isfile() and 0 < member.size <= limit,
                                'BOUNDED_REGULAR_IMAGE_METADATA_REQUIRED')
                        return archive.extractfile(member).read(limit + 1)
                    manifest = json.loads(small('manifest.json', 131072))
                    require(type(manifest) is list and len(manifest) == 1, 'ONE_QUALIFIED_IMAGE_REQUIRED')
                    config_raw = small(manifest[0]['Config'], 2097152)
                    require('sha256:' + hashlib.sha256(config_raw).hexdigest() == expected_image,
                            'EXACT_QUALIFIED_IMAGE_CONFIG_REQUIRED')
                    value = json.loads(config_raw)
                    require(value.get('os') == 'linux' and value.get('architecture') == 'amd64',
                            'EXACT_LINUX_AMD64_IMAGE_REQUIRED')
                    config = value['config']
                    require(config.get('Labels', {}).get('org.opencontainers.image.revision') == SOURCE,
                            'EXACT_QUALIFIED_SOURCE_LABEL_REQUIRED')
        require(identity(before) == identity(os.fstat(raw.fileno())) == identity(Path(path).lstat()),
                'PACKAGE_CHANGED_DURING_READ')
        return config


def rebase(declaration, contract, config):
    require(declaration.get('schema') == 'ouf.discovery.private-replacement-runtime-declaration.v1'
            and declaration.get('candidateImageId') == OLD_IMAGE
            and declaration.get('inputBindings', {}).get('applicationContractHash') == CONTRACT_HASH
            and contract.get('schema') == 'ouf.discovery.private-application-input-contract.v1',
            'EXACT_HISTORICAL_CONTRACT_REQUIRED')
    for item in (declaration, contract):
        require(all(item.get(k) is False for k in ('productionApplyReady', 'applicationCutoverAuthorized',
                                                  'completeReplacementOciProven')),
                'UNAPPLIED_HISTORICAL_CONTRACT_REQUIRED')
    old = declaration['candidateConfig']
    require(old == contract['candidateConfig'] and declaration['roleOwnedReadOnlyMounts'] == contract['roleOwnedReadOnlyMounts'],
            'HISTORICAL_DECLARATION_CONTRACT_DRIFT')
    require(config.get('User') == '10001:10001', 'EXACT_NON_ROOT_IMAGE_USER_REQUIRED')
    # Changes to execution defaults require a separate review, not an automatic rebase.
    fields = ('Entrypoint', 'Cmd', 'User', 'WorkingDir', 'ExposedPorts', 'Volumes',
              'StopSignal', 'Healthcheck', 'Shell')
    require(all(config.get(k) == old.get(k) for k in fields), 'CANDIDATE_EXECUTION_DEFAULT_CHANGE_REQUIRES_REVIEW')
    previous, new = environment(old['Env']), environment(config['Env'])
    application = {k: v for k, v in previous.items() if k.startswith(('OUF_', 'SPRING_', 'MANAGEMENT_'))
                   or k in ('PORT', 'JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS')}
    runtime = {'PATH', 'JAVA_HOME', 'JAVA_VERSION', 'LANG', 'LANGUAGE', 'LC_ALL', 'TZ'}
    require(set(previous) <= set(application) | runtime, 'UNREVIEWED_ENVIRONMENT_SETTING')
    require(application and new.get('JAVA_HOME') == '/opt/java/openjdk', 'EXACT_JAVA_APPLICATION_ENV_REQUIRED')
    merged = {**new, **application}
    result = copy.deepcopy(declaration)
    result['candidateImageId'] = IMAGE
    result['candidateConfig'] = copy.deepcopy(config)
    result['candidateConfig']['Env'] = [k + '=' + merged[k] for k in sorted(merged)]
    result['schema'] = 'ouf.discovery.private-qualified-package-runtime-declaration.v1'
    result['inputBindings']['historicalDeclarationHash'] = DECLARATION_HASH
    result['qualifiedPackageBinding'] = {'sourceCommit': SOURCE, 'zipSha256': ZIP_HASH, 'imageId': IMAGE}
    result['requiredBeforeMutation'] = [v.replace('NO_R9_REPLAY', 'NO_R9_OR_R10_REPLAY')
                                        for v in result['requiredBeforeMutation']]
    result['applicationContractIsHistorical'] = True
    result['historicalApplicationSettingsRetained'] = True
    result['freshRuntimeCustodyProven'] = False
    public = {'candidateImageId': IMAGE, 'sourceCommit': SOURCE, 'zipSha256': ZIP_HASH,
              'candidateConfigHash': digest(result['candidateConfig']),
              'preservedHostConfigHash': digest(result['proposedHostConfig']),
              'preservedCreationFrameHash': digest(result['retainedNativeCreationFrame']),
              'applicationEnvironmentNamesRetained': sorted(application),
              'runtimeDefaultsTakenFromQualifiedImage': True,
              'executionDefaultsMatchHistoricalReview': True,
              'observationsAreHistorical': True, 'freshRuntimeCustodyProven': False,
              'secretBytesFreshlyVerified': False, 'completeReplacementOciProven': False,
              'applicationCutoverAuthorized': False, 'productionApplyReady': False}
    return result, public


def main():
    report = dict(schema='ouf.discovery.qualified-package-declaration-preparation.v1',
                  containerLifecycleOperations=0, imageImports=0, credentialFilesOpened=0,
                  privateKeyFilesOpened=0, privateValuesPrinted=False, databaseWrites=0,
                  firewallWrites=0, commonLockAcquired=False, r10Touched=False,
                  signaturesIssued=0, existingConfigurationWrites=0, notReleaseAcceptance=True)
    try:
        require(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode and len(sys.argv) == 1,
                'ISOLATED_ROOT_COMPILATION_REQUIRED')
        source = globals().get('__custody_source__')
        require(type(source) is bytes and hashlib.sha256(source).hexdigest() == CUSTODY_HASH,
                'SEALED_CUSTODY_SOURCE_REQUIRED')
        custody = types.ModuleType('custody')
        exec(compile(source, 'sealed-custody', 'exec'), custody.__dict__)
        raw_declaration = custody.file_bytes(DECLARATION, 0, {0o600}, expected=DECLARATION_HASH)
        raw_contract = custody.file_bytes(CONTRACT, 0, {0o600}, expected=CONTRACT_HASH)
        # Package contents are authenticated by the exact ZIP digest of the
        # previously publisher-verified target bytes, and the image config ID.
        config = package_config(PACKAGE)
        private, public = rebase(json.loads(raw_declaration), json.loads(raw_contract), config)
        require(custody.file_bytes(DECLARATION, 0, {0o600}, expected=DECLARATION_HASH) == raw_declaration
                and custody.file_bytes(CONTRACT, 0, {0o600}, expected=CONTRACT_HASH) == raw_contract,
                'PROTECTED_CONTRACT_CHANGED_DURING_COMPILATION')
        directory = Path(tempfile.mkdtemp(prefix='semantic-qualified-package-declaration-', dir=custody.BASE))
        directory.chmod(0o700)
        body = encoded(private)
        custody.create(directory / 'private-runtime-declaration.json', body)
        report.update(status='QUALIFIED_PACKAGE_DECLARED_NOT_APPLY_READY', evidenceDirectory=str(directory),
                      privateDeclarationHash=hashlib.sha256(body).hexdigest(), **public)
        custody.create(directory / 'receipt.json', encoded(report))
        code = 0
    except Exception as error:
        reason = str(error)
        report.update(status='QUALIFIED_PACKAGE_DECLARATION_BLOCKED', errorType=type(error).__name__,
                      reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,120}', reason) else 'QUALIFIED_PACKAGE_DECLARATION_UNPROVEN')
        code = 1
    print('OUF_QUALIFIED_PACKAGE_DECLARATION=' + json.dumps(report, sort_keys=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
