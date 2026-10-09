"""Durable publication into one NEW private snapshot, never live activation.

The authenticated plan is consumed in-process; it is not an on-disk authority
token. The target loader must independently pin source and authority custody.
Partial installation is retained with a diagnosis and is never replayed in place.
"""
import hashlib
import os
import re
from pathlib import Path
import stat

from assemble_provider_profiles import digest, encoded
from authenticate_provider_transaction import TransactionDenied, require


def directory(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
            and not info.st_mode & 0o022, 'PUBLISH_PRIVATE_TRANSACTION', 'ROOT_PRIVATE_ANCESTOR_REQUIRED')


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def publish_once(path, raw):
    require(type(raw) is bytes and len(raw) <= 131072, 'PUBLISH_PRIVATE_TRANSACTION', 'BOUNDED_PRIVATE_FILE_REQUIRED')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw); stream.flush(); os.fsync(fd)
    finally: os.close(fd)
    sync(path.parent)


def producer_result_directories(configuration):
    root = Path(configuration['registryRoot'])
    result = []
    for cid in configuration['candidates']:
        require(re.fullmatch('[0-9a-f]{64}', cid) is not None,
                'PUBLISH_PRIVATE_TRANSACTION', 'EXACT_PRODUCER_CANDIDATE_PATH_REQUIRED')
        result.extend(root/cid/(name+'-results') for name in ('attestation','approval'))
    return tuple(result)


def publish_plan(root, plan, sources, observer_raw):
    """Install complete proposed files, with original authority records retained.

    This is NOT an allowlist switch. Runtime adapter proposal remains an inert
    private file. No signing/native command/guard/firewall/lifecycle call occurs.
    root must equal the root used by build_install_plan and must not exist.
    """
    stage = 'PUBLISH_PRIVATE_TRANSACTION'
    root = Path(root)
    require(os.geteuid() == 0 and root.is_absolute() and '..' not in root.parts
            and root == Path(str(root)), stage, 'EXPLICIT_ROOT_TRANSACTION_PATH_REQUIRED')
    for ancestor in (root.parent, *root.parent.parents): directory(ancestor)
    require(not os.path.lexists(root), stage, 'EXISTING_TRANSACTION_EVIDENCE_PRESERVED')
    require(plan['status'] == 'AUTHENTICATED_INSTALL_PLAN_ASSEMBLED'
            and plan['startAuthorized'] is False and plan['leaseAuthorized'] is False,
            stage, 'AUTHENTICATED_IN_PROCESS_PLAN_REQUIRED')
    require(plan['adapterConfiguration']['registryRoot'] == str(root/'registry'), stage, 'PLAN_DESTINATION_DRIFT')
    expected_sources = {**{name:digest(raw) for name,raw in sources.items()}, 'frame-observer.py':digest(observer_raw)}
    require(expected_sources == plan['sourceHashes'], stage, 'AUTHENTICATED_SOURCE_BYTES_CHANGED')
    files = dict(plan['files'])
    for name, raw in {**sources, 'frame-observer.py':observer_raw}.items():
        path = root/'source'/name
        require(Path(name).as_posix() == name and not Path(name).is_absolute() and '..' not in Path(name).parts,
                stage, 'SOURCE_PATH_ESCAPE_DENIED')
        require(str(path) not in files, stage, 'DUPLICATE_INSTALLATION_DESTINATION')
        files[str(path)] = raw
    for field, suffix in (('driverPath','scripts/semantic_provider_preexec_hook.py'),
                          ('admissionPath','scripts/semantic_provider_deployment_broker.py')):
        require(plan['adapterConfiguration'][field] == str(root/'source'/suffix), stage, 'PLAN_SOURCE_ROOT_DRIFT')
    for name, raw in files.items():
        path = Path(name)
        require(path.is_absolute() and '..' not in path.parts and path.is_relative_to(root)
                and path != root and str(path) == name and type(raw) is bytes and len(raw) <= 131072,
                stage, 'PRIVATE_PUBLICATION_PATH_OR_SIZE_DENIED')
    proposal = encoded(plan['adapterConfiguration'])
    files[str(root/'runtime-configuration-proposal.json')] = proposal
    hashes = {name:digest(raw) for name,raw in files.items()}
    root.mkdir(mode=0o700); root.chmod(0o700); sync(root.parent)
    claim = {'schema':'ouf.semantic-provider-transaction-installation-claim.v1', 'state':'INSTALLING',
             'inputHashes':plan['inputHashes'], 'proposedFileHashes':hashes,
             'liveRuntimeChanged':False, 'startAuthorized':False, 'notReleaseAcceptance':True}
    try:
        publish_once(root/'installation-claim.json', encoded(claim))
        for name, raw in sorted(files.items()):
            path = Path(name)
            pending = []
            for parent in path.parents:
                if parent == root: break
                pending.append(parent)
            for parent in reversed(pending):
                if not os.path.lexists(parent): parent.mkdir(mode=0o700); sync(parent.parent)
                info = parent.lstat()
                require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                        and stat.S_IMODE(info.st_mode) == 0o700, stage, 'PRIVATE_PUBLICATION_DIRECTORY_DRIFT')
            publish_once(path, raw)
        # ProducerEmission validates its empty private result directory before
        # reserving the first-use emission claim. Provision it during install,
        # never lazily inside a consumed broker operation.
        for path in producer_result_directories(plan['adapterConfiguration']):
            require(path.parent.is_relative_to(root) and str(path.parent/'broker.json') in files,
                    stage, 'AUTHENTICATED_PRODUCER_DIRECTORY_REQUIRED')
            path.mkdir(mode=0o700); path.chmod(0o700); sync(path.parent); sync(path)
        report = {'schema':'ouf.semantic-provider-transaction-installation.v1',
            'status':'PRIVATE_TRANSACTION_INSTALLED_RUNTIME_UNCHANGED', 'directory':str(root),
            'fileHashes':hashes, 'runtimeConfigurationProposalHash':digest(proposal),
            'runtimeConfigurationChanged':False, 'containerLifecycleOperations':0,
            'signaturesIssued':0, 'privateKeysRead':0, 'startAuthorized':False,
            'leaseAuthorized':False, 'notReleaseAcceptance':True}
        publish_once(root/'installation-receipt.json', encoded(report))
        return report
    except Exception as error:
        diagnosis = error.diagnosis if isinstance(error,TransactionDenied) else {
            'status':'BLOCKED','stage':stage,'reason':'DURABLE_PRIVATE_PUBLICATION_UNPROVEN',
            'secretValuesPrinted':False,'startAuthorized':False}
        diagnosis = {**diagnosis,'evidenceDirectory':str(root),'doNotRerunApply':True,
                     'liveRuntimeChanged':False}
        try: publish_once(root/'installation-denial.json', encoded(diagnosis))
        except OSError: pass
        failure = TransactionDenied(stage, diagnosis['reason'])
        failure.diagnosis = diagnosis
        raise failure from None
