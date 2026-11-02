"""Installation-bound offline control17. Reads only retained metadata artifacts.

The packaged entry includes the generic compiler before this source. No target
network, credential source, Docker socket, database or object body is opened.
"""
import os
from pathlib import Path
import stat
import sys
import time

INPUT = Path('/etc/ouf/deploy-snapshots/seaweedfs-inventory-inputs-20261102-v1')
HOST = Path('/etc/ouf/deploy-snapshots/seaweedfs-inventory-reconciliation-20261102-v1/host-baseline.private.json')
HOST_SHA = '49aaea817bff55ff5ab901f2f54784e97ac85b7e2bbf2ec489055bab94c790c4'
SCOPE = Path('/etc/ouf/deploy-snapshots/seaweedfs-offline-plan-20261102-v1')
EXPECTED_RECEIPT = None  # Bound to the public operator receipt by the packager.
INVENTORY_SHA = '43571bb43921f74adfa5974a0903acb54ee1eadecbc9d5d0d70539ce5cadba55'
PROFILE = {'schema': 'ouf.storage-offline-plan-control.v1', 'maximumAttempts': 1,
 'controlAttempt': 17, 'previousControlAttempts': 16, 'previousEngineGets': 52,
 'maximumEngineGets': 0, 'maximumS3Requests': 0, 'maximumCredentialFileReads': 0,
 'maximumInputFiles': 4, 'maximumInputInventoryBytes': 67108864,
 'maximumOutputPlanBytes': 67108864, 'maximumSeconds': 45, 'maximumMemoryBytes': 536870912,
 'objectBodiesRead': 0, 'sqlRequests': 0, 'containerLifecycleOperations': 0,
 'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False, 'migrationAuthorized': False}


def frame(info):
    return tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
                                          'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


class OfflineFiles:
    def __init__(self):
        self.seals = {}; self.opened = 0; self.bytes = 0; self.until = time.monotonic() + 45

    def check(self):
        require(time.monotonic() < self.until, 'OFFLINE_PLAN_DEADLINE')

    def ancestry(self, path):
        require(path.is_absolute() and '..' not in path.parts, 'ABSOLUTE_CANONICAL_PATH_REQUIRED')
        for parent in reversed(path.parents):
            info = parent.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                    'ROOT_PROTECTED_ANCESTRY_REQUIRED')
            self.seals[str(parent)] = frame(info)

    def read(self, path, maximum):
        self.check(); self.ancestry(path)
        require(self.opened < 4, 'OFFLINE_ARTIFACT_FILE_LIMIT')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        self.opened += 1
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                    and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                    and 0 < before.st_size <= maximum, 'PRIVATE_REGULAR_METADATA_ARTIFACT_REQUIRED')
            with os.fdopen(os.dup(fd), 'rb') as stream:
                raw = stream.read(maximum + 1)
            self.bytes += len(raw)
            require(len(raw) == before.st_size and frame(before) == frame(os.fstat(fd)) == frame(path.lstat()),
                    'RETAINED_ARTIFACT_CHANGED_DURING_READ')
            self.seals[str(path)] = frame(before)
            self.check(); return raw
        finally:
            os.close(fd)

    def stable(self):
        self.check()
        require(all(frame(Path(p).lstat()) == f for p, f in self.seals.items()),
                'RETAINED_METADATA_ARTIFACTS_CHANGED')


def put(scope, name, record):
    raw = canonical(record)
    require(0 < len(raw) <= PROFILE['maximumOutputPlanBytes'], 'BOUNDED_PRIVATE_PLAN_REQUIRED')
    fd = os.open(scope / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(scope, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return sha(raw)


def collect_plan(control):
    claim = decode(control.read(INPUT / 'capture.claim.json', 4096))
    require(canonical(claim) == canonical({'schema': 'ouf.m2-discovery-custody-capture-claim.v1', 'automaticReplayAllowed': False}),
            'EXACT_CONTROL16_CAPTURE_CLAIM_REQUIRED')
    receipt = decode(control.read(INPUT / 'result.json', 32768))
    require(type(EXPECTED_RECEIPT) is dict and canonical(receipt) == canonical(EXPECTED_RECEIPT),
            'EXACT_COMPLETE_CONTROL16_RECEIPT_REQUIRED')
    host = decode(control.read(HOST, 2097152))
    require(sha(canonical(host)) == HOST_SHA == receipt['retainedHostBaselineHash'], 'EXACT_RETAINED_HOST_HASH_REQUIRED')
    host_public = host_assessment(host)
    raw = control.read(INPUT / 's3/inventory.private.json', PROFILE['maximumInputInventoryBytes'])
    require(sha(raw) == INVENTORY_SHA == receipt['privateInventorySha256'],
            'EXACT_PRIVATE_INVENTORY_HASH_REQUIRED')
    inventory = decode(raw)
    require(canonical(inventory.get('summary')) == canonical(receipt['inventorySummary'])
            and len(inventory.get('records', [])) == receipt['records']
            and inventory.get('requests') == receipt['s3Requests'], 'RECEIPT_AND_PRIVATE_INVENTORY_MISMATCH')
    private, public = compile_plan(inventory)
    private.update(retainedHostBaseline=host, sourcePrivateInventorySha256=INVENTORY_SHA,
                   sourceReceiptSha256=sha(canonical(receipt)), controlProfile=PROFILE)
    public.update(host_public)
    control.stable()
    plan_sha = put(SCOPE, 'migration-plan.private.json', private)
    control.stable()
    public.update(privatePlanSha256=plan_sha, sourcePrivateInventorySha256=INVENTORY_SHA,
      control16EvidenceStableDuringAnalysis=True, priorScopesModified=False,
      sourceInventoryControl=16, retainedHostBaselineControl=14,
      capacityAndMemoryReobserved=False, cumulativeControlAttempts=17,
      cumulativeDirectEngineGets=52, privateMetadataFilesOpened=control.opened,
      privateMetadataBytesRead=control.bytes, scopeConsumed=True)
    return public


def main():
    created = False; control = None
    try:
        require(not sys.argv[1:] and os.geteuid() == os.getegid() == 0 and sys.flags.isolated
                and sys.flags.no_site and sys.dont_write_bytecode, 'ROOT_ISOLATED_NO_ARGUMENT_ENTRY_REQUIRED')
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (PROFILE['maximumMemoryBytes'], PROFILE['maximumMemoryBytes']))
        resource.setrlimit(resource.RLIMIT_CPU, (40, 40))
        import signal
        signal.signal(signal.SIGALRM, lambda *_: require(False, 'OFFLINE_PLAN_DEADLINE'))
        signal.alarm(45)
        os.umask(0o077); control = OfflineFiles(); control.ancestry(SCOPE)
        require(not os.path.lexists(SCOPE), 'OFFLINE_PLAN_SCOPE_CONSUMED_NO_REPLAY')
        os.mkdir(SCOPE, 0o700); created = True
        parent_fd = os.open(SCOPE.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        # Parent mtime changes only when creating this NEW scope; do not compare
        # it against its own pre-creation frame when preserving input artifacts.
        control.seals = {}
        put(SCOPE, 'claim.json', {'profile': PROFILE, 'automaticReplayAllowed': False})
        report = collect_plan(control); put(SCOPE, 'result.json', report)
        print(json.dumps(report, sort_keys=True)); return 0
    except Exception as error:
        reason = str(error) if type(error) is PlanError and re.fullmatch('[A-Z0-9_]{1,128}', str(error)) else 'OFFLINE_PLAN_UNPROVEN_PRIVATE_DETAILS_NOT_PRINTED'
        report = {'status': 'STOP_RECONCILE', 'reasonCode': reason,
          'scopeConsumed': os.path.lexists(SCOPE), 'newAnalysisClaimCreated': created,
          'cumulativeControlAttempts': 17 if os.path.lexists(SCOPE) else 16,
          'cumulativeDirectEngineGets': 52, 'directEngineGets': 0, 's3Requests': 0,
          'objectBodiesRead': 0, 'credentialFilesOpened': 0, 'runtimeAuthorityIssued': False,
          'targetApplyAuthorized': False, 'automaticReplayAllowed': False}
        if control:
            report.update(privateMetadataFilesOpened=control.opened, privateMetadataBytesRead=control.bytes)
        if created:
            try:
                put(SCOPE, 'result.json', report)
            except Exception:
                pass
        print(json.dumps(report, sort_keys=True)); return 1
