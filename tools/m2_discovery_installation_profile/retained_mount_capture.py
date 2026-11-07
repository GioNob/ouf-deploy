"""One private proposal of retained mount custody, never runtime admission.

The exact previously captured thirteen-peer record selects ten retained IDs.
Reobserve those IDs twice and capture mount ownership/type/inode metadata.
No mounted file content is read; mutable/ephemeral content stays unobserved. No raw Engine reply,
credential, key, SQL, OAuth request, lifecycle operation or authority is emitted.
"""
import http.client, os, re, socket, stat, struct, time
from pathlib import Path
from .custody_capture import Capture, attrs, decode, digest, encoded, process_pin, require, Stop

SEED = Path('/etc/ouf/deploy-snapshots/m2-discovery-current-bindings-0601fdfa-20261029-v1/inputs.json')
SEED_HASH = '14e42ac96293d342cd71b7386360b976882ac7ec75a18838d3960999430f3a13'
OUTPUT = Path('/etc/ouf/deploy-snapshots/m2-retained-mount-custody-14e42ac9-20261101-v1')
RETAINED = {'onboarding', 'postgres', 'minio', 'keycloak', 'gateway-owner', 'udp',
    'ingestion-evidence-read', 'caddy', 'udp-evidence-read', 'ingestion'}
ROLES = RETAINED | {'semantic', 'mcp', 'apisix'}
LIMITS = {'seconds': 90, 'engineGets': 20, 'engineResponseBytes': 2097152,
    'engineTotalBytes': 33554432, 'entries': 2048, 'mountsPerPeer': 64, 'depth': 32}
PROFILE = {'schema': 'ouf.retained-mount-input-capture-budget.v1', 'maximumAttempts': 1,
    'maximumSeconds': 90, 'reason': 'ONE_CURRENT_PRIVATE_REVIEW_SNAPSHOT_NO_AUTOMATIC_REPLAY',
    'partialOutputPreserved': True, 'automaticBudgetResetAllowed': False}


def identity(row):
    return {k: row[k] for k in ('Id', 'Name', 'Image', 'Config', 'HostConfig', 'Mounts', 'NetworkSettings')} | {
        'generation': {k: row['State'][k] for k in ('Pid', 'StartedAt', 'Running', 'Paused', 'Restarting')}}


class RetainedEngine:
    def __init__(self, capture, binding, ids):
        require(type(binding) is dict and set(binding) == {'socketPath', 'socketBinding', 'peerCredentials'}
            and len(ids) == len(set(ids)) == 10 and all(re.fullmatch('[a-f0-9]{64}', v) for v in ids),
            'EXACT_TEN_RETAINED_ENGINE_TARGETS_REQUIRED')
        self.c, self.binding = capture, binding
        self.allowed = {'/v1.44/containers/'+v+'/json' for v in ids}

    def get(self, cid):
        c, b = self.c, self.binding; c.guarded(); path = '/v1.44/containers/'+cid+'/json'
        require(path in self.allowed and c.counts['engineGets'] < LIMITS['engineGets'],
            'CLOSED_TWENTY_RETAINED_GET_ATTEMPTS_REQUIRED')
        selected = Path(b['socketPath']); c.ancestors(selected); info = selected.lstat()
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0
            and [info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)] == b['socketBinding'],
            'RETAINED_ENGINE_SOCKET_CUSTODY_CHANGED')
        class Local(http.client.HTTPConnection):
            def connect(self):
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.settimeout(min(3, max(.001, c.until-time.monotonic())))
                self.sock.connect(str(selected))
                require(list(struct.unpack('3i', self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))) == b['peerCredentials']
                    and b['peerCredentials'][1:] == [0, 0], 'RETAINED_ENGINE_PEER_CREDENTIALS_CHANGED')
        client = Local('exact-retained-engine'); c.counts['engineGets'] += 1
        try:
            client.request('GET', path, headers={'Connection': 'close'}); reply = client.getresponse()
            require(reply.status == 200, 'SUCCESSFUL_RETAINED_ENGINE_REPLY_REQUIRED')
            chunks = []; size = 0
            while size <= LIMITS['engineResponseBytes']:
                c.guarded(); block = reply.read1(min(65536, LIMITS['engineResponseBytes']+1-size))
                if not block: break
                size += len(block); chunks.append(block)
            raw = b''.join(chunks); c.counts['engineBytes'] += len(raw)
            require(reply.status == 200 and 0 < len(raw) <= LIMITS['engineResponseBytes']
                and c.counts['engineBytes'] <= LIMITS['engineTotalBytes'], 'BOUNDED_RETAINED_ENGINE_REPLY_REQUIRED')
            value = decode(raw); c.guarded(); return value
        finally: client.close()


class RetainedCapture(Capture):
    def __init__(self, scope):
        require(os.geteuid() == os.getegid() == 0, 'ROOT_RETAINED_CAPTURE_REQUIRED')
        super().__init__(scope); self.until = time.monotonic()+LIMITS['seconds']
        self.root_identity = attrs(self.scope.lstat())[:6]
        self.counts.update(engineGets=0, engineBytes=0, staticEntries=0, mountFileContentBytesRead=0,
            readonlyMounts=0, mutableMounts=0, ephemeralMounts=0, specialSources=0)
        self.observed = {}

    def guarded(self):
        self.check(); self.ancestors(self.scope/'placeholder')
        require(attrs(self.scope.lstat())[:6] == self.root_identity, 'RETAINED_CAPTURE_DIRECTORY_CHANGED')

    def node(self, path):
        """O_PATH first: opening an untrusted FIFO/device never performs I/O."""
        original = str(path); path = Path(path)
        if original.startswith('/var/run/'):
            alias = Path('/var/run').lstat()
            require(stat.S_ISLNK(alias.st_mode) and alias.st_uid == 0 and os.readlink('/var/run') == '/run',
                'EXACT_SYSTEM_RUN_ALIAS_REQUIRED')
            original = '/run/'+original[len('/var/run/'):]; path = Path(original)
        require(path.is_absolute() and str(path) == original and '..' not in path.parts
            and path != Path('/') and len(path.parts) <= 64, 'EXACT_NO_LINK_RETAINED_SOURCE_REQUIRED')
        fds = []; current = os.open('/', os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW); fds.append(current)
        try:
            for index, name in enumerate(path.parts[1:]):
                flags = os.O_PATH | os.O_NOFOLLOW
                if index < len(path.parts)-2: flags |= os.O_DIRECTORY
                child = os.open(name, flags, dir_fd=current); fds.append(child); current = child
                require(not stat.S_ISLNK(os.fstat(current).st_mode), 'RETAINED_SOURCE_LINK_DENIED')
            return os.dup(current)
        finally:
            for fd in reversed(fds): os.close(fd)

    def metadata_tree(self, path, depth=0):
        self.guarded(); path = Path(path); fd = self.node(path)
        try:
            before = attrs(os.fstat(fd)); mode = before[2]
            require(depth <= LIMITS['depth'] and self.counts['staticEntries'] < LIMITS['entries']
                and not stat.S_ISLNK(mode), 'BOUNDED_NO_LINK_RETAINED_STATIC_TREE_REQUIRED')
            self.counts['staticEntries'] += 1
            row = {'metadata': before, 'kind': 'DIRECTORY' if stat.S_ISDIR(mode) else ('REGULAR_FILE' if stat.S_ISREG(mode) else 'SPECIAL_FILE'), 'contentsObserved': False}
            old = self.observed.get(str(path))
            require(old is None or not old[1] or old[0] == before, 'RETAINED_STATIC_METADATA_CHANGED_BETWEEN_MOUNTS')
            self.observed[str(path)] = (before, True)
            if stat.S_ISREG(mode):
                require(before[5] == 1, 'SINGLE_LINK_RETAINED_FILE_REQUIRED')
                row['contentsObserved'] = False
            elif stat.S_ISDIR(mode):
                reader = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    row['children'] = {}
                    with os.scandir(reader) as entries:
                        for entry in entries:
                            self.guarded()
                            require(re.fullmatch(r'[A-Za-z0-9_.@+-]{1,255}', entry.name)
                                and entry.name not in ('.', '..'), 'EXACT_RETAINED_STATIC_MEMBER_NAME_REQUIRED')
                            row['children'][entry.name] = self.metadata_tree(path/entry.name, depth+1)
                finally: os.close(reader)
            else:
                self.counts['specialSources'] += 1
                row['protocolAccessIsReadOnlyProven'] = False
            again = self.node(path)
            try: require(attrs(os.fstat(fd)) == before == attrs(os.fstat(again)), 'RETAINED_STATIC_PATH_CHANGED')
            finally: os.close(again)
            return row
        finally: os.close(fd)

    def mounts(self, actual):
        rows = actual['Mounts']; require(type(rows) is list and len(rows) <= LIMITS['mountsPerPeer'], 'BOUNDED_RETAINED_MOUNTS_REQUIRED')
        result = []; destinations = set()
        for mount in rows:
            require(type(mount) is dict and type(mount.get('RW')) is bool
                and mount.get('Type') in {'bind', 'volume', 'tmpfs'}
                and type(mount.get('Destination')) is str and mount['Destination'].startswith('/')
                and mount['Destination'] not in destinations, 'EXACT_RETAINED_MOUNT_DECLARATION_REQUIRED')
            destinations.add(mount['Destination'])
            row = {'mountHash': digest(mount), 'type': mount['Type'], 'source': mount.get('Source', ''),
                'destination': mount['Destination'], 'readOnly': not mount['RW']}
            if mount['Type'] == 'tmpfs':
                self.counts['ephemeralMounts'] += 1; row.update(kind='EPHEMERAL_CONTENT_NOT_OBSERVED', contentsObserved=False)
            elif mount['RW']:
                fd = self.node(mount['Source'])
                try:
                    info = os.fstat(fd)
                    require(not stat.S_ISLNK(info.st_mode), 'MUTABLE_MOUNT_LINK_DENIED')
                    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)): self.counts['specialSources'] += 1
                    row.update(kind='MUTABLE_CONTENT_NOT_OBSERVED', contentsObserved=False, metadata=attrs(info))
                    if mount['Source'] not in self.observed: self.observed[mount['Source']] = (attrs(info), False)
                finally: os.close(fd)
                self.counts['mutableMounts'] += 1
            else:
                row.update(kind='READONLY_METADATA_CANDIDATE', contentsObserved=False, metadataTree=self.metadata_tree(mount['Source']))
                self.counts['readonlyMounts'] += 1
            result.append(row)
        return result


def collect(c, seed_path=SEED, seed_hash=SEED_HASH, *, engine_factory=RetainedEngine,
        pin=process_pin, boot_path=Path('/proc/sys/kernel/random/boot_id')):
    seed = decode(c.read(seed_path, 0, 0, 0o600, 2097152, 'metadataReads'))
    require(digest(seed) == seed_hash and seed.get('schema') == 'ouf.m2-discovery-current-private-bindings.v1'
        and set(seed['observations']) == set(seed['processPins']) == ROLES
        and all(seed.get(k) is False for k in ('historicalAuthorityReused', 'runtimeAuthorityIssued', 'automaticReplayAllowed', 'budgetReset')),
        'EXACT_UNADMITTED_THIRTEEN_PEER_SEED_REQUIRED')
    def roots():
        c.guarded()
        require(boot_path.read_text().strip() == seed['bootId'] and all(pin(v['pid']) == v for v in seed['rootProcessPins'].values()),
            'RETAINED_CAPTURE_BOOT_OR_ROOT_GENERATION_CHANGED')
        require(all(pin(seed['processPins'][r]['pid']) == seed['processPins'][r] for r in RETAINED),
            'RETAINED_CAPTURE_PROCESS_GENERATION_CHANGED')
    roots(); engine = engine_factory(c, seed['engineBinding'], [seed['observations'][r]['Id'] for r in sorted(RETAINED)])
    proofs = {}
    for role in sorted(RETAINED):
        prior = seed['observations'][role]; actual = engine.get(prior['Id']); roots()
        require(identity(actual) == identity(prior), 'RETAINED_CAPTURE_REVIEWED_CONFIGURATION_CHANGED')
        proofs[role] = {'containerId': actual['Id'], 'imageId': actual['Image'],
            'runtimeIdentityHash': digest(identity(actual)), 'processPin': seed['processPins'][role], 'mounts': c.mounts(actual)}
    for role in sorted(RETAINED):
        actual = engine.get(proofs[role]['containerId']); roots()
        require(digest(identity(actual)) == proofs[role]['runtimeIdentityHash'], 'RETAINED_CAPTURE_CHANGED_DURING_TWO_PASSES')
    for path, (before, static) in c.observed.items():
        fd = c.node(path)
        try:
            after = attrs(os.fstat(fd))
            require(after == before if static else after[:5] == before[:5], 'RETAINED_MOUNT_SOURCE_CHANGED_DURING_CAPTURE')
        finally: os.close(fd)
    roots(); require(c.counts['engineGets'] == 20, 'EXACT_TWENTY_RETAINED_GETS_REQUIRED')
    require(all(attrs(Path(p).lstat()) == v for p, v in c.seals.items()), 'RETAINED_CAPTURE_SEED_CHANGED')
    record = {'schema': 'ouf.m2-retained-mount-custody-candidates.v1', 'seedHash': seed_hash,
        'bootId': seed['bootId'], 'peers': proofs, 'limits': LIMITS, 'budgetProfile': PROFILE,
        'observedMetadataIsExpectedPolicy': False, 'mountFileContentsObserved': False, 'mutableContentsObserved': False,
        'runtimeAuthorityIssued': False, 'targetApplyAuthorized': False, 'releaseAcceptance': False}
    require(len(encoded(record)) <= 8388608, 'BOUNDED_PRIVATE_RETAINED_CANDIDATES_REQUIRED')
    c.put('retained-mounts.private.json', record)
    return {'schema': 'ouf.m2-retained-mount-capture-result.v1', 'status': 'PRIVATE_MOUNT_CANDIDATES_CAPTURED_NOT_ADMITTED',
        'scope': str(c.scope), 'candidateHash': digest(record), 'counts': dict(c.counts), 'selectedRetainedPeers': 10,
        'retainedRuntimeImageIds': {r: proofs[r]['imageId'] for r in sorted(proofs)},
        'completePrivateCustodyProven': False, 'mountFileContentsObserved': False, 'mutableContentsObserved': False,
        'privateInputPathsOrValuesPrinted': False,
        'runtimeAuthorityIssued': False, 'targetApplyAuthorized': False, 'releaseAcceptance': False}


def main():
    c = None
    try:
        c = RetainedCapture(OUTPUT); result = collect(c); c.put('result.json', result); code = 0
    except Exception as error:
        reason = str(error) if type(error) is Stop and re.fullmatch('[A-Z0-9_]{1,128}', str(error)) else 'RETAINED_MOUNT_CAPTURE_UNPROVEN'
        result = {'schema': 'ouf.m2-retained-mount-capture-result.v1', 'status': 'STOP_RECONCILE',
            'reasonCode': reason, 'scopeConsumed': os.path.lexists(OUTPUT),
            'runtimeAuthorityIssued': False, 'targetApplyAuthorized': False, 'automaticReplayAllowed': False}
        if c is not None:
            try: c.put('result.json', result)
            except Exception: pass
        code = 1
    import json
    print(json.dumps(result, sort_keys=True)); return code

if __name__ == '__main__': raise SystemExit(main())
