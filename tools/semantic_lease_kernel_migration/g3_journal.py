"""Custodied G3 state. All *_locked operations require the owner's common flock."""
import os
from pathlib import Path
import re
import stat

from . import g3_contract as g


def current_boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').rstrip('\n')


def private_directory(api, path):
    api.ancestors(path)
    info = path.lstat()
    api.need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
             and stat.S_IMODE(info.st_mode) == 0o700, 'G3_PRIVATE_DIRECTORY')


def make_directory(api, path):
    """Return True only to the caller that reserved the directory."""
    private_directory(api, path.parent)
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        private_directory(api, path)
        return False
    api.sync(path.parent)
    private_directory(api, path)
    return True


def optional(api, path):
    # Only a missing leaf in a checked, private parent means "not published".
    private_directory(api, path.parent)
    try:
        return api.private(path)
    except FileNotFoundError:
        return None


def sync_verified(api, path, expected, reason):
    """Finish a possibly interrupted exclusive write under the common lock."""
    flags = os.O_RDWR if os.name == 'nt' else os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(path, flags)
    try:
        api.need(api.private(path) == expected and os.path.samestat(os.fstat(fd), path.lstat()),
                 reason)
        os.fsync(fd)
    finally:
        os.close(fd)
    api.sync(path.parent)


def read_locked(api, path, head, owner):
    raw = api.private(path)
    value = api.document(raw)
    boot_id = current_boot_id()
    api.need(isinstance(value, dict) and value.get('head') == head
             and value.get('owner') == owner, g.BINDING)
    return raw, value, boot_id


def transition_locked(api, path, before, head, owner, target):
    """CAS after caller's operational checks. No nft or start effects here."""
    raw, journal, boot_id = read_locked(api, path, head, owner)
    api.need(raw == before, 'FOREIGN_PUBLICATION_PRESERVED')
    classification = g.classify_journal(journal, boot_id)
    api.need(journal.get('bootId') == boot_id, g.BINDING)
    # The guard intentionally denies active states in this boot. Use its
    # closed schema check for the binding and check the active flags here.
    closed = {**journal, 'state': 'QUIESCED', 'leaseAuthorized': False}
    api.need(g.classify_journal(closed, boot_id) == g.QUIESCENT, g.BINDING)
    active = journal['state'] in ('LEASE_READY', 'LEASE_UPDATING', 'QUIESCING')
    valid_active = active and journal['leaseAuthorized'] is (journal['state'] != 'QUIESCING')
    api.need(classification == g.QUIESCENT or valid_active, 'G3_TRANSITION_DENIED')
    edges = {'BLOCKED': ('QUIESCED',), 'QUIESCED': ('LEASE_READY', 'BLOCKED'),
             'LEASE_READY': ('LEASE_UPDATING', 'QUIESCING', 'BLOCKED'),
             'LEASE_UPDATING': ('LEASE_READY', 'QUIESCING', 'BLOCKED'),
             'QUIESCING': ('QUIESCED', 'BLOCKED')}
    api.need(target in edges[journal['state']], 'G3_TRANSITION_DENIED')
    after = {**journal, 'state': target, 'bootId': boot_id,
             'leaseAuthorized': target in ('LEASE_READY', 'LEASE_UPDATING'), 'startAuthorized': False}
    api.cas(path, before, api.canonical(after))


def cohort_empty(owner, api):
    """Read the two owner-bound cgroup v2 leaves, including all descendants."""
    paths = owner['cohortCgroups']
    api.need(isinstance(paths, dict) and paths.keys() == {'adapter', 'southbound'}, 'G3_COHORT')
    # Docker may not have created the per-driver parent on a fresh boot.
    hierarchy = Path('/sys/fs/cgroup')
    (hierarchy / 'cgroup.controllers').read_bytes()
    cids = set()
    for value in paths.values():
        path = api.safe(value)
        match = re.fullmatch(r'(?:docker-([0-9a-f]{64})\.scope|([0-9a-f]{64}))', path.name)
        api.need(match and path.is_relative_to(hierarchy), 'G3_COHORT')
        cids.add(match[1] or match[2])
        try:
            events = (path / 'cgroup.events').read_text(encoding='ascii').splitlines()
        except FileNotFoundError:
            try:
                path.stat()
            except FileNotFoundError:
                continue
            raise
        else:
            api.need([line for line in events if line.startswith('populated ')] == ['populated 0'],
                     'G3_COHORT')
    api.need(len(cids) == 2, 'G3_COHORT')


class BootState:
    """Inputs selected by the dispatcher's sealed generation receipt."""

    def __init__(self, receipt, api):
        self.api = api
        api.need(receipt['schema'] == 'ouf.semantic-lease-kernel-generation.v1'
                 and type(receipt['generation']) is int and receipt['generation'] == 3, g.BINDING)
        ref = receipt['bootProfile']
        profile = api.document(api.private(ref['path'], ref['sha256']))
        self.owner_hash = profile['coordinatedConfigurationHash']
        self.owner = owner = api.document(api.private(profile['coordinatedConfiguration'], self.owner_hash))
        boot = api.document(api.private(profile['bootConfiguration'], profile['bootConfigurationHash']))
        api.need(type(owner['generation']) is int and owner['generation'] == 3
                 and owner['kernel'] == boot['kernel'] and owner['commonLockFile'] == boot['lockFile']
                 and owner['nftPath'] == boot['nftPath'] and boot['projection'] == g.PROJECTION,
                 'BOOT_OWNER_SCOPE_DRIFT')
        self.head, self.footprint = boot['head'], boot['expectedFootprint']
        self.profile = owner['nftProfile']
        self.nft = {'path': owner['nftPath'], 'sha256': owner['nftSha256']}
        self.raw, self.journal, self.boot_id = read_locked(api, owner['journalFile'], self.head, self.owner_hash)
        api.need(g.classify_journal(self.journal, self.boot_id) != g.DENY, 'G3_JOURNAL_DENIED')
        self.directory = Path(owner['receiptDirectory']) / self.boot_id
        self.seal_path = Path(owner['sealDirectory']) / (self.boot_id + '.json')
        private_directory(api, self.directory.parent)
        private_directory(api, self.seal_path.parent)

    def tables(self):
        return self.api.tables(self.nft, self.owner['kernel']['tableName'])

    def confirm_journal(self):
        # CAS flushes its tempfile before replace. On replay the rename itself
        # may still be pending in the journal's own directory.
        path = Path(self.owner['journalFile'])
        self.api.need(self.api.private(path) == self.raw, 'FOREIGN_PUBLICATION_PRESERVED')
        self.api.sync(path.parent)

    def seal(self, tables):
        return g.local_seal(self.head, self.owner_hash, 3, self.boot_id, tables, self.profile)

    def verify(self, seal, tables):
        g.verify_boot(seal, self.boot_id, self.head, self.owner_hash, tables, self.profile, self.footprint)

    def previous(self):
        api = self.api
        private_directory(api, self.directory)
        raw = api.private(self.directory / 'previous.json')
        old = api.document(raw)
        api.need(g.classify_journal(old, self.boot_id) != g.DENY and old['bootId'] != self.boot_id
                 and old['head'] == self.head and old['owner'] == self.owner_hash, g.BINDING)
        return raw

    def guard(self, tables):
        api = self.api
        previous = self.previous()
        claim = api.document(api.private(self.directory / 'claim.json'))
        guard = api.document(api.private(self.directory / 'guard.json'))
        api.need(claim['previousSha256'] == api.sha(previous) and claim['bootId'] == self.boot_id
                 and guard['claimSha256'] == api.digest(claim), g.BINDING)
        self.verify(guard['instance'], tables)
        if claim['mode'] == 'present':
            self.verify(claim['instance'], tables)
        else:
            api.need(claim['mode'] == 'rebuild' and claim['instance'] is None, g.BINDING)
        return guard

    def intent(self, plan):
        return {'planSha256': self.api.digest(plan), 'sealSha256': plan['sealSha256']}

    def completion(self, plan):
        return {'schema': 'ouf.lease-kernel.reconciled.g3.v1', **self.intent(plan),
                'bootId': self.boot_id, 'journalSha256': plan['afterSha256']}

    def verify_completion(self, guard, seal_raw):
        api = self.api
        directory = self.directory / 'reconcile'
        private_directory(api, directory)
        plan = api.document(api.private(directory / 'plan.json'))
        api.need(plan['guardSha256'] == api.digest(guard)
                 and plan['afterSha256'] == api.sha(self.raw)
                 and plan['sealSha256'] == api.sha(seal_raw)
                 and api.private(directory / 'seal-intent.json') == api.canonical(self.intent(plan)),
                 g.BINDING)
        sync_verified(api, directory / 'receipt.json', api.canonical(self.completion(plan)), g.BINDING)

    def block_previous(self, tables):
        # Sole cross-boot transition: evidence and signed readback before CAS.
        self.api.need(self.journal['bootId'] != self.boot_id and self.boot_id == current_boot_id(),
                      g.BINDING)
        self.guard(tables)
        blocked = {**self.journal, 'bootId': self.boot_id, 'state': 'BLOCKED',
                   'leaseAuthorized': False, 'startAuthorized': False}
        self.api.cas(self.owner['journalFile'], self.raw, self.api.canonical(blocked))

    def transition(self, target):
        transition_locked(self.api, self.owner['journalFile'], self.raw, self.head, self.owner_hash, target)
