"""Runtime evidence and governed Engine submission for the qualified G3 transition."""
from contextlib import contextmanager
import http.client
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time

from tools.semantic_lease_kernel_migration import boot_dispatcher as boot
from tools.semantic_lease_kernel_migration import g3_contract as g
from tools.semantic_lease_kernel_migration import g3_journal as journal


class Runtime(journal.BootState):
    def __init__(self, receipt, coordinator, api):
        super().__init__(receipt, api, current_runtime=True)
        self.receipt = receipt
        self.name = self.owner['kernel']['tableName']
        self.predecessor = receipt['predecessorTableName']
        api.need(receipt['configurationHash'] == self.owner_hash == coordinator['ownerConfiguration']['sha256']
                 and self.owner_path == coordinator['ownerConfiguration']['path']
                 and self.owner['journalFile'] == coordinator['journalPath']
                 and self.owner['commonLockFile'] == coordinator['commonLockPath']
                 and self.predecessor == self.owner['predecessorTableName']
                 and self.name != self.predecessor and all(isinstance(n, str)
                     and re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,31}', n)
                     for n in (self.name, self.predecessor)), g.BINDING)
        self.admission_path = Path(self.owner['admissionFile'])
        self.denial_path = self.directory.with_name(self.boot_id + '.tick-denied.json')

    def authenticate(self, head):
        lease = head['authorization']['lease']
        self.api.need(head['decision'] == 'OPERATE' and head['sha256'] == self.head
                      and lease['ownerConfigurationSha256'] == self.owner_hash
                      and lease['projection'] == g.PROJECTION and lease['footprint'] == self.footprint,
                      g.BINDING)
        return dict(head=self.head, owner=self.owner_hash, generation=3, bootId=self.boot_id,
                    footprint=self.footprint, nftProfile=self.profile)

    def local_reference(self):
        api = self.api
        raw = journal.optional(api, self.seal_path)
        api.need(raw is not None, g.SEAL_DRIFT)
        seal = api.document(raw)
        api.need(isinstance(seal, dict) and seal.get('bootId') == self.boot_id, g.BINDING)
        if not os.path.lexists(self.directory):
            initial = self.receipt.get('initialSeal')
            api.need(initial and self.receipt['closure'].get(initial) == api.sha(raw), g.SEAL_DRIFT)
        else:
            claim, guard = self.guard_records()
            api.need((claim['mode'] == 'rebuild' and claim['instance'] is None)
                     or (claim['mode'] == 'present' and api.canonical(claim['instance']) == raw), g.SEAL_DRIFT)
            api.need(api.canonical(guard['instance']) == raw, g.SEAL_DRIFT)
            closed = {**self.journal, 'state': 'QUIESCED', 'leaseAuthorized': False}
            self.verify_completion(guard, raw, quiesced_raw=api.canonical(closed))
        journal.sync_verified(api, self.seal_path, raw, g.SEAL_DRIFT)
        return seal

    def membership(self, receipt):
        self.api.need(isinstance(receipt, dict) and 'validUntil' in receipt and
                      self.api.canonical(receipt) == self.api.canonical(self.admission(receipt['validUntil'])),
                      g.BINDING)
        ends = receipt['validUntil']
        flows = self.owner['kernel']['providerFlows']
        self.api.need(isinstance(ends, dict) and ends.keys() == {f'provider_{i}' for i in range(len(flows))},
                      g.MEMBERS)
        return {f'provider_{i}': {'validUntil': ends[f'provider_{i}'], 'maxSeconds': flow['leaseSeconds']}
                for i, flow in enumerate(flows)}

    def admission(self, deadlines):
        return {'schema': 'ouf.lease-kernel.admission.g3.v1', 'generation': 3, 'head': self.head,
                'owner': self.owner_hash, 'bootId': self.boot_id, 'validUntil': deadlines}

    def confirmed_admission(self):
        raw = self.api.private(self.admission_path)
        receipt = self.api.document(raw)
        self.membership(receipt)
        journal.sync_verified(self.api, self.admission_path, raw, g.BINDING)
        return raw

    def read_nft(self, deadline, *argv):
        binary = self.api.executable(self.nft['path'], self.nft['sha256'])
        try:
            with tempfile.TemporaryFile() as output:
                remaining = deadline - time.monotonic()
                self.api.need(remaining > 0, 'R3_READBACK_TIMEOUT')
                result = subprocess.run([binary, '-j', 'list', *argv], stdin=subprocess.DEVNULL,
                                        stdout=output, stderr=subprocess.DEVNULL, timeout=min(30, remaining),
                                        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
                output.seek(0)
                raw = output.read(8_388_609)
            self.api.need(result.returncode == 0 and len(raw) <= 8_388_608, 'BOUNDED_COMMAND_FAILED')
            return self.api.document(raw)
        finally:
            self.api.executable(self.nft['path'], self.nft['sha256'])

    def read_pair(self, deadline=None):
        if deadline is None:
            self.api.need(self.api.tables(self.nft, self.predecessor) is None, 'R3_LEASE_KERNEL_NOT_FINALIZED')
            pair = self.tables()
            self.api.need(pair is not None, g.SEAL_DRIFT)
            return pair

        inventory = self.read_nft(deadline, 'tables')['nftables']
        present = {(r['table']['family'], r['table']['name']) for r in inventory if 'table' in r}
        families = ('inet', 'bridge')
        for name in (self.predecessor, self.name):
            members = [(family, name) in present for family in families]
            self.api.need(all(members) or not any(members), 'PARTIAL_TABLE_PAIR_PRESERVED')
            if name == self.predecessor:
                self.api.need(not any(members), 'R3_LEASE_KERNEL_NOT_FINALIZED')
            else:
                self.api.need(all(members), g.SEAL_DRIFT)
        return {family: self.read_nft(deadline, 'table', family, self.name) for family in families}


@contextmanager
def locked(coordinator, api):
    # The authenticated supervisor configuration supplies the common lock and
    # the path of the mutable selection, never a boot-specific head digest.
    with api.lock(coordinator['commonLockPath']):
        pointer, receipt = journal.confirmed_selection(api, coordinator['bootPointer'])
        state = Runtime(receipt, coordinator, api)
        state.selection_hash = api.digest(pointer)
        yield state


def inspect_locked(state, owner, expected_journal, head, clock, deadline=None):
    api = state.api
    api.need(api.canonical(state.owner) == api.canonical(owner)
             and api.canonical(state.journal) == api.canonical(expected_journal), g.BINDING)
    policy = state.authenticate(head)
    state.confirm_journal()
    api.need(state.journal['state'] in ('QUIESCED', 'LEASE_READY')
             and journal.optional(api, state.denial_path) is None, 'G3_JOURNAL_DENIED')
    seal = state.local_reference()
    if state.journal['state'] == 'LEASE_READY':
        members = state.membership(api.document(state.confirmed_admission()))
        g.verify_tick(policy, seal, state.read_pair(deadline), members, int(clock()))
    else:
        state.verify(seal, state.read_pair(deadline))
    return {'generation': 3, 'bootId': state.boot_id, 'predecessorAbsent': True,
            'selectionSha256': state.selection_hash, 'footprint': state.footprint,
            'sealSha256': api.digest(seal)}


def observe(owner, expected_journal, coordinator, head, *, api=boot, clock=time.monotonic, deadline=None):
    with locked(coordinator, api) as state:
        return inspect_locked(state, owner, expected_journal, head, clock, deadline)


@contextmanager
def submission_gate(coordinator, approved, owner, expected_journal, authenticate, *, api=boot):
    generation = approved['generation']
    # Historical g2 supervisor documents predate the configurable pointer path.
    path = (coordinator['bootPointer'] if generation == 3 else
            coordinator.get('bootPointer', '/etc/ouf/coordinated-boot-installation.json'))
    with api.lock(coordinator['commonLockPath']):
        def verify():
            pointer, receipt = journal.confirmed_selection(api, path)
            api.need(receipt['schema'] == 'ouf.semantic-lease-kernel-generation.v1'
                     and type(receipt['generation']) is int and receipt['generation'] == generation
                     and receipt['configurationHash'] == coordinator['ownerConfiguration']['sha256'],
                     'R3_LEASE_KERNEL_GENERATION_DRIFT')
            head = authenticate(api)
            if generation == 3:
                state = Runtime(receipt, coordinator, api)
                state.selection_hash = api.digest(pointer)
                api.need(inspect_locked(state, owner, expected_journal, head, time.monotonic) == approved,
                         g.BINDING)
            else:
                path_journal = Path(owner['journalFile'])
                raw = api.private(path_journal)
                api.need(generation == 2 and owner['commonLockFile'] == coordinator['commonLockPath']
                         and api.document(raw) == expected_journal, g.BINDING)
                journal.sync_verified(api, path_journal, raw, g.BINDING)
                nft = {'path': owner['nftPath'], 'sha256': owner['nftSha256']}
                name = owner['kernel']['tableName']
                api.need(receipt['predecessorTableName'] == name[:-3] and api.tables(nft, name[:-3]) is None,
                         'R3_LEASE_KERNEL_NOT_FINALIZED')
                pair = api.tables(nft, name)
                api.need(pair is not None and api.digest(api.structure(pair)) == approved['structureHash'],
                         'R3_LEASE_KERNEL_STRUCTURE_DRIFT')
        yield verify


class EngineSocket(socket.socket):
    """HTTPResponse's buffered reader may need several reads to finish the headers."""

    def recv_into(self, buffer, *args):
        remaining = self.response_deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        self.settimeout(remaining)
        return super().recv_into(buffer, *args)


def connect_request(args, cid, connections):
    """Connect before the final verification. This sends no Engine request bytes."""
    boot.need(re.fullmatch(r'[0-9a-f]{64}', cid), g.BINDING)
    resource = {'start': 'start', 'restart-one': 'restart?t=30'}[args.action]
    client = http.client.HTTPConnection('localhost', timeout=args.timeout_seconds)
    connections.callback(client.close)
    client.sock = EngineSocket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.sock.settimeout(args.timeout_seconds)
    client.sock.connect(args.docker_socket.removeprefix('unix://'))
    return client, f'/v1.44/containers/{cid}/{resource}'
