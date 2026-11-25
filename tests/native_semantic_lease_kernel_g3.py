"""PET A3-11 and A3-22. The entire nft session runs inside one disposable network namespace."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.semantic_lease_kernel_migration import g3_contract as g
from tools.semantic_lease_kernel_migration.g3_install_profile import read_nft_profile


@unittest.skipUnless(os.environ.get('OUF_LEASE_KERNEL_G3_NATIVE') == '1', 'native netns opt-in')
class NativeContract(unittest.TestCase):
    def test_a3_11_recreated_pair(self):
        session = r'''
create_pair() {
    for f in inet bridge; do
        "$nft" -f - <<EOF
table $f sample {
    set provider_0 { type ipv4_addr; flags timeout; }
    chain guard { counter accept; }
}
EOF
    done
}
read_pair() {
    for f in inet bridge; do
        "$nft" -j list table "$f" sample
        printf '\000'
    done
}
nft=$1
create_pair
"$2" -I -B "$3" "$nft" "$4"
printf '\000'
read_pair
for f in inet bridge; do "$nft" delete table "$f" sample; done
create_pair
read_pair
'''
        nft = Path(shutil.which('nft')).resolve(strict=True)
        nft_sha256 = hashlib.sha256(nft.read_bytes()).hexdigest()
        output = subprocess.check_output(['unshare', '--net', '--', 'sh', '-ec', session, 'g3',
                                          nft, sys.executable, __file__, nft_sha256], timeout=30)
        candidate, first_inet, first_bridge, second_inet, second_bridge, tail = output.split(b'\0')
        profile = json.loads(candidate)
        self.assertEqual(tail, b'')
        first = {'inet': json.loads(first_inet), 'bridge': json.loads(first_bridge)}
        second = {'inet': json.loads(second_inet), 'bridge': json.loads(second_bridge)}
        binding = ('a' * 64, 'b' * 64, 3, '00000000-0000-4000-8000-000000000001')
        before = g.local_seal(*binding, first, profile)
        after = g.local_seal(*binding, second, profile)
        self.assertEqual(g.policy_footprint(first, profile), g.policy_footprint(second, profile))
        self.assertNotEqual(before['handles'], after['handles'])
        self.assertNotEqual(before['structureHash'], after['structureHash'])
        with self.assertRaisesRegex(ValueError, '^' + g.SEAL_DRIFT + '$'):
            g.verify_boot(before, binding[3], binding[0], binding[1], second, profile,
                          g.policy_footprint(first, profile))

    def test_a3_22_runner_reconcile_and_tick(self):
        subprocess.run(['unshare', '--net', '--', sys.executable, '-I', '-B', __file__, 'boot-proof'],
                       check=True, timeout=60)


def boot_proof():
    from uuid import uuid4

    sys.path.insert(0, str(Path(__file__).parent))
    from test_semantic_lease_kernel_g3_boot import stage
    from test_semantic_lease_kernel_v2 import kernel, m
    from tools.semantic_lease_kernel_migration import boot_dispatcher as api, g3_journal as journal
    from tools.semantic_lease_kernel_migration import g3_reconcile as reconcile

    assert os.environ['OUF_LEASE_KERNEL_G3_NATIVE'] == '1' and os.geteuid() == os.getegid() == 0
    assert Path('/proc/self/ns/net').stat().st_ino != Path('/proc/1/ns/net').stat().st_ino
    nft = Path(shutil.which('nft')).resolve(strict=True)
    binary = {'path': str(nft), 'sha256': api.sha(nft.read_bytes())}
    cfg = kernel(2)
    name = cfg['tableName']
    rules = m.materialize(cfg, empty_provider_sets=True)['nftRules'].encode('ascii')

    def remove_pair():
        batch = ''.join(f'delete table {family} {name}\n' for family in ('inet', 'bridge'))
        api.command(binary, ['-f', '-'], batch.encode('ascii'))

    with tempfile.TemporaryDirectory(prefix='g3-', dir='/run') as temp:
        root = Path(temp)
        api.command(binary, ['-f', '-'], rules)
        reference = api.tables(binary, name)
        profile = g.listing_profile(reference['inet']['nftables'][0])
        previous = str(uuid4())
        _, observed = stage(root, api, cfg, binary, reference, previous)
        raw = api.private(root / 'journal')
        remove_pair()
        assert api.tables(binary, name) is None
        pointer = root / 'pointer'
        for _ in range(2):
            result = subprocess.check_output([sys.executable, '-I', '-B', root / 'dispatcher',
                '--pointer', pointer, '--self-sha256', api.sha(api.private(root / 'dispatcher'))])
            assert b'LEASE_KERNEL_BOOT=EMPTY' in result
        current = journal.current_boot_id()
        guard = root / 'receipts' / current
        assert api.private(guard / 'previous.json') == raw
        assert api.document(raw)['bootId'] == previous != current
        blocked = api.document(api.private(root / 'journal'))
        assert (blocked['bootId'], blocked['state']) == (current, 'BLOCKED')
        assert blocked['leaseAuthorized'] is blocked['startAuthorized'] is False
        observed['bootId'] = current

        def observe(state):
            return observed.copy()

        planned = reconcile.plan(pointer, observe)
        result = reconcile.apply(pointer, planned['planSha256'], observe)
        closed = api.document(api.private(root / 'journal', result['journalSha256']))
        assert closed == {**blocked, 'state': 'QUIESCED'}
        seal = api.document(api.private(root / 'seals' / (current + '.json'), result['sealSha256']))
        policy = {key: observed[key] for key in ('head', 'owner', 'generation', 'bootId', 'footprint')}
        policy['nftProfile'] = profile
        members = {'provider_0': {'validUntil': {}, 'maxSeconds': 30}}
        g.verify_tick(policy, seal, api.tables(binary, name), members, 0)
        remove_pair()
        api.command(binary, ['-f', '-'], rules)
        replaced = api.tables(binary, name)
        assert g.policy_footprint(replaced, profile) == observed['footprint']
        with unittest.TestCase().assertRaisesRegex(ValueError, '^' + g.SEAL_DRIFT + '$'):
            g.verify_tick(policy, seal, replaced, members, 0)


if __name__ == '__main__':
    if sys.argv[1:] == ['boot-proof']:
        boot_proof()
    else:
        print(json.dumps(read_nft_profile(*sys.argv[1:])))
