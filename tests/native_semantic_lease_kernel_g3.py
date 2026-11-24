"""PET A3-11. The entire nft session runs inside one disposable network namespace."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
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
            g.verify_boot(before, binding[3], binding[0], binding[1], second, profile)


if __name__ == '__main__':
    print(json.dumps(read_nft_profile(*sys.argv[1:])))
