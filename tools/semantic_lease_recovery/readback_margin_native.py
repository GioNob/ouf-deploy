"""Reproduce native one-second JSON zero; qualify candidate admission only.

Disposable CI netns, synthetic observations. Not target timing attribution or
worker availability proof. Strict R10 backend is used unchanged.
"""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'semantic_lease_activation'))
from test_activation_native import fixture, load_compiler, run

def main():
    assert os.geteuid() == 0
    assert Path('/proc/self/ns/net').stat().st_ino != Path('/proc/1/ns/net').stat().st_ino
    source = Path(sys.argv[1]).resolve()
    nft = str(Path(shutil.which('nft')).resolve())
    with tempfile.TemporaryDirectory(prefix='ouf-readback-margin-ci-', dir='/etc') as directory:
        root = Path(directory); root.chmod(0o700)
        owner, _ = fixture(root, source, nft)
        from nft_seconds_backend import NftBackend
        original = load_compiler(HERE / 'materialize_southbound_lease_refresh.py')
        candidate = load_compiler(HERE / 'readback_margin_compiler.py')
        cfg = owner['kernel']
        backend = NftBackend([nft], cfg, owner['expectedStructureHash'], 5)
        def observations(now, seconds):
            return [dict(endpointRef=f['endpointRef'], endpoint=f['endpoint'], resolutionEvidenceRef=f['resolutionEvidenceRef'],
                         addresses=['1.1.1.1' if i == 0 else '8.8.8.8'], observedMonotonic=now,
                         expiresMonotonic=now + seconds, historicalEvidenceOnly=False) for i, f in enumerate(cfg['providerFlows'])]
        now = time.monotonic(); values = observations(now, 2.9)
        old = original.compile_refresh(cfg, values, now, apply_budget_seconds=1)
        assert not old['denyOnly'] and old['nftTransaction'].count('timeout 1s') == 4
        backend.verify_ownership(cfg)
        backend.apply(old['nftTransaction'], old['mustApplyByMonotonic'])
        try:
            backend.read_sets(cfg)
        except RuntimeError as error:
            assert str(error) == 'NFT_SET_TTL_UNPROVEN'
            assert error.nft_readback['expiresType'] == 'int' and error.nft_readback['expiresValue'] == 0
            assert not error.nft_readback['duplicateAddress']
            print('CI_NATIVE_ONE_SECOND_ZERO=' + json.dumps(error.nft_readback), flush=True)
        else:
            raise AssertionError('NATIVE_ZERO_NOT_REPRODUCED')
        new = candidate.compile_refresh(cfg, values, now, apply_budget_seconds=1)
        assert new['denyOnly'] and 'add element' not in new['nftTransaction']
        backend.apply(new['nftTransaction'], time.monotonic() + 5)
        assert not any(backend.read_sets(cfg).values())
        now = time.monotonic(); values = observations(now, 3.9)
        new = candidate.compile_refresh(cfg, values, now, apply_budget_seconds=1)
        assert not new['denyOnly'] and new['nftTransaction'].count('timeout 2s') == 4
        backend.apply(new['nftTransaction'], new['mustApplyByMonotonic'])
        sets = backend.read_sets(cfg)
        assert len(sets) == 4 and all(sets.values())
        assert all(ttl == 1 for members in sets.values() for ttl in members.values())
        backend.apply(candidate.compile_refresh(cfg, [], time.monotonic(), apply_budget_seconds=1)['nftTransaction'], time.monotonic() + 5)
        assert not any(backend.read_sets(cfg).values())
        print('CI_READBACK_MARGIN=ONE_SECOND_DENIED_TWO_SECONDS_POSITIVE_REVOCATION_PASS NOT_PRODUCTION_AUTHORITY=true', flush=True)

if __name__ == '__main__': main()
