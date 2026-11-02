#!/usr/bin/env python3
"""Evaluate only the accepted exact-binary disposition from public frozen evidence.

No executable, S3, Docker, database or credential access. CI authenticates the
original publisher before this script; local mode reads the immutable readback.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('accepted_applicability', ROOT / 'tools/storage_security/accepted_applicability.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--current-advisory', type=Path)
    args = parser.parse_args()
    archive = ROOT / 'evidence/artifacts/storage-copy-readback-41507064288.zip'
    raw = archive.read_bytes()
    assert len(raw) == 84954 and hashlib.sha256(raw).hexdigest() == '00a3559a38bcf84f122863e2aaa0e31122452603462735c3f16ea126a10fab4f', 'EXACT_RETAINED_READBACK_REQUIRED'
    with zipfile.ZipFile(archive) as z:
        names = z.namelist()
        assert len(names) == len(set(names)) and all('/' not in n and '\\' not in n for n in names), 'FLAT_UNIQUE_MEMBERS_REQUIRED'
        assert sum(n.file_size for n in z.infolist()) < 4 * 1024 * 1024, 'BOUNDED_METADATA_REQUIRED'
        data = {n: z.read(n) for n in names}
    for line in data['SHA256SUMS'].decode().splitlines():
        sha, name = line.split('  ', 1)
        if name != 'storage-copy-lab.test':
            assert hashlib.sha256(data[name]).hexdigest() == sha, 'ORIGINAL_MEMBER_CHANGED:' + name
    decision = json.loads((ROOT / 'evidence/seaweedfs-g1-applicability-owner-decision-20261102.json').read_text())
    advisory = json.loads((args.current_advisory if args.current_advisory else ROOT / decision['advisory']['canonicalSnapshotPath']).read_text())
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        assert args.current_advisory, 'FRESH_OFFICIAL_ADVISORY_REQUIRED_IN_CI'
    result = module.assess(decision, advisory, json.loads(data['candidate.json']), data['compiled-packages.json'], json.loads(data['trivy-binary.json']), json.loads((ROOT / 'evidence/seaweedfs-g1-openvex-20261102.json').read_text()))
    result.update(evidenceArchiveSha256=hashlib.sha256(raw).hexdigest(),
                  advisoryFreshlyFetchedByCi=bool(args.current_advisory and os.environ.get('GITHUB_ACTIONS') == 'true'),
                  provenanceBasis='FROZEN_INDEPENDENT_READBACK_41507064288_OF_EXACT_PRODUCER_41504703184',
                  newSignatureVerificationPerformedByThisScript=False,
                  originalProposalUnchanged=hashlib.sha256((ROOT / decision['acceptedProposal']['path']).read_bytes()).hexdigest() == decision['acceptedProposal']['sha256'],
                  targetOperations=0)
    assert result['originalProposalUnchanged'], 'ORIGINAL_REVIEWED_PROPOSAL_MUST_REMAIN_UNCHANGED'
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'ACCEPTED_APPLICABILITY_ONLY' else 1


if __name__ == '__main__':
    raise SystemExit(main())
