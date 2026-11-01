#!/usr/bin/env python3
"""Independently reread the preserved CI evidence, without image or target access."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ZIP = 'evidence/artifacts/m2-semantic-high-remediation-41351198866.zip'
ZIP_SHA = '4fed16f6a98975dbe02e03a8814b47fea7da76bf3e2abadcb583acaa3d4850eb'
MEMBERS = {'SHA256SUMS', 'origin-facts.json', 'empty.trivyignore', 'provenance.json',
           'remediation-result.json', 'trivy-image.json'}


def preserve(output):
    raw = (ROOT/ZIP).read_bytes()
    if len(raw) != 100936 or hashlib.sha256(raw).hexdigest() != ZIP_SHA or output.exists():
        raise ValueError('EXACT_CI_ZIP_AND_NEW_OUTPUT_REQUIRED')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        if (len(entries) != len(MEMBERS) or {r.filename for r in entries} != MEMBERS
                or any(stat.S_IFMT(r.external_attr >> 16) not in (0, stat.S_IFREG) for r in entries)
                or sum(r.file_size for r in entries) > 2097152):
            raise ValueError('EXACT_BOUNDED_REGULAR_EVIDENCE_MEMBERS_REQUIRED')
        contents = {name: archive.read(name) for name in MEMBERS}
    sums = contents['SHA256SUMS'].decode().splitlines()
    checksums = dict(row.split('  ', 1)[::-1] for row in sums)
    if len(sums) != len(checksums) or set(checksums) != MEMBERS-{'SHA256SUMS', 'provenance.json'}:
        raise ValueError('EXACT_SIGNED_CHECKSUM_CLOSURE_REQUIRED')
    for name, checksum in checksums.items():
        if hashlib.sha256(contents[name]).hexdigest() != checksum:
            raise ValueError('SIGNED_EVIDENCE_MEMBER_CHANGED')
    if contents['empty.trivyignore']:
        raise ValueError('EMPTY_IGNORE_FILE_REQUIRED')
    envelope = json.loads(contents['provenance.json'])['dsseEnvelope']
    import base64
    statement = json.loads(base64.b64decode(envelope['payload'], validate=True))
    if (statement['subject'] != [{'name': 'SHA256SUMS', 'digest': {'sha256': hashlib.sha256(contents['SHA256SUMS']).hexdigest()}}]
            or statement['predicateType'] != 'https://slsa.dev/provenance/v1'):
        raise ValueError('EXACT_CHECKSUM_ATTESTATION_SUBJECT_REQUIRED')
    # This subject comparison is not signature/chain verification. The separate
    # hosted gh attestation verifier enforces workflow/ref/source and trust.
    output.mkdir(mode=0o700)
    for name, content in contents.items():
        (output/name).write_bytes(content)
    spec = importlib.util.spec_from_file_location('remediation_gate', ROOT/'scripts/check-m2-semantic-high-remediation-20261101.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    expected = contents['remediation-result.json']
    module.check(output)
    if (output/'remediation-result.json').read_bytes() != expected:
        raise ValueError('INDEPENDENT_REMEDIATION_RESULT_DIFFERS')
    print(json.dumps({'zipSha256': ZIP_SHA, 'zipBytes': len(raw), 'membersRead': len(MEMBERS),
                      'signedMembersMatched': len(checksums), 'signatureChainVerifiedByThisReader': False,
                      'targetOperations': 0}, sort_keys=True))


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise ValueError('ONE_NEW_EVIDENCE_OUTPUT_REQUIRED')
    preserve(Path(sys.argv[1]))
