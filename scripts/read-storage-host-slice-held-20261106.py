#!/usr/bin/env python3
"""Read only the retained host attempt; no provider calls, credentials or writes."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

AREA = Path('/var/lib/ouf-storage-host-containment-20261106-v1')
DRAFT_SHA = 'c4d59b3894f59d6679f11d48dbec2a3d7f5cbba6c8aa89bbee78b63e86475d0a'
SERVICES = ('ouf-gateway-policy-token.service', 'ouf-ingestion-policy-token.service',
    'ouf-onboarding-identity-token.service', 'ouf-policy-token@onboarding.service',
    'ouf-policy-token@udp.service', 'ouf-registry-token-7cb59501000058b5dc5030ad.service')


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def protected(path):
    for parent in reversed(path.parents):
        s = parent.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022, 'PROTECTED_PARENT')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        s = os.fstat(stream.fileno())
        need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1 and
             stat.S_IMODE(s.st_mode) == 0o600 and 0 < s.st_size <= 2 << 20, 'PROTECTED_INPUT')
        raw = stream.read((2 << 20) + 1)
        need(len(raw) == s.st_size and os.fstat(stream.fileno()) == s, 'INPUT_CHANGED')
    return raw


def main():
    need(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode, 'ROOT_ISOLATED_REQUIRED')
    area_stat = AREA.lstat()
    need(stat.S_ISDIR(area_stat.st_mode) and area_stat.st_uid == 0 and stat.S_IMODE(area_stat.st_mode) == 0o700, 'PRIVATE_AREA')
    names = []
    with os.scandir(AREA) as entries:
        for entry in entries:
            names.append(entry.name)
            need(len(names) <= 600, 'JOURNAL_ENTRY_LIMIT')
    raws = {name: protected(AREA / name) for name in ('claim.private.json', 'reviewed-draft.private.json', 'command-001.private.json')}
    hashes = {name: hashlib.sha256(raw).hexdigest() for name, raw in raws.items()}
    claim = json.loads(raws['claim.private.json'])
    need(hashes['reviewed-draft.private.json'] == DRAFT_SHA and claim['draftSha256'] == DRAFT_SHA and
         claim['decisionReference'] == 'GIOVANNI-NONPROD-HOST-CONTAIN-20261106-01' and claim['attempts'] == 1, 'EXACT_ATTEMPT_BINDING')
    first = json.loads(raws['command-001.private.json'])
    need(first['binary'] == 'systemctl' and first['args'][:2] == ['show', '--all'] and first['returncode'] == 0, 'FIRST_SHOW_REQUIRED')
    rows = {}
    for block in first['stdout'].strip().split('\n\n'):
        row = {}
        for line in block.splitlines():
            key, sep, value = line.partition('=')
            need(bool(sep), 'PROPERTY_FORMAT')
            row.setdefault(key, []).append(value)
        need(len(row.get('Id', [])) == 1 and row['Id'][0] not in rows, 'UNIQUE_UNIT')
        rows[row['Id'][0]] = row
    observations = []
    for unit in SERVICES:
        row = rows[unit]
        need(len(row.get('Slice', [])) == len(row.get('ControlGroup', [])) == 1, 'SLICE_CARDINALITY')
        value = row['Slice'][0]
        valid = len(value) <= 255 and re.fullmatch(r'(?:[A-Za-z0-9_:.-]|\\x[0-9a-fA-F]{2})+\.slice', value) is not None
        observations.append({'unit': unit, 'controlGroupPresentAtAttempt': bool(row['ControlGroup'][0]),
            'slice': value if valid else None, 'sliceSha256': hashlib.sha256(value.encode()).hexdigest(),
            'legacyValidatorAccepted': re.fullmatch(r'[A-Za-z0-9_.-]+\.slice', value) is not None,
            'escapedSliceValidatorAccepted': valid})
    intent_count = sum(bool(re.fullmatch(r'(?:action-\d{3}|file-\d{2})\.intent\.json', name)) for name in names)
    reply_count = sum(bool(re.fullmatch(r'(?:action-\d{3}|file-\d{2})\.reply\.json', name)) for name in names)
    commands = sum(bool(re.fullmatch(r'command-\d{3}\.private\.json', name)) for name in names)
    unknown = sum(not (name in raws or re.fullmatch(r'command-\d{3}\.private\.json', name)) for name in names)
    print(json.dumps({'schema': 'ouf.storage-host-slice-held-readback.v1', 'status': 'RETAINED_HOST_JOURNAL_READ',
        'localInputSha256': hashes, 'serviceObservations': observations, 'commandReceipts': commands,
        'intentReceipts': intent_count, 'replyReceipts': reply_count, 'otherScopeEntries': unknown,
        'preMutationJournalConsistent': intent_count == reply_count == unknown == 0,
        'currentLiveStateProven': False, 'filesRead': 3, 'filesWritten': 0, 'providerRequests': 0,
        'credentialBodiesRead': 0, 'automaticReplayAllowed': False, 'automaticRestartAllowed': False,
        'runtimeAuthorityIssued': False, 'acceptanceCreditAdded': 0}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status': 'HELD', 'reason': str(error) if isinstance(error, ValueError) else type(error).__name__,
            'filesWritten': 0, 'providerRequests': 0, 'automaticReplayAllowed': False, 'runtimeAuthorityIssued': False}))
        sys.exit(2)
