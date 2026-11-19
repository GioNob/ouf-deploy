#!/usr/bin/env python3
"""v3 capture with order-independent Docker mount identity; no plan renewal.

The exact v3 source is retained and pinned. Only Mounts array ordering is
normalized; every field, duplicate, process generation and source stays bound.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

LEGACY = Path('/var/lib/ouf-storage-cold-backup-v3.py')
LEGACY_SHA = 'b23a822d0fd7000ac8806d47ff66c0ab053f0fa60ce33998268af792b9db53ac'
LEGACY_AREA = Path('/var/lib/ouf-storage-migration/cold-backup-20261106-v3')
AREA = Path('/var/lib/ouf-storage-migration/cold-backup-20261106-v4')


def load_legacy():
    for p in (LEGACY.parent, *LEGACY.parent.parents):
        s = p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid or s.st_mode & 0o022:
            raise ValueError('PROTECTED_LEGACY_ANCESTRY')
    fd = os.open(LEGACY, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        s = os.fstat(f.fileno())
        if not (stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1 and
                stat.S_IMODE(s.st_mode) == 0o600 and s.st_size == 32524):
            raise ValueError('PROTECTED_LEGACY_PROGRAM')
        return f.read(32525)


def definitions(raw):
    if hashlib.sha256(raw).hexdigest() != LEGACY_SHA:
        raise ValueError('LEGACY_PROGRAM_DIGEST')
    h = {'__name__': 'cold_v4_definitions', '__file__': __file__}
    exec(compile(raw, str(LEGACY), 'exec'), h)
    old_fingerprint, old_shared = h['fingerprint'], h['shared_outside_bindings']

    def normalized(doc):
        return dict(doc, Mounts=sorted(doc['Mounts'], key=h['canonical']))

    def mounts_equal(left, right):
        return sorted(map(h['canonical'], left)) == sorted(map(h['canonical'], right))

    def fingerprint(doc):
        return old_fingerprint(normalized(doc))

    def shared(host, selected_ids, roots):
        return old_shared({cid: normalized(doc) for cid, doc in host.items()}, selected_ids, roots)

    def derive(legacy_plan, retained_host, wrapper_sha):
        need = h['need']
        need(legacy_plan['programSha256'] == LEGACY_SHA, 'LEGACY_PLAN_PROGRAM')
        ids = {r['containerId'] for r in legacy_plan['roles'].values()}
        for row in legacy_plan['roles'].values():
            need(old_fingerprint(retained_host[row['containerId']]) == row['fingerprint'], 'LEGACY_ROLE_BINDING')
        need(old_shared(retained_host, ids, legacy_plan['sources']) == legacy_plan['stoppedSharingContainers'],
             'LEGACY_SHARED_BINDING')
        result = copy.deepcopy(legacy_plan)
        for row in result['roles'].values():
            row['fingerprint'] = fingerprint(retained_host[row['containerId']])
        result['stoppedSharingContainers'] = shared(retained_host, ids, result['sources'])
        result['programSha256'] = wrapper_sha
        result['mountIdentityCorrection'] = {
            'derivedFromPlanSha256': h['digest'](h['canonical'](legacy_plan)),
            'legacyProgramSha256': LEGACY_SHA, 'change': 'MOUNTS_ARRAY_ORDER_ONLY',
            'expiryRenewed': False, 'attemptsReset': False}
        return result

    h.update(fingerprint=fingerprint, shared_outside_bindings=shared,
             mounts_equal=mounts_equal, derive_legacy_plan=derive, AREA=AREA)
    return h


def main():
    # Never expose v3 prepare: deriving an existing plan must not renew its TTL.
    if len(sys.argv) < 2 or sys.argv[1] != 'capture':
        raise ValueError('CAPTURE_ONLY_NO_AUTOMATIC_PLAN_RENEWAL')
    h = definitions(load_legacy())
    h['need'](not os.path.lexists(LEGACY_AREA / 'capture'), 'LEGACY_CAPTURE_ALREADY_ATTEMPTED')
    h['main']()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        reason = str(error) if type(error).__name__ in ('Held', 'ValueError') else type(error).__name__
        print(json.dumps({'status': 'HELD', 'reason': reason, 'automaticReplayAllowed': False,
            'automaticRestartAllowed': False, 'runtimeAuthorityIssued': False, 'acceptanceCreditAdded': 0}))
        sys.exit(2)
