#!/usr/bin/env python3
"""Compare the two original data mounts with the sealed historical evidence."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.request import urlopen

SCHEMA = 'ouf.storage-retained-source-comparison.v1'
RAW = 'https://raw.githubusercontent.com/GioNob/ouf-deploy/'
G0 = Path('/var/lib/ouf-g0-network-preparation-20261106/evidence/seaweedfs-g0-20261106-v2')
G0_JOIN = '5c0bc6d7351008da9dd53af5489dcf0167c280fe73e99db52de3e9f8c2e5db6a'
BODY_SHA = 'c54d67b9ec8448e884a296c37e588845e3d128283af14e92c29b9bb3e3a8281f'
ROLES = ('postgres', 'minio')


def load(ref, name, size, sha):
    with urlopen(RAW + ref + '/scripts/' + name, timeout=20) as response:
        raw = response.read(size + 1)
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != sha:
        raise ValueError('DEPENDENCY_DIGEST')
    namespace = {'__name__': 'readback_dependency'}
    exec(compile(raw, name, 'exec'), namespace)
    return namespace


def object_index(rows, size_field):
    index = {(row['bucket'], row['key']): (row[size_field], row['sha256']) for row in rows}
    if (len(index) != len(rows) or len(index) != 120
            or any(row['versionId'] not in (None, '', 'null') for row in rows)):
        raise ValueError('OBJECT_PROFILE_MISMATCH')
    return index


def compare(report):
    pg = load('5ae47689adeaf39f241527c9364a2c0c9e9b0b9b', 'restore-retained-postgres.py', 19046,
              '3ff2281f380dcab555d22966f78622a4f4bd00798e5e623e5db8fb95dee2513d')
    mi = load('fc15882c6f4a8786a49efd88e09c9f3bd8e2f7c5', 'restore-retained-minio.py', 21823,
              'c363c38e6a1a9b5768e40ae0c21ba7aef9b74a06a85914b890a6a84afb15bb93')
    h = pg['load_producer']()
    need, digest, canonical = h['need'], h['digest'], h['canonical']

    def read(path, sha=None):
        raw = h['protected'](path, private=True)
        need(sha is None or digest(raw) == sha, 'PRIVATE_INPUT_DIGEST')
        return h['decode'](raw)

    old = pg['ROOT'] / 'historical-minio-restore-20261107-v1'
    members = read(old / 'verified-members.private.json')
    evidence = {'custody-claim.private.json': pg['SEALED'] / 'claim.private.json',
                'original-claim.private.json': pg['OLD'] / 'claim.private.json',
                'original-producer-claim.private.json': pg['OLD'] / 'capture/capture-claim.private.json'}
    manifest = {'schema': 'ouf.storage-retained-capture-custody.v1', 'members': members,
                'evidenceSha256': {name: digest(h['protected'](path, private=True, limit=8192))
                                   for name, path in evidence.items()},
                'captureEventCoverageProven': False, 'liveSourceContinuityProven': False,
                'historicalCustodyOnly': True, 'restorePerformed': False}
    need(len(members) == 53 and digest(canonical(manifest)) == pg['MANIFEST_SHA'], 'CUSTODY_BINDING')
    payload = pg['PAYLOAD']
    plan = read(payload / 'plan.private.json', members['plan.private.json']['sha256'])
    configs = read(payload / 'containers.private.json', members['containers.private.json']['sha256'])
    manifests = read(payload / 'source-manifests.private.json',
                     members['source-manifests.private.json']['sha256'])
    sources = [pg['source_binding'](h, plan, members), mi['minio_source'](h, pg, plan, members)]
    ids = [plan['roles'][role]['containerId'] for role in ROLES]
    report['custodyManifestVerified'] = True

    joined = read(G0 / 'reconciliation.json', G0_JOIN)
    collection = read(G0 / (G0.name + '-s3') / 'collection.private.json')
    need(collection['complete'] is True and joined['exportRows'] == 353
         and digest(canonical(collection)) == joined['bodyCollectionSha256'], 'G0_BINDING')
    historical = read(old / 's3-proof-v2/s3-bodies.private.json', BODY_SHA)
    need(all(row['isLatest'] is True and row['deleteMarker'] is False for row in historical),
         'HISTORICAL_OBJECT_PROFILE')
    a, b = object_index(collection['objects'], 'bytes'), object_index(historical, 'size')
    report['g0ObjectsMatched'] = sum(key in a and a[key] == value for key, value in b.items())
    report['g0ObjectSetsMatch'] = a == b

    def docker(*args):
        report['dockerReadCommands'] += 1
        result = subprocess.run(['/usr/bin/docker', '-H', 'unix:///var/run/docker.sock', *args],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=15, env={'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'LANG': 'C'})
        need(result.returncode == 0 and len(result.stdout) <= 4 << 20, 'DOCKER_READ_FAILED')
        return result.stdout

    def check_stopped():
        running = docker('ps', '-q')
        report['runningContainersObserved'] = len(running.splitlines())
        need(not running.strip(), 'CONTAINERS_RUNNING')
        rows = h['decode'](docker('container', 'inspect', *ids))
        need(len(rows) == 2 and {row['Id'] for row in rows} == set(ids), 'CONTAINER_SET_CHANGED')
        for row in rows:
            prior = configs[row['Id']]
            state = row['State']
            need(state['Status'] == 'exited' and state['Pid'] == 0 and state['ExitCode'] == 0
                 and not any(state.get(key) for key in ('Running', 'Paused', 'Restarting', 'OOMKilled', 'Error'))
                 and row['HostConfig']['RestartPolicy']['Name'] == 'no', 'SOURCE_STOP_STATE_CHANGED')
            need(row['Image'] == prior['Image'] and row['Mounts'] == prior['Mounts']
                 and all(state[key] == prior['State'][key] for key in ('StartedAt', 'FinishedAt')),
                 'SOURCE_CONTAINER_BINDING_CHANGED')

    check_stopped()
    until = time.monotonic() + 300
    for role, (_, _, source, _) in zip(ROLES, sources):
        previous = manifests[str(source)]
        need(0 < len(previous) <= 100000 and sum(row['size'] for row in previous) <= 1 << 30,
             'SOURCE_SCAN_BUDGET')
        current = h['tree_manifest'](str(source), until)
        before, after = ({row['path']: row for row in rows} for rows in (previous, current))
        report['sources'][role] = {'historicalEntries': len(before), 'currentEntries': len(after),
                                   'differingEntries': sum(before.get(key) != after.get(key)
                                                           for key in before.keys() | after.keys())}
    check_stopped()
    report['stoppedSourceBindingsVerified'] = True
    report['status'] = ('RETAINED_SOURCE_COMPARISON_MATCH'
                        if report['g0ObjectSetsMatch'] and
                        all(x['differingEntries'] == 0 for x in report['sources'].values())
                        else 'RETAINED_SOURCE_COMPARISON_DIVERGENCE')


def main():
    report = {'schema': SCHEMA, 'status': 'HELD', 'sources': {}, 'dockerReadCommands': 0,
              'captureEventCoverageProven': False, 'commonCutProven': False, 'acceptanceCreditAdded': 0}
    try:
        if os.geteuid() != 0 or not sys.flags.isolated or not sys.flags.no_site or not sys.dont_write_bytecode:
            raise ValueError('ISOLATED_ROOT_REQUIRED')
        compare(report)
    except Exception as exc:
        code = str(exc)
        report['reason'] = code if re.fullmatch(r'[A-Z][A-Z0-9_]{5,70}', code) else 'LOCAL_READ_FAILED'
    print(json.dumps(report, sort_keys=True))
    return int(report['status'] != 'RETAINED_SOURCE_COMPARISON_MATCH')


if __name__ == '__main__':
    raise SystemExit(main())
