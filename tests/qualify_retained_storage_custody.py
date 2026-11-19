"""Run a 34-source, 14-rootfs isolated custody fixture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import time


def put(path, data):
    path.write_bytes(data)


def qualifies(root, h, tool, local):
    old = root / 'old'
    capture = old / 'capture'
    payload = capture / 'payload'
    payload.mkdir(parents=True)
    source_dir = root / 'sources'
    source_dir.mkdir()
    sources = [source_dir / ('item-%03d' % i) for i in range(34)]
    for i, source in enumerate(sources):
        put(source, ('fixture %d' % i).encode())
        with tarfile.open(payload / ('source-%03d.tar' % i), 'w') as tar:
            tar.add(source, arcname=source.name)
    deadline = time.monotonic() + 120
    manifests = {str(p): h['tree_manifest'](p, deadline) for p in sources}
    roles = h['ROLES'] | {'etcd'}
    for role in roles:
        with tarfile.open(payload / (role + '.rootfs.tar'), 'w') as tar:
            tar.add(sources[0], arcname='fixture')
    with tarfile.open(payload / 'images.tar', 'w') as tar:
        tar.add(sources[0], arcname='fixture')
    expiry = int(time.time()) + 7200
    plan = h['canonical']({'roles': dict.fromkeys(roles, {}),
        'sources': [str(p) for p in sources], 'validUntilEpoch': expiry,
        'programSha256': '583a5e26ab18bfdb09d868fb3d7fabd9acf347f64dbf01b8caf0bf8cbec80184'})
    plan_sha = h['digest'](plan)
    decision = tool['DECISION']
    old_decision = tool['OLD_DECISION']
    claim = h['canonical']({'schema': 'ouf.storage-capture-after-held-stop-claim.v1',
        'decisionReference': old_decision, 'planSha256': plan_sha, 'attempts': 1,
        'captureSeconds': 3600, 'priorCumulativeStopCommandCalls': 184,
        'legacyValidUntilEpoch': expiry,
        'originalPlanSha256': 'f4cc75450360a1a30a7210b5ee8e492bc99c6737d98131537b87b65fa284cc3d',
        'retainedJournalDigest': '5f3416a62555adf1d6b4dc00370bd72cf33c0844bb7d671aaae05c08f4bc741f'})
    if local:
        # The local sandbox has no procfs or age. Exercise the real tar verifier and stream
        # against the same fixtures, with pass-through restricted to the test.
        verify = h['verify_source_archive']
        h['verify_source_archive'] = lambda _fd, name, rows, until: verify(
            payload / ('source-' + name.split('-')[1] + '.tar'), name, rows, until)
        recipient, argv = 'local-custody-fixture', ['/usr/bin/cat']
    else:
        key = root / 'identity'
        subprocess.run(['/usr/bin/age-keygen', '-o', str(key)], check=True, stderr=subprocess.DEVNULL)
        recipient = subprocess.check_output(['/usr/bin/age-keygen', '-y', str(key)], text=True).strip()
        argv = ['/usr/bin/age', '-r', recipient]
    recipient_sha = h['digest'](recipient.encode())
    put(old / 'claim.private.json', claim)
    aged = time.time() - 3700
    os.utime(old / 'claim.private.json', (aged, aged))
    put(capture / 'capture-claim.private.json', h['canonical']({
        'decisionReference': old_decision, 'planSha256': plan_sha, 'attempts': 1,
        'recipientSha256': recipient_sha}))
    put(old / 'plan.private.json', plan)
    put(payload / 'plan.private.json', plan)
    for name in ('containers.private.json', 'networks.private.json'):
        put(payload / name, b'{}\n')
    put(payload / 'source-manifests.private.json', h['canonical'](manifests))
    for ordinal in range(1, 57):
        put(capture / ('command-%03d.stderr.private' % ordinal), b'')
    put(capture / 'command-056.private', b'{}\n')
    tool.update(OLD=old, NEW=root / 'new', EXPIRY=expiry, OUTPUT_LIMIT=128 << 20,
                EXPECTED_TAR_BYTES=(
                    sum(p.stat().st_size for p in payload.glob('source-*.tar')),
                    sum(p.stat().st_size for p in payload.glob('*.rootfs.tar')),
                    (payload / 'images.tar').stat().st_size))
    execute = tool['execute']

    def rejects(args, ref, expected):
        try:
            execute(h, args, recipient_sha, ref, deadline)
        except Exception as error:
            assert type(error).__name__ == 'Held' and str(error) == expected, str(error)
        else:
            raise AssertionError(expected)

    rejects(argv, old_decision, 'EXACT_HISTORICAL_CUSTODY_DECISION_REQUIRED')
    tar = payload / 'source-000.tar'
    good = tar.read_bytes()
    bad = bytearray(good)
    offset = good.index(b'fixture 0')
    bad[offset] ^= 1
    put(tar, bad)
    rejects(argv, decision, 'ARCHIVE_CONTENT_MISMATCH')
    assert not tool['NEW'].exists()
    put(tar, good)
    before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in payload.iterdir()}
    result = execute(h, argv, recipient_sha, decision, deadline)
    archive = Path(result['archive'])
    assert result['archiveSha256'] == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert result['sourceArchivesVerified'] == 34 and result['retainedPayloadMembersHashed'] == 53
    assert not result['captureEventCoverageProven'] and not result['restorePerformed']
    assert set(p.name for p in archive.parent.iterdir()) == {
        'claim.private.json', 'retained-historical.tar.age', 'result.json'}
    clear = archive
    if not local:
        clear = root / 'fixture-decrypted.tar'
        subprocess.run(['/usr/bin/age', '-d', '-i', str(key), '-o', str(clear), str(archive)], check=True)
    with tarfile.open(clear) as bundle:
        manifest = json.load(bundle.extractfile('evidence/custody-manifest.private.json'))
        assert len(manifest['members']) == 53 and manifest['historicalCustodyOnly']
        for name, meta in manifest['members'].items():
            raw = bundle.extractfile('payload/' + name).read()
            assert meta == {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    rejects(argv, decision, 'HISTORICAL_CUSTODY_SCOPE_ALREADY_CLAIMED')
    assert before == {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in payload.iterdir()}
    tool['NEW'] = root / 'failed'
    try:
        execute(h, ['/usr/bin/false'], recipient_sha, decision, deadline)
    except (tool['Held'], BrokenPipeError):
        assert (tool['NEW'] / 'claim.private.json').is_file()
        assert (tool['NEW'] / 'retained-historical.tar.age.partial').is_file()
        assert not (tool['NEW'] / 'result.json').exists()
    else:
        raise AssertionError('failed cipher accepted')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--local-pass-through-fixture', action='store_true')
    local = parser.parse_args().local_pass_through_fixture
    assert os.geteuid() == 0 and (local or os.environ.get('GITHUB_ACTIONS') == 'true')
    os.umask(0o077)
    scripts = Path(__file__).resolve().parents[1] / 'scripts'
    h, tool = {'__name__': 'fixture_producer'}, {'__name__': 'fixture_custody'}
    for name, namespace in [('storage-cold-backup.py', h), ('seal-retained-storage-capture-20261107.py', tool)]:
        path = scripts / name
        exec(compile(path.read_bytes(), str(path), 'exec'), namespace)
    with tempfile.TemporaryDirectory(dir=Path.cwd() if local else '/var/lib',
                                     prefix='ouf-custody-fixture-') as directory:
        qualifies(Path(directory), h, tool, local)
    print('PASS 34-source custody, corruption, cipher failure, replay and member digests; ' +
          ('local pass-through' if local else 'native age decrypt'))
