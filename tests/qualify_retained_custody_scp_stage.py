"""Exercise the private staging boundary with a synthetic sealed archive."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import tempfile


def qualify(root, tool, uid, gid, native):
    source = root / 'sealed'
    source.mkdir()
    name = tool['NAME']
    archive = source / name
    contents = b'historical custody fixture' * 1000
    archive.write_bytes(contents)
    size = len(contents)
    digest = hashlib.sha256(contents).hexdigest()
    manifest = 'a' * 64
    (source / 'result.json').write_text(json.dumps({
        'schema': 'ouf.storage-retained-capture-custody.v1',
        'status': 'HISTORICAL_CUSTODY_ARCHIVE_SEALED', 'archive': str(archive),
        'archiveBytes': size, 'archiveSha256': digest, 'privateManifestSha256': manifest,
    }))
    ownership = []
    if not native:
        class RecordedOwnership:
            def __getattr__(self, name):
                return getattr(os, name)

            def fchown(self, fd, owner, group):
                ownership.append((stat.S_ISDIR(os.fstat(fd).st_mode), owner, group))

        tool['os'] = RecordedOwnership()
    shared = root / 'sticky'
    shared.mkdir()
    shared.chmod(0o1777)
    target = shared / 'transfer'

    def run(path=target, sha=digest):
        return tool['stage'](source, path, uid, gid, size, sha, manifest)

    def held(action, reason):
        try:
            action()
        except tool['Held'] as error:
            assert str(error) == reason
        else:
            raise AssertionError(reason)

    before = tool['frame'](archive.stat())
    result = run()
    staged = target / name
    assert result['status'] == 'SCP_SOURCE_STAGED' and staged.read_bytes() == contents
    assert stat.S_IMODE(target.stat().st_mode) == 0o700
    assert stat.S_IMODE(staged.stat().st_mode) == 0o400
    assert tool['frame'](archive.stat()) == before
    if native:
        assert target.stat().st_uid == staged.stat().st_uid == uid
    else:
        assert ownership == [(False, uid, gid), (True, uid, gid)]
    held(run, 'TRANSFER_SCOPE_ALREADY_EXISTS')
    held(lambda: run(shared / 'wrong-receipt', 'b' * 64), 'SEALED_RECEIPT_MISMATCH')
    assert not (shared / 'wrong-receipt').exists()
    archive.write_bytes(b'x' + contents[1:])
    partial = shared / 'partial'
    held(lambda: run(partial), 'SOURCE_DIGEST_MISMATCH')
    assert partial.stat().st_uid == 0 and not (partial / name).exists()
    assert (partial / (name + '.partial')).is_file()
    archive.unlink()
    archive.symlink_to(staged)
    try:
        run(shared / 'symlink')
    except OSError:
        pass
    else:
        raise AssertionError('accepted symlink')
    assert not (shared / 'symlink').exists()


if __name__ == '__main__':
    native = os.environ.get('GITHUB_ACTIONS') == 'true'
    account = pwd.getpwnam('nobody') if native else None
    uid, gid = (account.pw_uid, account.pw_gid) if account else (65534, 65534)
    os.umask(0o077)
    script = Path(__file__).resolve().parents[1] / 'scripts/stage-retained-custody-windows-20261107.py'
    tool = {'__name__': 'fixture_stage'}
    exec(compile(script.read_bytes(), str(script), 'exec'), tool)
    with tempfile.TemporaryDirectory(dir='/var/lib' if native else Path.cwd()) as temp:
        qualify(Path(temp), tool, uid, gid, native)
    print('PASS 5 private stage cases; ' + ('native ownership' if native else 'recorded ownership'))
