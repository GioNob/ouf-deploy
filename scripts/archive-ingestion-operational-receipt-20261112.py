#!/usr/bin/env python3
"""Archive the fixed candidate and reviewed deploy bundle; run only in build CI."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import zipfile

SOURCE = '01756a5a22ddc88beba270b7645a64440b1e5a7b'


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1048576), b''):
            h.update(chunk)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--image-tag', required=True)
    args = parser.parse_args()
    root, out = args.source_dir, args.output_dir
    assert command('git', '-C', str(root), 'rev-parse', 'HEAD') == SOURCE
    out.mkdir()
    image = json.loads(command('docker', 'image', 'inspect', args.image_tag))[0]
    assert image['Config']['Labels']['org.opencontainers.image.revision'] == SOURCE
    assert image['Config']['User'] == '10002:10002'
    assert image['Config']['Entrypoint'] == ['java', '-jar', '/app/app.jar']
    jar = root / 'target/candidate.jar'
    historical = json.loads(Path('scripts/ingestion-wide-source-resources-20261108.json').read_text())
    with zipfile.ZipFile(jar) as z:
        migrations = {Path(n).name: hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist()
                      if n.startswith('BOOT-INF/classes/db/migration/') and n.endswith('.sql')}
        assert migrations == {row['name']: row['sha256'] for row in historical['migrations']}
        for row in historical['migrations']:
            assert sha(root / 'src/main/resources/db/migration' / row['name']) == row['sha256']
        assert any(n.endswith('/SummaryIdentityConfiguration.class') for n in z.namelist())
        assert any(n.endswith('/receipt/SummaryReceiptFilter.class') for n in z.namelist())
    archive = out / 'image.tar.gz'
    # Same docker-save + timestamp-free gzip mechanism as the 20261108 archive.
    with archive.open('wb') as raw:
        with gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0) as compressed:
            save = subprocess.Popen(['docker', 'save', args.image_tag], stdout=subprocess.PIPE)
            try:
                shutil.copyfileobj(save.stdout, compressed)
            finally:
                save.stdout.close()
            assert save.wait() == 0
    image_ids = {image['Id']}
    with tarfile.open(archive, 'r:gz') as saved:
        names = saved.getnames()
        # Record OCI image-manifest identities as well as classic config IDs.
        # Docker stores can expose different IDs for the same saved bytes.
        if 'index.json' in names:
            def visit(descriptor):
                digest = descriptor['digest']
                member = 'blobs/sha256/' + digest.split(':')[1]
                raw = saved.extractfile(member).read()
                assert hashlib.sha256(raw).hexdigest() == digest.split(':')[1]
                node = json.loads(raw)
                if 'manifests' in node:
                    for child in node['manifests']:
                        visit(child)
                elif 'config' in node:
                    config_id = node['config']['digest']
                    config_raw = saved.extractfile('blobs/sha256/' + config_id.split(':')[1]).read()
                    assert hashlib.sha256(config_raw).hexdigest() == config_id.split(':')[1]
                    config = json.loads(config_raw)
                    if (config.get('architecture') == image['Architecture'] and config.get('os') == image['Os'] and
                            ((config.get('config') or {}).get('Labels') or {}).get('org.opencontainers.image.revision') == SOURCE):
                        image_ids.add(digest)
                        image_ids.add(config_id)
            for descriptor in json.load(saved.extractfile('index.json'))['manifests']:
                visit(descriptor)
    files = {}
    for name in ('scripts/apply-ingestion-operational-receipt-20261112.py',
                 'scripts/install-ingestion-operational-receipt-public-archive-20261112.sh',
                 'scripts/launch-ingestion-operational-receipt-20261112.sh',
                 'tools/acquisition_read_native/retained_mac.py'):
        target = out / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(name, target)
        files[name] = sha(target)
    manifest = {'schema': 'ouf.ingestion-operational-receipt-archive.v1', 'sourceCommit': SOURCE,
                'sourceTree': command('git', '-C', str(root), 'rev-parse', 'HEAD^{tree}'),
                'deployCommit': command('git', 'rev-parse', 'HEAD'),
                'imageIds': sorted(image_ids), 'buildImageId': image['Id'],
                'archiveSha256': sha(archive), 'archiveBytes': archive.stat().st_size,
                'jarSha256': sha(jar), 'unchangedMigrationHashes': migrations, 'files': files,
                'buildInputs': {'dockerfileSha256': sha(root / 'Dockerfile'),
                                'lockedDockerfileSha256': sha(root / 'Dockerfile.receipt-locked'),
                                'baseImages': json.loads((root / 'target/base-images.json').read_text())},
                'targetAccessed': False, 'targetInstalled': False}
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    shutil.copyfile(root / 'Dockerfile.receipt-locked', out / 'Dockerfile.receipt-locked')
    (out / 'SHA256SUMS').write_text(''.join(sha(p) + '  ' + p.relative_to(out).as_posix() + '\n'
                                          for p in sorted(out.rglob('*')) if p.is_file()))
    print(json.dumps({'manifestSha256': sha(out / 'manifest.json'), 'imageIds': sorted(image_ids),
                      'archiveSha256': manifest['archiveSha256'], 'sourceCommit': SOURCE}))


if __name__ == '__main__':
    main()
