"""Execute both real package producers with explicit disposable Docker/Git IO.

The records and delivery manifests come from production producer functions.
Only the external build/export/scan tooling and source revision are modeled.
No Docker, compiler, network or executable payload runs in this fixture.
"""
import importlib.util, json, sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT/'scripts'/filename)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def produce(source, output, module, image, archive_bytes, payload, lock_path):
    builder = load('fixture_image_producer', 'package-file-loop-candidate.py')
    delivery = load('fixture_delivery_producer', 'package-semantic-proposal-candidate.py')
    commit = image['sourceCommit']; source.mkdir(mode=0o700)
    (source/'Dockerfile').write_text('FROM scratch\n')

    def inspect(*args):
        if args[:4] == ('git', '-C', str(source), 'rev-parse'): return commit
        if args[:4] == ('git', '-C', str(source), 'status'): return ''
        if args[:3] == ('docker', 'image', 'inspect'):
            if '--format' in args: return image['imageId']
            return json.dumps([{'Id': image['imageId'], 'Config': image['imageConfig']}])
        if args[:2] == ('docker', 'create'): return 'disposable-container'
        raise AssertionError(('UNMODELED_BUILD_COMMAND', args))

    def external(args, **kwargs):
        if args[:2] == ['docker', 'save']: Path(args[3]).write_bytes(archive_bytes)
        elif args[:2] == ['docker', 'cp']: Path(args[-1]).write_bytes(payload)
        elif args[:2] not in (['docker', 'build'], ['docker', 'rm']):
            if args[:4] != ['git', '-C', str(source), 'archive']:
                raise AssertionError(('UNMODELED_EXPORT_COMMAND', args))
            Path(args[args.index('-o')+1]).write_bytes(b'disposable source archive; replaced with migration fixture')

    def phase(value):
        argv = ['package-file-loop-candidate.py', value, '--source', str(source), '--output', str(output),
            '--module', module, '--commit', commit]
        with patch.object(sys, 'argv', argv), patch.object(builder, 'run', inspect), \
                patch.object(builder, 'subprocess', SimpleNamespace(run=external, check_output=lambda args: b'')):
            builder.main()

    phase('build')
    scan = {'SchemaVersion': 2, 'Metadata': {'ImageID': image['imageId']}, 'Results': [
        {'Class': 'os-pkgs', 'Type': 'fixture'},
        {'Class': 'lang-pkgs', 'Type': 'gobinary' if module == 'mcp' else 'jar', 'Packages': [{'Name': module}]}]}
    (output/'trivy-image.json').write_text(json.dumps(scan))

    def delivery_tool(args, **kwargs):
        if args[:3] == ['git', 'rev-parse', 'HEAD']: return commit.encode()
        if args[:3] == ['git', 'status', '--porcelain']: return b''
        if args[:3] == ['git', 'ls-tree', '-rz']: return b''
        if args[0] == 'python3' and args[2] == 'export': phase('export'); return b''
        if args[:3] == ['go', 'version', '-m']:
            return b'go1.26.9 GOOS=linux GOARCH=amd64 CGO_ENABLED=0'
        raise AssertionError(('UNMODELED_DELIVERY_COMMAND', args))

    with patch.object(delivery, 'run', delivery_tool), patch.object(delivery, 'LOCK_PATH', lock_path), \
            patch.dict(delivery.SOURCES, {module: ('fixture-'+module, commit)}):
        manifest = delivery.export(source, output, module)
    for path in output.rglob('*'):
        if path.is_file(): path.chmod(0o600)
    return manifest
