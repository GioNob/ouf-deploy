"""Checks for secret-free read-only UDP diagnostics; does not contact Docker."""
import ast
import importlib.util
import json
from pathlib import Path

base = Path(__file__).resolve().parent
source = next(path for path in (
    base / 'read-current-udp-storage-20261107.py',
    base.parent / 'scripts/read-current-udp-storage-20261107.py') if path.exists())
raw = source.read_bytes()
spec = importlib.util.spec_from_file_location('udp_read', source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
secret = 'DO_NOT_EMIT_SECRET'
report = {
    'badEndpoint': module.safe_value('endpoint', 'https://user:' + secret + '@storage:9002/path?token=' + secret),
    'goodEndpoint': module.safe_value('endpoint', 'https://ouf-seaweedfs-stage:9002'),
    'arguments': module.arguments(['java', '-jar', '/app/application.jar',
        '--ouf.udp.lake.s3.bucket=ouf-udp-lake', '--ouf.udp.lake.s3.path-style', 'true',
        '-Douf.udp.lake.s3.endpoint=https://user:' + secret + '@storage:9002']),
    'environment': module.selected_environment({'OUF_UDP_S3_BUCKET': 'ouf-udp-lake',
        'AWS_SECRET_ACCESS_KEY': secret, 'OUF_UDP_S3_ENDPOINT': 'http://ouf-minio:9000'}, 'OUF_UDP_S3_')}
assert secret not in json.dumps(report)
assert report['goodEndpoint']['host'] == 'ouf-seaweedfs-stage'
assert report['arguments'][1]['value'] == 'true'
assert report['environment']['bucket'] == 'ouf-udp-lake'
assert report['badEndpoint'] == {'validEndpointWithoutCredentialsOrExtraParts': False}
assert module.safe_value('endpoint', 'https://host:bad') == {'validEndpointWithoutCredentialsOrExtraParts': False}
tree = ast.parse(raw)
verbs = [node.args[0].value for node in ast.walk(tree) if isinstance(node, ast.Call)
         and isinstance(node.func, ast.Name) and node.func.id == 'docker'
         and node.args and isinstance(node.args[0], ast.Constant)]
assert set(verbs) == {'container', 'network'}
assert not any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
               and node.func.attr in {'write_bytes', 'write_text', 'unlink', 'mkdir'} for node in ast.walk(tree))
print('PASS: syntax, URL secret redaction, allowlisted environment, argument forms, read-only calls; VPS not tested')
