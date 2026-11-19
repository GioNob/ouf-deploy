"""Checks for secret-free read-only UDP diagnostics; does not contact Docker."""
import ast
import importlib.util
import json
from pathlib import Path
import tempfile
import zipfile

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
# UDP Dockerfile at 0d40da05408a14db31d4d41af2372d6a71480291 uses app.jar,
# whereas Onboarding uses application.jar. Do not transplant the latter assumption.
udp = {'Path': 'java', 'Args': ['-jar', '/app/app.jar'],
       'Config': {'WorkingDir': '/app'}, 'State': {'Pid': 123}}
assert module.launch_jar_path(udp) == '/app/app.jar'
assert module.launch_jar_path(dict(udp, Args=['-jar', 'app.jar'])) == '/app/app.jar'
assert module.launch_jar_path(dict(udp, Args=['-jar', '/app/application.jar'])) == '/app/application.jar'
with tempfile.TemporaryDirectory() as folder:
    root = Path(folder)
    jar = root / '123/root/app/app.jar'
    jar.parent.mkdir(parents=True)
    with zipfile.ZipFile(jar, 'w') as archive:
        archive.writestr('BOOT-INF/lib/s3-2.40.0.jar', b'fixture-library')
        for name in ('S3LakeConfiguration', 'S3LakeObjectStorageAdapter'):
            archive.writestr('BOOT-INF/classes/it/comune/trieste/ouf/udp/' + name + '.class', b'fixture-class')
        archive.writestr('BOOT-INF/classes/application.yml', b'endpoint: ${OUF_UDP_S3_ENDPOINT:}\nbucket: ${OUF_UDP_S3_BUCKET:}\n')
    result = module.jar_summary(udp, root)
    assert result['status'] == 'READ', result
    assert result['containerJarPath'] == '/app/app.jar'
    assert result['selectedLibraries'] == ['s3-2.40.0.jar']
    assert result['storageEnvironmentPlaceholders'] == ['OUF_UDP_S3_BUCKET', 'OUF_UDP_S3_ENDPOINT']
    missing = module.jar_summary(dict(udp, Args=['-jar', '/app/absent.jar']), root)
    assert missing['status'] == 'INCOMPLETE' and missing['reason'] == 'FileNotFoundError'
    wrapped = module.jar_summary(dict(udp, Path='/bin/sh', Args=['-c', 'java -jar /app/app.jar ' + secret]), root)
    assert wrapped['status'] == 'INCOMPLETE'
    assert wrapped['reason'] == 'DIRECT_JAVA_JAR_LAUNCH_NOT_IDENTIFIED'
    assert secret not in json.dumps(wrapped)
    invalid = module.jar_summary(dict(udp, Args=['-jar', '../private.jar']), root)
    assert invalid['status'] == 'INCOMPLETE' and invalid['reason'] == 'JAR_PATH_NOT_CANONICAL'
tree = ast.parse(raw)
verbs = [node.args[0].value for node in ast.walk(tree) if isinstance(node, ast.Call)
         and isinstance(node.func, ast.Name) and node.func.id == 'docker'
         and node.args and isinstance(node.args[0], ast.Constant)]
assert set(verbs) == {'container', 'network'}
assert not any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
               and node.func.attr in {'write_bytes', 'write_text', 'unlink', 'mkdir'} for node in ast.walk(tree))
print('PASS: secret redaction, read-only calls, UDP/Onboarding/relative JAR paths, packaged JAR fixture, missing/wrapped/traversal launch handling; VPS not tested')
