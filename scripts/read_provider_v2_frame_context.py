"""Fixed Docker metadata read for the two owned, never-started v2 candidates.

No environment/config/key file read, start, mount, image import or root command.
Unknown storage representations remain unproven; never infer a rootfs path
from an OCI document or mistake Docker's metadata ID for its writable layer.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

DOCKER = Path('/usr/bin/docker')
DOCKER_SHA = '7f5b38163f9c5367f4b42d905c0505877eafa4c20abe49430c85a770aefacf40'
CANDIDATES = {
    'adapter': ('f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67',
                'sha256:277dcefd4744c244f4f6f23f8969f3d0acd64369e2ff1bd67594955c4ca7fbbc'),
    'southbound': ('1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916',
                   'sha256:c15541037a08276e36715a3c3798c2d07fe6faabf5547d3885a66cd10575e366')}


def require(ok, code):
    if not ok: raise ValueError(code)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def binary():
    for parent in DOCKER.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'DOCKER_CUSTODY_DRIFT')
    info = DOCKER.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
            and info.st_mode & 0o111 and 0 < info.st_size <= 64000000, 'DOCKER_CUSTODY_DRIFT')
    require(hashlib.sha256(DOCKER.read_bytes()).hexdigest() == DOCKER_SHA, 'DOCKER_BYTE_DRIFT')


def collect(config):
    def query(*args):
        binary()
        result = subprocess.run([str(DOCKER), '--config', config, '--host', 'unix:///var/run/docker.sock', *args],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        if result.returncode != 0:
            error = result.stderr.lower()
            reason = ('DOCKER_SOCKET_ACCESS_DENIED' if b'permission denied' in error else
                      'DOCKER_METADATA_FORMAT_UNSUPPORTED' if b"can't evaluate field" in error or b'template parsing error' in error else
                      'EXACT_CANDIDATE_MISSING' if b'no such object' in error else
                      'DOCKER_UNAVAILABLE' if b'cannot connect' in error else 'DOCKER_METADATA_READ_FAILED')
            raise ValueError(reason + '_AT_' + args[0].upper())
        require(0 < len(result.stdout) <= 131072, 'DOCKER_METADATA_READ_FAILED')
        binary(); return json.loads(result.stdout)
    info = query('info', '--format', '{"dataRoot":{{json .DockerRootDir}},"storageDriver":{{json .Driver}},"driverStatus":{{json .DriverStatus}}}')
    require(type(info['dataRoot']) is str and info['dataRoot'].startswith('/')
            and '..' not in info['dataRoot'].split('/'), 'DOCKER_DATA_ROOT_UNPROVEN')
    rows = []
    for role, (cid, image) in CANDIDATES.items():
        value = query('inspect', '--type', 'container', '--format',
                      '{"id":{{json .Id}},"image":{{json .Image}},"state":{{json .State}},"graph":{{json .GraphDriver}},"runtime":{{json .HostConfig.Runtime}}}', cid)
        require(value['id'] == cid and value['image'] == image and value['runtime'] == 'ouf-semantic-admitted-v2', 'EXACT_CANDIDATE_BINDING_DRIFT')
        state = value['state']
        require(state['Status'] == 'created' and state['Running'] is False and state['Restarting'] is False
                and state['Pid'] == 0 and state['StartedAt'].startswith('0001-01-01T'), 'CANDIDATE_NOT_NEVER_STARTED')
        graph = value['graph']; require(type(graph) is dict and set(graph) == {'Name', 'Data'}, 'STORAGE_SCHEMA_UNPROVEN')
        data = graph['Data'] or {}; require(type(data) is dict and len(data) <= 16, 'STORAGE_SCHEMA_UNPROVEN')
        # Finite recognized names only; unknown keys/values stay in memory.
        recognized = ('ID', 'Snapshotter', 'MergedDir', 'UpperDir', 'LowerDir', 'WorkDir', 'dir')
        summary = {name: {'valueHash': hashlib.sha256(encoded(data[name])).hexdigest(),
                          'isHex64': type(data[name]) is str and bool(re.fullmatch('[0-9a-f]{64}', data[name])),
                          'isAbsolutePath': type(data[name]) is str and data[name].startswith('/')}
                   for name in recognized if name in data}
        rows.append({'role': role, 'containerId': cid, 'imageId': image, 'neverStarted': True,
                     'runtime': value['runtime'], 'graphDriver': graph['Name'], 'storageMetadata': summary,
                     'unknownStorageFieldCount': len(set(data) - set(recognized)),
                     'independentRootfsBindingProven': False})
    return {'dockerDataRoot': info['dataRoot'], 'storageDriver': info['storageDriver'],
            'driverStatusHash': hashlib.sha256(encoded(info['driverStatus'])).hexdigest(), 'candidates': rows}


def main():
    try:
        with tempfile.TemporaryDirectory(prefix='ouf-empty-frame-docker-') as config:
            os.chmod(config, 0o700)
            first, second = collect(config), collect(config)
            require(first == second, 'DOCKER_FRAME_CONTEXT_CHANGED')
        report = {'schema': 'ouf.semantic-provider-v2-frame-context-read.v1', 'status': 'READ_ONLY_OBSERVATION',
                  **first, 'stableAcrossReads': True, 'privateKeysRead': 0, 'environmentValuesRead': False,
                  'configurationFilesRead': False, 'containerLifecycleOperations': 0, 'mountOperations': 0,
                  'providerCalls': 0, 'targetConfigurationWrites': 0, 'secretValuesPrinted': False,
                  'acceptanceGranted': False, 'startAuthorized': False}
        print('OUF_PROVIDER_V2_FRAME_CONTEXT=' + encoded(report).decode())
        return 0
    except Exception as error:
        code = str(error) if isinstance(error, ValueError) and re.fullmatch('[A-Z_]+', str(error)) else 'BOUNDED_METADATA_READ_FAILED'
        print('OUF_PROVIDER_V2_FRAME_CONTEXT=BLOCKED REASON=' + code + ' NO_RAW_OUTPUT=true')
        return 1


if __name__ == '__main__': raise SystemExit(main())
