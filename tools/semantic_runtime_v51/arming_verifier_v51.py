"""Read-only v5.1 RUNTIME_ARMING verifier (anchor + mandate ledger), isolated process.

Only private automatically removed verification temporaries may be written.
No broker imports, signing keys, persistent journals or runtime operations.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types


SUCCESS = 'RUNTIME_ARMING_VERIFIED'
CONFIG_FIELDS = {'schema','sourceHash','runtimePath','runtimeSha256','pythonPath','pythonSha256',
    'driverPath','driverSha256','admissionPath','admissionSha256','registryRoot','runtimeStateRoot',
    'acceptance','b1b2Anchor','mandateRoot','armingRoot','candidates','armingVerifierPath','armingVerifierSha256',
    'b1b2AuthorityModule','opensslBinding','armingIssuerRef'}
BROKER_FIELDS = {'schema','sourceRoot','sourceHashes','authorities','intentBinding','policyBinding',
    'signatureDirectory','opensslBinding','producers','preparerTemplate','candidateRoot','runtimeRootParent'}


def require(ok):
    if not ok: raise ValueError('RUNTIME_ARMING_UNPROVEN')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result); result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    require(type(value) is dict)
    return value


def absolute(value):
    require(type(value) is str)
    path = Path(value)
    require(path.is_absolute() and '..' not in path.parts and str(path) == value)
    return path


def attributes(info):
    return tuple(getattr(info, name) for name in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
                                                 'st_size','st_mtime_ns','st_ctime_ns'))


def private(path):
    path = absolute(str(path))
    for parent in path.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 131072)
        raw = os.read(fd, 131073)
        require(len(raw) == info.st_size and attributes(info) == attributes(os.fstat(fd)) == attributes(path.lstat()))
        return raw
    finally: os.close(fd)


def verify(configuration, cid, generation):
    """Return only on success; no persistent writes, including on rejection."""
    os.umask(0o077)
    require(type(cid) is str and re.fullmatch('[0-9a-f]{64}', cid)
            and type(generation) is int and generation >= 1)
    configuration = absolute(str(configuration)); original = private(configuration); config = decode(original)
    require(set(config) == CONFIG_FIELDS and config['schema'] == 'ouf.semantic-docker-runtime-adapter.v5.1')
    require(config['armingVerifierPath'] == str(Path(__file__).absolute())
            and sha(private(Path(__file__))) == config['armingVerifierSha256'])
    # Never import unverified mandates code, even temporarily. Compile exactly
    # the checked bytes rather than reopening a path through an import loader.
    module_binding = config['b1b2AuthorityModule']
    require(type(module_binding) is dict and set(module_binding) == {'path','sha256'})
    module_path = absolute(module_binding['path']); source = private(module_path)
    require(sha(source) == module_binding['sha256'])
    authority = types.ModuleType('ouf_bound_authority_mandates'); authority.__file__ = str(module_path)
    exec(compile(source, str(module_path), 'exec'), authority.__dict__)
    authority.binding(config['b1b2Anchor']); authority.binding(config['acceptance']); absolute(config['mandateRoot'])
    require(authority.identity(config['armingIssuerRef']))
    require(type(config['candidates']) is dict and len(config['candidates']) == 2
            and all(authority.hashed(item) for item in config['candidates']) and cid in config['candidates'])
    root = absolute(config['armingRoot']); info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700)
    payload_path = root/(str(generation)+'.json'); raw = private(payload_path); arming = decode(raw)
    signature_path = root/(str(generation)+'.RUNTIME_ARMING.json'); signature = private(signature_path)
    require(set(arming) == {'schema','installationRef','entityRef','generation','runtimeConfigurationSha256',
                          'acceptanceSha256','candidates','issuedAt'}
            and arming['schema'] == 'ouf.semantic-docker-runtime-arming.v1'
            and type(arming['generation']) is int and arming['generation'] == generation
            and arming['runtimeConfigurationSha256'] == sha(original)
            and arming['acceptanceSha256'] == config['acceptance']['sha256']
            and type(arming['issuedAt']) is int and arming['issuedAt'] >= 0
            and type(arming['candidates']) is dict and set(arming['candidates']) == set(config['candidates']))
    acceptance_path = absolute(config['acceptance']['path']); acceptance_raw = private(acceptance_path)
    require(sha(acceptance_raw) == config['acceptance']['sha256'])
    entry = arming['candidates'][cid]
    for candidate in arming['candidates'].values():
        require(type(candidate) is dict and set(candidate) == {'intentRef','admissionConfiguration','admissionConfigurationHash'}
                and authority.hashed(candidate['intentRef']) and authority.hashed(candidate['admissionConfigurationHash']))
        absolute(candidate['admissionConfiguration'])
    admission_path = absolute(entry['admissionConfiguration']); admission_raw = private(admission_path)
    require(sha(admission_raw) == entry['admissionConfigurationHash'])
    admission = decode(admission_raw)
    require(set(admission) == BROKER_FIELDS and admission['schema'] == 'ouf.semantic-deployment-broker.v1')
    authority.binding(admission['intentBinding'])
    require(admission['intentBinding']['sha256'] == entry['intentRef'])
    verifier = authority.MandateAuthenticator(config['b1b2Anchor'], config['mandateRoot'], config['opensslBinding'])
    verifier.verify_b1b2_detached(raw, signature, 'RUNTIME_ARMING', config['armingIssuerRef'],
                                arming['installationRef'], arming['entityRef'])
    for path, expected in ((configuration, original), (module_path, source), (payload_path, raw),
                           (signature_path, signature), (admission_path, admission_raw), (acceptance_path, acceptance_raw)):
        require(private(path) == expected)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('--configuration', required=True)
    parser.add_argument('--container-id', required=True)
    parser.add_argument('--generation', required=True, type=int)
    args = parser.parse_args()
    try:
        require(os.geteuid() == os.getegid() == 0 and sys.flags.isolated and sys.dont_write_bytecode)
        verify(args.configuration, args.container_id, args.generation)
    except Exception:
        print('RUNTIME_ARMING_DENIED', file=sys.stderr)
        return 1
    print(SUCCESS)
    return 0


if __name__ == '__main__': raise SystemExit(main())
