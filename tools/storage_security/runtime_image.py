"""Deterministic offline packaging of the already reviewed server, not admission.

No downloads, build, daemon access or target operations. The caller authenticates
the original producer before extracting its exact executable and licence.
"""
import hashlib
import io
import json
from pathlib import Path
import tarfile
from typing import NamedTuple

BINARY_SHA = 'bb9f768e5afca39c7fdc2113e5caafd9f911d4537917dd25c520ee4dbdab1f74'
SOURCE = '153ab668c99731a6d29492bf6c61d0b4fa701101'
IMAGE_TAG = 'ouf-seaweedfs-candidate:reviewed-bb9f768e'
OCI_MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
OCI_CONFIG = 'application/vnd.oci.image.config.v1+json'
OCI_LAYER = 'application/vnd.oci.image.layer.v1.tar'


class ImageProfile(NamedTuple):
    binary_sha: str
    source_commit: str
    image_tag: str
    licence_sha: str | None = None


def legacy_profile():
    return ImageProfile(BINARY_SHA, SOURCE, IMAGE_TAG)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def archive(entries):
    """No host times, users, paths or permissive executable ownership in layers."""
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for name, content, mode in sorted(entries):
            info = tarfile.TarInfo(name)
            info.uid = info.gid = info.mtime = 0
            info.mode = mode
            if content is None:
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            else:
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
    return stream.getvalue()


def assemble(binary, licence, source_record, *, profile=None):
    profile = profile or legacy_profile()
    require(sha(binary) == profile.binary_sha, 'EXACT_OWNER_REVIEWED_BINARY_REQUIRED')
    require(0 < len(licence) < 65536 and b'Apache License' in licence,
            'UPSTREAM_LICENCE_REQUIRED')
    require(profile.licence_sha is None or sha(licence) == profile.licence_sha,
            'EXACT_UPSTREAM_LICENCE_REQUIRED')
    require(source_record == {'sourceCommit': profile.source_commit, 'binarySha256': profile.binary_sha,
                             'licenceSha256': sha(licence)}, 'EXACT_SOURCE_RECORD_REQUIRED')
    layer = archive([
        ('data', None, 0o755), ('tmp', None, 0o1777),
        ('usr', None, 0o755), ('usr/local', None, 0o755),
        ('usr/local/bin', None, 0o755), ('usr/local/bin/weed', binary, 0o555),
        ('usr/share', None, 0o755), ('usr/share/licenses', None, 0o755),
        ('usr/share/licenses/SeaweedFS-LICENSE', licence, 0o444),
    ])
    config = canonical({
        'architecture': 'amd64', 'os': 'linux',
        'config': {'User': '10001:10001', 'Entrypoint': ['/usr/local/bin/weed'],
                   'WorkingDir': '/data',
                   'Labels': {'org.opencontainers.image.source': 'https://github.com/seaweedfs/seaweedfs',
                              'org.opencontainers.image.revision': profile.source_commit,
                              'org.opencontainers.image.licenses': 'Apache-2.0',
                              'org.ouf.binary.sha256': profile.binary_sha,
                              'org.ouf.release-admitted': 'false'}},
        'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + sha(layer)]},
    })
    def descriptor(raw, media):
        return {'mediaType': media, 'digest': 'sha256:' + sha(raw), 'size': len(raw)}
    manifest = canonical({'schemaVersion': 2, 'mediaType': OCI_MANIFEST,
                          'config': descriptor(config, OCI_CONFIG),
                          'layers': [descriptor(layer, OCI_LAYER)]})
    index = canonical({'schemaVersion': 2, 'manifests': [dict(
        descriptor(manifest, OCI_MANIFEST), platform={'architecture': 'amd64', 'os': 'linux'})]})
    docker_manifest = canonical([{'Config': sha(config) + '.json',
                                  'RepoTags': [profile.image_tag], 'Layers': ['layer.tar']}])
    docker = archive([(sha(config)+'.json', config, 0o444),
                      ('manifest.json', docker_manifest, 0o444), ('layer.tar', layer, 0o444)])
    return {'oci-layout': canonical({'imageLayoutVersion': '1.0.0'}), 'index.json': index,
            'blobs/sha256/' + sha(config): config, 'blobs/sha256/' + sha(manifest): manifest,
            'blobs/sha256/' + sha(layer): layer, 'runtime.docker.tar': docker,
            'image-record.json': canonical({
                'schema': 'ouf.storage-runtime-image.v1', 'status': 'PACKAGED_NOT_ADMITTED',
                'binarySha256': profile.binary_sha, 'sourceCommit': profile.source_commit,
                'configDigest': 'sha256:' + sha(config), 'manifestDigest': 'sha256:' + sha(manifest),
                'layerDigest': 'sha256:' + sha(layer), 'dockerArchiveSha256': sha(docker),
                'upstreamLicenceSha256': sha(licence), 'user': '10001:10001',
                'scratchRootfs': True, 'thirdPartyLicencesAccepted': False,
                'targetOperations': 0, 'runtimeAuthorityIssued': False,
                'releaseAdmitted': False, 'overallSwG1': 'OPEN'})}


def verify_layout(root, *, profile=None):
    """Resolve every descriptor then enforce the exact packaged filesystem/config."""
    profile = profile or legacy_profile()
    require(json.loads((root/'oci-layout').read_bytes()) == {'imageLayoutVersion': '1.0.0'}, 'OCI_LAYOUT_REQUIRED')
    index = json.loads((root/'index.json').read_bytes())
    require(index.get('schemaVersion') == 2 and len(index.get('manifests', [])) == 1, 'SINGLE_MANIFEST_REQUIRED')
    def read(desc, media):
        require(desc.get('mediaType') == media and desc.get('digest', '').startswith('sha256:'), 'EXPECTED_DESCRIPTOR_REQUIRED')
        digest = desc['digest'][7:]
        require(len(digest) == 64 and all(c in '0123456789abcdef' for c in digest), 'SAFE_SHA256_REQUIRED')
        path = root/'blobs/sha256'/digest
        require(path.is_file() and not path.is_symlink(), 'REGULAR_BLOB_REQUIRED')
        data = path.read_bytes()
        require(sha(data) == digest and len(data) == desc.get('size'), 'BLOB_IDENTITY_MISMATCH')
        return data
    manifest = json.loads(read(index['manifests'][0], OCI_MANIFEST))
    require(manifest.get('schemaVersion') == 2 and manifest.get('mediaType') == OCI_MANIFEST and len(manifest.get('layers', [])) == 1, 'SINGLE_LAYER_MANIFEST_REQUIRED')
    config_raw = read(manifest['config'], OCI_CONFIG)
    layer_raw = read(manifest['layers'][0], OCI_LAYER)
    with tarfile.open(fileobj=io.BytesIO(layer_raw)) as tar:
        members = tar.getmembers()
        require(len(members) == len({m.name for m in members}), 'UNIQUE_LAYER_MEMBERS_REQUIRED')
        require(all(m.isfile() or m.isdir() for m in members), 'LINK_OR_DEVICE_DENIED')
        files = {m.name: tar.extractfile(m).read() for m in members if m.isfile()}
    require(set(files) == {'usr/local/bin/weed', 'usr/share/licenses/SeaweedFS-LICENSE'}, 'EXACT_RUNTIME_FILES_REQUIRED')
    expected = assemble(files['usr/local/bin/weed'], files['usr/share/licenses/SeaweedFS-LICENSE'],
                        {'sourceCommit': profile.source_commit, 'binarySha256': profile.binary_sha,
                         'licenceSha256': sha(files['usr/share/licenses/SeaweedFS-LICENSE'])}, profile=profile)
    # Exact reconstruction also verifies ownership, modes, entrypoint and no hidden env/ports.
    for name, raw in expected.items():
        path = root/name
        require(path.is_file() and not path.is_symlink() and path.read_bytes() == raw,
                'RECONSTRUCTED_IMAGE_CHANGED:' + name)
    require(config_raw == expected['blobs/sha256/'+sha(config_raw)], 'CONFIG_CHANGED')
    return json.loads(expected['image-record.json'])


def write_image(binary, licence, out, *, profile=None):
    profile = profile or legacy_profile()
    require(not out.exists(), 'NEW_OUTPUT_REQUIRED')
    files = assemble(binary, licence, {'sourceCommit': profile.source_commit, 'binarySha256': profile.binary_sha,
                                      'licenceSha256': sha(licence)}, profile=profile)
    out.mkdir(parents=True)
    for name, raw in files.items():
        path = out/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    return verify_layout(out, profile=profile)
