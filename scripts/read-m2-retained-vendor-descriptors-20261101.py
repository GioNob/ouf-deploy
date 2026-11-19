#!/usr/bin/env python3
"""Public registry descriptors only, at the five already observed native digests.

Run on a disposable hosted runner. No Docker daemon, image import, layer/config
blob, target access, saved login, publisher signature or installation authority.
Registry failure is recorded; no mutable tag fallback or alternate source.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile
import time

MAXIMUM = 2 * 1024 * 1024
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
INDEXES = {'application/vnd.oci.image.index.v1+json','application/vnd.docker.distribution.manifest.list.v2+json'}
MANIFESTS = {'application/vnd.oci.image.manifest.v1+json','application/vnd.docker.distribution.manifest.v2+json'}


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def parse(raw):
    def unique(pairs):
        result = {}
        for key,value in pairs:
            require(key not in result,'DUPLICATE_DESCRIPTOR_KEY_DENIED')
            result[key] = value
        return result
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:require(False,'FINITE_JSON_REQUIRED'))


def descriptor(item):
    require(type(item) is dict and DIGEST.fullmatch(item.get('digest',''))
            and type(item.get('size')) is int and 0 < item['size'] <= 2**33
            and type(item.get('mediaType')) is str,'EXACT_BOUNDED_SHA256_DESCRIPTOR_REQUIRED')
    return item['digest']


def selected(root):
    require(root.get('schemaVersion') == 2,'REGISTRY_SCHEMA_TWO_REQUIRED')
    if root.get('mediaType') in MANIFESTS:
        return None
    require(root.get('mediaType') in INDEXES,'EXPLICIT_IMAGE_INDEX_OR_MANIFEST_REQUIRED')
    rows = root.get('manifests')
    require(type(rows) is list and 1 <= len(rows) <= 128,'BOUNDED_INDEX_MEMBERS_REQUIRED')
    candidates = []
    for row in rows:
        descriptor(row)
        platform = row.get('platform',{})
        if platform.get('os') == 'linux' and platform.get('architecture') == 'amd64' and not platform.get('variant'):
            require(row['mediaType'] in MANIFESTS,'SELECTED_RUNTIME_MUST_BE_IMAGE_MANIFEST')
            candidates.append(row)
    require(len(candidates) == 1,'ONE_EXACT_LINUX_AMD64_RUNTIME_REQUIRED')
    return candidates[0]


def manifest(document):
    require(document.get('schemaVersion') == 2 and document.get('mediaType') in MANIFESTS,'EXACT_SELECTED_RUNTIME_MANIFEST_REQUIRED')
    config = descriptor(document.get('config'))
    require(document['config']['mediaType'] in {'application/vnd.oci.image.config.v1+json','application/vnd.docker.container.image.v1+json'},'IMAGE_CONFIG_MEDIA_REQUIRED')
    layers = document.get('layers')
    require(type(layers) is list and 1 <= len(layers) <= 64,'BOUNDED_RUNTIME_LAYER_LIST_REQUIRED')
    for layer in layers:
        descriptor(layer)
        require(layer['mediaType'] in {'application/vnd.oci.image.layer.v1.tar',
            'application/vnd.oci.image.layer.v1.tar+gzip','application/vnd.oci.image.layer.v1.tar+zstd',
            'application/vnd.docker.image.rootfs.diff.tar.gzip'},'EXPLICIT_RUNTIME_LAYER_MEDIA_REQUIRED')
    return config,layers


def file_limit():
    resource.setrlimit(resource.RLIMIT_FSIZE,(MAXIMUM,MAXIMUM))


def run(root, output):
    inventory = json.loads((root/'releases/m2-retained-runtime-origin-inventory-20261101.json').read_text())
    require(inventory['selectedRuntimePublicResultHash'] == '039f03a7593c0b826e6597f755c838f85efa197d17d7df3339512f5ee7c52bcc','EXACT_CONSUMED_BYTE_RECEIPT_INVENTORY_REQUIRED')
    require(inventory['allRuntimeArtifactMembershipProven'] is False,'PUBLIC_INVENTORY_MUST_NOT_ISSUE_MEMBERSHIP')
    output.mkdir(parents=True,exist_ok=False)
    start = time.monotonic(); attempts = 0; results = {}
    with tempfile.TemporaryDirectory(prefix='ouf-public-registry-') as isolated:
        # --config prevents consulting the runner's saved registry logins.
        env = {'PATH':'/usr/local/bin:/usr/bin:/bin','LANG':'C.UTF-8','DOCKER_CONFIG':isolated}
        def fetch(repository, expected, role, kind):
            nonlocal attempts
            require(time.monotonic()-start < 420,'PUBLIC_REGISTRY_DESCRIPTOR_BUDGET_EXHAUSTED')
            attempts += 1
            with tempfile.TemporaryFile() as stdout,tempfile.TemporaryFile() as stderr:
                try:
                    process = subprocess.run(['/usr/bin/docker','--config',isolated,'buildx','imagetools',
                        'inspect','--raw',repository+'@'+expected],env=env,stdin=subprocess.DEVNULL,
                        stdout=stdout,stderr=stderr,timeout=min(45,420-(time.monotonic()-start)),preexec_fn=file_limit)
                except subprocess.TimeoutExpired:
                    raise ValueError('REGISTRY_DESCRIPTOR_LOOKUP_TIMEOUT') from None
                require(process.returncode == 0,'REGISTRY_DESCRIPTOR_UNAVAILABLE_AT_EXACT_REFERENCE')
                stdout.seek(0); raw = stdout.read(MAXIMUM+1)
                require(0 < len(raw) <= MAXIMUM,'BOUNDED_REGISTRY_DESCRIPTOR_BYTES_REQUIRED')
                require('sha256:'+hashlib.sha256(raw).hexdigest() == expected,'REGISTRY_DESCRIPTOR_DIGEST_MISMATCH')
                (output/(role+'-'+kind+'.json')).write_bytes(raw)
                return parse(raw),len(raw)
        for role in sorted(['apisix','caddy','keycloak','minio','postgres']):
            row = inventory['roles'][role]; repository = row['registryRepository']; native = row['nativeImageId']
            require(DIGEST.fullmatch(native) and re.fullmatch(r'(docker\.io|quay\.io)/[a-z0-9_.-]+/[a-z0-9_.-]+',repository),'EXACT_INVENTORIED_REGISTRY_REFERENCE_REQUIRED')
            result = {'registryRepository':repository,'requestedNativeDigest':native,
                'rootDescriptorProven':False,'selectedRuntimeDescriptorProven':False,
                'registryPublisherCryptographicallyAuthenticated':False,'privateSelectedProofRoleJoinPerformed':False}
            try:
                document,size = fetch(repository,native,role,'root')
                result.update(rootDescriptorProven=True,rootBytes=size)
                choice = selected(document)
                runtime = native
                if choice is not None:
                    runtime = choice['digest']; document,child_size = fetch(repository,runtime,role,'selected')
                    require(child_size == choice['size'],'SELECTED_DESCRIPTOR_SIZE_DRIFT')
                configuration,layers = manifest(document)
                result.update(status='EXACT_REGISTRY_RUNTIME_DESCRIPTOR_VERIFIED',selectedRuntimeDescriptorProven=True,
                    selectedRuntimeManifestDigest=runtime,configurationDigest=configuration,layerCount=len(layers),
                    layerDescriptorListSha256=hashlib.sha256(json.dumps(layers,sort_keys=True,separators=(',',':')).encode()).hexdigest())
            except (ValueError, json.JSONDecodeError) as error:
                # Only bounded local enum reasons leave this public reader.
                code = str(error)
                result.update(status='UNRESOLVED_NOT_ADMITTED',reasonCode=code if re.fullmatch('[A-Z_]{1,100}',code) else 'INVALID_REGISTRY_METADATA')
            results[role] = result
    result = {'schema':'ouf.m2-public-retained-vendor-descriptor-result.v1','selectedRuntimePublicResultHash':inventory['selectedRuntimePublicResultHash'],
        'registryLookupProcessInvocations':attempts,'roles':results,'allRuntimeArtifactMembershipProven':False,
        'sourcePublisherAuthenticated':False,'privateSelectedProofRoleJoinPerformed':False,'configurationOrLayerBlobsFetched':0,
        'targetControlAttemptsAdded':0,'directEngineGets':0,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}
    (output/'result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print(json.dumps({r:v['status'] for r,v in results.items()},sort_keys=True))


if __name__ == '__main__':
    root = Path(__file__).resolve().parents[1]
    run(root,root/'public-vendor-descriptors')
