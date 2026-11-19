#!/usr/bin/env python3
"""Recover/scan exact historical bytes from an explicitly untrusted public copy.

This is evidence-only recovery by immutable digest, not an installer fallback,
vendor endorsement, new image candidate, credential use or target operation.
"""
import argparse
from collections import Counter
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import urllib.error
import urllib.parse
import urllib.request

HOST = 'ghcr.io'
REPOSITORY = 'datalens-tech/minio'
ROOT_DIGEST = 'sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e'
MANIFEST = 'sha256:a1a8bd4ac40ad7881a245bab97323e18f971e4d4cba2c2007ec1bedd21cbaba2'
CONFIG = 'sha256:69b2ec208575b69597784255eec6fa6a2985ee9e1a47f4411a51f7f5fdd193a9'
ACCEPT = ', '.join(('application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json',
                    'application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json'))


def require(ok, reason):
    if not ok: raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class AnonymousCopy:
    def __init__(self):
        self.opener = urllib.request.build_opener(NoRedirect())
        self.token = None
        self.requests = 0

    def token_for_copy(self):
        url = 'https://ghcr.io/token?'+urllib.parse.urlencode({'service':'ghcr.io', 'scope':'repository:'+REPOSITORY+':pull'})
        with self.opener.open(url, timeout=30) as response:
            raw = response.read(65537)
        require(len(raw) <= 65536, 'BOUNDED_ANONYMOUS_TOKEN_RESPONSE_REQUIRED')
        token = json.loads(raw).get('token')
        require(type(token) is str and 0 < len(token) <= 32768, 'ANONYMOUS_COPY_READ_TOKEN_REQUIRED')
        self.token = token

    def fetch(self, kind, digest, maximum):
        require(kind in ('manifests', 'blobs') and digest.startswith('sha256:') and len(digest) == 71,
                'EXACT_CONTENT_ADDRESSED_COPY_READ_REQUIRED')
        self.requests += 1
        require(self.requests <= 32, 'BOUNDED_EXACT_COPY_REQUEST_SET_REQUIRED')
        url = 'https://'+HOST+'/v2/'+REPOSITORY+'/'+kind+'/'+digest
        for redirect in range(4):
            headers = {'Accept': ACCEPT}
            if urllib.parse.urlsplit(url).hostname == HOST:
                headers['Authorization'] = 'Bearer '+self.token
            try:
                with self.opener.open(urllib.request.Request(url, headers=headers), timeout=60) as response:
                    raw = response.read(maximum+1)
                require(0 < len(raw) <= maximum and 'sha256:'+sha(raw) == digest, 'EXACT_COPY_BYTE_DIGEST_AND_LIMIT_REQUIRED')
                return raw
            except urllib.error.HTTPError as error:
                if error.code not in (301,302,303,307,308):
                    raise ValueError('EXACT_COPY_HTTP_STATUS_'+str(error.code)) from None
                location = error.headers.get('Location', '')
                parsed = urllib.parse.urlsplit(location)
                require(parsed.scheme == 'https' and parsed.hostname in (HOST, 'pkg-containers.githubusercontent.com')
                        and not parsed.username and not parsed.password and redirect < 3,
                        'BOUNDED_PUBLIC_COPY_BLOB_REDIRECT_REQUIRED')
                # Never forward the registry bearer to the blob CDN.
                url = location
        raise ValueError('BOUNDED_COPY_REDIRECT_SET_EXHAUSTED')


def verify_descriptors(root, selected, config):
    require('sha256:'+sha(root) == ROOT_DIGEST and 'sha256:'+sha(selected) == MANIFEST
            and 'sha256:'+sha(config) == CONFIG, 'EXACT_RETAINED_ROOT_SELECTED_AND_CONFIGURATION_REQUIRED')
    index, manifest, configuration = map(json.loads, (root, selected, config))
    rows = [r for r in index.get('manifests', []) if r.get('digest') == MANIFEST]
    require(len(rows) == 1 and rows[0]['platform']['os'] == 'linux' and rows[0]['platform']['architecture'] == 'amd64'
            and rows[0]['size'] == len(selected), 'EXACT_AMD64_ROOT_MEMBERSHIP_REQUIRED')
    layers = manifest.get('layers')
    require(manifest.get('schemaVersion') == 2 and manifest['config']['digest'] == CONFIG
            and manifest['config']['size'] == len(config) and type(layers) is list and 0 < len(layers) <= 24
            and configuration.get('os') == 'linux' and configuration.get('architecture') == 'amd64'
            and configuration['rootfs']['type'] == 'layers'
            and len(configuration['rootfs']['diff_ids']) == len(layers), 'COMPLETE_EXACT_COPY_IMAGE_GRAPH_REQUIRED')
    return layers, configuration['rootfs']['diff_ids']


def stage(output):
    require(not output.exists(), 'NEW_COPY_EVIDENCE_DIRECTORY_REQUIRED')
    client = AnonymousCopy()
    client.token_for_copy()
    root = client.fetch('manifests', ROOT_DIGEST, 2097152)
    selected = client.fetch('manifests', MANIFEST, 2097152)
    config = client.fetch('blobs', CONFIG, 2097152)
    layers, diff_ids = verify_descriptors(root, selected, config)
    output.mkdir(mode=0o700)
    for name, raw in [('root.json', root), ('selected.json', selected), ('configuration.json', config)]:
        (output/name).write_bytes(raw)
    layer_names = ['layer-'+str(i)+'/layer.tar' for i in range(len(layers))]
    archive = output/'scan-input.docker.tar'
    observations = []
    with tarfile.open(archive, mode='w', format=tarfile.USTAR_FORMAT) as target:
        def add(name, raw):
            entry = tarfile.TarInfo(name); entry.size = len(raw); entry.mode = 0o600
            target.addfile(entry, io.BytesIO(raw))
        add('config.json', config)
        add('manifest.json', json.dumps([{'Config':'config.json', 'Layers':layer_names, 'RepoTags':[]}], separators=(',',':')).encode())
        total = 0
        for ordinal, row in enumerate(layers):
            require(type(row.get('size')) is int and 0 < row['size'] <= 268435456, 'BOUNDED_ORIGINAL_LAYER_DESCRIPTOR_REQUIRED')
            raw = client.fetch('blobs', row['digest'], row['size'])
            require(len(raw) == row['size'], 'EXACT_ORIGINAL_LAYER_SIZE_REQUIRED')
            if raw.startswith(b'\x1f\x8b'):
                with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
                    expanded = compressed.read(536870913)
            else: expanded = raw
            total += len(expanded)
            require(0 < len(expanded) <= 536870912 and total <= 2147483648
                    and 'sha256:'+sha(expanded) == diff_ids[ordinal], 'EXACT_BOUNDED_EXPANDED_LAYER_DIFF_ID_REQUIRED')
            add(layer_names[ordinal], expanded)
            observations.append({'ordinal':ordinal, 'blobDigest':row['digest'], 'blobBytes':len(raw),
                                 'diffId':diff_ids[ordinal], 'expandedBytes':len(expanded)})
    with archive.open('rb') as stream: checksum = hashlib.file_digest(stream, 'sha256').hexdigest()
    proof = {'schema':'ouf.m2-minio-exact-copy-security.v1', 'copyRegistry':HOST, 'copyRepository':REPOSITORY,
             'copyUse':'EVIDENCE_RECOVERY_ONLY_NO_RUNTIME_REFERENCE_CHANGE',
             'copyIsNotOriginalVendorPublisher':True, 'originalVendorPublisherAuthenticated':False,
             'rootIndexDigest':ROOT_DIGEST, 'selectedRuntimeManifestDigest':MANIFEST, 'configurationImageId':CONFIG,
             'allSelectedLayerAndExpandedDiffIdsVerified':True, 'layers':observations,
             'scannerArchiveSha256':checksum, 'contentAddressedReads':client.requests, 'anonymousTokenRequests':1,
             'existingUserCredentialsRead':False, 'imageExecuted':False, 'candidateSelectionChanged':False,
             'runtimeReferenceChanged':False, 'targetOperations':0, 'freshSecurityGatePassed':False,
             'runtimeAuthorityIssued':False, 'targetApplyAuthorized':False, 'releaseAcceptance':False}
    (output/'copy-result.json').write_text(json.dumps(proof,sort_keys=True,indent=2)+'\n')
    return proof


def scan(output):
    proof = json.loads((output/'copy-result.json').read_bytes())
    raw = (output/'trivy-image.json').read_bytes()
    report = json.loads(raw)
    require(report.get('SchemaVersion') == 2 and report.get('Metadata',{}).get('ImageID') == CONFIG
            and report.get('Results'), 'EXACT_COMPLETE_MINIO_IMAGE_SCAN_REQUIRED')
    coverage = {(r.get('Class'),r.get('Type')) for r in report['Results']}
    require(('lang-pkgs','gobinary') in coverage and any(c == 'os-pkgs' for c,_ in coverage), 'OS_AND_GO_BINARY_COVERAGE_REQUIRED')
    counts = Counter()
    for row in report['Results']:
        for finding in row.get('Vulnerabilities', []):
            severity = finding.get('Severity')
            require(severity in ('UNKNOWN','LOW','MEDIUM','HIGH','CRITICAL'), 'VALID_FINDING_SEVERITY_REQUIRED')
            counts[severity] += 1
    proof.update(scanSha256=sha(raw), vulnerabilityCounts=dict(counts),
                 freshSecurityGatePassed=not any(counts.get(s,0) for s in ('UNKNOWN','HIGH','CRITICAL')))
    (output/'copy-result.json').write_text(json.dumps(proof,sort_keys=True,indent=2)+'\n')
    print(json.dumps(proof,sort_keys=True))
    require(proof['freshSecurityGatePassed'], 'MINIO_EXACT_CONTENT_SECURITY_GATE_HELD')
    return proof


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=('stage','scan'))
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    (stage if args.phase == 'stage' else scan)(args.output)
