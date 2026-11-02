#!/usr/bin/env python3
"""Public CI evidence collector; never executes any downloaded module code."""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import time
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('licence_evidence', ROOT/'tools/storage_licenses/evidence.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
OUT = ROOT/'storage-licence-evidence'
ORIGINAL_SHA = '6c5b8c90b0e45e6261946d80653d3e8e6f2b3a0c82c4a47efc5ea5dc839419ee'
IMAGE_METADATA_SHA = 'b93bfefbc1d3a1e19f2a1cdd9c4fbea992f2f72510199bcbaa28b96e59583d2f'


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True)+'\n')


class OfficialGoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        u = urllib.parse.urlsplit(newurl)
        m.require(u.scheme == 'https' and u.username is None and u.hostname in ('go.dev', 'dl.google.com'), 'OFFICIAL_GO_HTTPS_REDIRECT_REQUIRED')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def go_release_bytes(url, limit):
    with urllib.request.build_opener(OfficialGoRedirect()).open(url, timeout=90) as r:
        raw = r.read(limit+1)
    m.require(0 < len(raw) <= limit, 'BOUNDED_OFFICIAL_GO_SOURCE_REQUIRED')
    return raw


def legal_tar(raw, prefix=''):
    texts = {}; total = 0
    with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
        seen = set()
        for member in tar:
            m.safe_path(member.name)
            m.require(member.name not in seen, 'DISTINCT_TAR_MEMBERS_REQUIRED'); seen.add(member.name)
            if not member.name.startswith(prefix):
                continue
            relative = member.name[len(prefix):]
            if not relative or member.isdir() or not m.legal_path(relative):
                continue
            m.require(member.isfile() and 0 <= member.size <= m.MAX_TEXT_BYTES, 'REGULAR_BOUNDED_TAR_LEGAL_TEXT_REQUIRED')
            total += member.size; m.require(total <= m.MAX_TEXT_TOTAL, 'TAR_LEGAL_TEXT_TOTAL_BUDGET')
            texts[relative] = tar.extractfile(member).read()
    return texts


def collect():
    m.require(os.environ.get('GITHUB_ACTIONS') == 'true', 'CI_ONLY')
    m.require(not OUT.exists(), 'NEW_LICENCE_EVIDENCE_DIRECTORY_REQUIRED')
    OUT.mkdir(); (OUT/'texts').mkdir()
    started = time.monotonic()
    def deadline():
        m.require(time.monotonic()-started < 1500, 'FINITE_25_MINUTE_COLLECTION_BUDGET')
    metadata = ROOT/'evidence/artifacts/storage-runtime-image-readback-41527990598.zip'
    m.require(m.sha(metadata.read_bytes()) == IMAGE_METADATA_SHA, 'EXACT_IMAGE_METADATA_REQUIRED')
    with zipfile.ZipFile(metadata) as z:
        scan_bytes = z.read('fresh-image-scan.json')
    inventory = m.package_inventory(json.loads(scan_bytes))
    (OUT/'original-image-scan.json').write_bytes(scan_bytes)
    source_archive = ROOT/'sw-readback/original.zip'
    with source_archive.open('rb') as f:
        m.require(source_archive.stat().st_size == 278756504 and hashlib.file_digest(f, 'sha256').hexdigest() == ORIGINAL_SHA,
                  'EXACT_ORIGINAL_SOURCE_ARCHIVE_REQUIRED')
    m.require(bool(json.loads((ROOT/'sw-readback/publisher-verification.json').read_bytes())), 'ORIGINAL_PUBLISHER_VERIFICATION_REQUIRED')
    with zipfile.ZipFile(source_archive) as z:
        sums_raw = z.read('go.sum'); mod_raw = z.read('go.mod')
        root_texts = legal_tar(z.read('source.tar'))
    (OUT/'original-go.sum').write_bytes(sums_raw); (OUT/'original-go.mod').write_bytes(mod_raw)
    sums = m.parse_sums(sums_raw)
    root = next(p for p in inventory if p[0] == 'github.com/seaweedfs/seaweedfs')
    components = [m.retain_component(OUT, *root, root_texts, {
        'kind': 'ORIGINAL_AUTHENTICATED_OUF_SOURCE_ARCHIVE', 'archiveSha256': ORIGINAL_SHA,
        'sourceCommit': '153ab668c99731a6d29492bf6c61d0b4fa701101',
        'sourceGitBlobsAndModesVerifiedByPreviousStep': 4390, 'dependencyPatchOnly': True})]
    go_version = subprocess.check_output(['go', 'version'], text=True, timeout=30).strip()
    m.require(go_version == 'go version go1.27.3 linux/amd64', 'EXACT_GO_TOOLCHAIN_REQUIRED')
    release_index_raw = go_release_bytes('https://go.dev/dl/?mode=json&include=all', 16*1024**2)
    release = next(r for r in json.loads(release_index_raw) if r['version'] == 'go1.27.3')
    src = next(f for f in release['files'] if f['kind'] == 'source' and f['filename'] == 'go1.27.3.src.tar.gz')
    m.require(type(src['size']) is int and 0 < src['size'] < 128*1024**2, 'BOUNDED_GO_SOURCE_RELEASE_REQUIRED')
    go_raw = go_release_bytes('https://go.dev/dl/go1.27.3.src.tar.gz', src['size'])
    m.require(len(go_raw) == src['size'] and m.sha(go_raw) == src['sha256'], 'OFFICIAL_GO_SOURCE_CHECKSUM_REQUIRED')
    write(OUT/'official-go-source-release.json', {'version': release['version'], 'file': src,
          'indexUrl': 'https://go.dev/dl/?mode=json&include=all', 'sourceUrl': 'https://go.dev/dl/go1.27.3.src.tar.gz',
          'indexSha256': m.sha(release_index_raw), 'sourceBytesVerified': True, 'upstreamSignatureClaimed': False})
    components.append(m.retain_component(OUT, 'stdlib', 'v1.27.3', legal_tar(go_raw, 'go/'),
                                        {'kind': 'OFFICIAL_GO_SOURCE_SHA256', 'sourceArchiveSha256': src['sha256'], 'toolchain': go_version}))
    del go_raw
    cache = Path(os.environ['RUNNER_TEMP'])/'ouf-licence-module-cache'
    cache.mkdir()
    env = dict(os.environ, GOENV='off', GOTOOLCHAIN='local', GOPROXY='https://proxy.golang.org',
               GOSUMDB='sum.golang.org', GOPRIVATE='', GONOSUMDB='', GONOPROXY='',
               GOWORK='off', GO111MODULE='on', GOMODCACHE=str(cache), GOFLAGS='')
    working = cache/'empty-work'; working.mkdir()
    total_archive_bytes = 0
    progress = {'schema': 'ouf.storage-licence-collection.v1', 'status': 'COLLECTING',
                'expectedComponents': 245, 'components': components, 'rootAndToolchain': 'COLLECTED',
                'sourceScanSha256': m.sha(scan_bytes), 'originalGoSumSha256': m.sha(sums_raw),
                'downloadedModuleCodeExecuted': False, 'licenceReview': 'OPEN', 'releaseAdmitted': False,
                'overallSwG1': 'OPEN', 'targetOperations': 0}
    write(OUT/'inventory.json', progress)
    for name, version in inventory:
        if name in ('stdlib', 'github.com/seaweedfs/seaweedfs'):
            continue
        deadline(); m.validate_module_identity(name, version)
        m.require((name, version) in sums and (name, version+'/go.mod') in sums, 'ORIGINAL_BOTH_MODULE_SUMS_REQUIRED:'+name)
        raw = subprocess.check_output(['go', 'mod', 'download', '-json', name+'@'+version], cwd=working, env=env, timeout=120)
        m.require(len(raw) < 1024**2, 'BOUNDED_GO_DOWNLOAD_RECORD_REQUIRED')
        info = json.loads(raw)
        m.require(not info.get('Error') and not info.get('Replace') and info.get('Path') == name
                  and info.get('Version') == version and info.get('Sum') == sums[name, version]
                  and info.get('GoModSum') == sums[name, version+'/go.mod'], 'EXACT_GO_DOWNLOAD_CHECKSUMS_REQUIRED:'+name)
        archive = Path(info['Zip']); gomod = Path(info['GoMod'])
        m.require(archive.is_relative_to(cache) and gomod.is_relative_to(cache) and not gomod.is_symlink()
                  and gomod.stat().st_size < 16*1024**2, 'TASK_CACHE_CONFINED_INPUTS_REQUIRED')
        total_archive_bytes += archive.stat().st_size
        m.require(total_archive_bytes <= 4*1024**3, 'CUMULATIVE_MODULE_ARCHIVE_BUDGET')
        texts, provenance = m.module_texts(name, version, archive, gomod.read_bytes(),
                                         sums[name, version], sums[name, version+'/go.mod'])
        provenance.update(kind='GO_SUM_AND_SUMDB_VERIFIED_MODULE',
                          goReportedSum=info['Sum'], goReportedGoModSum=info['GoModSum'],
                          independentH1EqualsOfficialGo=True)
        components.append(m.retain_component(OUT, name, version, texts, provenance))
        progress.update(completedComponents=len(components), downloadedModuleArchiveBytes=total_archive_bytes)
        write(OUT/'inventory.json', progress)
        print(json.dumps({'completed': len(components), 'expected': 245, 'module': name,
                          'retainedTexts': len(texts)}), flush=True)
    m.require({(c['name'], c['version']) for c in components} == set(inventory), 'COMPLETE_COMPONENT_TEXT_INVENTORY_REQUIRED')
    progress.update(status='COLLECTED_NOT_REVIEWED', completedComponents=len(components),
                    legalTextCount=sum(len(c['legalTexts']) for c in components),
                    componentsWithoutRootLicence=[c['name']+'@'+c['version'] for c in components if c['rootLicenceCandidates'] == 0])
    write(OUT/'inventory.json', progress)


def assess():
    inventory = json.loads((OUT/'inventory.json').read_bytes())
    m.require(inventory['status'] == 'COLLECTED_NOT_REVIEWED' and inventory['completedComponents'] == 245, 'COMPLETE_COLLECTION_REQUIRED')
    for component in inventory['components']:
        for r in component['legalTexts']:
            p = OUT/'texts'/r['evidencePath']
            m.require(not p.is_symlink() and p.stat().st_size == r['bytes'] and m.sha(p.read_bytes()) == r['sha256'], 'LEGAL_TEXT_CHANGED')
    report = json.loads((OUT/'trivy-licences.json').read_bytes())
    result = m.assess_classification(inventory, report)
    write(OUT/'classification.json', result)
    summary = {k: v for k, v in result.items() if k != 'components'}
    write(OUT/'summary.json', summary); print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('mode', choices=['collect', 'assess']); a = p.parse_args()
    try:
        collect() if a.mode == 'collect' else assess()
    except BaseException as e:
        if OUT.exists():
            write(OUT/'failure.json', {'status': 'INCOMPLETE_NOT_ADMITTED', 'errorClass': type(e).__name__,
                                      'licenceReview': 'OPEN', 'releaseAdmitted': False, 'targetOperations': 0})
        raise
