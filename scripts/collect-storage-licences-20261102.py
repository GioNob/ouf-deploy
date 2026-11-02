#!/usr/bin/env python3
"""Public CI evidence collector; never executes any downloaded module code."""
import argparse
import base64
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


def flatbuffers_parent_licence(archive):
    """Bind the omitted parent licence to every Go module ZIP file at its commit."""
    commit = '3b8644d32c50e86872584829af4b8caf180235ab'
    base = 'https://api.github.com/repos/google/flatbuffers'
    def get(url, limit):
        req = urllib.request.Request(url, headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'OUF-checksum-bound-licence-evidence'})
        m.require(bool(os.environ.get('GH_TOKEN')), 'CI_GITHUB_READ_TOKEN_REQUIRED')
        req.add_unredirected_header('Authorization', 'Bearer '+os.environ['GH_TOKEN'])
        with urllib.request.urlopen(req, timeout=60) as response:
            raw = response.read(limit+1)
        m.require(0 < len(raw) <= limit, 'BOUNDED_PUBLIC_GIT_METADATA_REQUIRED')
        return json.loads(raw)
    tree = get(base+'/git/trees/'+commit+'?recursive=1', 4*1024**2)
    m.require(tree.get('truncated') is False, 'COMPLETE_EXACT_PARENT_TREE_REQUIRED')
    files = {f['path']: f for f in tree['tree'] if f['type'] == 'blob'}
    expected = files['LICENSE.txt']
    m.require(expected['sha'] == 'd645695673349e3947e8e5ae42332d0ac3164cd7', 'EXACT_PARENT_LICENCE_BLOB_REQUIRED')
    matches = []
    with zipfile.ZipFile(archive) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            relative = info.filename.split('@', 1)[1].split('/', 1)[1]
            path = 'go/'+relative
            raw = z.read(info)
            blob = hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\x00'+raw).hexdigest()
            m.require(path in files and files[path]['sha'] == blob and files[path]['mode'] in ('100644', '100755'), 'EXACT_SUBMODULE_GIT_BLOB_REQUIRED:'+relative)
            matches.append({'path': path, 'gitBlob': blob, 'sha256': m.sha(raw)})
    m.require(len(matches) == 10, 'ALL_TEN_FLATBUFFERS_MODULE_FILES_REQUIRED')
    blob = get(base+'/git/blobs/'+expected['sha'], 65536)
    raw = base64.b64decode(blob['content'])
    m.require(len(raw) == expected['size'] and hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\x00'+raw).hexdigest() == expected['sha'], 'PARENT_LICENCE_GIT_BLOB_MISMATCH')
    proof = {'repository': 'google/flatbuffers', 'commit': commit, 'parentLicencePath': 'LICENSE.txt',
             'parentLicenceGitBlob': expected['sha'], 'parentLicenceSha256': m.sha(raw),
             'moduleFilesMatchedToSameCommit': matches, 'treeTruncated': False,
             'currentBranchUsed': False, 'licenceAcceptanceClaimed': False}
    write(OUT/'flatbuffers-parent-licence-proof.json', proof)
    return raw, proof


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
    env.pop('GH_TOKEN', None)
    env.pop('GITHUB_TOKEN', None)
    working = cache/'empty-work'; working.mkdir()
    total_archive_bytes = 0
    module_sources = {}
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
        if name == 'github.com/google/flatbuffers/go':
            parent, proof = flatbuffers_parent_licence(archive)
            m.require('LICENSE.txt' not in texts, 'PARENT_LICENCE_MUST_NOT_OVERWRITE_MODULE_TEXT')
            texts['LICENSE.txt'] = parent
            provenance['parentLicenceSupplement'] = proof
        provenance.update(kind='GO_SUM_AND_SUMDB_VERIFIED_MODULE',
                          goReportedSum=info['Sum'], goReportedGoModSum=info['GoModSum'],
                          independentH1EqualsOfficialGo=True)
        module_sources[name+'@'+version] = {'cacheRelativePath': str(archive.relative_to(cache)),
                                           'zipSha256': provenance['zipSha256']}
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
    write(OUT/'module-source-records.json', module_sources)
    views = []
    for component in components:
        for record in component['legalTexts']:
            if not record['licenceCandidate'] or record['bytes'] == 0:
                continue
            raw = (OUT/'texts'/record['evidencePath']).read_bytes()
            view = component['id']+'/'+m.sha(record['evidencePath'].encode())+'/LICENSE'
            p = OUT/'classifier-views'/view; p.parent.mkdir(parents=True, exist_ok=True)
            with p.open('xb') as f:
                f.write(raw)
            views.append({'viewPath': view, 'originalEvidencePath': record['evidencePath'], 'sha256': m.sha(raw)})
    write(OUT/'classifier-views.json', views)


def assess():
    inventory = json.loads((OUT/'inventory.json').read_bytes())
    m.require(inventory['status'] == 'COLLECTED_NOT_REVIEWED' and inventory['completedComponents'] == 245, 'COMPLETE_COLLECTION_REQUIRED')
    for component in inventory['components']:
        for r in component['legalTexts']:
            p = OUT/'texts'/r['evidencePath']
            m.require(not p.is_symlink() and p.stat().st_size == r['bytes'] and m.sha(p.read_bytes()) == r['sha256'], 'LEGAL_TEXT_CHANGED')
    report = json.loads((OUT/'trivy-licences.json').read_bytes())
    views = json.loads((OUT/'classifier-views.json').read_bytes())
    for view in views:
        m.require(m.sha((OUT/'classifier-views'/view['viewPath']).read_bytes()) == view['sha256'], 'CLASSIFIER_VIEW_BYTES_CHANGED')
    result = m.assess_classification(inventory, report, views)
    write(OUT/'classification.json', result)
    summary = {k: v for k, v in result.items() if k != 'components'}
    write(OUT/'summary.json', summary); print(json.dumps(summary, indent=2))


def source_offer():
    """Retain the exact whole module source for every observed MPL root licence."""
    inventory = json.loads((OUT/'inventory.json').read_bytes())
    classification = json.loads((OUT/'classification.json').read_bytes())
    sources = json.loads((OUT/'module-source-records.json').read_bytes())
    cache = Path(os.environ['RUNNER_TEMP'])/'ouf-licence-module-cache'
    by_key = {c['name']+'@'+c['version']: c for c in inventory['components']}
    offered = []
    for component in classification['components']:
        if not any(f['Name'] == 'MPL-2.0' for f in component['rootClassifications']):
            continue
        key = component['name']+'@'+component['version']; original = by_key[key]
        record = sources[key]; m.safe_path(record['cacheRelativePath'])
        path = cache/record['cacheRelativePath']
        m.require(not path.is_symlink(), 'REGULAR_AUTHENTICATED_MPL_SOURCE_REQUIRED')
        raw = path.read_bytes()
        m.require(m.sha(raw) == record['zipSha256'] == original['provenance']['zipSha256'], 'EXACT_MPL_SOURCE_ZIP_REQUIRED')
        p = OUT/'sources'/(original['id']+'.zip'); p.parent.mkdir(exist_ok=True)
        with p.open('xb') as f:
            f.write(raw)
        offered.append({'name': component['name'], 'version': component['version'], 'path': str(p.relative_to(OUT)),
                        'sha256': m.sha(raw), 'goSum': original['provenance']['sum'],
                        'goModSum': original['provenance']['goModSum'], 'originalLicence': 'MPL-2.0',
                        'moduleSourcesModified': False, 'redistributionAccepted': False})
    m.require(bool(offered), 'OBSERVED_MPL_COMPONENT_SOURCES_REQUIRED')
    write(OUT/'mpl-source-manifest.json', {'schema': 'ouf.storage-mpl-source-custody.v1', 'components': offered,
                                         'sourceCount': len(offered), 'status': 'SOURCE_PACKAGE_PREPARED_NOT_ACCEPTED',
                                         'redistributionAccepted': False, 'releaseAdmitted': False})
    notice = ('OUF SeaweedFS candidate - MPL source package (draft, not a release acceptance)\n\n'
              'Exact source modules for the MPL-2.0 components listed below accompany this package.\n'
              'Their original licence texts and notices remain in the source ZIP files and texts/.\n'
              'This packaging workflow has not modified these module sources. The separately recorded\n'
              'OUF dependency patch changes only the SeaweedFS go.mod and go.sum manifests.\n'
              'Each source archive is bound to the original build go.sum and a SHA256 in the manifest.\n'
              'No requirement is discharged merely by this draft notice. Distribution review remains open.\n\n')
    (OUT/'MPL-SOURCE-NOTICE.txt').write_text(notice+''.join(c['name']+'@'+c['version']+'  '+c['path']+'\n' for c in offered))


if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('mode', choices=['collect', 'assess', 'source-offer']); a = p.parse_args()
    try:
        {'collect': collect, 'assess': assess, 'source-offer': source_offer}[a.mode]()
    except BaseException as e:
        if OUT.exists():
            write(OUT/'failure.json', {'status': 'INCOMPLETE_NOT_ADMITTED', 'errorClass': type(e).__name__,
                                      'licenceReview': 'OPEN', 'releaseAdmitted': False, 'targetOperations': 0})
        raise
