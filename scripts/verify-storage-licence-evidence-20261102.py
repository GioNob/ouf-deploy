#!/usr/bin/env python3
"""Reproduce legal evidence from exact native CI bytes, without executing code."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('licence_evidence', ROOT/'tools/storage_licenses/evidence.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


def verify(archive, lock, out):
    m.require(not out.exists() and lock['status'] == 'PASS', 'NEW_OUTPUT_AND_QUALIFIED_LOCK_REQUIRED')
    with archive.open('rb') as f:
        m.require(archive.stat().st_size == lock['archiveBytes'] and hashlib.file_digest(f, 'sha256').hexdigest() == lock['archiveSha256'],
                  'EXACT_NATIVE_LICENCE_ARCHIVE_REQUIRED')
    with zipfile.ZipFile(archive) as z, tempfile.TemporaryDirectory() as temporary:
        infos = z.infolist(); names = z.namelist()
        m.require(len(names) == len(set(names)) and sum(i.file_size for i in infos) <= 128*1024**2, 'BOUNDED_DISTINCT_EVIDENCE_ARCHIVE_REQUIRED')
        for name in names:
            m.safe_path(name)
        sums = {}
        for line in z.read('SHA256SUMS').decode().splitlines():
            digest, name = line.split('  ', 1)
            m.require(name not in sums, 'DISTINCT_CHECKSUM_SUBJECTS_REQUIRED'); sums[name] = digest
        m.require(set(sums) == set(names)-{'SHA256SUMS', 'provenance.json'}, 'COMPLETE_LICENCE_CHECKSUM_CLOSURE_REQUIRED')
        for name, digest in sums.items():
            m.require(m.sha(z.read(name)) == digest, 'LICENCE_ARCHIVE_MEMBER_CHANGED:'+name)
        sources = json.loads(z.read('source-records.json'))
        m.require(len(sources) == 4, 'FOUR_COLLECTOR_SOURCES_REQUIRED')
        for path, digest in sources.items():
            m.safe_path(path); m.require(m.sha((ROOT/path).read_bytes()) == digest, 'COLLECTOR_SOURCE_CHANGED:'+path)
        q = json.loads(z.read('qualification.json'))
        m.require(q['status'] == 'PASS' and q['producerSource'] == lock['producerSource'] and q['runId'] == lock['runId']
                  and q['unitTests'] == 10 and q['moduleCodeExecuted'] is False and q['releaseAdmitted'] is False,
                  'EXACT_NATIVE_LICENCE_QUALIFICATION_REQUIRED')
        expected = {'original-go.sum': '5f5cee2acd51c8fb55a16dc372520e3f8cf3aebb5dc873b150e5d15624a29b02',
                    'original-go.mod': '5b7892540b197eb5156333ffc9ae108084849db07d0dea57b7060339f840a1a9',
                    'original-image-scan.json': 'ff78fc35bfa3c9f4a465f89c55e7fa99e70139df34d6aef59a4b66a6a351fed8'}
        for path, digest in expected.items():
            m.require(m.sha(z.read(path)) == digest, 'EXACT_ORIGINAL_BUILD_OR_IMAGE_INPUT_REQUIRED:'+path)
        inv = json.loads(z.read('inventory.json'))
        components = inv['components']; keys = {(c['name'], c['version']) for c in components}
        m.require(len(components) == 245 and keys == set(m.package_inventory(json.loads(z.read('original-image-scan.json'))))
                  and inv['status'] == 'COLLECTED_NOT_REVIEWED', 'ALL_EXACT_245_COMPONENTS_REQUIRED')
        go_sums = m.parse_sums(z.read('original-go.sum'))
        modules = [c for c in components if c['name'] not in ('stdlib', 'github.com/seaweedfs/seaweedfs')]
        for c in modules:
            p = c['provenance']; key = c['name'], c['version']
            m.require(p['sum'] == p['goReportedSum'] == go_sums[key]
                      and p['goModSum'] == p['goReportedGoModSum'] == go_sums[c['name'], c['version']+'/go.mod']
                      and p['independentH1EqualsOfficialGo'] is True and p['moduleCodeExecuted'] is False,
                      'ALL_243_MODULE_CHECKSUM_BINDINGS_REQUIRED')
        for c in components:
            for t in c['legalTexts']:
                m.safe_path(t['evidencePath'])
                raw = z.read('texts/'+t['evidencePath'])
                m.require(len(raw) == t['bytes'] and m.sha(raw) == t['sha256'], 'EXACT_RETAINED_LEGAL_TEXT_REQUIRED')
        views = json.loads(z.read('classifier-views.json'))
        for view in views:
            m.safe_path(view['viewPath'])
            m.require(m.sha(z.read('classifier-views/'+view['viewPath'])) == view['sha256'] and
                      z.read('classifier-views/'+view['viewPath']) == z.read('texts/'+view['originalEvidencePath']),
                      'CLASSIFIER_VIEWS_MUST_EQUAL_ORIGINAL_BYTES')
        actual = m.assess_classification(inv, json.loads(z.read('trivy-licences.json')), views)
        m.require(actual == json.loads(z.read('classification.json')), 'CLASSIFICATION_REPRODUCTION_REQUIRED')
        offer = json.loads(z.read('mpl-source-manifest.json'))
        mpl = {(c['name'], c['version']) for c in actual['components'] if any(f['Name'] == 'MPL-2.0' for f in c['rootClassifications'])}
        offered = offer['components']
        m.require(len(offered) == len(mpl) and {(c['name'], c['version']) for c in offered} == mpl and len(mpl) > 0,
                  'ALL_OBSERVED_MPL_SOURCES_REQUIRED')
        for c in offered:
            m.safe_path(c['path']); raw = z.read(c['path'])
            m.require(m.sha(raw) == c['sha256'] and c['goSum'] == go_sums[c['name'], c['version']], 'EXACT_OFFERED_SOURCE_ZIP_REQUIRED')
            path = Path(temporary)/'module.zip'; path.write_bytes(raw)
            with zipfile.ZipFile(path) as module:
                module_infos = module.infolist(); records = []
                m.require(len(module_infos) == len({i.filename for i in module_infos}) and
                          sum(i.file_size for i in module_infos) <= m.MAX_EXPANDED_BYTES, 'BOUNDED_UNIQUE_MPL_SOURCE_MEMBERS')
                for member in module_infos:
                    m.safe_path(member.filename)
                    m.require(member.filename.startswith(c['name']+'@'+c['version']+'/'), 'EXACT_MPL_MODULE_PREFIX_REQUIRED')
                    records.append((member.filename, m.sha(module.read(member))))
                m.require(m.h1_records(records) == c['goSum'], 'INDEPENDENT_MPL_H1_REPRODUCTION_REQUIRED')
        parent = json.loads(z.read('flatbuffers-parent-licence-proof.json'))
        m.require(parent['commit'] == '3b8644d32c50e86872584829af4b8caf180235ab'
                  and parent['parentLicenceGitBlob'] == 'd645695673349e3947e8e5ae42332d0ac3164cd7'
                  and len(parent['moduleFilesMatchedToSameCommit']) == 10 and parent['currentBranchUsed'] is False,
                  'EXACT_PARENT_LICENCE_PROOF_REQUIRED')
        flat = next(c for c in components if c['name'] == 'github.com/google/flatbuffers/go')
        t = next(t for t in flat['legalTexts'] if t['sourcePath'] == 'LICENSE.txt')
        raw = z.read('texts/'+t['evidencePath'])
        m.require(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\x00'+raw).hexdigest() == parent['parentLicenceGitBlob'], 'INDEPENDENT_PARENT_LICENCE_BLOB_REQUIRED')
        out.mkdir()
        # Preserve the complete licence corpus and all offered source archives.
        for name in names:
            p = out/name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(z.read(name))
        result = {'schema': 'ouf.storage-licence-independent-readback.v1', 'status': 'PASS',
                  'archiveSha256': lock['archiveSha256'], 'archiveBytes': lock['archiveBytes'],
                  'producerSource': lock['producerSource'], 'producerRunId': lock['runId'],
                  'archiveChecksumSubjects': len(sums), 'collectorSourcesCompared': 4,
                  'exactRuntimeComponents': 245, 'nativeIndependentGoH1Comparisons': len(modules),
                  'legalTexts': actual['legalTextCount'], 'classifierFiles': actual['classifiedFileCount'],
                  'rootClassifications': actual['componentsWithRootClassification'],
                  'unclassifiedRoots': actual['componentsRequiringRootReview'], 'licenceSeverities': actual['severities'],
                  'mplSourceArchivesIndependentlyRehashed': len(offered), 'flatbuffersParentSourceFilesMatched': 10,
                  'downloadedModuleCodeExecuted': False, 'imageChanged': False, 'rawSpdxChanged': False,
                  'publisherSignatureVerifiedByThisScript': False, 'licenceReview': 'OPEN',
                  'redistributionAccepted': False, 'overallSwG1': 'OPEN', 'targetOperations': 0}
        (out/'independent-byte-result.json').write_text(json.dumps(result, indent=2)+'\n')
        return result


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(); p.add_argument('archive', type=Path); p.add_argument('lock', type=Path); p.add_argument('output', type=Path)
    a = p.parse_args(); print(json.dumps(verify(a.archive, json.loads(a.lock.read_bytes()), a.output), indent=2))
