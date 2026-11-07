#!/usr/bin/env python3
"""Independent offline archive readback. No enclosed executable is started."""
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import shutil
import stat
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = 13180033257
ARCHIVE_BYTES = 186961604
ARCHIVE_SHA = '459ef6d3b746cfd7387d10517949dcd30d507c33df9d4fedafe612cb31c5c98a'
PRODUCER = 'd4cfa1f08bb25dace29ed94946d4a7c97a729af0'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def verify(path, output):
    require(not output.exists(), 'NEW_READBACK_OUTPUT_REQUIRED')
    with path.open('rb') as f:
        require(path.stat().st_size == ARCHIVE_BYTES and hashlib.file_digest(f, 'sha256').hexdigest() == ARCHIVE_SHA,
                'EXACT_ORIGINAL_IMAGE_ARTIFACT_REQUIRED')
    with zipfile.ZipFile(path) as z, tempfile.TemporaryDirectory() as tmp:
        infos = z.infolist(); names = [i.filename for i in infos]
        require(len(names) == 25 and len(names) == len(set(names)), 'EXACT_UNIQUE_ARCHIVE_MEMBERS_REQUIRED')
        require(sum(i.file_size for i in infos) <= 1024**3, 'UNCOMPRESSED_ARCHIVE_BUDGET')
        for i in infos:
            p = PurePosixPath(i.filename)
            require(str(p) == i.filename and not p.is_absolute() and '..' not in p.parts
                    and '\\' not in i.filename and not i.is_dir()
                    and not stat.S_ISLNK(i.external_attr >> 16), 'SAFE_REGULAR_MEMBERS_REQUIRED')
        sums = {}
        for line in z.read('SHA256SUMS').decode().splitlines():
            digest, name = line.split('  ', 1)
            require(name not in sums, 'DUPLICATE_CHECKSUM_SUBJECT')
            sums[name] = digest
        require(set(sums) == set(names)-{'SHA256SUMS', 'provenance.json'}, 'COMPLETE_CHECKSUM_CLOSURE_REQUIRED')
        root = Path(tmp)/'image'; root.mkdir()
        for i in infos:
            data = z.read(i.filename)
            if i.filename in sums:
                require(hashlib.sha256(data).hexdigest() == sums[i.filename], 'CHECKSUM_MISMATCH:'+i.filename)
            p = root/i.filename; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(data)
        sources = json.loads((root/'source-records.json').read_bytes())
        require(len(sources) == 5, 'FIVE_PACKAGING_SOURCES_REQUIRED')
        for name, digest in sources.items():
            p = PurePosixPath(name)
            require(str(p) == name and not p.is_absolute() and '..' not in p.parts
                    and hashlib.sha256((ROOT/name).read_bytes()).hexdigest() == digest,
                    'QUALIFIED_SOURCE_CHANGED:'+name)
        readback = Path(tmp)/'original'; readback.mkdir()
        for name in ['candidate.json', 'compiled-packages.json']:
            shutil.copyfile(root/('original-'+name), readback/name)
        spec = importlib.util.spec_from_file_location('assess_image', ROOT/'scripts/assess-storage-runtime-image-20261102.py')
        m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
        actual = m.assess(root, readback, ROOT/'evidence')
        require(actual == json.loads((root/'assessment.json').read_bytes()), 'ASSESSMENT_REPRODUCTION_REQUIRED')
        q = json.loads((root/'qualification.json').read_bytes())
        require(q['status'] == 'PASS' and q['producerSource'] == PRODUCER and q['runId'] == 41527393253
                and q['packagingAndBoundaryTests'] == 12 and q['targetOperations'] == 0
                and q['releaseAdmitted'] is False and q['overallSwG1'] == 'OPEN', 'EXACT_QUALIFICATION_REQUIRED')
        require((root/'daemon-image-id.txt').read_text().strip() == actual['configDigest']
                and bool((root/'version-smoke.txt').read_text().strip()), 'EXACT_DAEMON_IMAGE_AND_SMOKE_REQUIRED')
        output.mkdir()
        omitted = []
        for name in names:
            if name == 'runtime.docker.tar' or name == 'blobs/sha256/'+actual['layerDigest'][7:]:
                omitted.append({'name': name, 'bytes': z.getinfo(name).file_size, 'sha256': sums[name],
                                'verifiedFromOriginal': True, 'includedInMetadataArchive': False})
            else:
                p = output/name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(z.read(name))
        result = {'schema': 'ouf.storage-runtime-image-independent-readback.v1', 'status': 'PASS',
                  'artifactId': ARTIFACT, 'archiveBytes': ARCHIVE_BYTES, 'archiveSha256': ARCHIVE_SHA,
                  'checksumMembers': len(sums), 'packagingSourcesCompared': len(sources),
                  'imageConfigDigest': actual['configDigest'], 'ociManifestDigest': actual['manifestDigest'],
                  'binarySha256': actual['binarySha256'], 'scanPackages': actual['scannedPackages'],
                  'spdxPackages': actual['spdxPackages'], 'allScannedPackagesInSpdx': True,
                  'licenceNoAssertionCount': sum(p['declared'] == 'NOASSERTION' for p in actual['licenceInventory']),
                  'rawCounts': actual['acceptedApplicability']['rawCounts'],
                  'unresolvedCounts': actual['acceptedApplicability']['unresolvedCounts'],
                  'assessmentReproduced': True, 'ociAndDockerReconstructedByteForByte': True,
                  'enclosedExecutablesExecuted': False, 'targetOperations': 0,
                  'publisherSignatureVerifiedByThisScript': False,
                  'omittedMembers': omitted, 'durableReleaseCustody': 'OPEN',
                  'licenceReview': 'OPEN', 'cohortQualification': 'OPEN', 'overallSwG1': 'OPEN'}
        (output/'byte-readback.json').write_text(json.dumps(result, indent=2)+'\n')
        return result


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(); p.add_argument('archive', type=Path); p.add_argument('output', type=Path)
    a = p.parse_args(); print(json.dumps(verify(a.archive, a.output), indent=2))
