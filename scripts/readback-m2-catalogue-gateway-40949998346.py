"""Read a source-only package and separately supplied immutable GitHub tree.

No extraction, execution of packaged code, network, signature acceptance or
runtime/target admission. The caller obtains the tree through GitHub separately.
"""
import argparse,collections,hashlib,io,json,re,stat,tarfile,zipfile
from pathlib import Path,PurePosixPath

ROOT=Path(__file__).resolve().parent
EXPECTED_SOURCE='c666c0f0080b8802fc71daa27c32a0af2ed98544'
EXPECTED_PRODUCER='18773790fe0874486cf94abd8eb40be951d0788f'
EXPECTED_ARCHIVE='22cd26a29460de69d9aae9392cebad2a3eca28b3b6bc0153bbaab7b68aa24441'


def canonical(name):
    path=PurePosixPath(name)
    assert not path.is_absolute() and '..' not in path.parts and str(path)==name and name not in ('','.','..')
    return name


def main(directory=None):
    global ROOT
    if directory is not None:ROOT=Path(directory).resolve()
    raw=(ROOT/'gateway.zip').read_bytes();assert len(raw)==1658434
    assert hashlib.sha256(raw).hexdigest()==EXPECTED_ARCHIVE
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        infos=archive.infolist();assert 1<=len(infos)<=32
        assert len({v.filename for v in infos})==len(infos)
        assert sum(v.file_size for v in infos)<=8388608
        assert all(not stat.S_ISLNK(v.external_attr>>16) for v in infos)
        payload={canonical(v.filename):archive.read(v) for v in infos if not v.is_dir()}
    sums={}
    for line in payload['SHA256SUMS'].decode('ascii').splitlines():
        digest,name=line.split('  ',1);canonical(name)
        assert re.fullmatch('[a-f0-9]{64}',digest) and name not in sums
        sums[name]=digest
    assert set(sums)==set(payload)-{'SHA256SUMS'}
    for name,digest in sums.items():assert hashlib.sha256(payload[name]).hexdigest()==digest
    record=json.loads(payload['package-record.json']);producer=json.loads(payload['producer.json'])
    assert record['sourceCommit']==producer['applicationSourceCommit']==EXPECTED_SOURCE
    assert producer['producerCommit']==EXPECTED_PRODUCER
    assert record['artifactKind']=='SOURCE_AND_MATERIALIZERS_NOT_TARGET_ROUTES'
    assert record['routePackageTargetBound'] is record['transitiveRuntimeAdmissionProven'] is False
    assert all(record[k] is False and producer[k] is False for k in ('runtimeAuthorityIssued','targetApplyAuthorized','releaseAcceptance'))
    github=json.loads((ROOT/'github-tree.json').read_text());files={}
    with tarfile.open(fileobj=io.BytesIO(payload['source.tar']),mode='r:') as source:
        entries=source.getmembers();assert 1<=len(entries)<=2048
        assert sum(v.size for v in entries)<=16777216
        for entry in entries:
            if entry.isdir():canonical(entry.name.rstrip('/'));continue
            assert entry.isfile() and not entry.issym() and not entry.islnk()
            name=canonical(entry.name);assert name not in files and name in github
            data=source.extractfile(entry).read();assert len(data)==entry.size
            blob=b'blob '+str(len(data)).encode()+b'\0'+data
            assert hashlib.sha1(blob).hexdigest()==github[name]['sha']
            assert entry.mode&0o777==(0o755 if github[name]['mode']=='100755' else 0o644)
            files[name]=data
    assert set(files)==set(github)
    inventory=json.loads(payload['source-inventory.json']);assert set(inventory)==set(files)
    for name,digest in inventory.items():assert hashlib.sha256(files[name]).hexdigest()==digest
    materializers=json.loads(payload['materializer-inventory.json']);assert len(materializers)==10
    assert {'tools/mcp_union_projection.py','schemas/mcp-gateway-permissions-dispatch-v1.json',
        'tools/materialize_permission_proposals.py','tools/lua/execute_permissions.lua'}<=set(materializers)
    for name,digest in materializers.items():assert hashlib.sha256(files[name]).hexdigest()==digest
    assert payload['gateway-scan/requirements.txt']==files['requirements-dev.txt']
    scan=json.loads(payload['trivy-image.json']);results=scan['Results']
    assert scan['ArtifactType']=='filesystem' and scan['ArtifactName'].endswith('package/gateway-scan')
    assert any(v.get('Type')=='pip' and v.get('Target')=='requirements.txt' and v.get('Packages') for v in results)
    severities=collections.Counter(v.get('Severity','UNKNOWN') for result in results for v in result.get('Vulnerabilities',[]))
    assert not any(severities[v] for v in ('HIGH','CRITICAL','UNKNOWN'))
    output={'schema':'ouf.m2-catalogue-gateway-offline-readback.v1','sourceCommit':EXPECTED_SOURCE,
        'producerCommit':EXPECTED_PRODUCER,'runId':40949998346,'jobId':123715265457,'artifactId':12930098785,
        'archiveSha256':EXPECTED_ARCHIVE,'archiveBytes':len(raw),'sourceBlobsCompared':len(files),
        'payloadHashesVerified':len(sums),'materializerFilesVerified':len(materializers),
        'sourceBytesMatchGithubTree':True,'sourceInventoryComplete':True,
        'archiveEntryModesMatchGithubExecutableBitsAndAreNotGroupWritable':True,
        'permissionCatalogueAndDiscoveryMaterializersIncluded':True,
        'reportedSeverityCounts':{v:severities[v] for v in ('LOW','MEDIUM','HIGH','CRITICAL','UNKNOWN')},
        'severityFilteredReport':True,'lowAndMediumAbsenceProven':False,'targetRoutesMaterialized':False,
        'cryptographicPublisherTrustAccepted':False,'transitiveRuntimeAdmissionProven':False,
        'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'stableCapabilitiesOperationalProven':False,
        'applicationE2EProven':False,'releaseAcceptance':False}
    (ROOT/'result.json').write_text(json.dumps(output,sort_keys=True,indent=2)+'\n')
    print(json.dumps(output,sort_keys=True))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--directory',required=True)
    main(parser.parse_args().directory)
