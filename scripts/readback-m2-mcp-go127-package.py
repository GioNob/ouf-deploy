"""Offline MCP package readback against a separately obtained GitHub tree.

Never extracts or executes source/image code, contacts a host, accepts publisher
signatures or grants admission. Go build info is decoded from the ELF section,
following the official Go1.27.3 debug/buildinfo inline-string format.
"""
import argparse,collections,hashlib,io,json,re,stat,struct,sys,tarfile,zipfile
from pathlib import Path,PurePosixPath

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools/semantic_application_cutover'))
from image_custody import archive as image_archive,parsed

SOURCE='9539cbb40e09d10a76fb4b72368438f9772c7690'
PAYLOADS={'Dockerfile.resolved','go-build-info.txt','image.docker.tar','ouf-mcp',
    'package-record.json','producer.json','sbom.cdx.json','source-inventory.json','source.tar','trivy-image.json'}


def canonical(name):
    p=PurePosixPath(name)
    assert not p.is_absolute() and '..' not in p.parts and str(p)==name and name not in ('','.','..')
    return name


def go_build_info(raw):
    assert raw[:6]==b'\x7fELF\x02\x01' and struct.unpack_from('<H',raw,18)[0]==62
    offset=struct.unpack_from('<Q',raw,40)[0];size,count,names_index=struct.unpack_from('<HHH',raw,58)
    assert size==64 and 0<count<=4096 and names_index<count and offset+size*count<=len(raw)
    sections=[struct.unpack_from('<IIQQQQIIQQ',raw,offset+size*i) for i in range(count)]
    names=sections[names_index];assert names[4]+names[5]<=len(raw)
    strings=raw[names[4]:names[4]+names[5]]
    selected=[]
    for section in sections:
        assert section[0]<len(strings)
        if strings[section[0]:].split(b'\0',1)[0]==b'.go.buildinfo':selected.append(section)
    assert len(selected)==1
    section=selected[0];assert section[3]%16==0 and 32<section[5]<=1048576 and section[4]+section[5]<=len(raw)
    data=raw[section[4]:section[4]+section[5]]
    assert data[:14]==b'\xff Go buildinf:' and data[14]==8 and data[15]==2
    def string(position):
        length=0
        for i in range(10):
            assert position<len(data);byte=data[position];position+=1;length|=(byte&127)<<(7*i)
            if byte<128:break
        else:raise AssertionError('INVALID_GO_BUILD_INFO_VARINT')
        assert length<=1048576 and position+length<=len(data)
        return data[position:position+length],position+length
    version,position=string(32);module,_=string(position)
    assert version==b'go1.27.3' and len(module)>=33 and module[-17]==10
    lines=module[16:-16].decode().splitlines()
    assert 'path\tgithub.com/GioNob/ouf-mcp-server/cmd/ouf-mcp' in lines
    sdk=[line.split('\t') for line in lines if line.startswith('dep\tgithub.com/modelcontextprotocol/go-sdk\t')]
    assert len(sdk)==1 and len(sdk[0])==4 and sdk[0][2]=='v1.7.0'
    for value in ('CGO_ENABLED=0','GOOS=linux','GOARCH=amd64'):
        assert 'build\t'+value in lines
    return {'goVersion':version.decode(),'mcpSdk':sdk[0][2],'mcpSdkChecksum':sdk[0][3],
        'format':'ELF64_AMD64_GO_INLINE_BUILDINFO','cgoEnabled':False}


def image_binary(raw):
    binary=None;target=PurePosixPath('usr/local/bin/ouf-mcp');ancestors=set(target.parents)
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as image:
        manifest=parsed(image.extractfile('manifest.json').read());assert len(manifest)==1
        for layer in manifest[0]['Layers']:
            with image.extractfile(layer) as stream,tarfile.open(fileobj=stream,mode='r:*') as tar:
                members=tar.getmembers();assert len(members)<=100000
                def name(member):
                    value=member.name[2:] if member.name.startswith('./') else member.name
                    path=PurePosixPath(value);assert not path.is_absolute() and '..' not in path.parts
                    return path
                # OCI whiteouts remove lower-layer entries before this layer's additions.
                for member in members:
                    path=name(member)
                    if path.name=='.wh..wh..opq' and path.parent in ancestors:binary=None
                    elif path.name.startswith('.wh.'):
                        removed=path.parent/path.name[4:]
                        if removed==target or removed in ancestors:binary=None
                    assert not (path in ancestors and (member.issym() or member.islnk()))
                matching=[member for member in members if name(member)==target]
                assert len(matching)<=1
                if matching:
                    member=matching[0];assert member.isfile() and 0<member.size<=67108864
                    binary=tar.extractfile(member).read();assert len(binary)==member.size
    assert binary is not None
    return binary


def main(args):
    root=Path(args.directory).resolve();raw=(root/args.archive_name).read_bytes()
    assert len(raw)==args.archive_bytes and hashlib.sha256(raw).hexdigest()==args.archive_sha256
    assert re.fullmatch('[a-f0-9]{40}',args.producer)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries=archive.infolist();assert len(entries)==len(PAYLOADS)+1
        assert sum(v.file_size for v in entries)<=134217728
        assert len({v.filename for v in entries})==len(entries)
        assert all(not stat.S_ISLNK(v.external_attr>>16) for v in entries)
        payload={canonical(v.filename):archive.read(v) for v in entries if not v.is_dir()}
    assert set(payload)==PAYLOADS|{'SHA256SUMS'}
    sums={}
    for line in payload['SHA256SUMS'].decode('ascii').splitlines():
        digest,name=line.split('  ',1);canonical(name)
        assert re.fullmatch('[a-f0-9]{64}',digest) and name not in sums
        sums[name]=digest
    assert set(sums)==PAYLOADS
    for name,digest in sums.items():assert hashlib.sha256(payload[name]).hexdigest()==digest
    record=parsed(payload['package-record.json']);producer=parsed(payload['producer.json'])
    assert record['sourceCommit']==producer['applicationSourceCommit']==SOURCE
    assert producer['producerCommit']==args.producer and producer['module']==record['module']=='mcp'
    assert record['runtimeUser']=='10005:10005' and record['notReleaseAcceptance'] is True
    assert record['signatureIssued'] is record['targetApplyAuthorized'] is False
    assert all(producer[k] is False for k in ('runtimeAuthorityIssued','targetApplyAuthorized','applicationE2EProven','releaseAcceptance'))
    tree=parsed((root/'source-tree.json').read_bytes());assert tree['truncated'] is False
    github={e['path']:e for e in tree['tree'] if e['type']=='blob'};files={}
    with tarfile.open(fileobj=io.BytesIO(payload['source.tar']),mode='r:') as source:
        members=source.getmembers();assert 0<len(members)<=4096 and sum(m.size for m in members)<=33554432
        for member in members:
            if member.isdir():
                canonical(member.name.rstrip('/'));assert not member.mode&0o022,'SOURCE_ARCHIVE_DIRECTORY_MODE_DRIFT';continue
            assert member.isfile() and not member.issym() and not member.islnk()
            name=canonical(member.name);assert name in github and name not in files
            data=source.extractfile(member).read();assert len(data)==member.size
            assert hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==github[name]['sha']
            assert member.mode&0o777==(0o755 if github[name]['mode']=='100755' else 0o644),'SOURCE_ARCHIVE_MODE_DRIFT'
            files[name]=data
    assert set(files)==set(github)
    inventory=parsed(payload['source-inventory.json']);assert inventory['truncated'] is False
    assert {e['path']:(e['mode'],e['type'],e['sha']) for e in inventory['tree']}=={
        name:(e['mode'],e['type'],e['sha']) for name,e in github.items()}
    assert b'go 1.27.3\n' in files['go.mod']
    for base in record['baseImages']:
        assert re.fullmatch(r'.+@sha256:[a-f0-9]{64}',base['resolved'])
        assert base['resolved'].encode() in payload['Dockerfile.resolved']
    with io.BytesIO(payload['image.docker.tar']) as stream:
        audit=image_archive(stream,sums['image.docker.tar'],record['imageId'],SOURCE)
    assert audit['imageConfig']['User']=='10005:10005'
    assert image_binary(payload['image.docker.tar'])==payload['ouf-mcp']
    binary=go_build_info(payload['ouf-mcp'])
    assert ('github.com/modelcontextprotocol/go-sdk v1.7.0 '+binary['mcpSdkChecksum']).encode() in files['go.sum']
    info=payload['go-build-info.txt'].decode()
    assert 'go1.27.3' in info and 'github.com/modelcontextprotocol/go-sdk\tv1.7.0' in info
    scan=parsed(payload['trivy-image.json']);assert scan['SchemaVersion']==2 and scan['Metadata']['ImageID']==record['imageId']
    coverage={(r.get('Class'),r.get('Type')) for r in scan['Results']}
    assert ('lang-pkgs','gobinary') in coverage and any(c=='os-pkgs' for c,_ in coverage)
    severities=collections.Counter(v.get('Severity','UNKNOWN') for r in scan['Results'] for v in r.get('Vulnerabilities',[]))
    assert not any(severities[v] for v in ('HIGH','CRITICAL','UNKNOWN'))
    sbom=parsed(payload['sbom.cdx.json']);assert sbom['bomFormat']=='CycloneDX' and sbom['components']
    assert any(c.get('name')=='github.com/modelcontextprotocol/go-sdk' and c.get('version')=='v1.7.0' for c in sbom['components'])
    output={'schema':'ouf.m2-mcp-go127-offline-readback.v1','sourceCommit':SOURCE,'producerCommit':args.producer,
        'artifactId':args.artifact_id,'archiveSha256':args.archive_sha256,'archiveBytes':len(raw),'imageId':record['imageId'],
        'sourceBlobsCompared':len(files),'sourceBytesAndModesMatchGithubTree':True,'payloadHashesVerified':len(sums),
        'allLayerDiffIdsVerified':True,'imageConfigBytesVerified':True,'binaryBytesMatchImageLayer':True,
        'executableSha256':sums['ouf-mcp'],'goBuildInfoDecodedFromElf':binary,'runtimeUser':'10005:10005',
        'baseImages':record['baseImages'],'sbomFormat':'CycloneDX','sbomComponents':len(sbom['components']),
        'reportedSeverityCounts':{v:severities[v] for v in ('LOW','MEDIUM','HIGH','CRITICAL','UNKNOWN')},
        'severityFilteredReport':False,'fileSha256':sums,'cryptographicPublisherTrustAccepted':False,
        'currentNativeAdmissionProven':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,
        'applicationE2EProven':False,'releaseAcceptance':False}
    (root/'result.json').write_text(json.dumps(output,sort_keys=True,indent=2)+'\n')
    print(json.dumps(output,sort_keys=True))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('directory','archive-name','archive-sha256','producer'):parser.add_argument('--'+name,required=True)
    for name in ('archive-bytes','artifact-id'):parser.add_argument('--'+name,required=True,type=int)
    main(parser.parse_args())
