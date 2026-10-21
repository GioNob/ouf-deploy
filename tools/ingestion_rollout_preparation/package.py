"""Authenticate the retained scanned ZIP without extraction or target effects."""
import hashlib
import io
import json
import re
import stat
import zipfile
from pathlib import PurePosixPath

SOURCE='0fe0de60c6d980fe97610acf195d4bfd46d3777f'
IMAGE='sha256:5dfdf2239fa9eb3ae2ff8510521322cf91718bc787eee179db8e65c515a30e8b'
ZIP_SHA='02974a024e66d2f3adb9933f654954868598f6dfcec8899bf76daced9a1aeb02'
ZIP_BYTES=352127312
LOCK_SHA='5f9b0af870f123ca804d4ac0e63613728c13bcff75b590235464e4e49c5a8a83'
LIMIT=2147483648

def require(ok,code):
    if not ok:raise ValueError(code)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def hashed(stream,maximum):
    h=hashlib.sha256();size=0
    for block in iter(lambda:stream.read(1048576),b''):
        size+=len(block);require(size<=maximum,'BOUNDED_PACKAGE_BYTES_REQUIRED');h.update(block)
    return h.hexdigest(),size

def parsed(raw):
    def unique(rows):
        result={}
        for k,v in rows:
            require(k not in result,'UNIQUE_PACKAGE_JSON_KEYS_REQUIRED');result[k]=v
        return result
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:require(False,'FINITE_PACKAGE_JSON_REQUIRED'))

def inventory(stream,expected_sha=ZIP_SHA,expected_bytes=ZIP_BYTES):
    stream.seek(0);require(hashed(stream,LIMIT)==(expected_sha,expected_bytes),'EXACT_SCANNED_ZIP_REQUIRED');stream.seek(0)
    with zipfile.ZipFile(stream)as z:
        rows=z.infolist();require(1<=len(rows)<=128,'BOUNDED_PACKAGE_INDEX_REQUIRED');files={};total=0
        for row in rows:
            p=PurePosixPath(row.filename);mode=row.external_attr>>16
            require(not p.is_absolute()and '..'not in p.parts and str(p)==row.filename
                    and not row.is_dir()and row.filename not in files and not row.flag_bits&1
                    and stat.S_IFMT(mode)in(0,stat.S_IFREG)and 0<row.file_size<=LIMIT,'SAFE_UNIQUE_PACKAGE_MEMBERS_REQUIRED')
            total+=row.file_size;require(total<=LIMIT,'BOUNDED_EXPANDED_PACKAGE_REQUIRED');files[row.filename]=row
        require('SHA256SUMS'in files and files['SHA256SUMS'].file_size<=32768,'BOUNDED_PACKAGE_CHECKSUMS_REQUIRED')
        checks={}
        for line in z.read(files['SHA256SUMS']).decode('ascii').splitlines():
            match=re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_./-]+)',line)
            require(match and match[2]not in checks,'EXACT_UNIQUE_PACKAGE_CHECKSUMS_REQUIRED');checks[match[2]]=match[1]
        require(set(checks)==set(files)-{'SHA256SUMS'},'COMPLETE_PACKAGE_CHECKSUM_SET_REQUIRED')
        for name,wanted in checks.items():
            with z.open(files[name])as f:require(hashed(f,LIMIT)==(wanted,files[name].file_size),'PACKAGE_MEMBER_DIGEST_DRIFT')
        needed={'image.docker.tar','application.jar','candidate-manifest.json','package-record.json','trivy-image.json','source-inventory.json'}
        require(needed<=set(files),'COMPLETE_SCANNED_PACKAGE_REQUIRED')
        require(all(files[n].file_size<=16777216 for n in needed-{'image.docker.tar','application.jar'}),'BOUNDED_PACKAGE_METADATA_REQUIRED')
        manifest=parsed(z.read(files['candidate-manifest.json']))
        require(manifest.get('sourceCommit')==SOURCE and manifest.get('imageId')==IMAGE
                and manifest.get('sourceLockSha256')==LOCK_SHA and manifest.get('module')=='ingestion'
                and manifest.get('repository')=='GioNob/ouf-ingestion-runtime'
                and manifest.get('scanGate')=='PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED'
                and manifest.get('runtimeAuthorityIssued')is False and manifest.get('targetApplyAuthorized')is False,
                'EXACT_QUALIFIED_PACKAGE_PROVENANCE_REQUIRED')
        record=parsed(z.read(files['package-record.json']))
        require(record.get('sourceCommit')==SOURCE and record.get('imageId')==IMAGE and record.get('module')=='ingestion',
                'EXACT_PACKAGE_IMAGE_RECORD_REQUIRED')
        scan=parsed(z.read(files['trivy-image.json']))
        require(scan.get('SchemaVersion')==2 and scan.get('Metadata',{}).get('ImageID')==IMAGE
                and type(scan.get('Results'))is list,'SCANNED_IMAGE_REPORT_BINDING_REQUIRED')
        coverage={(r.get('Class'),r.get('Type'))for r in scan['Results']}
        require(('lang-pkgs','jar')in coverage and any(c=='os-pkgs'for c,_ in coverage),'SCANNER_COVERAGE_REQUIRED')
        for row in scan['Results']:
            require(row.get('Class')in('os-pkgs','lang-pkgs')and type(row.get('Vulnerabilities',[]))is list,'CLOSED_SCANNER_REPORT_REQUIRED')
            for finding in row.get('Vulnerabilities',[]):
                require(finding.get('Severity')in('LOW','MEDIUM'),'HIGH_CRITICAL_UNKNOWN_SCAN_GATE_BLOCKED')
        return {'schema':'ouf.ingestion-scanned-package-custody.v1','zipSha256':expected_sha,'zipBytes':expected_bytes,
                'files':{n:{'sha256':checks[n],'bytes':files[n].file_size}for n in checks},
                'sourceCommit':SOURCE,'imageId':IMAGE,'sourceLockSha256':LOCK_SHA,'scanGate':manifest['scanGate'],
                'runtimeAuthorityIssued':False,'targetApplyAuthorized':False}

def copy_member(stream,name,output,proof):
    require(name in proof['files'],'EXACT_AUTHENTICATED_PACKAGE_MEMBER_REQUIRED')
    stream.seek(0);h=hashlib.sha256();size=0
    with zipfile.ZipFile(stream)as z,z.open(name)as f:
        for block in iter(lambda:f.read(1048576),b''):
            size+=len(block);require(size<=proof['files'][name]['bytes'],'PACKAGE_MEMBER_CHANGED');h.update(block);output.write(block)
    require((h.hexdigest(),size)==(proof['files'][name]['sha256'],proof['files'][name]['bytes']),'PACKAGE_MEMBER_CHANGED')

def jar_proof(raw,sql_manifest):
    require(type(raw)is bytes and 0<len(raw)<=268435456,'BOUNDED_APPLICATION_JAR_REQUIRED')
    with zipfile.ZipFile(io.BytesIO(raw))as z:
        rows=z.infolist();require(len(rows)<=20000 and len({r.filename for r in rows})==len(rows),'UNIQUE_BOUNDED_JAR_REQUIRED')
        expected={'BOOT-INF/classes/db/migration/'+r['script']:r['resourceSha256']for r in sql_manifest['migrations']}
        selected={r.filename:r for r in rows if r.filename.startswith('BOOT-INF/classes/db/migration/')and not r.is_dir()}
        require(len(expected)==18 and set(selected)==set(expected),'EXACT18_UNCHANGED_MIGRATION_SET_REQUIRED')
        for name,wanted in expected.items():
            row=selected[name];require(not row.flag_bits&1 and 0<row.file_size<=1048576 and sha(z.read(row))==wanted,
                                       'EXACT18_UNCHANGED_MIGRATION_BYTES_REQUIRED')
        require(any(r.filename.endswith('/IngestionValidateOnlyStartup.class')for r in rows),'QUALIFIED_STARTUP_GUARD_CLASS_REQUIRED')
    return {'jarSha256':sha(raw),'migrationCount':18,'sqlBytesUnchanged':True,'runtimeAuthorityIssued':False}
