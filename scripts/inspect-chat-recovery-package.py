#!/usr/bin/env python3
"""Check the delivered candidate bytes and derive the exact migration contract."""
import hashlib,json,os,re,stat,sys,zipfile,zlib
from pathlib import Path,PurePosixPath
def require(ok, code):
    if not ok: raise ValueError(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def blob(raw):return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def inspect(root, expected):
    root=Path(root)
    require(root.is_dir() and not root.is_symlink(),'PACKAGE_DIRECTORY_REQUIRED')
    manifest=(root/'SHA256SUMS').read_bytes()
    mapping={}
    for line in manifest.decode('ascii').splitlines():
        match=re.fullmatch(r'([0-9a-f]{64})  (.+)',line)
        require(match is not None,'HASH_MANIFEST_INVALID')
        name=match[2];p=PurePosixPath(name)
        require(str(p)==name and not p.is_absolute() and '..' not in p.parts and name not in mapping,'MEMBER_SCOPE_INVALID')
        file=root/name
        require(all(not q.is_symlink() for q in (file,*file.parents)) and file.is_file(),'MEMBER_CUSTODY_INVALID')
        require(file.stat().st_size<=1200000000,'MEMBER_BOUND')
        h=hashlib.sha256()
        with file.open('rb') as stream:
            for block in iter(lambda:stream.read(1048576),b''):h.update(block)
        require(h.hexdigest()==match[1],'MEMBER_HASH_DRIFT')
        mapping[name]=match[1]
    require(set(mapping)=={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}-{'SHA256SUMS','SHA256SUMS.sigstore.json'},'PACKAGE_CLOSURE_DRIFT')
    rows=[];metas={}
    for module,prefix in [('udp','src/main/resources/db/migration/'),('mcp','internal/adapter/postgres/migrations/')]:
        part=root/'parts'/('chat-only-recovery-part-'+module+'-39078879773')
        meta=json.loads((part/'candidate-manifest.json').read_bytes())
        require(meta['sourceCommit']==expected[module]['toCommit'] and meta['module']==module
            and meta['scanGate']=='PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED'
            and meta['targetApplyAuthorized'] is False and meta['runtimeAuthorityIssued'] is False,'CANDIDATE_BINDING_DRIFT')
        inventory=json.loads((part/'source-inventory.json').read_bytes())
        require(inventory['truncated'] is False,'SOURCE_INVENTORY_TRUNCATED')
        actual=[{'path':v['path'],'sha':v['sha']} for v in inventory['tree'] if v['path'].startswith(prefix) and v['path'].endswith('.sql')]
        require(actual==expected[module]['after'],'MIGRATION_SOURCE_DRIFT')
        metas[module]={'imageId':meta['imageId'],'sourceCommit':meta['sourceCommit'],'sourceLockSha256':meta['sourceLockSha256']}
        if module=='udp':
            with zipfile.ZipFile(part/'application.jar') as jar:
                entries=[r for r in jar.infolist() if r.filename.startswith('BOOT-INF/classes/db/migration/') and not r.is_dir()]
                require(len(entries)==36 and sum(r.file_size for r in entries)<=8388608,'JAR_MIGRATION_BOUND')
                wanted={Path(r['path']).name:r['sha'] for r in actual}
                require({Path(r.filename).name for r in entries}==set(wanted),'JAR_MIGRATION_SET_DRIFT')
                for entry in entries:
                    raw=jar.read(entry);name=Path(entry.filename).name
                    require(blob(raw)==wanted[name],'JAR_MIGRATION_BYTES_DRIFT')
                    checksum=zlib.crc32(''.join(raw.decode('utf8').removeprefix('\ufeff').splitlines()).encode())
                    rows.append({'version':re.fullmatch(r'V([0-9]+)__.+\.sql',name)[1],'script':name,
                        'checksum':checksum if checksum<2**31 else checksum-2**32,'sha256':sha(raw),'success':True})
    rows.sort(key=lambda row:int(row['version']))
    return {'schema':'ouf.chat-recovery-package-migrations.v1','manifestSha256':sha(manifest),
        'sourceLockSha256':sha((root/'source-lock.json').read_bytes()),'candidates':metas,
        'udpMigrations':rows,'mcpMigrationSourcesUnchanged':True,'runtimeMutations':0,
        'databaseStateProven':False,'rootCustodyProven':False,'readyForExecution':False,
        'completedTechnicalPhases':8,'functionalMilestonesProven':3}
if __name__=='__main__':
    try:
        require(len(sys.argv)==3,'EXACT_ARGUMENTS_REQUIRED')
        print(json.dumps(inspect(sys.argv[1],json.loads(Path(sys.argv[2]).read_bytes())),sort_keys=True))
    except Exception as error:
        print(json.dumps({'complete':False,'errorClass':type(error).__name__,'exceptionMessagePrinted':False,'runtimeMutations':0}))
        sys.exit(1)
