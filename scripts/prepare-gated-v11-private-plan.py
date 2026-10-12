"""Prepare a new private gate request and all retained mount metadata.

No native commands, source-file content/key reads, signatures, image import,
runtime authority or target application effects. Original intake stays intact.
The ZIP/config bytes are verified for integrity; publisher crypto is separate.
"""
import hashlib,json,os,re,signal,stat,sys,tarfile,types,zipfile
from pathlib import Path
HASHES={'atomic':'c113f578b027c39573b4562cd3ac324abb8108a393b82dde19f8eb53d98e0ea6',
        'publisher':'6ec32cdd81af7fd8e70b4dc2f876ecfabfd2772c1cd6fba70b8e9e4bafe9f666',
        'journal':'ac21979816e4eb0fadfd4fba6035830a0e16e7a53164de5a831856e11271377a',
        'gate':'a4e13489d52697117246f979c42a2df766d19f67c7a99e0922c3bb4ac6b45c44'}
BASE=Path('/etc/ouf/deploy-snapshots')
PARENT_HASH='9ec18cf053e5925e42df93b75990343cc1d09696975fc2a224d76b4b28becdae'
PARENT=BASE/('semantic-native-v11-intake-'+PARENT_HASH)
ZIP=Path('/home/oufadmin/ouf-durable-v11-stage.drTnFl4m/semantic.zip')
ZIP_SHA='b6ae1051cee4ec9fb1b28f532622ecd39e038ec2e6a384d50565cbf92f2a0def'
CONFIG_SHA='83635be46d1fe61dea08597ea4488980b4349e5f6e0ed8bbd3ab6f5e2686370e'
def require(ok,reason):
    if not ok:raise ValueError(reason)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def modules(sources):
    require(type(sources) is dict and set(sources)==set(HASHES),'EXACT_GATED_PLANNER_SOURCE_SET_REQUIRED')
    for name,value in sources.items():require(type(value) is bytes and len(value)<=131072 and sha(value)==HASHES[name],'GATED_PLANNER_SOURCE_HASH_MISMATCH')
    result={}
    for name in ('atomic','publisher','journal','gate'):
        m=types.ModuleType('sealed_gated_planner_'+name)
        if name=='journal':sys.modules['transition_journal']=m
        exec(compile(sources[name],m.__name__,'exec'),m.__dict__);result[name]=m
    return result
def metadata(path,max_entries=512,max_depth=16):
    """No-follow bounded metadata only; never open a mounted source file."""
    path=Path(path);require(path.is_absolute() and '..' not in path.parts and path!=Path('/'),'EXACT_MOUNT_METADATA_PATH_REQUIRED')
    records=[]
    def visit(item,relative,depth):
        require(depth<=max_depth and len(records)<max_entries,'MOUNT_METADATA_BOUND_EXCEEDED');s=item.lstat()
        kind='directory' if stat.S_ISDIR(s.st_mode) else 'file' if stat.S_ISREG(s.st_mode) else 'symlink' if stat.S_ISLNK(s.st_mode) else 'special'
        records.append({'path':relative,'kind':kind,'device':s.st_dev,'inode':s.st_ino,'uid':s.st_uid,'gid':s.st_gid,
                        'mode':stat.S_IMODE(s.st_mode),'links':s.st_nlink,'size':s.st_size,'mtimeNs':s.st_mtime_ns,'ctimeNs':s.st_ctime_ns})
        if kind=='directory':
            # Directory enumeration only. No link is traversed and no file
            # content is read, including any old private-key files.
            names=sorted(os.listdir(item));require(len(names)+len(records)<=max_entries,'MOUNT_METADATA_BOUND_EXCEEDED')
            for name in names:visit(item/name,relative+'/'+name if relative else name,depth+1)
        require((s.st_dev,s.st_ino,s.st_mode,s.st_mtime_ns,s.st_ctime_ns)==tuple(getattr(item.lstat(),k) for k in ('st_dev','st_ino','st_mode','st_mtime_ns','st_ctime_ns')),'MOUNT_METADATA_CHANGED_DURING_READ')
    visit(path,'',0);return records
def image_configuration(path,expected_zip=ZIP_SHA,expected_config=CONFIG_SHA):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(fd);require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=4294967296,'BOUNDED_ORIGINAL_V11_ZIP_REQUIRED')
        h=hashlib.sha256()
        while block:=stream.read(1048576):h.update(block)
        require(h.hexdigest()==expected_zip,'ORIGINAL_V11_ZIP_BYTES_DRIFT');stream.seek(0)
        with zipfile.ZipFile(stream) as package:
            members=[m for m in package.infolist() if Path(m.filename).name=='image.docker.tar']
            require(len(members)==1 and 0<members[0].file_size<=4294967296,'EXACT_ORIGINAL_IMAGE_ARCHIVE_REQUIRED');configs=[];count=0
            with package.open(members[0]) as archive,tarfile.open(fileobj=archive,mode='r|*') as tar:
                for item in tar:
                    count+=1;require(count<=64,'IMAGE_ARCHIVE_MEMBER_BOUND_EXCEEDED')
                    if item.name in (expected_config+'.json','blobs/sha256/'+expected_config):
                        require(item.isfile() and 0<item.size<=131072,'EXACT_IMAGE_CONFIGURATION_ENTRY_REQUIRED')
                        raw=tar.extractfile(item).read(131073);require(len(raw)==item.size and sha(raw)==expected_config,'IMMUTABLE_IMAGE_CONFIGURATION_DRIFT');configs.append(json.loads(raw))
            require(len(configs)==1,'ONE_IMMUTABLE_IMAGE_CONFIGURATION_REQUIRED')
        after=os.fstat(fd);require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'ORIGINAL_ZIP_CHANGED_DURING_PLAN')
        return configs[0]
def mount_metadata(declaration):
    old=declaration['retainedNativeCreationFrame']['Mounts'];require(type(old) is list and len(old)==2,'EXACT_TWO_RETAINED_MOUNTS_REQUIRED')
    result=[]
    for mount in old:
        require(type(mount) is dict and mount.get('Type') in ('bind','volume') and mount.get('RW') is False,'EXACT_RETAINED_READONLY_MOUNT_REQUIRED')
        result.append({'binding':mount,'sourceMetadata':metadata(mount['Source'])})
    return result
def main():
    os.umask(0o077);report={'schema':'ouf.semantic-gated-v11-private-preparation.v1','protectedFileWrites':0,'protectedFileWriteAttempts':0,
        'budgetReset':False,'r12Touched':False,'applicationCutoverAuthorized':False,'productionApplyReady':False,'runtimeAuthorityIssued':False,
        'containerLifecycleOperations':0,'databaseQueries':0,'databaseWrites':0,'providerCalls':0,'dnsQueries':0,'firewallWrites':0,
        'imageImports':0,'signaturesIssued':0,'privateKeysRead':0,'mountedSourceContentBytesRead':0,'privateValuesPrinted':False,
        'commonLeaseLockAcquired':False,'observationsAreHistorical':True,'notReleaseAcceptance':True,
        'preparationProfile':'ouf.gated-v11-private-preparation.v1','maxPreparationSeconds':120}
    try:
        require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode and len(sys.argv)==1,'ISOLATED_ROOT_GATED_PLAN_REQUIRED')
        def deadline(*args):raise TimeoutError('GATED_PRIVATE_PREPARATION_DEADLINE_EXCEEDED')
        signal.signal(signal.SIGALRM,deadline);signal.alarm(120)
        m=modules(globals().get('__gated_sources__'));atomic,publisher,gate=m['atomic'],m['publisher'],m['gate']
        raw_manifest=atomic.read(PARENT/'intake.json',0);require(sha(raw_manifest)==PARENT_HASH,'EXACT_PARENT_NATIVE_INTAKE_REQUIRED');manifest=json.loads(raw_manifest)
        files={name:atomic.read(PARENT/name,0) for name in publisher.NAMES};atomic.verify(PARENT,files,raw_manifest,0);values=publisher.validate(files)
        declaration,parent=values[publisher.NAMES[0]],values[publisher.NAMES[1]]
        config=image_configuration(ZIP);request,proposal=gate.compile_gate(parent,publisher.EXPECTED['requestHash'],config)
        legacy=mount_metadata(declaration)
        require(all(atomic.read(PARENT/name,0)==raw for name,raw in files.items()) and atomic.read(PARENT/'intake.json',0)==raw_manifest
                and mount_metadata(declaration)==legacy,'PARENT_OR_LEGACY_METADATA_CHANGED')
        source_hash=globals().get('__sealed_program_sha__');require(type(source_hash) is str and re.fullmatch('[0-9a-f]{64}',source_hash),'SEALED_GATED_PLANNER_REQUIRED')
        prepared={'gated-creation-request.private.json':encoded(request),'gate-proposal.json':encoded(proposal),
                  'retained-mount-metadata.private.json':encoded(legacy),'parent-review-reference.json':encoded({'intakeHash':PARENT_HASH,'fileHashes':manifest['fileHashes'],'declarationHash':publisher.EXPECTED['declarationHash']})}
        output_manifest={'schema':'ouf.native-v11-atomic-review-intake.v1','purpose':'GATED_REQUEST_AND_FULL_RETAINED_MOUNT_METADATA_ONLY',
                         'fileHashes':{n:sha(raw) for n,raw in prepared.items()},'sourceHashes':{'program':source_hash,**HASHES},
                         'parentIntakeHash':PARENT_HASH,'applicationCutoverAuthorized':False,'productionApplyReady':False,
                         'runtimeAuthorityIssued':False,'observationsAreHistorical':True,'notReleaseAcceptance':True}
        def checkpoint(point):
            if point.startswith('BEFORE_FILE_'):report['protectedFileWriteAttempts']+=1
            if point.startswith('AFTER_FILE_'):report['protectedFileWrites']+=1
        report.update(atomic.publish(BASE,prepared,output_manifest,0,checkpoint));report.update(status='GATED_V11_REQUEST_AND_RETAINED_METADATA_PREPARED_NOT_APPLY_READY',
            creationRequestHash=sha(prepared['gated-creation-request.private.json']),gateProposalHash=sha(prepared['gate-proposal.json']),
            qualifiedZipBytesReverified=True,imageConfigurationBytesReverified=True,publisherCryptoVerifiedHere=False,
            parentIntakePreserved=True,retainedMountCount=len(legacy),gatedPlanNeedsNewHumanAuthority=True,completeSixMountClosureProven=False,
            plannedHostnameExplicit=bool(request.get('Hostname')),retainedMounts=[{'kind':v['sourceMetadata'][0]['kind'],
                'readOnly':True,'entryCount':len(v['sourceMetadata']),'fileCount':sum(r['kind']=='file' for r in v['sourceMetadata']),
                'directoryCount':sum(r['kind']=='directory' for r in v['sourceMetadata']),'symlinkCount':sum(r['kind']=='symlink' for r in v['sourceMetadata']),
                'sourceUid':v['sourceMetadata'][0]['uid'],'sourceGid':v['sourceMetadata'][0]['gid'],'sourceMode':v['sourceMetadata'][0]['mode'],
                'metadataHash':sha(encoded(v['sourceMetadata']))} for v in legacy]);code=0
    except Exception as error:
        reason=str(error);report.update(status='GATED_V11_PRIVATE_PREPARATION_BLOCKED',reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,120}',reason) else 'GATED_V11_PRIVATE_PREPARATION_UNPROVEN');code=1
        if report['protectedFileWriteAttempts']>report['protectedFileWrites']:report.update(protectedFileWrites=None,privateWriteOutcomeRequiresReconciliation=True)
    finally:signal.alarm(0)
    print('OUF_GATED_V11_PRIVATE_PREPARATION='+json.dumps(report,sort_keys=True));return code
if __name__=='__main__':raise SystemExit(main())
