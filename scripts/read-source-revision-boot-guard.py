#!/usr/bin/env python3
"""One bounded protected boot diagnosis. No service start, guard execution or repair."""
import hashlib,importlib.util,json,os,re,signal,stat,subprocess,sys,traceback
from pathlib import Path

KNOWN={'boot':'ff8d1e483496f9201f9663f58cc3f942c4b6c2ef9041743d52419050fe8134c6',
       'owner':'c2937a39578311018d47c0d414e6687278ce8b6b103de62c422cfe7b760b6889',
       'restorer':'cceab662620d1abf97c09be1147c79e4e43022298cb0560dc604ed4bdeb6a606',
       'compiler':'98e3004300226fecd509a46c009585df14021927f20d4e5c82d8ff7a8a8180de'}

def require(ok,code):
    if not ok:raise ValueError(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def parse(raw):
    def unique(pairs):
        value={}
        for key,item in pairs:require(key not in value,'DUPLICATE_METADATA_KEY');value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=unique)
def read(path,maximum=2097152):
    path=Path(path);require(path.is_absolute()and'..'not in path.parts,'EXACT_READ_PATH_REQUIRED')
    for parent in path.parents:
        info=parent.lstat();require(stat.S_ISDIR(info.st_mode)and info.st_uid==0 and not info.st_mode&0o022,'ROOT_READ_CUSTODY_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        first=os.fstat(fd);require(stat.S_ISREG(first.st_mode)and first.st_uid==0 and first.st_nlink==1
            and not first.st_mode&0o022 and 0<=first.st_size<=maximum,'BOUNDED_ROOT_METADATA_REQUIRED')
        chunks=[];size=0
        while size<=maximum:
            part=os.read(fd,min(65536,maximum+1-size))
            if not part:break
            chunks.append(part);size+=len(part)
        raw=b''.join(chunks);pin=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        require(size==first.st_size and pin(first)==pin(os.fstat(fd))==pin(path.lstat()),'METADATA_READ_CHANGED')
        return raw
    finally:os.close(fd)
def sealed(path,digest):
    require(type(digest)is str and re.fullmatch('[a-f0-9]{64}',digest),'EXACT_METADATA_HASH_REQUIRED')
    raw=read(path);require(sha(raw)==digest,'METADATA_SEAL_CHANGED');return raw
def command(argv,maximum=1048576):
    reply=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=15,
        env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    require(len(reply.stdout)<=maximum and len(reply.stderr)<=maximum,'COMMAND_OUTPUT_BOUND')
    return reply
def binding(text,parent):
    base=re.escape(str(Path(parent)))
    source=re.findall('('+base+r'/[A-Za-z0-9_-]+/source/scripts/run_semantic_coordinated_boot_guard\.py)',text)
    profile=re.findall(r'--configuration\s+('+base+r'/[A-Za-z0-9_-]+/boot-profile\.json)',text)
    digest=re.findall(r'--configuration-sha256\s+([a-f0-9]{64})(?:\s|;|$)',text)
    require(len(source)==len(profile)==len(digest)==1,'EXACT_LOADED_BOOT_COMMAND_REQUIRED')
    root=Path(profile[0]).parent
    require(root.parent==Path(parent)and Path(source[0])==root/'source/scripts/run_semantic_coordinated_boot_guard.py',
            'SAME_SEALED_BOOT_CONTEXT_REQUIRED')
    return {'source':source[0],'profile':profile[0],'sha256':digest[0]}
def load_known(path,expected,name):
    raw=sealed(path,expected);module=importlib.util.module_from_spec(importlib.util.spec_from_loader(name,loader=None))
    module.__file__=str(path);exec(compile(raw,str(path),'exec'),module.__dict__);return module
def journal_metadata(path,parent):
    require(Path(path).is_relative_to(Path(parent)),'OWNED_JOURNAL_PATH_REQUIRED')
    value=parse(read(path));out={}
    for key in ('state','schema'):
        item=value.get(key)
        if type(item)is str and re.fullmatch('[A-Za-z0-9_.-]{1,120}',item):out[key]=item
    for key in ('leaseAuthorized','startAuthorized'):
        if type(value.get(key))is bool:out[key]=value[key]
    if type(value.get('leaseAddresses'))is list:
        out['leaseAddressCounts']=[len(r)for r in value['leaseAddresses']if type(r)is list]
    return out

def failure(error):
    out={'errorClass':type(error).__name__,'exceptionMessagePrinted':False,
         'frames':[{'file':Path(f.filename).name,'function':f.name,'line':f.lineno}
                   for f in traceback.extract_tb(error.__traceback__)[-5:]]}
    # Only constants from the pinned, reviewed readers; never emit arbitrary exception text.
    reasons={'explicit configuration hash required':'OWNER_HASH_REQUIRED',
        'configuration hash drift':'OWNER_CONFIGURATION_DRIFT',
        'coordinated configuration closure required':'OWNER_CONFIGURATION_CLOSURE',
        'source closure drift':'OWNER_SOURCE_DRIFT','unsealed package initializer':'UNSEALED_INITIALIZER',
        'unsafe nft executable':'UNSAFE_NFT_EXECUTABLE','nft executable drift':'NFT_EXECUTABLE_DRIFT',
        'lease structure binding required':'LEASE_STRUCTURE_BINDING',
        'sealed profile invalid':'BOOT_PROFILE_INVALID','empty bootstrap required':'BOOT_NOT_EMPTY'}
    if type(error)is ValueError:
        reason=reasons.get(str(error))
        if reason:out['reason']=reason
    return out

def independent(report,key,call):
    try:report[key]={'passed':True,'metadata':call()}
    except Exception as error:report[key]={'passed':False,**failure(error)}

def collect(selection):
    report={'schema':'ouf.source-revision-private-boot-read.v1','completedTechnicalPhases':8,
        'functionalMilestonesProven':4,'runtimeMutations':0,'serviceStarts':0,'guardExecutions':0,
        'privateKeysRead':0,'credentialValuesPrinted':False,'rawJournalPrinted':False,
        'runtimeAuthorityIssued':False,'automaticRetry':False,'installationSpecific':True}
    stage='UNIT_METADATA'
    try:
        require(selection['schema']=='ouf.source-revision-private-boot-read-selection.v1','EXACT_SELECTION_REQUIRED')
        parent=selection['privateParent'];ctl=selection['systemctl'];units={};commands={}
        for unit,prop in ((selection['guardUnit'],'ExecStart'),(selection['dockerUnit'],'ExecStartPre')):
            reply=command([ctl,'show','--no-pager','--property=ActiveState,SubState,Result,ExecMainStatus,'+prop,unit],65536)
            require(reply.returncode==0,'LOADED_UNIT_READ_FAILED')
            values=dict(line.split('=',1)for line in reply.stdout.decode().splitlines()if'='in line)
            units[unit]={k:values.get(k)for k in ('ActiveState','SubState','Result','ExecMainStatus')}
            commands[unit]=binding(values[prop],parent)
        report['units']=units
        require(commands[selection['guardUnit']]==commands[selection['dockerUnit']],'LOADED_GUARD_PAIR_CHANGED')
        chosen=commands[selection['guardUnit']];report['loadedBinding']=chosen
        for filename in selection['unitFiles']:
            independent(report,filename,lambda filename=filename:{'sha256':sha(read(filename,65536))})
        stage='BOOT_PROFILE';profile=parse(sealed(chosen['profile'],chosen['sha256']))
        require(profile['schema']=='ouf.semantic-coordinated-boot-profile.v1','UNSUPPORTED_BOOT_PROFILE')
        source=Path(chosen['source']);source_root=source.parents[1]
        report['bootSourceHash']=sha(read(source));report['knownBootSource']=report['bootSourceHash']==KNOWN['boot']
        stage='OWNER_CONFIGURATION';owner=parse(sealed(profile['coordinatedConfiguration'],profile['coordinatedConfigurationHash']))
        require(type(owner['sourceHashes'])is dict and 1<=len(owner['sourceHashes'])<=16,'BOUNDED_SOURCE_SET_REQUIRED')
        report['ownerSourceHashesMatch']={}
        for name,expected in owner['sourceHashes'].items():
            require(type(name)is str and re.fullmatch(r'(?:scripts|tools)/[A-Za-z0-9_]+\.py',name)
                and type(expected)is str and re.fullmatch('[a-f0-9]{64}',expected),'EXACT_SOURCE_ENTRY_REQUIRED')
            independent(report['ownerSourceHashesMatch'],name,
                lambda name=name,expected=expected:{'matches':sha(read(source_root/name))==expected})
        # The loaded root-owned unit seals the native configuration and executable reference.
        nft=Path(owner['nftPath'])
        actual_nft=sha(read(nft,16777216));report['nftExecutableMatches']=actual_nft==owner['nftSha256']
        stage='BOOT_CONFIGURATION';boot=parse(sealed(profile['bootConfiguration'],profile['bootConfigurationHash']))
        independent(report,'ownerJournal',lambda:journal_metadata(owner['journalFile'],parent))
        independent(report,'bootJournal',lambda:journal_metadata(boot['journalFile'],parent))
        report['pairedConfigurationMatches']={'kernel':boot['kernel']==owner['kernel'],
            'nftPath':boot['nftPath']==owner['nftPath'],'commonLock':boot['lockFile']==owner['commonLockFile'],
            'separateJournals':boot['journalFile']!=owner['journalFile']}
        report['restorerSourceHash']=sha(read(profile['bootGuardFile']))
        report['restorerMatchesProfile']=report['restorerSourceHash']==profile['bootGuardHash']
        report['compilerMatchesProfile']=sha(read(boot['compilerFile']))==boot['compilerHash']
        stage='PURE_NATIVE_VALIDATION'
        owner_path=source_root/'scripts/run_semantic_coordinated_lease_owner.py'
        if report['knownBootSource']and sha(read(owner_path))==KNOWN['owner']:
            native=load_known(owner_path,KNOWN['owner'],'verified_owner_read_only')
            independent(report,'nativeOwnerReadConfiguration',lambda:
                bool(native.read_configuration(Path(profile['coordinatedConfiguration']),profile['coordinatedConfigurationHash'],source_root)))
        else:report['nativeOwnerReadConfiguration']={'notExecuted':'UNKNOWN_CODE_VERSION'}
        if report['restorerSourceHash']==KNOWN['restorer']and boot['compilerHash']==KNOWN['compiler']:
            native=load_known(Path(profile['bootGuardFile']),KNOWN['restorer'],'verified_boot_validate_only')
            independent(report,'nativeBootValidation',lambda:bool(native.validate(boot)))
        else:report['nativeBootValidation']={'notExecuted':'UNKNOWN_CODE_VERSION'}
        stage='KERNEL_MEMBERSHIP_READ'
        if report['nftExecutableMatches']:
            table=owner['kernel']['tableName'];require(re.fullmatch('[A-Za-z0-9_]{1,128}',table),'EXACT_OWNED_TABLE_REQUIRED')
            reply=command([str(nft),'-j','list','tables']);require(reply.returncode==0,'NFT_MEMBERSHIP_READ_FAILED')
            value=parse(reply.stdout);report['ownedTableFamilies']=sorted(r['table']['family']for r in value['nftables']
                if'table'in r and r['table'].get('name')==table)
        report['readComplete']=True
        report['guardRecoveryProven']=False
    except Exception as error:
        report.update(readComplete=False,blockedStage=stage,**failure(error))
    return report

if __name__=='__main__':
    require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
            'ISOLATED_ROOT_READ_REQUIRED')
    require(len(sys.argv)==2,'ONE_VERSIONED_SELECTION_REQUIRED')
    signal.alarm(90)
    result=collect(parse(Path(sys.argv[1]).read_bytes()))
    print(json.dumps(result,sort_keys=True));sys.exit(0 if result['readComplete']else 2)
