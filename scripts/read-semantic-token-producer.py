"""Inspect only the configured Python producer as redacted AST, never run it."""
import ast,hashlib,json,os,re,shlex,signal,stat,subprocess,sys,types
from pathlib import Path
PLANNER_HASH='c89caa119ef7c4fea07ac6a65dd5d2b173c144cf6a802e646929418acc859d56'
UNIT='ouf-policy-token@semantic.service'
SOURCE_ROOTS=('/usr/local/','/opt/ouf/','/etc/ouf/')
SAFE_STRINGS={'semantic','gateway','onboarding','ingestion','udp','client_credentials','grant_type','client_id','client_secret','access_token','expires_in','token_type','scope','Authorization','Bearer','Content-Type','application/json','__main__'}
class Denied(ValueError):pass
def require(ok,reason):
    if not ok:raise Denied(reason)
def load_planner(raw):
    require(type(raw) is bytes and len(raw)<=131072 and hashlib.sha256(raw).hexdigest()==PLANNER_HASH,'EXACT_TOKEN_PRODUCER_PLANNER_REQUIRED')
    p=types.ModuleType('sealed_token_producer_planner');exec(compile(raw,'<sealed-token-producer-planner>','exec'),p.__dict__);return p
def command(raw):
    fields={}
    for line in raw.splitlines():
        key,sep,value=line.partition('=')
        if sep and key in {'ExecStart','Type','User'}:
            require(key not in fields,'DUPLICATE_TOKEN_UNIT_PROPERTY');fields[key]=value
    require(fields.get('Type')=='oneshot' and fields.get('User')=='root','EXACT_ROOT_TOKEN_ONESHOT_REQUIRED')
    text=fields.get('ExecStart','');require(text.count('argv[]=')==1,'EXACT_SINGLE_TOKEN_PRODUCER_COMMAND_REQUIRED')
    executable=re.search(r'\bpath=([^ ;}]+)',text);argv=re.search(r'argv\[\]=(.*?);',text)
    require(executable and executable.group(1)=='/usr/bin/python3' and argv,'EXACT_TOKEN_PYTHON_COMMAND_REQUIRED')
    args=shlex.split(argv.group(1));require(args and args[0]=='/usr/bin/python3','EXACT_TOKEN_PRODUCER_ARGV_REQUIRED')
    index=1
    while index<len(args) and args[index] in {'-I','-B','-u','-E','-s','-S'}:index+=1
    require(index<len(args) and re.fullmatch('/[A-Za-z0-9_./-]+',args[index]) and '..' not in Path(args[index]).parts
            and (args[index].endswith('.py') or Path(args[index]).name.startswith('ouf-')),
            'DIRECT_PYTHON_PRODUCER_SOURCE_REQUIRED')
    return Path(args[index]),args,'semantic' in args[index+1:]
def source(p,path,excluded):
    require(path.is_absolute() and any(str(path).startswith(root) for root in SOURCE_ROOTS)
            and all(path!=root and not path.is_relative_to(root) for root in excluded),'PRODUCER_MUST_NOT_BE_A_MOUNTED_CREDENTIAL_SOURCE')
    parent=Path('/')
    for part in path.parts[1:-1]:
        parent/=part;s=parent.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'PROTECTED_PRODUCER_ANCESTOR_REQUIRED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_nlink==1 and not before.st_mode&0o022
                and 0<before.st_size<=131072,'BOUNDED_ROOT_PRODUCER_SOURCE_REQUIRED')
        raw=os.read(fd,131073)
        require(len(raw)==before.st_size and p.identity(before)==p.identity(os.fstat(fd))==p.identity(path.lstat()),'TOKEN_PRODUCER_SOURCE_CHANGED')
        return raw,before
    finally:os.close(fd)
def redact(raw,token):
    tree=ast.parse(raw);require(sum(1 for _ in ast.walk(tree))<=20000,'TOKEN_PRODUCER_AST_UNBOUNDED')
    references=[];labels={}
    known={str(token):'MOUNT0_TOKEN_FILE',str(token.parent):'MOUNT0_TOKEN_DIRECTORY',str(token.parent.parent):'MOUNT0_TOKEN_DIRECTORY_PARENT',token.name:'MOUNT0_TOKEN_MEMBER'}
    class Redactor(ast.NodeTransformer):
        def visit_Dict(self,node):
            # Public protocol/role KEY names are retained, never their values.
            node.keys=[key if isinstance(key,ast.Constant) and type(key.value) is str and key.value in SAFE_STRINGS else self.visit(key) if key is not None else None for key in node.keys]
            node.values=[self.visit(value) for value in node.values]
            return node
        def visit_Constant(self,node):
            value=node.value
            if type(value) is str and value in known:
                label=known[value];references.append(label);return ast.copy_location(ast.Constant('__'+label+'__'),node)
            if value is None or type(value) is bool:return node
            key=(type(value).__name__,repr(value))
            if key not in labels:labels[key]='__REDACTED_LITERAL_'+str(len(labels)+1)+'__'
            return ast.copy_location(ast.Constant(labels[key]),node)
    text=ast.unparse(ast.fix_missing_locations(Redactor().visit(tree)))
    return {'redactedSource':text[:12000],'redactedSourceTruncated':len(text)>12000,
            'mountedTokenLiteralReferences':sorted(set(references)),
            'literalReferenceIsNotOutputBindingProof':True,'redactedLiteralCount':len(labels)}
def unit_read():
    r=subprocess.run(['/usr/bin/systemctl','--no-pager','show',UNIT,'--property=ExecStart,Type,User'],capture_output=True,timeout=15)
    require(r.returncode==0 and len(r.stdout)<=65536,'TOKEN_UNIT_COMMAND_METADATA_UNPROVEN');return r.stdout.decode()
def collect(p,atomic):
    scope=p.review_scope(p.PARENT);manifest_raw=atomic.read(p.PARENT/'intake.json',0)
    p.require(p.sha(manifest_raw)==p.PARENT_HASH,'EXACT_PRODUCER_PARENT_INTAKE_REQUIRED');manifest=p.decode(manifest_raw)
    p.require(set(manifest.get('fileHashes',{}))==set(p.NAMES),'EXACT_PRODUCER_PARENT_FILE_SET_REQUIRED')
    files={n:atomic.read(p.PARENT/n,0) for n in p.NAMES}
    p.require(manifest['fileHashes']=={n:p.sha(raw) for n,raw in files.items()},'PRODUCER_PARENT_FILE_HASH_DRIFT');atomic.verify(p.PARENT,files,manifest_raw,0)
    p.require(p.sha(files[p.NAMES[0]])==p.REQUEST_HASH,'EXACT_PRODUCER_CREATION_REQUEST_REQUIRED')
    p.request_mount_shape(p.decode(files[p.NAMES[0]]));old=p.decode(files[p.NAMES[2]])
    p.require(type(old) is list and len(old)==2 and tuple(p.sha(p.encoded(v['sourceMetadata'])) for v in old)==p.METADATA_HASHES,'EXACT_PRODUCER_MOUNT_METADATA_SEALS_REQUIRED')
    token=Path(old[0]['binding']['Source'])/old[0]['sourceMetadata'][1]['path']
    excluded=[Path(item['binding']['Source']) for item in old]
    path,args,role=command(unit_read());raw,info=source(p,path,excluded)
    result=redact(raw,token)
    next_path,next_args,next_role=command(unit_read())
    again,next_info=source(p,path,excluded)
    require((path,args,role)==(next_path,next_args,next_role) and raw==again and p.identity(info)==p.identity(next_info),'TOKEN_PRODUCER_CHANGED_DURING_INSPECTION')
    atomic.verify(p.PARENT,files,manifest_raw,0);p.require(p.review_scope(p.PARENT)==scope,'TOKEN_PRODUCER_PARENT_SCOPE_CHANGED')
    return {'status':'SEMANTIC_TOKEN_PRODUCER_SOURCE_INSPECTED_NOT_ACCEPTED','unit':UNIT,
            'producerSourcePath':str(path),'producerSourceSha256':hashlib.sha256(raw).hexdigest(),
            'sourceCustody':{'uid':info.st_uid,'gid':info.st_gid,'mode':stat.S_IMODE(info.st_mode)},
            'semanticArgumentObserved':role,'stableSourceAndCommand':True,**result}
def main():
    report={'schema':'ouf.semantic-token-producer-inspection.v1','maxReadSeconds':120,'mountedCredentialBytesRead':0,'protectedFileWrites':0,
            'execStartArgumentsPrinted':False,'environmentValuesPrinted':False,'credentialPathsPrinted':False,'producerExecutedByReader':False,
            'serviceMutations':0,'tokenGrantRequests':0,'providerCalls':0,'r12Touched':False,'budgetReset':False,'baselineRefreshed':False,
            'outputBindingProven':False,'writerAuthorityProven':False,'runtimeAuthorityIssued':False,'signaturesIssued':0,
            'completeSixMountClosureProven':False,'notReleaseAcceptance':True}
    p=None
    try:
        require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode and len(sys.argv)==1,'ISOLATED_ROOT_TOKEN_PRODUCER_READ_REQUIRED')
        def deadline(*_):raise Denied('TOKEN_PRODUCER_READ_DEADLINE')
        signal.signal(signal.SIGALRM,deadline);signal.alarm(120)
        p=load_planner(globals().get('__planner_source__'));atomic=p.atomic_source(globals().get('__atomic_source__'))
        report.update(collect(p,atomic));code=0
    except Exception as e:
        reason=str(e);trusted=type(e) is Denied or p is not None and type(e) is p.Denied
        report.update(status='SEMANTIC_TOKEN_PRODUCER_INSPECTION_BLOCKED',reason=reason if trusted and re.fullmatch('[A-Z][A-Z0-9_]{0,120}',reason) else 'TOKEN_PRODUCER_INSPECTION_UNPROVEN');code=1
    finally:signal.alarm(0)
    print('OUF_SEMANTIC_TOKEN_PRODUCER='+json.dumps(report,sort_keys=True));return code
if __name__=='__main__':raise SystemExit(main())
