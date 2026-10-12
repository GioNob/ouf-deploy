"""Observe private config/output correspondence, never accept writer authority."""
import ast, hashlib, json, os, re, signal, stat, subprocess, sys, types
from pathlib import Path
OBSERVER_SOURCE = b'"""Untrusted static observation only; never authenticate or execute the producer."""\nimport ast, hashlib, json, os, re, shlex, signal, stat, subprocess\nfrom pathlib import Path\n\nTARGET = Path(\'/opt/ouf/ops/refresh-policy-token.py\')\nEXPECTED = {\'/opt\': (0, 0, 0o755), \'/opt/ouf\': (1000, 1000, 0o750),\n            \'/opt/ouf/ops\': (0, 0, 0o700)}\nPUBLIC_KEYS = {\'grant_type\', \'client_id\', \'client_secret\', \'access_token\',\n               \'expires_in\', \'token_type\', \'scope\', \'Authorization\', \'Content-Type\'}\n\ndef require(ok):\n    if not ok:\n        raise ValueError(\'STATIC_OBSERVATION_UNPROVEN\')\n\ndef identity(s):\n    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,\n            s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)\n\ndef routing():\n    r = subprocess.run([\'/usr/bin/systemctl\', \'--no-pager\', \'show\',\n        \'ouf-policy-token@semantic.service\', \'--property=ExecStart,Type,User\'],\n        capture_output=True, timeout=15)\n    require(r.returncode == 0 and len(r.stdout) <= 65536)\n    fields = dict(line.partition(\'=\')[::2] for line in r.stdout.decode().splitlines() if \'=\' in line)\n    require(fields.get(\'Type\') == \'oneshot\' and fields.get(\'User\') == \'root\')\n    text = fields.get(\'ExecStart\', \'\')\n    exe = re.search(r\'\\bpath=([^ ;}]+)\', text)\n    argv = re.search(r\'argv\\[\\]=(.*?);\', text)\n    require(text.count(\'argv[]=\') == 1 and exe and argv and exe.group(1) == \'/usr/bin/python3\')\n    args = shlex.split(argv.group(1)); require(args and args[0] == \'/usr/bin/python3\')\n    index = 1\n    while index < len(args) and args[index] in {\'-I\', \'-B\', \'-u\', \'-E\', \'-s\', \'-S\'}:\n        index += 1\n    require(index < len(args) and args[index] == str(TARGET))\n    return tuple(args)\n\ndef snapshot(path=TARGET, expected=EXPECTED):\n    fds = []; entries = []\n    try:\n        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK\n        root = os.open(\'/\', directory_flags); fds.append(root)\n        s = os.fstat(root); require(s.st_uid == 0 and not s.st_mode & 0o022)\n        parent = root; current = Path(\'/\')\n        for part in path.parts[1:-1]:\n            current /= part\n            before = os.stat(part, dir_fd=parent, follow_symlinks=False)\n            require(stat.S_ISDIR(before.st_mode))\n            custody = (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode))\n            require(custody == expected[str(current)])\n            child = os.open(part, directory_flags, dir_fd=parent); fds.append(child)\n            require(identity(before) == identity(os.fstat(child)))\n            entries.append((parent, part, child, identity(before))); parent = child\n        before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)\n        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0\n                and stat.S_IMODE(before.st_mode) == 0o755 and before.st_nlink == 1\n                and 0 < before.st_size <= 131072)\n        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)\n        fds.append(fd); require(identity(before) == identity(os.fstat(fd)))\n        raw = bytearray()\n        while len(raw) <= 131072:\n            chunk = os.read(fd, min(16384, 131073 - len(raw)))\n            if not chunk: break\n            raw.extend(chunk)\n        require(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd))\n                == identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)))\n        for parent, name, child, saved in entries:\n            require(saved == identity(os.fstat(child))\n                    == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)))\n        return bytes(raw), identity(before)\n    finally:\n        for fd in reversed(fds): os.close(fd)\n\ndef redact(raw):\n    tree = ast.parse(raw); require(sum(1 for _ in ast.walk(tree)) <= 20000)\n    labels = {}\n    class Mask(ast.NodeTransformer):\n        def visit_Dict(self, node):\n            node.keys = [key if isinstance(key, ast.Constant) and type(key.value) is str\n                         and key.value in PUBLIC_KEYS else self.visit(key) if key is not None\n                         else None for key in node.keys]\n            node.values = [self.visit(value) for value in node.values]; return node\n        def visit_Constant(self, node):\n            if node.value is None or type(node.value) is bool: return node\n            key = (type(node.value).__name__, repr(node.value))\n            labels.setdefault(key, \'__REDACTED_LITERAL_\' + str(len(labels) + 1) + \'__\')\n            return ast.copy_location(ast.Constant(labels[key]), node)\n    text = ast.unparse(ast.fix_missing_locations(Mask().visit(tree)))\n    return {\'redactedSource\': text[:12000], \'redactedSourceTruncated\': len(text) > 12000}\n\ndef main():\n    report = {\'schema\': \'ouf.semantic-token-untrusted-static-observation.v1\',\n        \'sourceAuthenticationProven\': False, \'writerAuthorityProven\': False,\n        \'outputBindingProven\': False, \'producerExecuted\': False, \'serviceMutations\': 0,\n        \'protectedFileWrites\': 0, \'providerCalls\': 0, \'tokenGrantRequests\': 0,\n        \'baselineRefreshed\': False, \'budgetReset\': False, \'r12Touched\': False,\n        \'runtimeAuthorityIssued\': False, \'notReleaseAcceptance\': True,\n        \'sourceContentBytesRead\': 0, \'execStartArgumentsPrinted\': False,\n        \'environmentValuesPrinted\': False, \'credentialPathsPrinted\': False}\n    try:\n        require(os.geteuid() == 0 and __import__(\'sys\').flags.isolated\n                and __import__(\'sys\').dont_write_bytecode)\n        def deadline(*_): raise ValueError(\'STATIC_OBSERVATION_DEADLINE\')\n        signal.signal(signal.SIGALRM, deadline); signal.alarm(60)\n        command = routing(); raw, seal = snapshot()\n        report[\'sourceContentBytesRead\'] += len(raw)\n        masked = redact(raw)\n        again, next_seal = snapshot(); report[\'sourceContentBytesRead\'] += len(again)\n        require(command == routing() and raw == again and seal == next_seal)\n        report.update(status=\'UNTRUSTED_PRODUCER_STATIC_SOURCE_OBSERVED_NOT_ACCEPTED\',\n            producerSourcePath=str(TARGET), sourceSha256=hashlib.sha256(raw).hexdigest(),\n            rootOnlyAncestorCustody=False, stableDoubleRead=True,\n            sourceByteAccountingComplete=True, **masked)\n        code = 0\n    except Exception:\n        report.update(status=\'UNTRUSTED_PRODUCER_STATIC_OBSERVATION_BLOCKED\',\n                      reason=\'STATIC_OBSERVATION_UNPROVEN\', sourceContentBytesRead=None,\n                      sourceByteAccountingComplete=False); code = 1\n    finally: signal.alarm(0)\n    print(\'OUF_TOKEN_PRODUCER_STATIC_OBSERVATION=\' + json.dumps(report, sort_keys=True))\n    return code\n\nif __name__ == \'__main__\': raise SystemExit(main())\n'
OBSERVER_HASH="ff796823c8bdd93bbe182f7c578a33d44048260760546660263306abe8026634"
CODE_HASH="728b4c44d0e24b3c3bfc31769346c0c05752e870e93c096fac1c2897250e5c79"
INTAKE_HASH="005f6a7afad7d493a52d9b183816fa0346f1bb1a4de5ab4b63c8b0b39f3fb092"
PARENT=Path("/etc/ouf/deploy-snapshots/semantic-native-v11-intake-"+INTAKE_HASH)
NAMES=("gated-creation-request.private.json","gate-proposal.json","retained-mount-metadata.private.json","parent-review-reference.json")
KEYS={"OUF_POLICY_TOKEN_"+v for v in ("CLIENT_ID","ENDPOINT","REQUIRED_SCOPE","RUNTIME_DIR","RUNTIME_GID","SECRET_FILE")}

def require(ok):
    if not ok: raise ValueError('PRIVATE_BINDING_UNPROVEN')

def sha(raw): return hashlib.sha256(raw).hexdigest()

def identity(s):
    return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,
            s.st_size,s.st_mtime_ns,s.st_ctime_ns)

def private_read(path):
    require(path.is_absolute() and '..' not in path.parts and len(path.parts)<=32)
    fds=[]; entries=[]
    try:
        flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK
        parent=os.open('/',flags); fds.append(parent)
        for part in path.parts[1:-1]:
            before=os.stat(part,dir_fd=parent,follow_symlinks=False)
            require(stat.S_ISDIR(before.st_mode) and before.st_uid==0 and not before.st_mode&0o022)
            child=os.open(part,flags,dir_fd=parent); fds.append(child)
            require(identity(before)==identity(os.fstat(child)))
            entries.append((parent,part,child,identity(before))); parent=child
        before=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode) and before.st_uid==0
                and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1
                and 0<before.st_size<=2000000)
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent); fds.append(fd)
        require(identity(before)==identity(os.fstat(fd)))
        raw=bytearray()
        while len(raw)<=2000000:
            chunk=os.read(fd,min(16384,2000001-len(raw)))
            if not chunk: break
            raw.extend(chunk)
        require(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))
                ==identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False)))
        for directory,name,child,seal in entries:
            require(seal==identity(os.fstat(child))==identity(os.stat(name,dir_fd=directory,follow_symlinks=False)))
        return bytes(raw)
    finally:
        for fd in reversed(fds): os.close(fd)

def decode(raw):
    def pairs(rows):
        result={}
        for key,value in rows:
            require(key not in result); result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:require(False))

def plan():
    require(stat.S_IMODE(PARENT.lstat().st_mode)==0o700 and set(os.listdir(PARENT))==set(NAMES)|{'intake.json'})
    manifest=private_read(PARENT/'intake.json'); require(sha(manifest)==INTAKE_HASH)
    hashes=decode(manifest)['fileHashes']; require(set(hashes)==set(NAMES))
    files={name:private_read(PARENT/name) for name in NAMES}
    require({name:sha(raw) for name,raw in files.items()}==hashes)
    require(sha(files[NAMES[0]])=='37b517eda22f5997504687222679d458c9478ee66ba5ef2377cf5588ef3f0a9d')
    old=decode(files[NAMES[2]]); require(type(old) is list and len(old)==2)
    seals=['edd17c66ebb3c64747bcb69fa17a69380198ae0b2a4dadf86d941473b55dfa02',
           '22ce221e8216648947bd861cb18c8b3c888467d8e2eec8bda057d08a03ce79ed']
    require([sha(json.dumps(item['sourceMetadata'],sort_keys=True,separators=(',',':'),allow_nan=False).encode()) for item in old]==seals)
    return old,manifest,files

def parse_config(raw):
    require(len(raw)<=65536); result={}
    for line in raw.decode('utf-8').splitlines():
        line=line.strip()
        if not line or line.startswith(('#',';')): continue
        match=re.fullmatch(r'([A-Z][A-Z0-9_]*)=(.*)',line); require(match)
        key,value=match.groups(); require(key in KEYS and key not in result)
        value=value.strip()
        if value.startswith(('"',"'")):
            require(len(value)>=2 and value[-1]==value[0]); value=value[1:-1]
        require(not any(c in value for c in ('\\','"',"'",'\x00','\r','\n')))
        result[key]=value.strip()
    require(set(result)==KEYS)
    require(all(value for key,value in result.items() if key!='OUF_POLICY_TOKEN_REQUIRED_SCOPE'))
    return result

def routing():
    properties=['EnvironmentFiles','UnsetEnvironment','RootDirectory','RootImage',
                'BindPaths','BindReadOnlyPaths','TemporaryFileSystem']
    r=subprocess.run(['/usr/bin/systemctl','--no-pager','show','ouf-policy-token@semantic.service',
                      '--property='+','.join(properties)],capture_output=True,timeout=15)
    require(r.returncode==0 and len(r.stdout)<=65536)
    fields=dict(line.partition('=')[::2] for line in r.stdout.decode().splitlines() if '=' in line)
    require(all(key in fields and not fields[key] for key in properties[1:]))
    match=re.fullmatch(r'(/[A-Za-z0-9_./@:-]+) \(ignore_errors=no\)',fields.get('EnvironmentFiles',''))
    require(match); path=Path(match.group(1)); require('..' not in path.parts)
    return path,fields

def output_member(raw):
    tree=ast.parse(raw)
    config=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='config')
    refresh=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='refresh')
    assign=next(node for node in config.body if isinstance(node,ast.Assign) and ast.unparse(node.targets[0])=='runtime_dir')
    require(ast.unparse(assign.value)=="Path(required('OUF_POLICY_TOKEN_RUNTIME_DIR'))")
    returned=next(node.value for node in config.body if isinstance(node,ast.Return)); require(isinstance(returned,ast.Dict))
    runtime_key=next(k.value for k,v in zip(returned.keys,returned.values) if isinstance(k,ast.Constant) and isinstance(v,ast.Name) and v.id=='runtime_dir')
    directory=next(node for node in refresh.body if isinstance(node,ast.Assign) and ast.unparse(node.targets[0])=='directory')
    require(isinstance(directory.value,ast.Subscript) and ast.unparse(directory.value.value)=='cfg'
            and isinstance(directory.value.slice,ast.Constant) and directory.value.slice.value==runtime_key)
    calls=[n for n in ast.walk(refresh) if isinstance(n,ast.Call) and ast.unparse(n.func)=='os.replace']
    require(len(calls)==1 and len(calls[0].args)==2)
    destination=calls[0].args[1]
    require(isinstance(destination,ast.BinOp) and isinstance(destination.op,ast.Div)
            and ast.unparse(destination.left)=='directory' and isinstance(destination.right,ast.Constant))
    member=destination.right.value
    require(type(member) is str and re.fullmatch('[A-Za-z0-9_.-]{1,128}',member) and member not in {'.','..'})
    return member

def compare(cfg,member,old):
    runtime=Path(cfg['OUF_POLICY_TOKEN_RUNTIME_DIR'])
    require(runtime.is_absolute() and '..' not in runtime.parts and str(runtime)==cfg['OUF_POLICY_TOKEN_RUNTIME_DIR'])
    gid=cfg['OUF_POLICY_TOKEN_RUNTIME_GID']; require(re.fullmatch('[0-9]{1,10}',gid))
    metadata=old[0]['sourceMetadata']; binding=old[0]['binding']
    require(len(metadata)==2 and binding['RW'] is False and metadata[0]['kind']=='directory')
    retained=Path(binding['Source']); historical=retained/metadata[1]['path']
    return {'configuredOutputMatchesHistoricalMount0': runtime/member==historical,
            'configuredRuntimeDirectoryMatchesHistoricalMount0': runtime==retained,
            'configuredRuntimeGidMatchesHistoricalMount0': int(gid)==metadata[0]['gid']==metadata[1]['gid'],
            'clientIdConfigured': bool(cfg['OUF_POLICY_TOKEN_CLIENT_ID']),
            'scopeConfigured': bool(cfg['OUF_POLICY_TOKEN_REQUIRED_SCOPE']),
            'endpointHasHttpsPrefix': cfg['OUF_POLICY_TOKEN_ENDPOINT'].startswith('https://'),
            'factsAreConfigurationCorrespondenceNotIssuerOrWriterAuthority':True}

def main():
    report={'schema':'ouf.semantic-token-private-output-correspondence.v1',
        'sourceAuthenticationProven':False,'writerAuthorityProven':False,'outputBindingProven':False,
        'runtimeAuthorityIssued':False,'notReleaseAcceptance':True,'producerExecuted':False,
        'configurationValuesPrinted':False,'credentialPathsPrinted':False,
        'referencedSecretFilesOpened':0,'mountedTokenFilesOpened':0,'delegationKeyFilesOpened':0,
        'serviceMutations':0,'protectedFileWrites':0,'providerCalls':0,'tokenGrantRequests':0,
        'baselineRefreshed':False,'budgetReset':False,'r12Touched':False}
    try:
        require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode)
        def deadline(*_): raise ValueError('DEADLINE')
        signal.signal(signal.SIGALRM,deadline); signal.alarm(120)
        require(sha(OBSERVER_SOURCE)==OBSERVER_HASH)
        observer=types.ModuleType('sealed_static_observer'); exec(compile(OBSERVER_SOURCE,'<sealed-observer>','exec'),observer.__dict__)
        command=observer.routing(); code,seal=observer.snapshot(); require(sha(code)==CODE_HASH)
        member=output_member(code); old,manifest,files=plan()
        path,properties=routing()
        require(all(path!=Path(item['binding']['Source']) and not path.is_relative_to(Path(item['binding']['Source'])) for item in old))
        raw=private_read(path); cfg=parse_config(raw)
        facts=compare(cfg,member,old)
        next_code,next_seal=observer.snapshot(); next_old,next_manifest,next_files=plan()
        require(code==next_code and seal==next_seal and command==observer.routing())
        require((path,properties)==routing() and raw==private_read(path)
                and manifest==next_manifest and files==next_files and old==next_old)
        report.update(status='PRIVATE_OUTPUT_CORRESPONDENCE_OBSERVED_NOT_ACCEPTED',stableDoubleRead=True,
                      configurationContentBytesRead=2*len(raw),observedProducerSha256=CODE_HASH,**facts); result=0
    except Exception:
        report.update(status='PRIVATE_OUTPUT_CORRESPONDENCE_BLOCKED',reason='PRIVATE_BINDING_UNPROVEN'); result=1
    finally: signal.alarm(0)
    print('OUF_TOKEN_PRIVATE_OUTPUT_CORRESPONDENCE='+json.dumps(report,sort_keys=True)); return result

if __name__=='__main__': raise SystemExit(main())
