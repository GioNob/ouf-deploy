"""Deterministic offline capsule for the complete Registry postboot entry.

This developer-side generator reads only exact source paths. It never executes
the collected application sources, contacts the target or issues authority.
The generated target capsule imports the closed declaration into memory before
calling one explicit controller mode.
"""
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import types

MODES = ('prepare', 'review', 'issue', 'install', 'bootstrap', 'owner', 'continue', 'status')
BOOTSTRAP = '''import base64,gzip,hashlib,io,json,os,re,signal,sys
def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def unique(pairs):
 v={}
 for k,x in pairs:
  require(k not in v,'DUPLICATE_POSTBOOT_DELIVERY_FIELD');v[k]=x
 return v
mode=None
try:
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_POSTBOOT_CAPSULE_REQUIRED')
 require(1<=len(sys.argv[1:])<=4 and sys.argv[1] in ('prepare','review','issue','install','bootstrap','owner','continue','status'),'ONE_EXPLICIT_POSTBOOT_MODE_REQUIRED');mode=sys.argv[1]
 require(hashlib.sha256(BOOTSTRAP.encode()).hexdigest()==DELIVERY['bootstrapHash'] and hashlib.sha256(encoded(DELIVERY)).hexdigest()==DELIVERY_HASH,'POSTBOOT_DELIVERY_DECLARATION_CHANGED')
 require(type(CASE)is dict and hashlib.sha256(encoded(CASE)).hexdigest()==DELIVERY['caseHash'],'POSTBOOT_CASE_CHANGED')
 signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_POSTBOOT_OPERATION_DEADLINE'));signal.alarm(900)
 compressed=base64.b64decode(PACKED,validate=True);require(0<len(compressed)<=2097152,'BOUNDED_POSTBOOT_COMPRESSED_CAPSULE_REQUIRED')
 with gzip.GzipFile(fileobj=io.BytesIO(compressed))as stream:raw=stream.read(12582913)
 require(0<len(raw)<=12582912,'BOUNDED_POSTBOOT_SOURCE_PAYLOAD_REQUIRED')
 payload=json.loads(raw,object_pairs_hook=unique)
 require(type(payload)is dict and set(payload)=={'loader','sources'},'CLOSED_POSTBOOT_SOURCE_PAYLOAD_REQUIRED')
 declaration=DELIVERY['nativeDeclaration']
 loader=payload['loader'].encode()
 require(hashlib.sha256(loader).hexdigest()==declaration['loaderHash'],'POSTBOOT_LOADER_CHANGED')
 require(set(payload['sources'])==set(declaration['sourceHashes']),'POSTBOOT_SOURCE_SET_CHANGED')
 sources={name:value.encode()for name,value in payload['sources'].items()}
 require(all(hashlib.sha256(value).hexdigest()==declaration['sourceHashes'][name]for name,value in sources.items()),'POSTBOOT_SOURCE_BYTES_CHANGED')
 namespace={};exec(compile(loader,'<verified-postboot-loader>','exec'),namespace)
 entry,manifest=namespace['load_entry'](declaration['sourceCommit'],sources,loader,hashlib.sha256(encoded(declaration)).hexdigest(),declaration['sourcePins'])
 require(manifest==declaration,'POSTBOOT_SOURCE_DECLARATION_CHANGED')
 result=entry.execute(CASE,manifest,sources,sys.argv[1:])
 require(type(result)is dict,'POSTBOOT_CONTROLLER_RECEIPT_REQUIRED')
 print(encoded(result).decode(),flush=True)
 signal.alarm(0)
except (Exception,KeyboardInterrupt)as error:
 signal.alarm(0)
 code=str(error);reason=code if re.fullmatch('[A-Z][A-Z0-9_]{0,127}',code)else'POSTBOOT_OUTCOME_UNPROVEN_PRIVATE_DETAILS_REDACTED'
 print(encoded({'schema':'ouf.semantic-registry-postboot-operator-result.v1','status':'STOP_RECONCILE','complete':False,'reasonCode':reason,'contextsAndClaimsRetained':True,'runtimeEffectsMayBePartial':mode in('issue','install','bootstrap','owner','continue'),'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}).decode(),flush=True)
 raise SystemExit(2)
'''


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def loader_module(root):
    path = 'tools/semantic_registry_recovery_execution/runtime.py'
    raw = source_bytes(root, path, 65536)
    module = types.ModuleType('qualified_postboot_build_loader')
    # The generator executes only its own explicitly selected loader. Collected
    # application sources below are parsed/compiled but never imported.
    exec(compile(raw, '<qualified-postboot-build-loader>', 'exec'), module.__dict__)
    return module, raw


def source_bytes(root, path, maximum):
    root = Path(root).resolve()
    target = root / path
    if target.resolve() != target or not target.is_relative_to(root):
        raise ValueError('SOURCE_PATH_SYMLINK_OR_ESCAPE')
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= maximum:
            raise ValueError('BOUNDED_REGULAR_SOURCE_REQUIRED')
        with os.fdopen(os.dup(fd), 'rb') as source:
            raw = source.read(maximum + 1)
        pin = lambda s: (s.st_dev, s.st_ino, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if len(raw) != before.st_size or pin(before) != pin(os.fstat(fd)) or pin(before) != pin(target.lstat()):
            raise ValueError('SOURCE_CHANGED_DURING_PACKAGING')
        return raw
    finally:
        os.close(fd)


def collect_sources(root, loader):
    root = Path(root).resolve()
    result, pending = {}, [loader.ENTRY]
    while pending:
        name = pending.pop()
        if name in result:
            continue
        if len(result) >= loader.MAX_MODULES:
            raise ValueError('POSTBOOT_SOURCE_MODULE_LIMIT')
        raw = source_bytes(root, loader.source_path(name), loader.MAX_SOURCE_BYTES)
        result[name] = raw
        if sum(map(len, result.values())) > loader.MAX_TOTAL_BYTES:
            raise ValueError('POSTBOOT_SOURCE_BYTE_LIMIT')
        _, refs = loader.references(name, raw)
        for module, members in refs:
            if module.split('.')[0] in loader.STDLIB:
                continue
            path = None if module == 'tools' else root / loader.source_path(module)
            if path is not None and path.is_file():
                pending.append(module)
                continue
            package = root / module.replace('.', '/')
            if not members or not module.startswith('tools') or package.resolve() != package or not package.is_dir() or (package / '__init__.py').exists():
                raise ValueError('UNRESOLVED_SOURCE_PACKAGE_DEPENDENCY')
            for member in members:
                child = module + '.' + member
                if not (root / loader.source_path(child)).is_file():
                    raise ValueError('UNRESOLVED_SOURCE_PACKAGE_MEMBER')
                pending.append(child)
    loader.compile_sources(result)
    return result


def generate(root, case, source_commit, source_pins):
    if type(case) is not dict:
        raise ValueError('EXACT_POSTBOOT_CASE_REQUIRED')
    loader, raw_loader = loader_module(root)
    sources = collect_sources(root, loader)
    manifest = loader.declaration(source_commit, sources, raw_loader, source_pins)
    payload = encoded({'loader': raw_loader.decode(), 'sources': {n: v.decode() for n, v in sorted(sources.items())}})
    if len(payload) > 12582912:
        raise ValueError('POSTBOOT_SOURCE_PAYLOAD_LIMIT')
    output = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=output, mtime=0) as stream:
        stream.write(payload)
    compressed = output.getvalue()
    if len(compressed) > 2097152:
        raise ValueError('POSTBOOT_COMPRESSED_CAPSULE_LIMIT')
    declaration = {
        'schema': 'ouf.semantic-registry-postboot-delivery.v1',
        'nativeDeclaration': manifest, 'caseHash': sha(encoded(case)),
        'bootstrapHash': sha(BOOTSTRAP.encode()), 'runtimeAuthorityIssued': False,
        'targetExecutionPerformed': False, 'releaseAcceptance': False,
    }
    artifact = ('CASE=' + repr(json.loads(encoded(case))) + '\nDELIVERY=' + repr(declaration)
                + '\nDELIVERY_HASH=' + repr(sha(encoded(declaration)))
                + '\nPACKED=' + repr(base64.b64encode(compressed).decode())
                + '\nBOOTSTRAP=' + repr(BOOTSTRAP)
                + '\nexec(compile(BOOTSTRAP,"<postboot-operator-capsule>","exec"))\n').encode()
    if len(artifact) > 3145728:
        raise ValueError('POSTBOOT_OPERATOR_ARTIFACT_LIMIT')
    return artifact, declaration
