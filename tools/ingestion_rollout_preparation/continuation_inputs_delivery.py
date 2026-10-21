"""Bind an offline snapshot and GET-only metadata bridge to frozen native predicates."""
import ast
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path


def encoded(v): return json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
def sha(v): return hashlib.sha256(v).hexdigest()


BOOTSTRAP = '''
import ast,base64,gzip,hashlib,io,json,os,re,signal,sys
def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def unique(pairs):
 v={}
 for k,x in pairs:
  require(k not in v,'DUPLICATE_METADATA_DELIVERY_FIELD');v[k]=x
 return v
phase='VERIFY_METADATA_DELIVERY'
try:
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and len(sys.argv)==1,'ISOLATED_ROOT_METADATA_READER_REQUIRED')
 require(hashlib.sha256(BOOTSTRAP.encode()).hexdigest()==DECLARATION['bootstrapHash']and hashlib.sha256(encoded(DECLARATION)).hexdigest()==DECLARATION_HASH,'METADATA_DELIVERY_DECLARATION_CHANGED')
 require(hashlib.sha256(encoded(CASE)).hexdigest()==DECLARATION['caseHash'],'PINNED_METADATA_CASE_CHANGED')
 signal.signal(signal.SIGALRM,lambda *_:require(False,'METADATA_READER_DEADLINE'));signal.alarm(180)
 compressed=base64.b64decode(PACKED,validate=True);require(len(compressed)<=786432,'BOUNDED_COMPRESSED_METADATA_DELIVERY_REQUIRED')
 with gzip.GzipFile(fileobj=io.BytesIO(compressed))as stream:raw=stream.read(4194305)
 require(0<len(raw)<=4194304,'BOUNDED_METADATA_SOURCE_PAYLOAD_REQUIRED')
 p=json.loads(raw,object_pairs_hook=unique)
 require(set(p)=={'loader','sources','snapshot','bridge'},'CLOSED_METADATA_PAYLOAD_REQUIRED')
 for name in('snapshot','bridge','loader'):require(hashlib.sha256(p[name].encode()).hexdigest()==DECLARATION[name+'Hash'],'PINNED_METADATA_SOURCE_CHANGED')
 declaration=DECLARATION['nativeDeclaration'];sources={k:v.encode()for k,v in p['sources'].items()}
 require({n:hashlib.sha256(v).hexdigest()for n,v in sources.items()}==declaration['sourceHashes'],'FROZEN_NATIVE_PREDICATES_CHANGED')
 loader={};exec(compile(p['loader'],'<frozen-native-loader>','exec'),loader)
 entry,manifest=loader['load_entry'](declaration['sourceCommit'],sources,p['loader'].encode(),hashlib.sha256(encoded(declaration)).hexdigest(),declaration['sourcePins'])
 require(manifest==declaration,'FROZEN_NATIVE_DECLARATION_CHANGED')
 for name in('snapshot','bridge'):
  tree=ast.parse(p[name])
  for node in ast.walk(tree):
   refs=[a.name for a in node.names]if isinstance(node,ast.Import)else[]
   if isinstance(node,ast.ImportFrom):require(node.level==0 and node.module is not None,'RELATIVE_METADATA_IMPORT_DENIED');refs=[node.module]
   for ref in refs:require(ref.split('.')[0]in('copy','hashlib','http','json','math','os','pathlib','re','signal','socket','stat','sys','time','urllib'),'STDLIB_ONLY_METADATA_BRIDGE_REQUIRED')
   require(not(isinstance(node,ast.Call)and isinstance(node.func,ast.Name)and node.func.id=='__import__'),'DYNAMIC_METADATA_IMPORT_DENIED')
 snapshot={'__name__':'verified_stopped_snapshot'};exec(compile(p['snapshot'],'<verified-stopped-snapshot>','exec'),snapshot)
 bridge={'__name__':'verified_continuation_metadata'};exec(compile(p['bridge'],'<verified-continuation-metadata>','exec'),bridge)
 modules=[sys.modules['tools.ingestion_rollout_execution.'+n]for n in('contract','runtime_guard','replacement','runtime_bindings')]
 phase='READ_RETAINED_PREFIX_AND_LIVE_METADATA'
 result=bridge['inspect'](CASE,snapshot,modules)
 print(encoded(result).decode(),flush=True)
except (Exception,KeyboardInterrupt)as error:
 code=str(error);reason=code if type(error).__name__ in('Denied','ValueError','RuntimeDenied','CreationDenied')and re.fullmatch('[A-Z][A-Z0-9_]{0,127}',code)else'METADATA_CHECK_UNPROVEN_PRIVATE_DETAILS_REDACTED'
 print(encoded({'schema':'ouf.ingestion-rollout-continuation-input-read.v1','complete':False,'status':'STOP_RECONCILE','reasonCode':reason,'phase':phase,'contextsAndClaimsRetained':True,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,'budgetReset':False,'newLoginPerformed':False,'privateValuesPrinted':False}).decode(),flush=True)
 raise SystemExit(2)
'''


def generate(root, case):
    root = Path(root)
    frozen = (root / 'scripts/ingestion-rollout-production-control-20261020.py').read_bytes()
    if sha(frozen) != '42b2569a0ba1f2234dfbcc011588cdf133d0e5c97a3f3433b903750f010448ea':
        raise ValueError('FROZEN_PRODUCTION_ARTIFACT_CHANGED')
    values = {n.targets[0].id: ast.literal_eval(n.value) for n in ast.parse(frozen).body
              if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
              and n.targets[0].id in ('PACKED', 'DELIVERY')}
    old = json.loads(gzip.decompress(base64.b64decode(values['PACKED'])))
    snapshot = (root / 'scripts/read-ingestion-rollout-stopped-20261021.py').read_bytes()
    if sha(snapshot) != '57a5941574bf5beb0fcfe6e3d5465914a34673c651d74c892133be782e0a5e32':
        raise ValueError('QUALIFIED_STOPPED_READER_CHANGED')
    bridge = (root / 'tools/ingestion_rollout_preparation/continuation_inputs.py').read_bytes()
    declaration = {'schema': 'ouf.ingestion-rollout-continuation-input-delivery.v1',
        'bootstrapHash': sha(BOOTSTRAP.encode()), 'caseHash': sha(encoded(case)),
        'snapshotHash': sha(snapshot), 'bridgeHash': sha(bridge),
        'loaderHash': sha(old['loader'].encode()), 'nativeDeclaration': values['DELIVERY']['nativeDeclaration'],
        'maximumEngineGets': 18, 'newAuthorityAllowed': False, 'runtimeEffectsAllowed': False}
    payload = {'loader': old['loader'], 'sources': old['sources'],
               'snapshot': snapshot.decode(), 'bridge': bridge.decode()}
    raw = encoded(payload)
    if len(raw) > 4194304: raise ValueError('METADATA_PAYLOAD_TOO_LARGE')
    compressed = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=compressed, mtime=0, compresslevel=9) as stream:
        stream.write(raw)
    packed = base64.b64encode(compressed.getvalue()).decode('ascii')
    header = '\n'.join(k + '=' + repr(v) for k, v in (
        ('PACKED', packed), ('CASE', case), ('DECLARATION', declaration),
        ('DECLARATION_HASH', sha(encoded(declaration))), ('BOOTSTRAP', BOOTSTRAP)))
    result = (header + "\nexec(compile(BOOTSTRAP,'<verified-continuation-metadata-loader>','exec'))\n").encode()
    if len(result) > 1048576: raise ValueError('METADATA_ARTIFACT_TOO_LARGE')
    return result, declaration
