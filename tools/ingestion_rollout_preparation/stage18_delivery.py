"""Separate HUMAN closure and unchanged frozen-native runtime continuation."""
import ast
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
from tools.governed_human_successor import auth_delivery
from tools.ingestion_rollout_preparation import continuation_inputs_delivery as frozen


def encoded(v): return json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
def sha(v): return hashlib.sha256(v).hexdigest()

AUTH_BOOTSTRAP = auth_delivery.BOOTSTRAP.replace(
    "('open-window','step','status','reconcile-read')", "('prepare','open-window','step','status')").replace(
    "(sys.argv[1]=='open-window')", "(sys.argv[1]in('prepare','open-window'))").replace(
    "sys.modules.get('tools.governed_human_successor.operator')", "sys.modules.get(DECLARATION['entryModule'])").replace(
    "'ouf.human-explicit-successor-operator-result.v1'", "'ouf.ingestion-rollout-stage18-human-result.v1'").replace(
    'def main():', "import signal\ndef main():\n signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_STAGE18_OPERATOR_DEADLINE'));signal.alarm(180)").replace(
    "module=importlib.import_module(DECLARATION['entryModule'])",
    "require(DECLARATION['sourceHashes'][DECLARATION['entryModule']]==CASE['authControllerHash']and DECLARATION['sourceHashes']['tools.ingestion_rollout_preparation.stage18_control']==CASE['runtimeControllerHash']and DECLARATION['sourceHashes']['tools.ingestion_rollout_preparation.continuation_common']==CASE['commonHash'],'STAGE18_CASE_AND_HUMAN_SOURCE_BINDINGS_CHANGED')\n module=importlib.import_module(DECLARATION['entryModule'])")

RUNTIME_BOOTSTRAP = '''
import ast,base64,gzip,hashlib,io,json,os,re,signal,sys,types
def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def unique(pairs):
 v={}
 for k,x in pairs:
  require(k not in v,'DUPLICATE_STAGE18_DELIVERY_FIELD');v[k]=x
 return v
phase='VERIFY_STAGE18_RUNTIME_DELIVERY';mode=None
try:
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_STAGE18_RUNTIME_REQUIRED')
 require(len(sys.argv)==2 and sys.argv[1]in('preflight','review','approve','import-prefix','step','reconcile','status'),'ONE_EXPLICIT_STAGE18_RUNTIME_MODE_REQUIRED');mode=sys.argv[1]
 require(hashlib.sha256(BOOTSTRAP.encode()).hexdigest()==DECLARATION['bootstrapHash']and hashlib.sha256(encoded(DECLARATION)).hexdigest()==DECLARATION_HASH,'STAGE18_RUNTIME_DECLARATION_CHANGED')
 require(hashlib.sha256(encoded(CASE)).hexdigest()==DECLARATION['caseHash'],'STAGE18_RUNTIME_CASE_CHANGED')
 signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_STAGE18_RUNTIME_DEADLINE'));signal.alarm(180)
 compressed=base64.b64decode(PACKED,validate=True);require(len(compressed)<=786432,'BOUNDED_STAGE18_RUNTIME_PACKAGE_REQUIRED')
 with gzip.GzipFile(fileobj=io.BytesIO(compressed))as stream:raw=stream.read(4194305)
 require(0<len(raw)<=4194304,'BOUNDED_STAGE18_RUNTIME_SOURCE_REQUIRED')
 p=json.loads(raw,object_pairs_hook=unique)
 require(set(p)=={'loader','sources','snapshot','budget','common','controller'},'CLOSED_STAGE18_RUNTIME_PAYLOAD_REQUIRED')
 for name in('loader','snapshot','budget','common','controller'):require(hashlib.sha256(p[name].encode()).hexdigest()==DECLARATION[name+'Hash'],'EXACT_STAGE18_RUNTIME_SOURCE_REQUIRED')
 require(DECLARATION['commonHash']==CASE['commonHash']and DECLARATION['controllerHash']==CASE['runtimeControllerHash'],'STAGE18_CASE_SOURCE_BINDING_CHANGED')
 declaration=DECLARATION['nativeDeclaration'];sources={k:v.encode()for k,v in p['sources'].items()}
 require(hashlib.sha256(encoded(declaration)).hexdigest()==CASE['nativeDeclarationHash']and {n:hashlib.sha256(v).hexdigest()for n,v in sources.items()}==declaration['sourceHashes'],'FROZEN_STAGE18_NATIVE_SOURCE_CHANGED')
 loader={};exec(compile(p['loader'],'<frozen-stage18-native-loader>','exec'),loader)
 entry,manifest=loader['load_entry'](declaration['sourceCommit'],sources,p['loader'].encode(),hashlib.sha256(encoded(declaration)).hexdigest(),declaration['sourcePins'])
 require(manifest==declaration,'FROZEN_STAGE18_NATIVE_DECLARATION_CHANGED')
 ns={}
 for name in('snapshot','budget','common','controller'):
  tree=ast.parse(p[name])
  for node in ast.walk(tree):
   refs=[a.name for a in node.names]if isinstance(node,ast.Import)else[]
   if isinstance(node,ast.ImportFrom):require(node.level==0 and node.module is not None,'RELATIVE_STAGE18_BRIDGE_IMPORT_DENIED');refs=[node.module]
   for ref in refs:require(ref.split('.')[0]in('copy','fcntl','hashlib','json','math','os','pathlib','re','select','signal','stat','sys','termios','time'),'STDLIB_ONLY_STAGE18_RUNTIME_BRIDGE_REQUIRED')
   require(not(isinstance(node,ast.Call)and isinstance(node.func,ast.Name)and node.func.id=='__import__'),'DYNAMIC_STAGE18_RUNTIME_IMPORT_DENIED')
  ns[name]={'__name__':'verified_stage18_'+name};exec(compile(tree,'<verified-stage18-'+name+'>','exec'),ns[name])
 phase='EXPLICIT_STAGE18_'+mode.upper().replace('-','_')
 result=ns['controller']['execute'](entry,manifest,CASE,ns['snapshot'],ns['budget'],types.SimpleNamespace(**ns['common']),mode)
 print(encoded(result).decode(),flush=True)
except (Exception,KeyboardInterrupt)as error:
 code=str(error);reason=code if type(error).__name__in('Denied','ValueError','RuntimeDenied','CreationDenied','PlanDenied','Paused')and re.fullmatch('[A-Z][A-Z0-9_]{0,127}',code)else'STAGE18_CHECK_OR_OUTCOME_UNPROVEN_PRIVATE_DETAILS_REDACTED'
 print(encoded({'schema':'ouf.ingestion-rollout-stage18-result.v1','complete':False,'status':'STOP_RECONCILE','reasonCode':reason,'phase':phase,'runtimeEffectsMayBePartial':mode in('approve','import-prefix','step','reconcile'),'contextsAndClaimsRetained':True,'runtimeAuthorityIssued':False,'newLoginPerformed':False,'automaticReplayAllowed':False,'budgetReset':False,'credentialValuesPrinted':False}).decode(),flush=True)
 raise SystemExit(2)
'''.replace("type(error).__name__in(", "type(error).__name__ in(")


def native_payload(root):
    raw = (root / 'scripts/ingestion-rollout-production-control-20261020.py').read_bytes()
    if sha(raw) != '42b2569a0ba1f2234dfbcc011588cdf133d0e5c97a3f3433b903750f010448ea':
        raise ValueError('EXACT_FROZEN_PRODUCTION_ARTIFACT_REQUIRED')
    values = {n.targets[0].id: ast.literal_eval(n.value) for n in ast.parse(raw).body
              if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
              and n.targets[0].id in ('PACKED', 'DELIVERY')}
    return json.loads(gzip.decompress(base64.b64decode(values['PACKED']))), values['DELIVERY']['nativeDeclaration']


def check_case(root, case):
    pairs = [('commonHash', 'tools/ingestion_rollout_preparation/continuation_common.py'),
        ('runtimeControllerHash', 'tools/ingestion_rollout_preparation/stage18_control.py'),
        ('authControllerHash', 'tools/governed_human_successor/stage18.py')]
    if any(sha((root / p).read_bytes()) != case[k] for k, p in pairs):
        raise ValueError('EXACT_STAGE18_BRIDGE_CASE_SOURCE_HASHES_REQUIRED')


def generate_auth(root, case):
    root = Path(root); check_case(root, case)
    extra = {'.'.join(p.with_suffix('').parts): str(p) for p in (
        Path('tools/ingestion_rollout_preparation') / n for n in (
            'oauth_budget_extension.py', 'continuation_common.py', 'stage18_control.py'))}
    extra['ouf_stopped_snapshot'] = 'scripts/read-ingestion-rollout-stopped-20261021.py'
    result, declaration = auth_delivery.generate(root, case, {}, entry='tools.governed_human_successor.stage18',
        bootstrap=AUTH_BOOTSTRAP, extra_paths=extra)
    _, native = native_payload(root)
    if any(declaration['sourceHashes'].get(k) != v for k, v in native['sourceHashes'].items()):
        raise ValueError('FROZEN_NATIVE_SOURCE_MUST_BE_UNCHANGED_IN_HUMAN_CLOSURE')
    return result, declaration


def generate_runtime(root, case):
    root = Path(root); check_case(root, case); old, declaration = native_payload(root)
    if sha(encoded(declaration)) != case['nativeDeclarationHash']: raise ValueError('EXACT_FROZEN_STAGE18_DECLARATION_REQUIRED')
    payload = {'loader': old['loader'], 'sources': old['sources']}
    for key, path in [('snapshot', 'scripts/read-ingestion-rollout-stopped-20261021.py'),
        ('budget', 'tools/ingestion_rollout_preparation/oauth_budget_extension.py'),
        ('common', 'tools/ingestion_rollout_preparation/continuation_common.py'),
        ('controller', 'tools/ingestion_rollout_preparation/stage18_control.py')]: payload[key] = (root / path).read_text()
    if sha(payload['snapshot'].encode()) != '57a5941574bf5beb0fcfe6e3d5465914a34673c651d74c892133be782e0a5e32':
        raise ValueError('EXACT_QUALIFIED_STOPPED_SNAPSHOT_REQUIRED')
    d = {'schema': 'ouf.ingestion-rollout-stage18-runtime-delivery.v1', 'caseHash': sha(encoded(case)),
        'bootstrapHash': sha(RUNTIME_BOOTSTRAP.encode()), 'nativeDeclaration': declaration,
        **{k + 'Hash': sha(v.encode()) for k, v in payload.items() if k != 'sources'}}
    raw = encoded(payload)
    if len(raw) > 4194304: raise ValueError('STAGE18_RUNTIME_SOURCE_TOO_LARGE')
    compressed = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=compressed, mtime=0, compresslevel=9) as stream: stream.write(raw)
    header = '\n'.join(k + '=' + repr(v) for k, v in (
        ('PACKED', base64.b64encode(compressed.getvalue()).decode('ascii')), ('CASE', case),
        ('DECLARATION', d), ('DECLARATION_HASH', sha(encoded(d))), ('BOOTSTRAP', RUNTIME_BOOTSTRAP)))
    return (header + "\nexec(compile(BOOTSTRAP,'<verified-stage18-runtime-bootstrap>','exec'))\n").encode(), d


def launcher(kind, artifact):
    if kind not in ('human', 'runtime'): raise ValueError('EXACT_STAGE18_LAUNCHER_KIND_REQUIRED')
    blob = hashlib.sha1(b'blob ' + str(len(artifact)).encode() + b'\0' + artifact).hexdigest()
    limits = '''[[ "$#" -ge 1 && "$#" -le 2 ]] || exit 2
case "$1" in
 prepare|open-window) [[ "$#" -eq 1 ]] || exit 2 ;;
 step|status) [[ "$#" -eq 2 ]] || exit 2 ;;
 *) exit 2 ;;
esac''' if kind == 'human' else '''[[ "$#" -eq 1 ]] || exit 2
case "$1" in preflight|review|approve|import-prefix|step|reconcile|status) ;; *) exit 2 ;; esac'''
    return ('''#!/usr/bin/env bash
# Retained-installation foreground stage18 control. No automatic invocation.
set -euo pipefail
umask 077
''' + limits + '''
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { printf '%s\\n' 'STOP: client GitHub non disponibile; nessun sudo.' >&2; exit 2; }
ouf_stage="$(mktemp -d "$HOME/ouf-stage18-''' + kind + '''.XXXXXXXX")"
trap 'printf "Log conservato: %s/operator.log\\nLauncher conservato: %s\\n" "$ouf_stage" "$0"' EXIT
ouf_cache="${0}.operator.py"
if [[ -e "$ouf_cache" || -L "$ouf_cache" ]]; then
 [[ -f "$ouf_cache" && ! -L "$ouf_cache" ]] || exit 2
 cat -- "$ouf_cache" > "$ouf_stage/operator.py"
else
 "$ouf_gh" api 'repos/GioNob/ouf-deploy/git/blobs/''' + blob + '''' --jq .content | tr -d '\\n' | base64 --decode > "$ouf_stage/operator.py"
fi
printf '%s  %s\\n' ''' + "'" + sha(artifact) + "'" + ''' "$ouf_stage/operator.py" | sha256sum -c -
if [[ ! -e "$ouf_cache" && ! -L "$ouf_cache" ]]; then
 ( set -o noclobber; cat -- "$ouf_stage/operator.py" > "$ouf_cache" ) || exit 2
fi
sudo python3 -I -B -S - "$ouf_stage/operator.py" ''' + "'" + sha(artifact) + "'" + ''' "$@" <<'OUF_STAGE18' | tee "$ouf_stage/operator.log"
import hashlib,os,stat,sys
try:
 fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  info=os.fstat(fd)
  if not(stat.S_ISREG(info.st_mode)and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1 and 0<info.st_size<=1048576):raise ValueError()
  raw=os.read(fd,1048577)
  pin=lambda v:tuple(getattr(v,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  if len(raw)!=info.st_size or pin(info)!=pin(os.fstat(fd))or pin(info)!=pin(os.stat(sys.argv[1],follow_symlinks=False))or hashlib.sha256(raw).hexdigest()!=sys.argv[2]:raise ValueError()
 finally:os.close(fd)
 sys.argv=['<verified-stage18-operator>']+sys.argv[3:]
 exec(compile(raw,sys.argv[0],'exec'),{'__name__':'__main__','__file__':sys.argv[0]})
except (Exception,KeyboardInterrupt):
 print('STOP_RECONCILE: pacchetto stage18 non verificato; conserva contesti e claim.',flush=True)
 raise SystemExit(2)
OUF_STAGE18
''').encode()
