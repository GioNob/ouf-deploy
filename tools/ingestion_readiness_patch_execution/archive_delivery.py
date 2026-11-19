"""Build the exact offline archive capsule. No target I/O or source discovery."""
import base64
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path

BOOTSTRAP='''import base64,gzip,hashlib,importlib,io,json,os,re,signal,sys
def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def unique(pairs):
 v={}
 for k,x in pairs:
  require(k not in v,'DUPLICATE_NATIVE_ARCHIVE_DELIVERY_FIELD');v[k]=x
 return v
try:
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_NATIVE_ARCHIVE_PREPARATION_REQUIRED')
 require(sys.argv[1:]==['prepare'],'ONE_EXPLICIT_OFFLINE_ARCHIVE_PREPARATION_REQUIRED')
 require(hashlib.sha256(BOOTSTRAP.encode()).hexdigest()==DELIVERY['bootstrapHash']and hashlib.sha256(encoded(DELIVERY)).hexdigest()==DELIVERY_HASH,'NATIVE_ARCHIVE_DELIVERY_CHANGED')
 require(hashlib.sha256(encoded(CASE)).hexdigest()==DELIVERY['caseHash'],'NATIVE_ARCHIVE_CASE_CHANGED')
 signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_OFFLINE_NATIVE_ARCHIVE_DEADLINE'));signal.alarm(180)
 compressed=base64.b64decode(PACKED,validate=True);require(len(compressed)<=786432,'BOUNDED_NATIVE_ARCHIVE_CAPSULE_REQUIRED')
 with gzip.GzipFile(fileobj=io.BytesIO(compressed))as stream:raw=stream.read(4194305)
 require(0<len(raw)<=4194304,'BOUNDED_NATIVE_ARCHIVE_SOURCES_REQUIRED')
 p=json.loads(raw,object_pairs_hook=unique);require(set(p)=={'loader','sources'},'CLOSED_NATIVE_ARCHIVE_SOURCE_PAYLOAD_REQUIRED')
 require(hashlib.sha256(p['loader'].encode()).hexdigest()==DELIVERY['nativeDeclaration']['loaderHash'],'NATIVE_ARCHIVE_LOADER_CHANGED')
 loader={};exec(compile(p['loader'],'<verified-native-archive-loader>','exec'),loader)
 declaration=DELIVERY['nativeDeclaration']
 entry,manifest=loader['load_entry'](declaration['sourceCommit'],{n:v.encode()for n,v in p['sources'].items()},p['loader'].encode(),hashlib.sha256(encoded(declaration)).hexdigest(),declaration['sourcePins'])
 require(manifest==declaration,'NATIVE_ARCHIVE_DECLARATION_CHANGED')
 module=importlib.import_module('tools.ingestion_readiness_patch_execution.archive_preparation')
 result=module.prepare(CASE);print(encoded(result).decode(),flush=True)
except (Exception,KeyboardInterrupt)as error:
 code=str(error);reason=code if re.fullmatch('[A-Z][A-Z0-9_]{0,127}',code)else'NATIVE_ARCHIVE_PREPARATION_UNPROVEN_PRIVATE_DETAILS_REDACTED'
 print(encoded({'schema':'ouf.ingestion-readiness-native-archive-result.v1','status':'STOP_RECONCILE','complete':False,'reasonCode':reason,'contextsAndClaimsRetained':True,'automaticReplayAllowed':False,'oauthRequests':0,'runtimeAuthorityIssued':False,'runtimeEffectsDispatched':0,'budgetReset':False}).decode(),flush=True)
 raise SystemExit(2)
'''

def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def generate(root,case,source_commit,source_pins):
    root=Path(root);path=root/'tools/ingestion_readiness_patch_execution/runtime.py'
    spec=importlib.util.spec_from_file_location('qualified_patch_archive_loader',path)
    runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
    sources={n:(root/runtime.SOURCE_PATHS[n]).read_bytes()for n in runtime.MODULES}
    loader=path.read_bytes();native=runtime.declaration(source_commit,sources,loader,source_pins)
    declaration={'schema':'ouf.ingestion-readiness-native-archive-delivery.v1','nativeDeclaration':native,
                 'caseHash':sha(encoded(case)),'bootstrapHash':sha(BOOTSTRAP.encode()),'runtimeAuthorityIssued':False}
    payload=encoded({'loader':loader.decode(),'sources':{n:v.decode()for n,v in sorted(sources.items())}})
    compressed=io.BytesIO()
    with gzip.GzipFile(filename='',mode='wb',fileobj=compressed,mtime=0)as stream:stream.write(payload)
    packed=base64.b64encode(compressed.getvalue()).decode()
    artifact=('CASE='+repr(case)+'\nDELIVERY='+repr(declaration)+'\nDELIVERY_HASH='+repr(sha(encoded(declaration)))+
              '\nPACKED='+repr(packed)+'\nBOOTSTRAP='+repr(BOOTSTRAP)+'\nexec(compile(BOOTSTRAP,"<native-archive-preparation>","exec"))\n').encode()
    if len(artifact)>1048576:raise ValueError('BOUNDED_NATIVE_ARCHIVE_OPERATOR_REQUIRED')
    return artifact,declaration

def launcher(artifact,artifact_commit):
    if len(artifact_commit)!=40 or any(c not in '0123456789abcdef'for c in artifact_commit):raise ValueError('EXACT_ARCHIVE_ARTIFACT_COMMIT_REQUIRED')
    return ('''#!/usr/bin/env bash
set -euo pipefail
umask 077
if [ "$#" -ne 0 ]; then printf '%s\\n' 'Solo preparazione offline esplicita; nessun argomento ammesso.' >&2; exit 2; fi
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$ouf_gh" ]; then ouf_gh="$(command -v gh || true)"; fi
if [ -z "$ouf_gh" ] || [ ! -x "$ouf_gh" ]; then printf '%s\\n' 'Client GitHub gia autenticato non disponibile; nessuna modifica eseguita.' >&2; exit 2; fi
ouf_output="$(mktemp -d "$HOME/ouf-native-archive.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/prepare-ingestion-native-archive-20261022.py?ref=ARTIFACT_COMMIT' --jq .content > "$ouf_output/operator.b64"
base64 --decode "$ouf_output/operator.b64" > "$ouf_output/operator.py"
printf '%s  %s\\n' ARTIFACT_SHA "$ouf_output/operator.py" | sha256sum -c -
set +e
sudo /usr/bin/python3 -I -B -S "$ouf_output/operator.py" prepare 2>&1 | tee "$ouf_output/operator.log"
ouf_status=${PIPESTATUS[0]}
set -e
printf 'Directory conservata: %s\\nLog conservato: %s/operator.log\\nDopo STOP conserva tutto: non rieseguire.\\n' "$ouf_output" "$ouf_output"
exit "$ouf_status"
'''.replace('ARTIFACT_COMMIT',artifact_commit).replace('ARTIFACT_SHA',sha(artifact))).encode()
