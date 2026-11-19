#!/usr/bin/env bash
# One retained-host preparation; no native login or runtime authority.
set -euo pipefail
umask 077
gh_exe="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [ ! -x "$gh_exe" ]; then gh_exe="$(command -v gh || true)"; fi
if [ -z "$gh_exe" ] || [ ! -x "$gh_exe" ]; then printf '%s\n' 'STOP: GitHub client unavailable; no sudo or preparation performed.' >&2; exit 2; fi
work="$(mktemp -d "$HOME/ouf-ingestion-owner-draft.XXXXXXXX")"
printf 'Log privato: %s/run.log\n' "$work"
"$gh_exe" api "repos/GioNob/ouf-deploy/contents/releases/ingestion-read-owner-draft-bundle-20261019.json?ref=f1ac45529ae3c16080f012ca7cee02730f47ed74" --jq .content | tr -d '\n' | base64 --decode > "$work/bundle.json"
printf '%s  %s\n' '26225e9909018f5a69529e3fc191580fc7e7a8662110c6005d6a876d41c4fa2c' "$work/bundle.json" | sha256sum -c -
sudo python3 -I -B -S - "$work/bundle.json" '26225e9909018f5a69529e3fc191580fc7e7a8662110c6005d6a876d41c4fa2c' <<'PY' | tee "$work/run.log"
import ast,base64,hashlib,json,os,re,stat,sys,types
safe=set()
try:
    if not (os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode): raise ValueError('ISOLATED_ROOT_REQUIRED')
    fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        if not (stat.S_ISREG(before.st_mode)and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=2097152): raise ValueError('EXACT_PRIVATE_DELIVERY_REQUIRED')
        with os.fdopen(os.dup(fd),'rb')as f: raw=f.read(2097153)
        pin=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
        if len(raw)!=before.st_size or pin(before)!=pin(os.fstat(fd))or hashlib.sha256(raw).hexdigest()!=sys.argv[2]: raise ValueError('AUTHENTICATED_DELIVERY_CHANGED')
    finally: os.close(fd)
    value=json.loads(raw)
    names={'base','compiler','audit','jar_reader','image_custody','gateway_renderer','delegation.lua','execute_ingestion_read.lua'}
    if value.get('schema')!='ouf.ingestion-read-owner-draft-delivery.v1' or set(value['files'])!=names or value['runtimeAuthorityIssued']is not False: raise ValueError('EXACT_DRAFT_DELIVERY_REQUIRED')
    sources={}
    for name,row in value['files'].items():
        raw=base64.b64decode(row['base64'],validate=True)
        if not 0<len(raw)<=262144 or hashlib.sha256(raw).hexdigest()!=row['sha256']: raise ValueError('DRAFT_SOURCE_CHANGED')
        sources[name]=raw
    modules={}
    for name in ('base','compiler','audit','jar_reader','image_custody'):
        tree=ast.parse(sources[name])
        safe.update(v.value for v in ast.walk(tree)if isinstance(v,ast.Constant)and type(v.value)is str and re.fullmatch('[A-Z][A-Z0-9_]{2,150}',v.value))
        module=types.ModuleType('authenticated_draft_'+name)
        module.__file__='<authenticated-draft-'+name+'>'
        exec(compile(tree,module.__file__,'exec'),module.__dict__)
        modules[name]=module
    lua={name:sources[name].decode('utf-8')for name in ('delegation.lua','execute_ingestion_read.lua')}
    audit=lambda inputs,context:modules['audit'].run(modules['base'],modules['jar_reader'],modules['image_custody'],inputs,context)
    report=modules['compiler'].main(modules['base'],lua,audit)
except (Exception,KeyboardInterrupt)as error:
    report={'schema':'ouf.ingestion-read-owner-rollout-draft-result.v1','complete':False,'status':'STOP_RECONCILE','exceptionClass':type(error).__name__,
        'reasonCode':str(error)if str(error)in safe else'PRIVATE_DETAILS_REDACTED','automaticReplayAllowed':False,'budgetReset':False,'runtimeAuthorityIssued':False}
print(json.dumps(report,sort_keys=True,separators=(',',':')),flush=True)
raise SystemExit(0 if report['complete']else 2)
PY
