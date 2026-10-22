"""Build cached foreground launchers; authentication never downloads code.

The setup command fetches/hash-checks both complete closures before its single
read-only preflight. Every later command uses only the pinned local cache.
"""
import hashlib
from tools.ingestion_readiness_patch_execution import operator_delivery_v2 as runtime,human_delivery_v2 as human


def blob(raw):return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()


def launcher(kind,artifact):
    if kind not in ('human','runtime'):raise ValueError('EXACT_PATCH_RELEASE_KIND_REQUIRED')
    limits='''case "$1" in
 prepare|grant-budget|budget-status|open-window) [[ "$#" -eq 1 ]] || exit 2 ;;
 step|status|reconcile-read) [[ "$#" -eq 2 ]] || exit 2 ;;
 *) exit 2 ;;
esac''' if kind=='human' else '''case "$1" in
 review) [[ "$#" -eq 2 ]] || exit 2 ;;
 preflight|approve|initialize|step|reconcile|status) [[ "$#" -eq 1 ]] || exit 2 ;;
 *) exit 2 ;;
esac'''
    return ('''#!/usr/bin/env bash
# Cached exact one-Ingestion patch; one explicit mode, never downloads code.
set -euo pipefail
umask 077
[[ "$#" -ge 1 && "$#" -le 2 ]] || exit 2
'''+limits+'''
ouf_cache="${0}.operator.py"
[[ -f "$ouf_cache" && ! -L "$ouf_cache" ]] || { printf '%s\n' 'STOP: cache verificata assente; nessuna invocazione.' >&2; exit 2; }
ouf_stage="$(mktemp -d "$HOME/ouf-readiness-'''+kind+'''.XXXXXXXX")"
trap 'printf "Log conservato: %s/operator.log\\nLauncher conservato: %s\\n" "$ouf_stage" "$0"' EXIT
cat -- "$ouf_cache" > "$ouf_stage/operator.py"
printf '%s  %s\\n' '''+repr(runtime.sha(artifact))+''' "$ouf_stage/operator.py" | sha256sum -c -
sudo python3 -I -B -S - "$ouf_stage/operator.py" '''+repr(runtime.sha(artifact))+''' "$@" <<'OUF_PATCH_VERIFIED' | tee "$ouf_stage/operator.log"
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
 sys.argv=['<verified-ingestion-patch>']+sys.argv[3:]
 exec(compile(raw,sys.argv[0],'exec'),{'__name__':'__main__','__file__':sys.argv[0]})
except (Exception,KeyboardInterrupt):
 print('STOP_RECONCILE: pacchetto patch non verificato; conserva contesti e claim.',flush=True)
 raise SystemExit(2)
OUF_PATCH_VERIFIED
''').encode()


def setup(files):
    expected={'human.sh','human.sh.operator.py','runtime.sh','runtime.sh.operator.py'}
    if set(files)!=expected:raise ValueError('EXACT_TWO_CACHED_PATCH_CLOSURES_REQUIRED')
    commands=[]
    for name,raw in sorted(files.items()):
        commands.append('"$ouf_gh" api \'repos/GioNob/ouf-deploy/git/blobs/'+blob(raw)+
            '\' --jq .content | tr -d \'\\n\' | base64 --decode > "$ouf_cache/'+name+'"\n'+
            "printf '%s  %s\\n' '"+runtime.sha(raw)+"' \"$ouf_cache/"+name+'" | sha256sum -c -')
    return ('''#!/usr/bin/env bash
# Fetch all code before timers/consent; one read-only runtime/HUMAN preflight.
set -euo pipefail
umask 077
[[ "$#" -eq 0 ]] || exit 2
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { printf '%s\\n' 'STOP: client GitHub non disponibile; nessun sudo.' >&2; exit 2; }
ouf_cache="$(mktemp -d "$HOME/ouf-readiness-launchers.XXXXXXXX")"
trap 'printf "Directory conservata: %s\\nLauncher HUMAN: %s/human.sh\\nLauncher runtime: %s/runtime.sh\\n" "$ouf_cache" "$ouf_cache" "$ouf_cache"' EXIT
'''+ '\n'.join(commands)+'''
bash "$ouf_cache/human.sh" prepare
''').encode()


def generate(root,case):
    h,hdecl=human.generate(root,case);r,rdecl=runtime.generate(root,case['runtimeCase'],case['nativeDeclaration'])
    files={'human.sh.operator.py':h,'runtime.sh.operator.py':r,'human.sh':launcher('human',h),'runtime.sh':launcher('runtime',r)}
    return {**files,'setup.sh':setup(files)}, {'human':hdecl,'runtime':rdecl}
