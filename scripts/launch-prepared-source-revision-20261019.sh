#!/usr/bin/env bash
# Exact prepared release; all authority remains in the existing native gates.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'Client GitHub autorizzato non disponibile.' >&2; exit 1; }
ouf_release_dir="$(mktemp -d "$HOME/ouf-prepared-source-revision.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/deliver-prepared-source-revision-20261019.py?ref=120fb243c81b9a5fc78691163194911da8093aec' --jq '.content' | base64 --decode > "$ouf_release_dir/deliver.py"
printf '%s  %s\n' '47129694ccaf82bae744859eba4997e3493c5f8c15d54aa476670b63c8f96b5a' "$ouf_release_dir/deliver.py" | sha256sum --check
printf '%s\n' 'Tecniche8/8; funzionali4/6. Verifico la preparazione gezxi85l e raggiungo i gate nativi del rilascio.' 'Dopo i controlli, il programma puo richiedere RIAPRO LOGIN e APPROVO con hash correnti.' 'Leggere la revisione: dopo APPROVO sono previsti backup, Flyway V34, sostituzione Onboarding/MCP e due rotte.' 'Il ruolo richiede conferma separata nella THS. Nessuna pubblicazione del profilo o acquisizione in questo comando.' 'In caso di STOP o interruzione non rilanciare; conservare log e nuovo contesto per riconciliazione.' "Log: $ouf_release_dir/run.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_release_dir/deliver.py" <<'OUF_PREPARED_RELEASE' | tee "$ouf_release_dir/run.log"
import hashlib,os,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 with os.fdopen(os.dup(fd),'rb') as stream:raw=stream.read(262145)
finally:os.close(fd)
if hashlib.sha256(raw).hexdigest()!='47129694ccaf82bae744859eba4997e3493c5f8c15d54aa476670b63c8f96b5a':
 raise SystemExit('STOP: hash della consegna non valido; esecutore non avviato.')
exec(compile(raw,'<verified-prepared-source-revision-delivery>','exec'),{'__name__':'__main__','__file__':sys.argv[1]})
OUF_PREPARED_RELEASE
