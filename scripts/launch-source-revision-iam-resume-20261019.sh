#!/usr/bin/env bash
# Exact prepared release; all authority remains in the existing native gates.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'Client GitHub autorizzato non disponibile.' >&2; exit 1; }
ouf_release_dir="$(mktemp -d "$HOME/ouf-source-revision-iam-resume.XXXXXXXX")"
"$ouf_gh" api 'repos/GioNob/ouf-deploy/contents/scripts/resume-source-revision-iam-20261019.py?ref=7f9d752e9dce87295b734647dff66a873a7302eb' --jq '.content' | base64 --decode > "$ouf_release_dir/deliver.py"
printf '%s  %s\n' '8dc594b9c7cc07477d66303b4b0e86ddcdaf50dbe19eec9e630459848f5ee8f8' "$ouf_release_dir/deliver.py" | sha256sum --check
printf '%s\n' 'Tecniche8/8; funzionali4/6. Verifico tvc2ilnv e riuso la preparazione kfy691gh, senza ripeterla.' 'Un solo rinnovo IAM: password nel prompt Keycloak del terminale, mai nella chat. Seguono i gate RIAPRO LOGIN e APPROVO con hash correnti.' 'Leggere la revisione: dopo APPROVO sono previsti backup, Flyway V34, sostituzione Onboarding/MCP e due rotte.' 'Il ruolo richiede conferma separata nella THS. Nessuna pubblicazione del profilo o acquisizione in questo comando.' 'In caso di STOP o interruzione non rilanciare; conservare log e nuovo contesto per riconciliazione.' "Log: $ouf_release_dir/run.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_release_dir/deliver.py" <<'OUF_PREPARED_RELEASE' | tee "$ouf_release_dir/run.log"
import hashlib,os,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 with os.fdopen(os.dup(fd),'rb') as stream:raw=stream.read(262145)
finally:os.close(fd)
if hashlib.sha256(raw).hexdigest()!='8dc594b9c7cc07477d66303b4b0e86ddcdaf50dbe19eec9e630459848f5ee8f8':
 raise SystemExit('STOP: hash della consegna non valido; esecutore non avviato.')
exec(compile(raw,'<verified-prepared-source-revision-delivery>','exec'),{'__name__':'__main__','__file__':sys.argv[1]})
OUF_PREPARED_RELEASE
