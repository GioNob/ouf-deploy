#!/usr/bin/env bash
# Installation-specific, one-use preserved-input continuation; native gates remain.
set -euo pipefail
umask 077
ouf_stage='/home/oufadmin/ouf-deploy-runner/_work/ouf-deploy/ouf-source-revision-custody-code-39206613640'
ouf_manifest='7145b253a4946fdc6e85de99de59a67cf2516d40ea261c5e6bfe3dc7df85101b'
[[ -r "$ouf_stage/manifest.json" && -r "$ouf_stage/prepare.py" ]] || { echo 'STOP: pacchetto qualificato non disponibile; nessun sudo eseguito.' >&2; exit 1; }
printf '%s  %s\n' "$ouf_manifest" "$ouf_stage/manifest.json" '5a245e1907b28e1131b2c756e6283440f5f1384d16fc4a6bbb37a7a904b1237f' "$ouf_stage/prepare.py" | sha256sum --check
ouf_log_dir="$(mktemp -d "$HOME/ouf-custody-continuation.XXXXXXXX")"
printf '%s\n' 'Tecniche8/8; funzionali4/6. Capsula privata unica, massimo300secondi.' 'Riuso input kfy691gh e sessione HUMAN READY:188/256, senza nuovo login o reset budget.' 'Verifico originali,22file dvf517sr, provider e generazioni; poi nuovo case/codice/closure e piano nativo privati.' 'Preservo i metadati MCP root:10005/0440 e il claim originale; nessun chmod/chown.' 'Il nuovo APPROVO autorizza anche un unico claim successore; authority scaduta non riutilizzata.' 'Dopo END il nuovo processo esegue solo refresh HUMAN nativo e presenta APPROVO con hash corrente.' 'Solo dopo APPROVO: backup, Flyway V34, Onboarding/MCP e due rotte. Ruolo da confermare nella THS.' 'Nessuna pubblicazione del profilo, acquisizione CSV o retry job. Dopo STOP/interruzione non rilanciare; conservare il log.' "Log: $ouf_log_dir/run.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_stage" "$ouf_manifest" <<'OUF_CUSTODY_CONTINUATION' | tee "$ouf_log_dir/run.log"
import hashlib,os,sys
from pathlib import Path
stage=Path(sys.argv[1]);expected_manifest=sys.argv[2];helper=stage/'prepare.py'
fd=os.open(helper,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(262145)
finally:os.close(fd)
if hashlib.sha256(raw).hexdigest()!='5a245e1907b28e1131b2c756e6283440f5f1384d16fc4a6bbb37a7a904b1237f':raise SystemExit('STOP: hash della consegna non valido; nessuna preparazione avviata.')
sys.argv=[str(helper),str(stage),expected_manifest]
exec(compile(raw,'<verified-custody-private-continuation>','exec'),{'__name__':'__main__','__file__':str(helper)})
OUF_CUSTODY_CONTINUATION
