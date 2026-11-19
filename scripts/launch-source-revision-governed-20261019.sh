#!/usr/bin/env bash
# Installation-specific, one-use preserved-input continuation; native gates remain.
set -euo pipefail
umask 077
ouf_stage='/home/oufadmin/ouf-deploy-runner/_work/ouf-deploy/ouf-source-revision-governed-code-39203223055'
ouf_manifest='2c106bf3456a42de6024980379af2f9ebc0e3d8f56cf94e928f471e72b1a7ac4'
[[ -r "$ouf_stage/manifest.json" && -r "$ouf_stage/prepare.py" ]] || { echo 'STOP: pacchetto qualificato non disponibile; nessun sudo eseguito.' >&2; exit 1; }
printf '%s  %s\n' "$ouf_manifest" "$ouf_stage/manifest.json" 'f6c7905c36920af4c30116d8e611c4f9c2663d35339e8fcfefd97e0d2f336b03' "$ouf_stage/prepare.py" | sha256sum --check
ouf_log_dir="$(mktemp -d "$HOME/ouf-governed-continuation.XXXXXXXX")"
printf '%s\n' 'Tecniche8/8; funzionali4/6. Capsula privata unica, massimo300secondi.' 'Riuso input kfy691gh e sessione HUMAN READY:186/256, senza nuovo login o reset budget.' 'Verifico originali,11file daxl0o6h, provider e generazioni; poi nuovo case/codice/closure e piano nativo privati.' 'Dopo END il nuovo processo esegue solo refresh HUMAN nativo e presenta APPROVO con hash corrente.' 'Solo dopo APPROVO: backup, Flyway V34, Onboarding/MCP e due rotte. Ruolo da confermare nella THS.' 'Nessuna pubblicazione del profilo, acquisizione CSV o retry job. Dopo STOP/interruzione non rilanciare; conservare il log.' "Log: $ouf_log_dir/run.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_stage" "$ouf_manifest" <<'OUF_GOVERNED_CONTINUATION' | tee "$ouf_log_dir/run.log"
import hashlib,os,sys
from pathlib import Path
stage=Path(sys.argv[1]);expected_manifest=sys.argv[2];helper=stage/'prepare.py'
fd=os.open(helper,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(262145)
finally:os.close(fd)
if hashlib.sha256(raw).hexdigest()!='f6c7905c36920af4c30116d8e611c4f9c2663d35339e8fcfefd97e0d2f336b03':raise SystemExit('STOP: hash della consegna non valido; nessuna preparazione avviata.')
sys.argv=[str(helper),str(stage),expected_manifest]
exec(compile(raw,'<verified-governed-private-continuation>','exec'),{'__name__':'__main__','__file__':str(helper)})
OUF_GOVERNED_CONTINUATION
