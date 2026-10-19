#!/usr/bin/env bash
# Installation-specific, standalone native HUMAN administration; one use.
set -euo pipefail
umask 077
ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
if [[ ! -x "$ouf_gh" ]]; then ouf_gh="$(command -v gh || true)"; fi
[[ -n "$ouf_gh" && -x "$ouf_gh" ]] || { echo 'STOP: client GitHub approvato non disponibile; nessun sudo.' >&2; exit 1; }
ouf_stage='/home/oufadmin/ouf-deploy-runner/_work/ouf-deploy/ouf-ingestion-read-administrative-code-39221983431'
ouf_manifest='6462f6f506dee6904123fcc94975b16727476d482969f5020f03d43ddb69e09c'
[[ -r "$ouf_stage/manifest.json" && -r "$ouf_stage/prepare.py" ]] || { echo 'STOP: pacchetto qualificato non disponibile; nessun sudo eseguito.' >&2; exit 1; }
printf '%s  %s\n' "$ouf_manifest" "$ouf_stage/manifest.json" '68068635b76b54bb0911a5321cae6e3b09149c2256b81c5b8b958f0297e8b3fc' "$ouf_stage/prepare.py" | sha256sum --check
ouf_log_dir="$(mktemp -d "$HOME/ouf-ingestion-admin.XXXXXXXX")"
printf '%s\n' 'Tecniche8/8; funzionali4/6. Azione amministrativa distinta; preparazione privata massimo180secondi.' 'Riuso la sola storia completata uow4n8lp e la selezione installativa sotto custodia. Non rilancio installazione o readback.' 'Prima di PREPARED: nessun OAuth, login, authority o chiamata infrastrutturale.' 'Dopo PREPARED: metadata IAM; un login amministrativo nel terminale solo se la sessione esistente e scaduta.' 'HUMAN: riuso della finestra valida; RIAPRO LOGIN con hash corrente solo se necessario. Cumulativo256 preservato.' 'APPROVO distinto: sola registrazione ingestion.operations.read, descrittore policy e relativo scope OAuth ChatGPT.' 'Nessun ruolo o grant pubblicato; grant temporaneo successivo nella THS. Nessuna attivazione, acquisizione, rotta, migrazione o modifica servizi.' 'Dopo STOP/interruzione non rilanciare; conservare il log. Non incollare password o codici OAuth nella chat.' "Log: $ouf_log_dir/run.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_stage" "$ouf_manifest" <<'OUF_INGESTION_ADMIN' | tee "$ouf_log_dir/run.log"
import hashlib,os,sys
from pathlib import Path
stage=Path(sys.argv[1]);expected_manifest=sys.argv[2];helper=stage/'prepare.py'
fd=os.open(helper,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(262145)
finally:os.close(fd)
if hashlib.sha256(raw).hexdigest()!='68068635b76b54bb0911a5321cae6e3b09149c2256b81c5b8b958f0297e8b3fc':raise SystemExit('STOP: hash della consegna non valido; nessuna preparazione avviata.')
sys.argv=[str(helper),str(stage),expected_manifest]
exec(compile(raw,'<verified-ingestion-read-administrative-preparation>','exec'),{'__name__':'__main__','__file__':str(helper)})
OUF_INGESTION_ADMIN

