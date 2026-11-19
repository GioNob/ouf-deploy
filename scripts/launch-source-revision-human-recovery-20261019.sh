#!/usr/bin/env bash
# Installation-specific, one-use preserved-input continuation; native gates remain.
set -euo pipefail
umask 077
ouf_stage='/home/oufadmin/ouf-deploy-runner/_work/ouf-deploy/ouf-source-revision-human-recovery-code-39212047375'
ouf_manifest='a84ffb91c6ca6ea8ac6ecfef4aa7554f826b99f1d6f9dfcb914ed3a8fc4f00c9'
[[ -r "$ouf_stage/manifest.json" && -r "$ouf_stage/prepare.py" ]] || { echo 'STOP: pacchetto qualificato non disponibile; nessun sudo eseguito.' >&2; exit 1; }
printf '%s  %s\n' "$ouf_manifest" "$ouf_stage/manifest.json" '28ab555e2eb38e7928c4f1ded7e84ad69449c26bc407bb78506a45862ead550f' "$ouf_stage/prepare.py" | sha256sum --check
ouf_log_dir="$(mktemp -d "$HOME/ouf-human-recovery.XXXXXXXX")"
printf '%s\n' 'Tecniche8/8; funzionali4/6. Nuova preparazione privata unica, massimo300secondi.' 'Verifico inmfuoj2:9file e nessuna authority/login; HUMAN BLOCKED/REFRESH189/256,67residui. Nessun replay del refresh.' 'Riuso input originali kfy e81file custody; verifico host/provider/generazioni. Nuovi case/codice/closure e piani privati.' 'Prima di END: nessun OAuth, login, authority o modifica runtime. Custodia MCP root:10005/0440 conservata.' 'Solo dopo END: verifica IAM nativa; se sessione scaduta,un prompt password Keycloak nel terminale. Mai password in chat.' 'Poi RIAPRO LOGIN con hash corrente per una nuova finestra HUMAN finita; cumulativo189/256 preservato.' 'Il distinto APPROVO autorizza backup,V34,Onboarding/MCP,due rotte e capability; ruolo da confermare nella THS.' 'Nessuna pubblicazione profilo,acquisizione CSV o retry job. Dopo STOP/interruzione non rilanciare; conservare il log.' "Log: $ouf_log_dir/run.log"
sudo /usr/bin/python3 -u -I -B -S - "$ouf_stage" "$ouf_manifest" <<'OUF_HUMAN_RECOVERY' | tee "$ouf_log_dir/run.log"
import hashlib,os,sys
from pathlib import Path
stage=Path(sys.argv[1]);expected_manifest=sys.argv[2];helper=stage/'prepare.py'
fd=os.open(helper,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(262145)
finally:os.close(fd)
if hashlib.sha256(raw).hexdigest()!='28ab555e2eb38e7928c4f1ded7e84ad69449c26bc407bb78506a45862ead550f':raise SystemExit('STOP: hash della consegna non valido; nessuna preparazione avviata.')
sys.argv=[str(helper),str(stage),expected_manifest]
exec(compile(raw,'<verified-human-recovery-private-continuation>','exec'),{'__name__':'__main__','__file__':str(helper)})
OUF_HUMAN_RECOVERY
