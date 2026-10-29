# Recupero R3 approvato — unico comando operatore

Approvazione umana del 9 ottobre 2026 alle 09:30:08 Europe/Rome registrata nel commit 14a0da47544e4f56313e25b521c27b3ea7481b60. Non richiedere nuovamente consenso per questo ambito. Witness: evidence/provider-v2-post-signature-recovery-human-approval-20261009.json. Specifica: releases/PROVIDER_V2_POST_SIGNATURE_RECOVERY_REVIEW_20261009.md.

Launcher immutabile: commit dbe84b8ee74df81042f8053fb393a6765a24ce97, SHA25631938cc8863a54c65966504bc64f03a016c7d50424372b62c082198eaf18a024. Helper approvato: commit14a0da47544e4f56313e25b521c27b3ea7481b60, SHA2565ff0a5ac9de85132371026584124f26ad57301601d16882c06974a9c21356328.

CI reale run37899824534/job113719510510 SUCCESS:9 test collegati,7 recupero,1 test launcher con2 scenari (trasferimento fallito/hash errato, sudo mai invocato). Log acquisito e conteggi verificati. Contenuto launcher GitHub confrontato esattamente con quello locale; sintassi del bootstrap verificata. CI non è autorità target. Tutti e quattro i job nativi/profile dell'ultima modifica runtime restano verdi nel run37899168794.

Eseguire una sola volta nel terminale VPS, come oufadmin. Usare gh già autenticato o il fallback già installato. Il bridge già scaricato /home/oufadmin/ouf-reviewed-recovery.qGpE9is0/execute.py viene riutilizzato e verificato; niente nuovo trasferimento dell'artefatto evidenze, scansioni, installazione gh o verifica ripetuta dei sei soggetti. Solo il helper approvato viene scaricato. Hash nel launcher e nel loader root impediscono sostituzioni tra verifica e uso. Il wrapper del bootstrap gestisce codici nonzero senza exit sulla shell SSH; il launcher esegue set-e nel proprio processo e ferma qualsiasi fallimento prima del root.

```bash
if (
  set -u
  set -o pipefail
  gh_bin="$(command -v gh || true)"
  if [[ -z "$gh_bin" ]]; then
    gh_bin="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  fi
  [[ -x "$gh_bin" ]] || exit 1
  r3_launch_dir="$(mktemp -d "$HOME/ouf-r3-launch.XXXXXXXX")" || exit 1
  "$gh_bin" api 'repos/GioNob/ouf-deploy/contents/releases/provider-v2-post-signature-recovery-20261009.sh?ref=dbe84b8ee74df81042f8053fb393a6765a24ce97' --jq '.content' |
    base64 --decode > "$r3_launch_dir/run.sh" || exit 1
  printf '%s  %s\n' '31938cc8863a54c65966504bc64f03a016c7d50424372b62c082198eaf18a024' "$r3_launch_dir/run.sh" |
    sha256sum -c - || exit 1
  bash "$r3_launch_dir/run.sh"
); then
  printf 'OUF_R3_BOOTSTRAP_EXIT=0\n'
else
  ouf_r3_rc=$?
  printf 'OUF_R3_BOOTSTRAP_EXIT=%s\n' "$ouf_r3_rc"
fi
```

Restituire OUF_POST_SIGNATURE_RECOVERY, OUF_R3_RECOVERY_EXIT e OUF_R3_BOOTSTRAP_EXIT. In caso di rifiuto non ripetere il comando; i claim e tutte le evidenze restano conservati. Il recupero osserva il guard e le generazioni prima delle chiavi, riusa16 binding/closure runtime originali, conserva kanx36_x, genera nuova finestra240s/mandati/firme nello snapshot nuovo e invoca solo il percorso coordinato originariamente approvato dei due CID. Nessuna lease/provider API grant, riavvio daemon, sudo generale, job Teatri o release acceptance è concessa. Nessuna esecuzione R3 è stata effettuata dal cloud o riportata dall'operatore al momento della pubblicazione.
