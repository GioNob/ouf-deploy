# OUF — consegna pinned del repair rete, 24 ottobre 2026

Comando consegnato per una sola esecuzione da oufadmin sul VPS, in un terminale interattivo. Nessuna esecuzione target osservata da questa sessione. Il prossimo dato necessario è l'output JSON reale; non rilanciare in caso di STOP.

Sorgente invariato: `a7de09a7d5fee0b41022ff450c6bb7e1c58ca0b1`.
SHA256 riletto e verificato: `dbd7bccc32904974e0b9e85491c9dc3a5100c9c51d550e0951e773523fcbd808`.

Letti integralmente entrambi i handoff del commit 6bcbb0a, l'intestazione corrente di AGENTS.md e il precedente handoff running-policy. Riletti il sorgente completo, i log diretti dei job 120808901590/120808901748 e lo stato SUCCESS della CI40072536778: 67 componenti +14 native, ulteriori2 native dedicate. Le prove restano CI, non risultati sul server. Il comando sotto passa bash -n; il launcher non è stato eseguito contro il VPS né qualificato come intera entry TTY di produzione.

Il comando scarica con gh già disponibile, verifica prima di sudo, crea una root esclusiva0700, installa una copia root0400, riverifica e avvia Python isolato. Conserva directory, log ed exit status anche in STOP. Non riutilizza root esistenti né cancella claim.

Il repair presenta la revisione privata corrente e richiede `APPROVO <hash esatto mostrato>` dal controlling terminal. Non usare hash storici né input simulato. La firma reale usa le autorità esistenti e una finestra nuova di900secondi. Il prompt TTY può comparire separatamente dal log stdout/stderr; revisione e ricevute sono conservate dal repair nello scope privato.

```bash
(
  set -euo pipefail
  umask 077
  work=$(mktemp -d "$HOME/ouf-network-repair.XXXXXXXX")
  log="$work/operator.log"
  : > "$log"
  trap 'rc=$?; trap - EXIT; set +e; printf "\nExit=%s\nDirectory=%s\nLog=%s\n" "$rc" "$work" "$log" | tee -a "$log"; exit "$rc"' EXIT
  {
    gh_bin="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
    if [ ! -x "$gh_bin" ]; then
      gh_bin=$(command -v gh || true)
    fi
    if [ -z "$gh_bin" ] || [ ! -x "$gh_bin" ]; then
      printf '%s\n' 'STOP: client gh esistente assente; nessun sudo eseguito.'
      exit 2
    fi
    "$gh_bin" api --hostname github.com --method GET \
      -H 'Accept: application/vnd.github.raw+json' \
      'repos/GioNob/ouf-deploy/contents/scripts/repair-registry-network-projection-20261024.py?ref=a7de09a7d5fee0b41022ff450c6bb7e1c58ca0b1' \
      > "$work/repair.py"
    expected='dbd7bccc32904974e0b9e85491c9dc3a5100c9c51d550e0951e773523fcbd808'
    printf '%s  %s\n' "$expected" "$work/repair.py" | sha256sum -c -
    sudo -- /bin/bash -c '
      set -euo pipefail
      umask 077
      root="$2"
      mkdir -m 0700 -- "$root"
      chown 0:0 -- "$root"
      install -o 0 -g 0 -m 0400 -- "$1" "$root/repair.py"
      printf "%s  %s\n" "$3" "$root/repair.py" | sha256sum -c -
      exec /usr/bin/python3 -I -B -S "$root/repair.py"
    ' ouf-network-repair "$work/repair.py" \
      '/etc/ouf/deploy-snapshots/semantic-network-repair-dbd7bccc32904974' \
      "$expected"
  } 2>&1 | tee "$log"
)
```

Esito atteso: `NETWORK_PROJECTION_INSTALLED_OWNER_PUBLISHED`. Anche in quel caso la GET applicativa originale200, la policy effettiva, il rinnovo continuativo e la release acceptance richiedono prove successive. La sequenza resta502/403, E2E, Supervisor.

In `STOP_RECONCILE` conservare JSON pubblico e percorso del log, senza rilanciare, rollback automatico, reinstallazione o riavvio worker, reset contatori o replay di scope consumati. Un effetto parziale è possibile dopo il claim manager; il normale worker prosegue indipendentemente. Non incollare credenziali, indirizzi o contenuto della revisione privata.

Stato funzionale invariato:8/8 tecnico,4/6 funzionale,G3OPEN. Ultimo dato target398 tentativi cumulativi/pubblicazioni0, storico e non congelato.
