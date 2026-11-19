# OUF — GET originale dopo il repair rete, 24 ottobre2026

## Evidenza target disponibile

L'operatore ha riportato NETWORK_PROJECTION_INSTALLED_OWNER_PUBLISHED/complete=true/Exit0: kernel path e TLS originali provati, discovery200 nel worker, una proiezione persistente, worker invariato/NRestarts0, normale owner ACTIVE416/new95/pub1/finestra positiva. Review ebbac33ca55a0b8625eebeafe29d3ca8750c705cc20bc5f0ffd44050082021c3; authority e33353a3b74777b5233c3b684b5bdef2aafa20d97a26bf725f3aa1a7cee04e3f. Log /home/oufadmin/ouf-network-repair.9eOcCnnC/operator.log. Repair consumato: non rilanciare.

## Nuova verifica separata

Script `scripts/probe-registry-post-network-get-20261024.py`, commit `3cad913653a28ab04f99d4f6706cfb4903a66e60`, SHA256 `e65fd9ba2a31ccc7aea7f34847ef9255e98a865bbfc4cfd28f1b14d046dd3bdb`. Byte pubblicati riletti uguali. Comando sotto verificato con bash -n.

CI [40074500548/job120814864325](https://github.com/GioNob/ouf-deploy/actions/runs/40074500548/job/120814864325): tutti10 test PASS,4.103sec, log diretti letti. Otto verificano gate/classificazione/custodia/Ed25519 reale; due usano vero namespace e HTTPS per token corrente/reference esatta e rifiuto peer pin errato prima di HTTP. Storia/configurazione del fixture sono sintetiche, crypto/filesystem/TLS/trasporto reali. Non è una qualifica dell'intera entry di produzione o un risultato della GET VPS. Localmente8 PASS e2native esplicitamente skipped. Nessuna suite ripetuta senza variazioni.

Lo script incorpora esattamente le definizioni del precedente diagnostico con SHA256 e36d39186023298177adf5aaa85bc4b0db289d19f8c9e0d40af0671c16362d4e. Non esegue la vecchia entry né riapre le sue claim. Le142 dipendenze F7 e gli8moduli owner non cambiano. La closure viene verificata/caricata una sola volta; il secondo punto di utilizzo verifica gli stessi byte e usa quelle classi già caricate, rispettando il rifiuto del loader per moduli applicativi preesistenti.

Gate prima del trasporto: ricevuta completa del repair, hash esatti review/authority, tre firme Ed25519 con autorità pubbliche correnti, drop-in persistente corrispondente, configurazione/unit/manager e contatori owner correnti. La vecchia autorità900sec è letta come fatto storico completato; non estesa né riutilizzata per un effetto. Entrambi gli esiti403 precedenti devono essere completi e vengono preservati/verificati dopo.

Nuovo scope stabile: `<root repair>/post-network-original-get-v1`, esclusivo e fsynced prima di Engine/HTTP. Max4EngineGETs,1GET della prima reference originale,0OAuth/grant/manager/ledgerwrites. Stesso caller/configurazione/mount RO, token configurato corrente letto privatamente, namespace caller reale, CA/hostname/peer pin e vista resolver esistente verificati. Nessun endpoint, port, bearer o permission override. Token ruotato durante la richiesta o generation/configurazione mutate negano l'accettazione. Scope consumato anche se la richiesta fallisce.

Esito pubblico atteso `POST_NETWORK_ORIGINAL_CALLER_GET_OBSERVED`. Leggere `httpStatus`, `exactActiveReferenceMatched`, `allConfiguredReferencesProven` e `originalRequestResource200Proven`: Exit0 significa osservazione completata anche con403, non successo funzionale automatico. Successo della risorsa esatta resta separato da policy cache, identità SERVICE indipendente, rinnovo continuativo, DNS durevole, E2E/readiness complessiva e release acceptance. Il token SERVICE del caller non viene sostituito con quello dell'owner Registry.

## Comando unico da oufadmin

Nessuna nuova approvazione TTY di rete: questa è una osservazione runtime senza mutazioni. Non rilanciare il repair.

```bash
(
  set -euo pipefail
  umask 077
  work=$(mktemp -d "$HOME/ouf-post-network-get.XXXXXXXX")
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
      'repos/GioNob/ouf-deploy/contents/scripts/probe-registry-post-network-get-20261024.py?ref=3cad913653a28ab04f99d4f6706cfb4903a66e60' \
      > "$work/probe.py"
    expected='e65fd9ba2a31ccc7aea7f34847ef9255e98a865bbfc4cfd28f1b14d046dd3bdb'
    printf '%s  %s\n' "$expected" "$work/probe.py" | sha256sum -c -
    sudo -- /bin/bash -c '
      set -euo pipefail
      umask 077
      root="$2"
      mkdir -m 0700 -- "$root"
      chown 0:0 -- "$root"
      install -o 0 -g 0 -m 0400 -- "$1" "$root/probe.py"
      printf "%s  %s\n" "$3" "$root/probe.py" | sha256sum -c -
      exec /usr/bin/python3 -I -B -S "$root/probe.py"
    ' ouf-post-network-get "$work/probe.py" \
      '/etc/ouf/deploy-snapshots/semantic-post-network-get-e65fd9ba2a31ccc7' \
      "$expected"
  } 2>&1 | tee "$log"
)
```

Conservare JSON pubblico e percorso log; mai credenziali o revisione privata in chat. In STOP_RECONCILE non rilanciare: riconciliare lo scope nuovo e l'eventuale GET tentata. Il rinnovatore continua indipendentemente. Dopo questa prova valutare403/policy effettiva o200 esatto, osservare rinnovo continuativo e resilienza richiesta, poi E2E e infine Supervisor. Stato tuttora8/8 tecnico,4/6 funzionale,G3OPEN.
