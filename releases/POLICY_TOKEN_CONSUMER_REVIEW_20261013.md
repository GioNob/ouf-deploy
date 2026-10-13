# Lettura unica dei consumer noti del policy token

**Già eseguita sul VPS il 13 ottobre alle 20:32 CEST. Non ripetere il comando sottostante.** [Esito, revisione del codice e integrazione successiva](POLICY_TOKEN_MIGRATION_ASSEMBLY_20261013.md).

Il prossimo passo serve a delimitare l'impatto di una futura rigenerazione della credenziale. Le policy IAM sono già state osservate; i servizi e tre percorsi script sono già stati identificati. Non ripetere i precedenti comandi separati. Il quarto layout, previsto dall'installer onboarding sotto `/var/lib/ouf-r4a-identity/`, è incluso qui.

La procedura è una sola osservazione di operator review, non un installer o una nuova componente runtime. Legge i metadati correnti delle quattro unità, i quattro sorgenti noti senza eseguirli, i riferimenti di configurazione nel layout `/etc/ouf/policy-token/*.conf`, l'ambiente dichiarato delle unità e i quattro timer. Raccoglie inoltre gli altri nomi di unità `ouf-*token*.service`: questo selector non certifica un inventario completo di tutti i possibili consumer. Le proprietà correnti sono lette nuovamente per collegarle alla stessa raccolta dei sorgenti; non viene ripetuta l'osservazione IAM.

I nomi dei client, gli argomenti completi, le variabili d'ambiente, i percorsi delle credenziali e i sorgenti grezzi non vengono stampati né copiati nell'evidenza. I programmi sono analizzati come AST: nessun import/exec dei writer, grant, chiamata IAM, cambio servizio, chiave privata o file bearer. I riferimenti ai secret non vengono seguiti. Sorgenti e configurazioni potrebbero contenere valori privati incorporati: la procedura non sostiene di averne provato l'assenza; li mantiene soltanto in memoria durante l'analisi e produce un report redatto.

## Perimetro e limiti

- Riusa gli input host `93fa9bc8fe4d90fe445bb310363f11966f9ed89df74d169ad925cda0a157acc4` e l'osservazione policy `3aef37971d405e0a84c60e0e110f7ababdba8e5c62cbda815e44e9ea5077d060`, verificandone gli hash. Non crea radici di installazione e non aggiorna baseline o budget.
- Verifica i byte del programma systemctl rispetto alla precedente osservazione host. Sono ammesse solo operazioni show/list-unit-files: massimo nove invocazioni, cinque secondi ciascuna, sessanta secondi per la raccolta; novanta per il corpo root. Nessun retry automatico.
- Legge al massimo quattro sorgenti noti da 512 KiB e fino a quattro configurazioni da 64 KiB per writer; rifiuta symlink, file non regolari, hardlink multipli, dimensioni e identità cambiate. L'eventuale ancestry debole del sorgente viene segnalata e non accettata come custody di esecuzione.
- Non cerca credenziali, non esplora percorsi arbitrari e non legge configurazioni fuori dal layout dichiarato. Riferimenti diversi, espressioni dinamiche, conflitti, namespace e comandi non riconosciuti restano visibili come limiti, senza attribuzioni inventate. Un errore su un writer non nasconde i restanti writer o timer.
- Conserva una singola evidenza root0600, content-addressed, contenente solo il report redatto. Una corrispondenza statica di client non prova il data flow eseguito. `credentialConsumerScopeProven`, `allConsumerDiscoveryProven`, `runtimeAuthorityIssued` e `productionApplyReady` rimangono falsi.

Questa lettura non prova da sola l'esclusività globale della credenziale né autorizza una rigenerazione. Permette una revisione concreta dei quattro writer noti, con esiti e limiti nello stesso report. I layout non previsti non devono essere risolti con nuovi microcomandi improvvisati: prima usare l'evidenza raccolta e il codice disponibile per definire l'eventuale reale dato mancante.

## Qualificazione e consegna

Il commit `c33d39c6922fbcd87a853c8b9f12e6bbb193e22a` ha superato [CI 38446905118](https://github.com/GioNob/ouf-deploy/actions/runs/38446905118), job `115467555342`: 15 test, zero esclusioni, dei quali 10 specifici della nuova raccolta. Anche la PR CI `38446909875`, job `115467571273`, è riuscita. Il filesystem e la pubblicazione privata sono nativi; i comandi systemctl sono simulati nei test. Non è una prova eseguita sul VPS. [Ricevuta di qualificazione](../evidence/policy-token-consumer-review-qualified-20261013.json).

## Unico comando VPS

Il comando usa il GitHub client già presente, scarica soltanto la nuova procedura e ne verifica l'hash. Non richiede login IAM. Può richiedere la password sudo per leggere i sorgenti/configurazioni protetti e pubblicare il report privato. Incollare l'intero report risultante; in caso di errore conservarlo senza ripetere automaticamente la procedura. Non rieseguire i vecchi probe, apply IAM o preparazioni host.

```bash
set -o pipefail
(
  set -eu
  umask 077
  ouf_gh="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  [ -x "$ouf_gh" ] || ouf_gh="$(command -v gh || true)"
  [ -n "$ouf_gh" ] && [ -x "$ouf_gh" ] || {
    echo "phase=DELIVERY reason=EXISTING_GH_UNAVAILABLE"; exit 1;
  }
  ouf_work="$(mktemp -d "$HOME/ouf-consumer-review.XXXXXXXX")"
  if ! timeout 30 "$ouf_gh" api \
    'repos/GioNob/ouf-deploy/contents/scripts/observe-policy-token-consumers.py?ref=c33d39c6922fbcd87a853c8b9f12e6bbb193e22a' \
    --jq '.content' | base64 --decode > "$ouf_work/observe.py"; then
    echo "phase=DELIVERY reason=QUALIFIED_OBSERVER_DOWNLOAD_FAILED"; exit 1
  fi
  printf '%s  %s\n' \
    'aae257252f861bddc3d8532939241bd2966970aac45ff6c6d353d8e63486342f' \
    "$ouf_work/observe.py" | sha256sum -c -
  python3 -I -B -S "$ouf_work/observe.py"
) | tee ouf-policy-token-consumer-review-receipt.json
```
