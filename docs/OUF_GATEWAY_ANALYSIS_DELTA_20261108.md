# Gateway: delta 1024 colonne e discovery da dati già acquisiti

8 novembre 2026, preparatore corretto. La prima preparazione delle 09:53 CET si è fermata su `INSTALLED_MANAGED_SCHEMA_NOT_QUALIFIED_BASELINE`, senza effetti runtime. Errore del preparatore: la baseline preview includeva già ASSETS; review usava uno schema successivo e ometteva la proiezione APISIX già applicata il 16 ottobre. Ricostruite dai sorgenti le quattro impronte esatte della ricevuta, conservando il controllo stretto. [Ricevuta](../evidence/gateway-analysis-preparation-held-operator-20261108.json). Il comando qui sotto sostituisce quello precedente; produce una proposta privata, non applica route e non modifica servizi.

## Risultato e interventi

| Punto | Stato acquisito | Intervento |
| --- | --- | --- |
| MCP DB | Migrazioni 1–13 con checksum coincidenti; tabelle analisi assenti | Migrazione 14 insieme al rilascio coerente PR83. Nessuna ripetizione 12→13. |
| Gateway | 84 route, create ancora 256 campi, review ancora 32 segnali, discovery assente | Preparare cinque aggiornamenti e tre aggiunte, conservando 79 route e l'owner operativo. |
| Provider | Provider/worker dichiarati false, credenziale workload senza mount dichiarato | Correggere il binding sul Registry corrente dopo verifica della configurazione e del servizio southbound. |
| Semantic DB | Stderr classificato MISSING_COLUMN; nome della colonna e backlog non ancora noti | Dal medesimo stderr estrarre soltanto eventuali nomi della query pubblica già nota. Nessuna nuova query. Non dedurre che manchi una specifica migrazione. |

L'assenza delle route provider da APISIX non prova l'assenza sul diverso endpoint `https://ouf-semantic-southbound-v2:10443`. Questo preparatore non aggiunge route provider ad APISIX e non accende il worker.

## Delta proposto

- `managed.file/create`: schema da sorgente qualificato per 1024 campi, body 3 MiB e timeout send/read 10 s.
- `managed.file/review-prepare`: schema per 1024 segnali, body 3 MiB, timeout send/read 10 s.
- `managed.file/preview`: modalità COLUMNS/pagine; body 64 KiB, timeout send/read 10 s.
- `managed.file/profile`: conserva schema e body 64 KiB/timeout 3 s; aggiorna il Lua condiviso che legge il body anche quando è su file.
- `/mcp`: body 4 MiB.
- Aggiunta `semantic/discovery/request|status|candidates`: body 64 KiB, timeout 3 s, retries 0; schema/Lua qualificati, upstream ricavato dalla route Semantic search corrente.

I limiti 32 delle semanticRefs o delle chiavi non sono limiti di colonne e restano quelli del contratto. Non vengono sostituiti indiscriminatamente.

Si verifica l'impronta delle sei route di riferimento della ricevuta, il vecchio schema e l'intera funzione Lua generata. Issuer, audience, workload e riferimenti alle chiavi vengono estratti dalle funzioni esistenti e conservati; nessuna chiave viene generata. Le aggiunte conservano i plugin IAM/admission del template execute e usano il binding già presente per Semantic. Configurazione inattesa o collisione di URI interrompono la preparazione.

Baseline sorgente ricostruita: schema managed-file da `75733a974798c40d23e3201112a83f217f6fe1d8`; review da `4b0017fa3c507ae9a549f9274a41e8a7e9f9a25e`, con rimozione del solo `$id` annidato in assenza di riferimenti, come nel precedente `tools/chatbot_file_cohort/gateway_recovery_plan.py`. Lua invariato da `c666c0f0080b8802fc71daa27c32a0af2ed98544`. Le quattro impronte degli schemi coincidono esattamente con la ricevuta target del lettore, senza leggere nuovamente il VPS.

Il candidato resta `560fbf6e769c7639a0bc0ddb09380811a4e324e4`. Anche per lo schema review candidato viene proiettato soltanto l'identificatore annidato noto: riferimenti o identificatori inattesi sono rifiutati. Vincoli, limiti numerici e semantica di validazione sono conservati. Questa composizione corretta è verificata offline; non è ancora una prova di applicazione APISIX. Nessuna sostituzione del ramo/immagine dell'owner Gateway.

## Unico comando operatore corrente

Legge soltanto `routes.private.json` e `semantic-database.stderr.private` in `/var/lib/ouf-storage-migration/discovery-contract-read-guaps__4`. Le sole richieste di rete del comando sono i due download GitHub; il programma Python non emette HTTP, Docker, SQL, token, provider o S3.

```bash
(
  set -eu
  ouf_delta=$(mktemp -d /tmp/ouf-gateway-delta.XXXXXX)
  trap 'rm -rf -- "$ouf_delta"' EXIT
  ouf_base='https://raw.githubusercontent.com/GioNob/ouf-deploy/8a12592fdbf7b321a8b3c564081a1ab90b5b8c80'
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 30 \
    "$ouf_base/scripts/prepare-gateway-analysis-delta-20261108.py" \
    -o "$ouf_delta/prepare-gateway-analysis-delta-20261108.py"
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 30 \
    "$ouf_base/releases/gateway-analysis-assets-20261108.json" \
    -o "$ouf_delta/gateway-analysis-assets-20261108.json"
  (
    cd "$ouf_delta"
    sha256sum -c - <<'SHA256'
51807cf46bd1ffb300f6da4c37ac7b22aaa578eb3eaeab9dd04f606d1e13eeeb  prepare-gateway-analysis-delta-20261108.py
abc984168e6942e58ab2f3536a874c69a0233f41e4a8412eee56d927345958df  gateway-analysis-assets-20261108.json
SHA256
  )
  sudo python3 -I -B "$ouf_delta/prepare-gateway-analysis-delta-20261108.py"
)
```

Restituire soltanto il JSON pubblico. Le route complete possono contenere segreti: la proposta resta in directory root 0700/file 0600, non va incollata. `GATEWAY_DELTA_PREPARED_NOT_APPLIED` significa preparazione riuscita, **non installazione**. `PREPARATION_INCOMPLETE` conserva gli indizi SQL eventualmente letti; non autorizza un retry cieco. Gli indizi sono categorie, non una causa provata.

Prima di applicare servirà una lettura fresca delle route e la riconciliazione del piano con lo stato corrente. L'applicazione non è implementata in questo script. Restano inoltre il rilascio coerente MCP/Onboarding, migrazione 14, binding/trasporto provider e lavori pendenti Semantic, grant e attivazione governata dei sei descrittori. Poi discovery delle proprietà sul profilo Teatri esistente, mapping, THS e Ingestion→UDP. Nessun nuovo upload/profilo.

## Verifica del preparatore corretto

[CI 42465156653](https://github.com/GioNob/ouf-deploy/actions/runs/42465156653), job 128682843439: **13 test riusciti, zero skip**, log letti. Dodici locali riusciti; validatore JSON Schema eseguito in CI.

Il test nuovo usa le quattro impronte della ricevuta target come oracolo indipendente: la prima versione fallisce questo controllo. Le fixture precedenti generavano lo schema atteso con la stessa funzione del preparatore e non intercettavano la baseline errata. Verificati inoltre rifiuto di riferimenti/identificatori inattesi, conservazione integrale dei vincoli dopo la proiezione, redazione dello stderr, 1024/1025 campi, cinque aggiornamenti/tre aggiunte e 79 route conservate.

I blob sorgente inclusi sono verificati contro gli SHA Git. Restano prove di composizione offline, non dell'applicazione live APISIX, del VPS o della presenza di una specifica migrazione Semantic. La vecchia CI a nove test resta storica e insufficiente per riconoscere lo stato installato. [Evidenza della correzione](../evidence/gateway-analysis-baseline-fix-qualification-20261108.json).
