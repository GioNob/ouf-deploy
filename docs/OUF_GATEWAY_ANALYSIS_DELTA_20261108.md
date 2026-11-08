# Gateway: delta 1024 colonne e discovery da dati già acquisiti

8 novembre 2026. La [ricevuta delle 09:31:53 CET](../evidence/discovery-contract-operator-summary-20261108.json) è acquisita. Non ripetere il lettore di dipendenze. Questo passo produce una proposta privata, non applica route e non modifica servizi.

## Risultato e interventi

| Punto | Stato acquisito | Intervento |
| --- | --- | --- |
| MCP DB | Migrazioni 1–13 con checksum coincidenti; tabelle analisi assenti | Migrazione 14 insieme al rilascio coerente PR83. Nessuna ripetizione 12→13. |
| Gateway | 84 route, create ancora 256 campi, review ancora 32 segnali, discovery assente | Preparare cinque aggiornamenti e tre aggiunte, conservando 79 route e l'owner operativo. |
| Provider | Provider/worker dichiarati false, credenziale workload senza mount dichiarato | Correggere il binding sul Registry corrente dopo verifica della configurazione e del servizio southbound. |
| Semantic DB | Lettura fallita, causa e backlog sconosciuti | Classificare soltanto lo stderr già conservato. Nessuna nuova query in questo passo. |

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

Sorgente Gateway: baseline `c666c0f0080b8802fc71daa27c32a0af2ed98544`, candidato `560fbf6e769c7639a0bc0ddb09380811a4e324e4`. Non è una sostituzione del ramo/immagine dell'owner Gateway.

## Unico comando operatore corrente

Legge soltanto `routes.private.json` e `semantic-database.stderr.private` in `/var/lib/ouf-storage-migration/discovery-contract-read-guaps__4`. Le sole richieste di rete del comando sono i due download GitHub; il programma Python non emette HTTP, Docker, SQL, token, provider o S3.

```bash
(
  set -eu
  ouf_delta=$(mktemp -d /tmp/ouf-gateway-delta.XXXXXX)
  trap 'rm -rf -- "$ouf_delta"' EXIT
  ouf_base='https://raw.githubusercontent.com/GioNob/ouf-deploy/5a8449b1a145a9607c5b9af537bd53d790c18aaf'
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
7ce1ba4bf321933d57896b507106615df9f61c47415d514a5692b7c47159b6a7  prepare-gateway-analysis-delta-20261108.py
98d199c4c00dc88b9cc95b5bbdcf0209aa35a938a8e910369ed59c21f4d62aaf  gateway-analysis-assets-20261108.json
SHA256
  )
  sudo python3 -I -B "$ouf_delta/prepare-gateway-analysis-delta-20261108.py"
)
```

Restituire soltanto il JSON pubblico. Le route complete possono contenere segreti: la proposta resta in directory root 0700/file 0600, non va incollata. `GATEWAY_DELTA_PREPARED_NOT_APPLIED` significa preparazione riuscita, **non installazione**. `PREPARATION_INCOMPLETE` conserva gli indizi SQL eventualmente letti; non autorizza un retry cieco. Gli indizi sono categorie, non una causa provata.

Prima di applicare servirà una lettura fresca delle route e la riconciliazione del piano con lo stato corrente. L'applicazione non è implementata in questo script. Restano inoltre il rilascio coerente MCP/Onboarding, migrazione 14, binding/trasporto provider e lavori pendenti Semantic, grant e attivazione governata dei sei descrittori. Poi discovery delle proprietà sul profilo Teatri esistente, mapping, THS e Ingestion→UDP. Nessun nuovo upload/profilo.

## Verifica del preparatore

[CI 42464333835](https://github.com/GioNob/ouf-deploy/actions/runs/42464333835), job 128680226233: nove test riusciti, zero skip, log letti. Verificati conservazione delle 79 route, rifiuto di Lua/schema inattesi e collisioni, segreti assenti dallo stdout, permessi del file privato, JSON Schema valido, 1024 campi ammessi e 1025 rifiutati. Otto test locali riusciti; il validatore JSON Schema è eseguito in CI.

Sono prove di composizione offline su fixture, non dell'applicazione live APISIX o del VPS. La qualifica del candidato Gateway sul vero APISIX resta quella del [run 42417102228](https://github.com/GioNob/ouf-api-gateway/actions/runs/42417102228), con il suo ambito. [Evidenza di questa preparazione](../evidence/gateway-analysis-preparation-qualification-20261108.json).
