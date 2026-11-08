# Applicazione del delta Gateway e lettura Semantic

8 novembre 2026. La preparazione delle 17:32 CET è [riuscita](../evidence/gateway-analysis-prepared-operator-20261108.json): proposta `2876c0c3a892f0dce8accb08f5cbac523cfc541c43a264dfcb5944cd003c8f19`, cinque aggiornamenti, tre aggiunte e 79 route conservate. Non ripetere il preparatore. **Applicazione eseguita alle 17:56 CET:** otto route verificate, 87 totali/79 conservate, Semantic V10 letto e nessuna richiesta discovery. [Ricevuta](../evidence/gateway-analysis-applied-operator-20261108.json). Non ripetere il comando sotto; [prossimo passo Semantic V11/V12](OUF_SEMANTIC_V11_V12_UPGRADE_20261108.md).

## Effetti del prossimo comando

1. Verifica la proposta privata esatta e le otto impronte desiderate. Usa una directory di tentativo unica; un tentativo già presente interrompe senza ripetere scritture.
2. Verifica identità, immagine e frame correnti di APISIX/Semantic rispetto alla ricevuta dell'8 novembre, compreso Config.MacAddress. Gli snapshot originali sono verificati con le impronte della ricevuta; soltanto l'ordine della lista Mounts è reso irrilevante confrontando tutti i record completi per Destination univoca. Nessun campo mount o MAC è escluso, nessuna impronta storica è riscritta e nessun lifecycle container è eseguito. Legge PostgreSQL associato al binding Semantic dichiarato.
3. Una sessione SQL READ ONLY legge storia Flyway, presenza effettiva di `recovery_state` e conteggi per stato. La query sceglie fra il nome pubblico della colonna e NULL in base ai metadati, evitando di riferirsi a una colonna assente. Non legge identificativi, intenti o payload discovery, non modifica schema/dati.
4. Legge le route APISIX attuali e richiede corrispondenza con la proposta di partenza. Esegue al massimo otto PUT, ciascuna preceduta da verifica delle route e intento durevole, seguita da ACK conservato e rilettura esatta dell'intera mappa. Alla fine devono risultare 87 route, di cui 79 invariate.
5. Non sostituisce il Gateway owner, non riavvia container, non avvia provider/worker e non richiede token. Nessun S3, upload, profilo o richiesta business.

I cinque aggiornamenti sono preview, profile, create, review-prepare e /mcp. Le tre aggiunte sono semantic/discovery/request, status e candidates. I binding IAM vengono dalla proposta verificata e restano conservati. Le sole esclusioni nel confronto Admin sono `create_time` e `update_time`, assegnati da APISIX: nessun limite numerico, plugin o upstream è escluso.

APISIX non applica tutte le route in un'unica transazione: i controlli prima/dopo ogni PUT rilevano divergenze, ma non sono una CAS atomica contro altri scrittori. Eseguire nel filone operativo unico già stabilito. In caso di esito incerto conserva il parziale senza retry o rollback automatici; restituire il JSON prima di qualsiasi prosecuzione.

## Interpretazione Semantic

Lo stderr precedente identifica `recovery_state`. Il [sorgente V12](https://github.com/GioNob/ouf-semantic-registry/blob/c2dae77b42f1811b704465f6ab813c91d808ade4/src/main/resources/db/migration/V12__discovery_durable_recovery.sql) introduce quella colonna. Questo fatto non prova che V12 manchi dalla storia corrente né autorizza un ALTER isolato.

La nuova lettura distingue almeno: V12 non registrata/colonna assente; V12 registrata/colonna assente (incoerenza da riconciliare); colonna presente. I conteggi PENDING/RUNNING non significano da soli lavoro eseguibile. Nessuna migrazione Semantic viene applicata da questo comando. Un errore della lettura SQL viene riportato separatamente e non cancella un eventuale risultato Gateway riuscito.

## Verifica prima della consegna

Sorgente `57647000a4d66ce4bc659ed54631e44ea8959978`. [CI 42501682255](https://github.com/GioNob/ouf-deploy/actions/runs/42501682255), job 128795585765: **10 test riusciti, zero skip**, log letti. APISIX reale sul digest trattenuto ed etcd, otto PUT e rilettura di 87 route con precisione numerica conservata; PostgreSQL17 con ruolo fixture non amministrativo, tabella senza e poi con recovery_state, transazione READ ONLY e scrittura rifiutata. Le fixture contengono dati sintetici: non provano il VPS, i grant, il provider, l'applicazione della migrazione V12 o l'E2E.

Coperti inoltre proposta errata, route divergenti, ACK perduto senza ripetizione, scrittura concorrente rilevata dopo ACK, directory di tentativo già esistente e conservazione dei 79 record. In CI sono state osservate 28 variazioni del solo ordine dei mount; i record completi coincidevano. Le variazioni Source/RW/Destination, destinazioni duplicate e qualsiasi variazione Config.MacAddress restano rifiutate.

Le prime prove native hanno trovato una fixture YAML da correggere e il falso disallineamento dei mount: conservate nell'[evidenza di qualifica](../evidence/gateway-analysis-apply-qualification-20261108.json). Otto test locali riusciti, i due nativi eseguiti in CI. Tutti e quattro i workflow PR del sorgente sono success.

## Comando storico già eseguito — non ripetere

Questo comando **scrive le otto route APISIX** e legge i metadati Semantic. I tre file sono scaricati dal commit qualificato e verificati per SHA256; i due lettori sono importati come librerie, non rieseguiti come comandi autonomi. Limite applicazione: 380 secondi; al massimo otto PUT e 17 GET Admin. Nessun retry automatico.

```bash
(
  set -eu
  ouf_apply=$(mktemp -d /tmp/ouf-gateway-apply.XXXXXX)
  trap 'rm -rf -- "$ouf_apply"' EXIT
  ouf_base='https://raw.githubusercontent.com/GioNob/ouf-deploy/57647000a4d66ce4bc659ed54631e44ea8959978'
  for ouf_script in \
    read-analysis-discovery-runtime-20261107.py \
    read-discovery-contract-20261108.py \
    apply-gateway-analysis-delta-20261108.py
  do
    curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
      --connect-timeout 10 --max-time 30 \
      "$ouf_base/scripts/$ouf_script" -o "$ouf_apply/$ouf_script"
  done
  (
    cd "$ouf_apply"
    sha256sum -c - <<'SHA256'
ef8dc8c4887122f2b2d76c05eaff7a8850c31004fcd661de2b3e49f51d6cc1b4  read-analysis-discovery-runtime-20261107.py
468660ed73a24c7b8a842f5b99a9c268890c99bb4206ca2e4719865326b27277  read-discovery-contract-20261108.py
7064c8443bb323c12a56846267e4faa9cb25bf3e6dfb35455e753fbe71ce8b01  apply-gateway-analysis-delta-20261108.py
SHA256
  )
  sudo python3 -I -B "$ouf_apply/apply-gateway-analysis-delta-20261108.py"
)
```

Restituire soltanto il JSON pubblico. I file privati possono contenere credenziali nelle route e non vanno incollati. Directory di tentativo: `/var/lib/ouf-storage-migration/gateway-analysis-apply-2876c0c3a892f0dc`. Non cancellarla per ripetere il comando.

- `GATEWAY_APPLIED_SEMANTIC_METADATA_READ`: otto route applicate/rilette e metadati Semantic letti.
- `GATEWAY_APPLIED_SEMANTIC_READ_INCOMPLETE`: Gateway applicato; errore SQL separato da affrontare, senza ripetere le scritture.
- `HELD`: fermarsi e restituire la ricevuta. I contatori e il journal distinguono il parziale; `runtimeChanged:null` indica esito di una scrittura non dimostrato.

## Dopo il risultato

- Gateway riuscito: non ripetere le otto PUT.
- Semantic: scegliere il percorso di migrazione soltanto dopo confronto storia/struttura; conservare i lavori preesistenti.
- Restano rilascio MCP PR83 e migrazione14, servizi compatibili a 1024 colonne, binding/trasporto provider, grant e attivazione governata. Poi discovery delle proprietà sul profilo Teatri conservato, mapping, THS e Ingestion→UDP.
- Nessuna dichiarazione di E2E completo o di supporto applicativo live a 1024 colonne dalla sola modifica Gateway.
