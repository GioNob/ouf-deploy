# E2E Teatri v4: nuovo file su una sorgente esistente (2026-11-10)

Esito: **completato**, dall'onboarding alla ricerca MCP. I 13 teatri caricati con un
nuovo file sono stati ricondotti, tramite revisione umana THS, ai 13 oggetti
urbani storici. Non sono nati duplicati e tutti gli UUID sono rimasti invariati.

Evidenze in forma strutturata: `evidence/teatri-e2e-v4-20261110.json`.
Strumenti riusabili: `tools/ops_kit/` (vedi il suo README).

## Obiettivo

Verificare che una seconda sorgente, che pubblica gli stessi oggetti di una
sorgente storica, venga riconciliata sugli oggetti esistenti senza duplicarli:
- sorgente storica: `teatri-csv-6609b245`;
- seconda sorgente: `teatri-seaweedfs-c51745c5`.

Si voleva anche esercitare il cambio di file su una sorgente già attiva:
nuova versione di onboarding, nuovo run e risoluzione delle identità.

## Cronologia

1. **v3 con file corrotto.** Il CSV usato per la v3 era stato aperto e salvato
   in un foglio di calcolo.
   - Coordinate e date sono diventate stringhe con formato locale.
   - Per esempio, il civico "5/2" è diventato "05-feb".
   - Il profiler ha classificato le colonne come STRING invece che DECIMAL e DATE,
     senza segnalarlo.
   - In UDP i 13 record non concordavano con nessun candidato: i campi
     `latitudine`, `longitudine` e `data_verifica` erano in disaccordo.
2. **Ricostruzione dell'originale.** Il CSV originale è stato ricostruito dai
   payload canonici in UDP della sorgente storica con
   `tools/ops_kit/rebuild_csv_from_udp.py`.
   - Risultato: 4404 byte, sha256 `08b20658…c9e9`, BOM UTF-8, CRLF, delimitatore `;`.
   - Il file è identico byte per byte all'originale.
3. **v4.** L'utente ha caricato e profilato il CSV originale: asset `bea48388…`,
   profilo `b57de6f4…`, con i tipi corretti.
   - La configurazione v4 è stata derivata dalla v3 sostituendo asset, profilo e
     hash, e portando le etichette a RESTRICTED: 50 foglie cambiate.
   - Poi clone e PUT via API nativa (bozza), approvazione e pubblicazione da UI.
   - Risultato: v4 `8580e892…` ACTIVE, pubblicazione `3ece4301…`.
4. **Run v4** `f78029ff…`: 13 handoff, 13 issue `UNRESOLVED_IDENTITY`.
   - Il candidato migliore concordava su tutti i segnali e c'era un solo
     candidato pieno per issue.
   - Ma l'auto-link richiede anche che gli altri candidati siano esclusi, e senza
     `distinctRules` non lo sono mai.
5. **Revisione THS:** un pacchetto da 26 decisioni, `701b3fb6…`.
   - 13 APPROVE della v4 sugli oggetti storici;
   - 13 DISMISS delle issue v3 rimaste aperte.
   - Il primo tentativo è fallito con un 403 per sessione THS scaduta; il secondo
     è andato a buon fine.
6. **Materializzazione.** Per ognuno dei 13 oggetti:
   - revisione 3, con hash canonico invariato e hash di autorità cambiato, quindi
     `material_change=true`;
   - 2 binding ACTIVE, uno per sorgente;
   - 20 proprietà RESTRICTED, ognuna con il contributo di entrambe le sorgenti.
7. **MCP:** la ricerca restituisce 13 oggetti con valori corretti. L'hash
   dell'insieme di UUID coincide con la baseline `ec64c2e6…`.

## Corrispondenza issue v4 → oggetto storico

| Issue | Teatro | Oggetto |
|---|---|---|
| 53684986 | Hangar | c2f83340 |
| ae44edcb | Politeama Rossetti | 43d6d5c7 |
| 19f7a2fb | Basaglia | 76d5d321 |
| 667e1373 | Verdi | d6051381 |
| 653025bf | Miela | 535ea2cc |
| bddda3bf | Bobbio | fe0f7632 |
| 55ac8fa3 | Rojan | 3969605f |
| a3ade08f | Romano | ec6897bf |
| bae606db | Silvio Pellico | f4f18054 |
| 6f0a78ee | Stabile Sloveno | 96aa4cb9 |
| 9f1d870d | Fabbri | 3db3a213 |
| b992d437 | Salesiani | 2606bba6 |
| 40b80620 | San Giovanni | 63d4fde8 |

## Cosa abbiamo imparato

- **Il file è vincolato alla versione.**
  - `extractionProfile.selection` e il runtime puntano a un asset preciso, quindi
    cambiare file richiede una nuova versione di onboarding.
  - Con `sourceObjectIdentityPolicy = NATIVE_KEY` su `nome_teatro`, i
    `sourceObjectId` restano stabili tra le versioni.
- **L'upload è deduplicato:** un file identico a uno già caricato non crea un nuovo
  asset.
- **Il profiler non avvisa** quando i tipi inferiti peggiorano rispetto al file
  precedente, per esempio da DECIMAL a STRING. È il primo punto in cui il file
  corrotto poteva essere fermato.
- **Il motore di identità** richiede che tutti i campi comuni concordino. Anche
  con dati identici serve una decisione umana, perché gli altri candidati non
  risultano esclusi.
- **DISMISS** ("Chiudi il caso") scarta il record in ingresso ma lascia il job in
  QUARANTINED.
- **Sessione THS:** il filtro di sicurezza decodifica il token salvato senza
  rinnovarlo, quindi le sessioni di revisione lunghe falliscono alla conferma.
  La conferma è un'unica transazione: se fallisce, non viene applicato nulla.
- **Riconciliazione:** la v4 ha `reconciliation = null` (rank legacy), mentre il
  bundle storico usava la policy V1
  `urn:ouf:policy:linked-object-property-reconciliation:v1`. I contributi di
  entrambe le sorgenti vengono comunque conservati.
- **Il CSV originale è ricostruibile da UDP.** I payload canonici, insieme a
  projection, mapping e delimitatore della configurazione, bastano a riprodurlo
  esattamente. È una rete di sicurezza utile.

## Backlog di miglioramento

| Area | Proposta |
|---|---|
| Normalizzazione | Validazione e normalizzazione dei tipi come prerequisito per le sorgenti delta (vedi [ouf-semantic-registry#43](https://github.com/GioNob/ouf-semantic-registry/pull/43)) |
| Profiler | Segnalare quando il tipo inferito di una colonna peggiora rispetto alla versione precedente |
| THS sessione | Rinnovo del token di sessione e salvataggio in bozza delle decisioni; il problema riguarda tutte le pagine THS con lo stesso filtro |
| THS etichette | "Chiudi il caso" → "Scarta il record in ingresso"; "Lascia in quarantena" → "Decidi più tardi" |
| THS DISMISS | Chiudere anche il job, non lasciarlo QUARANTINED |
| Identità | Regole di esclusione degli altri candidati, così che i record identici vengano collegati in automatico |
| Identità | La NATIVE_KEY sul nome è fragile: valutare una chiave più stabile |
| IAM | Il client `ouf-human-admin` rilascia scope di default eccessivi (authorization.policy.admin, installation.*) |
| Onboarding | `source.metadata` punta ancora al vecchio asset `c51745c5` |
| Riconciliazione | v5 della sorgente con la policy V1 esplicita |
| Grant | `ingestion.operations.read` per `ouf-admin` sulla nuova sorgente (storico ingestion via MCP); i grant vecchi erano legati a `teatri-csv` e sono scaduti |
| Grant | Rinnovo automatico prima della scadenza del 2026-12-31T23:00Z |

## Riferimenti

- Proposta di normalizzazione canonica:
  [ouf-semantic-registry#43](https://github.com/GioNob/ouf-semantic-registry/pull/43).
- Script per il rinnovo dei grant (r4a): ouf-source-onboarding PR #55.
- Strumenti: `tools/ops_kit/`.
