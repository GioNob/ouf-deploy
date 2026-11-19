## Esito successivo — tentativo consumato

Giovanni ha eseguito la raccolta: HELD/HOST_BEFORE/G0_HOST_CONTAINER_LIMIT,1GET Docker/285226byte,53GET cumulativi,nessun child S3/DB. **Non eseguire nuovamente il comando sotto.** Prossima azione: [readback locale del tentativo](OUF_STORAGE_G0_HELD_READBACK_20261106.md). Autorizzazione monouso consumata,nessun retry o reset implicito. Le sezioni sotto descrivono la consegna storica precedente all'esecuzione.

# Raccolta G0: proposta concreta OUF-G0-COLLECT-20261106-01

Stato: **AUTORIZZATA DALL'OPERATORE, ESECUZIONE PENDENTE**. Giovanni ha risposto «autorizzo» alla proposta esatta. [Decisione conversazionale](../evidence/storage-g0-collection-decision-20261106.json). Non richiedere nuovamente questa autorizzazione. Il riferimento non autentica identità IAM/HUMAN/THS e non emette grant.

## Esito acquisito

Giovanni riporta preparazione capacità riuscita: tre directory create (padre e due figli), figli dati vuoti, percorsi compatibili con il collector e check locale positivo. Nessuna connessione provider, scope raccolta o credenziale ricopiata. [Ricevuta](../evidence/storage-g0-capacity-operator-20261106.json). È output operatore, non osservazione diretta agent.

CAPACITY è ora presente come osservazione tecnica. Sufficienza, crescita, throughput, indipendenza backup e accettazione rimangono non provati. Non ripetere preparatori, diagnosi, check precedente o laboratori riusciti.

## Azione sottoposta alla decisione

Un solo tentativo operatore sul VPS, tramite il bundle9053aa38 già qualificato/installato, per inventario Docker/MinIO, corpi condizionali, tre export PostgreSQL read-only e riconciliazione locale. Nessun nuovo collector, installazione, fermo writer, cambio endpoint o migrazione.

| Vincolo | Valore |
|---|---|
| Proposta | OUF-G0-COLLECT-20261106-01 |
| Operazione | seaweedfs-g0-20261106-v1 |
| Installazione correlata | ouf-retained-14e42ac9; non identità IAM |
| Input esatto | `/var/lib/ouf-g0-network-preparation-20261106/inputs/capacity-directory-preparation-20261106/package-input.review.json` |
| SHA256 input | `6b5a2ba087cd5bfbc956f3bb240cf103b0bbf8d0aeaebb14d6a10f9aaaa22af1` |
| Manifest pacchetto | `1e542f786ac1606cf72f273bc079eaa5b06b6bd22a210d615c10d13a9d9f8adf` |
| Scope nuovo, da non creare prima di collect | `/var/lib/ouf-g0-network-preparation-20261106/evidence/seaweedfs-g0-20261106-v1` |
| Tentativi e tempo | 1; 900 secondi |
| Docker | massimo130 GET,32MiB; due osservazioni, fino64 container ciascuna |
| S3 | massimo3000 richieste,256 corpi,64MiB corpi/128MiB wire,16MiB per corpo |
| PostgreSQL | 3 export,32MiB ciascuno,10000 righe per sezione; READ ONLY REPEATABLE READ |
| Storico preservato | 17 controlli,52 Engine GET; scope13–17 consumati |
| Dati privati | file root protetti sul VPS; alla chat solo result.json redatto |

I conteggi sono massimi, non una previsione del numero corrente di oggetti. Le letture hanno costo/carico limitato dai budget e possono consumare il tentativo anche se il risultato è parziale.

## Gate applicabile e evidenze mancanti

Il [contratto operatore](OUF_STORAGE_G0_OPERATOR_PACKAGE_20261105.md), sezione «Verifica e comando da sottoporre al gate», richiede decisione esplicita applicabile al comando dopo review di binding/digest e custodia. La delega di sviluppo e ouf-admin non la sostituiscono. Il programma controlla solo un riferimento non vuoto e **non autentica HUMAN**: non usare quel campo per simulare una decisione mancante.

Giovanni ha autorizzato l'esecuzione diretta della raccolta diagnostica descritta tramite il suo accesso VPS. La decisione è registrata come conversazionale: non firma THS, grant operativo o approvazione di riconciliazione owner. Il collector diagnostico e il relativo accesso operatore restano distinti dalle capability protette di riconciliazione o migrazione.

ACCESS/CUSTODY/WINDOW/WRITERS restano null. Il collector li ammette come input mancanti e li conserva come MISSING_OPERATOR_EVIDENCE: non inventarli e non richiedere l'inventario corrente prima della raccolta destinata a ottenerlo. La finestra di900s è il budget diagnostico, non una finestra di manutenzione approvata. Nessun common-cut o quiescenza è assunto. Backup/DR restano da verificare per accettazione/cutover, senza riaprirne la ricognizione come prerequisito della preparazione.

## Comando esatto previsto dopo la decisione

La sola trasformazione autorizzabile è una **nuova copia privata0600** dell'input dal digest sopra, con `collectionDecisionRef` da null a `OUF-G0-COLLECT-20261106-01`. Tutti gli altri valori e i file referenziati restano invariati. La copia viene creata in modo esclusivo come `package-input.collection.json`, senza sovrascrivere il candidato o una copia già esistente. Prima dell'avvio confrontare i binding con `preflight.private.json` della preparazione capacità, mantenere i quattro documenti mancanti e rifiutare drift. Registrare il nuovo digest con la decisione.

```sh
sudo /usr/bin/python3 -I -B -S \
  /var/lib/ouf-g0-network-preparation-20261106/package/launch.py collect \
  /var/lib/ouf-g0-network-preparation-20261106/inputs/capacity-directory-preparation-20261106/package-input.collection.json \
  --package-sha256 1e542f786ac1606cf72f273bc079eaa5b06b6bd22a210d615c10d13a9d9f8adf
```

**Autorizzato, non ancora eseguito.** Il candidato di partenza contiene ancora null: non lanciarvi collect direttamente. Il helper di ingresso crea la copia e il controllo di binding finale già autorizzati; non è previsto un altro giro di preparazione dati. Il preflight interno di collect è necessario perché cambia il riferimento decisione e inizia un nuovo effetto target, non una ripetizione gratuita del vecchio check.

Se il controllo o la raccolta falliscono, conservare copia/scope/parziali. Nessun retry, cancellazione, cambio operationId, rebind o nuova sessione per recuperare budget. Condividere solo il JSON redatto; non config, credenziali, chiavi oggetto, export o archivi privati.

## Criterio del prossimo risultato

Il risultato atteso è evidenza tecnica corrente da rivedere, non G0 già chiuso. Il collector può restituire OBSERVATIONS_SEALED_G0_REVIEW_REQUIRED o HELD con contatori e causa. Il rapporto mantiene g0Complete=false e acceptanceCreditAdded=0; eventuali crediti richiedono review dei criteri MiniPET, comprese le sezioni mancanti. Gli oggetti letti/verificati non sono oggetti migrati.

MiniPET invariato18,3/46=39,78%;0/8 gate,0/21 AT,0/120 oggetti migrati. [Proposta strutturata](../releases/storage-g0-collection-proposal-20261106.json). Nessuna modifica a MinIO/source-lock/piano congelato, source Onboarding, authority o traffico.

## Consegna dell'ingresso autorizzato

`scripts/execute-storage-g0-authorized-20261106.py` esegue la trasformazione e la CLI sopra senza argomenti operatore aggiuntivi. Verificare SHA256 dei byte scaricati dall'esatto commit qualificato, quindi eseguire quei byte con sudo /usr/bin/python3 -I -B -S -c. Non eseguire sia helper sia CLI manuale: il helper già avvia collect. Manifest e tutti i file del bundle sono verificati prima dell'import; input originale pin6b5a2ba0, binding confrontati con preflight.private.json e sei digest noti. Decisione e copia sono0600, O_EXCL e fsync; decisione privata è il claim locale. Reingresso legge soltanto result.json esistente; ogni parziale senza risultato resta HOLD, nessun reset. Il codice originario del collector è invariato.

Qualifica ingresso:8test locali PASS con preflight originale/provider non invocati; dedicata CI e digest di consegna riportati nella PR54. Questi test non dimostrano raccolta target, autenticazione remota o accettazione. CI precedente b142ae01:50SUCCESS/1FAIL (Maven Central HTTP403 jackson-bom2.21.7), nessun retry.
