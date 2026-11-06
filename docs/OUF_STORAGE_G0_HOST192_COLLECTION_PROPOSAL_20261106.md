# Raccolta G0 host192 — decisione OUF-G0-COLLECT-20261106-02

Stato: **AUTORIZZATA DALL'OPERATORE, ESECUZIONE PENDENTE**. Giovanni: «Autorizzo la raccolta». [Decisione registrata](../evidence/storage-g0-host192-collection-decision-20261106.json). Non richiedere di nuovo questa autorizzazione. Nessuna autenticazione HUMAN/THS o authority runtime emessa.

## Preparazione acquisita

Giovanni riporta HOST192_STAGED_LOCAL_CHECK_PASSED_SEPARATE_DECISION_REQUIRED: nuovo bundle pronto,check locale riuscito,4receipt precedenti vincolate,5filecredenziali validati localmente,zero copie credenziali/provider. Vecchio bundle/tentativo preservati,scopev2 non creato. [Ricevuta operatore](../evidence/storage-g0-host192-preparation-operator-20261106.json). È output operatore,non accesso diretto agent.

La qualifica del pacchetto cfa806d5/run42218997469 resta valida:145container nativi completi,292GET nuovi/345cumulativi,4child,3DBexport,2corpi sintetici,join0findings. Consegna d9693d7a/run42220077286:7/7PASS. Non ripetere laboratori,preparatore,readback o il check già riuscito.

## Comando e perimetro sottoposti alla decisione

| Vincolo | Valore |
|---|---|
| Operatore | Giovanni sul VPS, accesso oufadmin/sudo già disponibile |
| Operazione nuova | seaweedfs-g0-20261106-v2 |
| Input base | `/var/lib/ouf-g0-host192-preparation-20261106/inputs/package-input.review.json` |
| SHA256 input base | `dc0ab6d4bf36c03b8086ecbae1be1c3e2e381c94152be01dd1ff6bfbfcd04f6e` |
| Manifest qualificato | `1496517d24b65aaa20dce7cdb3bb4440ffbf2bc620c3dfd0ffffc17ea22b0f69` |
| Scope nuovo | `/var/lib/ouf-g0-network-preparation-20261106/evidence/seaweedfs-g0-20261106-v2` |
| Docker | massimo192container,fermi/fuori roster inclusi;386GET totali,32MiB/2MiB risposta |
| Tempo | massimo900s,60s per osservazione host |
| S3 | massimo3000richieste,256corpi,64MiB corpi/128MiB wire,16MiB per corpo |
| DB | 3export read-only,32MiB ciascuno,10000righe per sezione |
| Storico conservato | 17controlli/52GET storici più1GET del tentativo fermato:53precedenti |
| Cumulativo massimo | 439GET; nessun reset dei53precedenti |
| Tentativi | uno,nessun replay automatico |

La sola trasformazione ammessa è una nuova copia privata0600 esclusiva dell'input base,con collectionDecisionRef da null a OUF-G0-COLLECT-20261106-02. Registrare la decisione applicabile e il nuovo digest; mantenere ogni altro valore identico. Confrontare tutti i binding/limiti con il preflight.private.json della nuova preparazione; le4receipt precedenti rimangono fissate ai digest del readback. Nessuna sovrascrittura di candidato,receipt,vecchio scope o bundle.

Il comando concreto dopo la decisione e la copia verificata è:

```sh
sudo /usr/bin/python3 -I -B -S \
  /var/lib/ouf-g0-host192-preparation-20261106/package/launch.py collect \
  /var/lib/ouf-g0-host192-preparation-20261106/inputs/package-input.collection.json \
  --package-sha256 1496517d24b65aaa20dce7cdb3bb4440ffbf2bc620c3dfd0ffffc17ea22b0f69
```

L'ingresso autorizzato sotto crea la copia decisionale e avvia già questa CLI: non eseguire anche il comando manuale. Il preflight interno del nuovo comando resta obbligatorio all'avvio; non comporta rilancio del vecchio check a scopo di prova. Il pacchetto rifiuta la decisione01 e richiede operazione distinta,senza presentare una stringa come autenticazione HUMAN.

## Perché la decisione è distinta

Il [contratto operatore G0](OUF_STORAGE_G0_OPERATOR_PACKAGE_20261105.md),sezione «Verifica e comando da sottoporre al gate»,stabilisce che una ripresa dopo errore richiede riconciliazione e decisione separata. Il tentativo01 era monouso ed è consumato. La riconciliazione locale è ora riportata dall'operatore; il nuovo budget passa da130a386GET massimi e il comando usa un input/pacchetto differenti. La delega di sviluppo non autorizza automaticamente questa seconda raccolta.

Questa decisione riguarda solo la raccolta diagnostica e le sue evidenze private. Non comprende migrazione,deploy,fermo/ripresa writer,grant,cambio endpoint,start/stop/exec container,mutazioni S3/SQL o retry. Dati privati e corpi restano sul VPS; alla chat solo result.json redatto. Il budget900s non è una finestra di manutenzione approvata.

## Esito atteso e limiti

ACCESS/CUSTODY/WINDOW/WRITERS restano mancanti e devono essere conservati come tali. CAPACITY non prova ancora sufficienza,indipendenza backup o accettazione.145directory locali non è un conteggio live; il collector misura il numero effettivo e,se supera192,si ferma senza troncamento conservandolo anche nel JSON pubblico. Non si assume quiescenza o common-cut S3/DB.

Qualsiasi diniego/crash conserva scope/parziali: non cancellare,rinominare,cambiare operationId o azzerare contatori per ripetere. Una raccolta completa produce evidenza da rivedere,non G0 chiuso. MiniPET18,3/46=39,78%,0/8gate,0/21AT,0/120oggetti migrati,credito0.

CI generale d969 al controllo:48SUCCESS/1FAIL/3attive. Fail42220098717/job127899698625,fixture sealed-worker in phase.observe: PROTOCOL_AUTHORITY_EXPIRED_OR_NOT_YET_VALID. Nessun retry o guard indebolito; distinto dalle qualifiche dedicate G0. Questo checkpoint modifica solo documenti/ricevute/stato e non rilancia test riusciti.

## Ingresso unico autorizzato

`scripts/execute-storage-g0-host192-authorized-20261106.py`, eseguito con sudo /usr/bin/python3 -I -B -S, verifica il bundle qualificato e l'input dc0ab6d4, confronta binding e limiti con la preparazione, fissa i quattro digest del tentativo precedente e il budget386/53. Registra la decisione conversazionale e crea package-input.collection.json con la sola modifica decisionRef; entrambi O_EXCL/0600/fsync. Il comando collect viene avviato direttamente, senza shell. Non ripetere preparazione o CLI manuale.

Riusa le guardie dell'ingresso01 e il preflight v3 originale. 10test locali PASS per delta esatto, percorsi separati,53GET conservati, immutabilità precedenti, drift e assenza di replay. Workflow dedicato `storage-g0-host192-authorized-entry.yml`; digest e CI di consegna nella PR54. I test di ingresso non sono nuove prove native di raccolta o crediti MiniPET.
