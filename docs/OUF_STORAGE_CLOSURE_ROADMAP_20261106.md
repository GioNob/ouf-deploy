## 7 novembre — parità verificata sul VPS

Il rehearsal isolato del dataset storico è riuscito. SeaweedFS OCI33 contiene i 120 oggetti dei due bucket (203.743 byte) con insieme delle chiavi, corpi, metadati e tag coincidenti. La continuazione ha riusato l'immagine verificata e distinto il digest della configurazione dall'ID del daemon. [Ricevuta operatore](../evidence/storage-retained-oci33-rehearsal-parity-operator-20261107.json).

Il restore isolato di PostgreSQL aveva già aperto 7 database e letto una riga in ciascuno. Le due prove si riferiscono alla stessa custodia storica. Restano aperti la baseline comune corrente, il contenimento verificabile dei writer e i binding applicativi. Credito aggiunto 0, G4 aperto, oggetti operativi migrati 0. Avanzamento MiniPET 18,3/46 (39,78%), gate 0/8, AT 0/21.

Il prossimo riscontro è il [confronto unico sul VPS](OUF_STORAGE_RETAINED_SOURCE_COMPARISON_20261107.md) fra le sorgenti originali PostgreSQL e MinIO, la custodia e l'inventario G0. Una corrispondenza rende riutilizzabile la prova storica per la pianificazione e lascia separata l'ammissione operativa.

## 7 novembre — continuazione di sola cattura autorizzata

Decisione GIOVANNI-NONPROD-CAPTURE-ONLY-20261107-01 acquisita sul pacchetto esatto 67ad84d. [Ricevuta](../evidence/storage-capture-only-operator-decision-20261107.json). Ora eseguire una sola cattura sul VPS, senza ripetere il fermo e conservando l'anomalia etcd. Il prossimo risultato è l'archivio reale con digest e dimensione, poi Windows e restore isolato. Esecuzione ancora pendente; nessun credito MiniPET.

## Risultato corrente — sola cattura pronta per decisione

**Il dubbio sul fermo è risolto dalle ricevute target:**49azioni/35policy/14servizi fermati,0running nell'ultimo inventario,nessuna cattura avviata. La nuova continuazione è qualificata conHOLDreale simulato e archivio decifrato;non reinvia gli arresti. [Pacchetto concreto](OUF_STORAGE_CAPTURE_AFTER_HELD_STOP_20261107.md),decisione GIOVANNI-NONPROD-CAPTURE-ONLY-20261107-01 pendente.

| Traguardo | Stato |
| --- | --- |
| Contenimento host | Riuscito sul VPS |
| Fermo Docker | Effetti confermati nel journal;HOLD sugli execetcd conservato |
| Archivio reale | Sola cattura qualificata,pronta per decisione/esecuzione |
| Copia Windows e restore target | Dopo l'archivio reale |
| Migrazione SeaweedFS | 0/120migrati,0/8gate,0/21AT |

Questa coppia ha acquisito il fermo target e rimosso la dipendenza dal replay del fermo per produrre l'archivio. Non chiude un criterioMiniPET.39,78%invariato;nessuna nuova stima in “passi”. La decisione conserva esplicitamente la storia conexecnonattribuiti,senza considerarli innocui oautorizzati;backupNONPROD non significa accettazioneoperativa.

## 7 novembre — fermo confermato nelle ricevute; manca la cattura

La lettura target ha confermato49azioni/35policy/14servizi arrestati e0running su145container nell'ultimo inventario. Capture vuota. I nove eventi respinti sono tre sequenze exec di etcd con exit0,non attribuite. Non servono altri arresti né un'altra raccolta della stessa diagnostica.

Coppia attuale: acquisita la prova target del fermo; implementata continuazione di sola cattura, ora in qualifica. Essa conserva il vecchioHELD e gli eventi nel backup cifrato,senza presentarli come autorizzati. Nessun rilassamento del filtro originale. Prossimo risultato richiesto: archivio reale→Windows→restore isolato→SeaweedFS. Nuova decisione concreta sulla continuazione dopo qualifica;nessun nuovo consenso sviluppo.

MiniPET39,78%,0gate/0AT/0migrati invariato. Questa è rimozione di un blocco operativo,nonaccettazione storage. [Ricevuta target](../evidence/storage-cold-event-target-operator-20261107.json).

## Stato corrente 7 novembre — HOLD dopo il percorso di arresto, prima della cattura

Il tentativo autorizzato ha restituito UNEXPECTED_CONTAINER_EVENT. Il controllo è dopo il fermo nel codice; il journal target deve ancora confermare le49azioni e lo stato osservato. **Non ripetere stop o contenimento host.** [Ricevuta operatore](../evidence/storage-host-bound-cold-held-operator-20261107.json).

| Traguardo | Stato corrente |
| --- | --- |
| Contenimento host | Già riuscito sul VPS |
| Fermo Docker | Tentativo consumato; errore nel controllo finale eventi, readback pendente |
| Archivio cifrato target | Nessun successo attestato; cattura non raggiunta secondo il percorso del codice |
| Copia Windows e restore isolato | In attesa dell'archivio reale |
| Migrazione SeaweedFS | 0/120 migrati, nessun gate/AT chiuso |

Coppia completata lato sviluppo: registrazione del blocco reale e lettore raggruppato senza provider. [Unico comando VPS corrente](OUF_STORAGE_COLD_EVENT_HOLD_20261107.md). Il prossimo JSON identifica eventi e ricevute; se coerenti, preparare cattura senza replay del fermo. Non allargare ora il filtro degli eventi sulla base di un'ipotesi.

MiniPET39,78% invariato. Non trasformare questa diagnosi in un nuovo filone di resilienza: il risultato richiesto resta l'archivio reale per copia/restore e prosecuzione SeaweedFS. Nessuna nuova stima in “passi” prima di quel risultato.

## Decisione acquisita 7 novembre — fermo Docker e backup cifrato

Giovanni autorizza il singolo tentativo collegato:35policy,14stop,34fonti/interoPGcondiviso,capturecifrata,limiti e scadenza invariati rispetto alpacchetto proposto. [Decisione](../evidence/storage-host-bound-cold-operator-decision-20261107.json). ComandoVPSconsegnato;esito reale pendente. Nonrichiedere nuovamenteconsenso,nonripeterecontenimentohostriuscito. Prossimorisultato:archivio reale→Windows→restoreisolato. NessuncreditoMiniPETancora.

## 7 novembre — contenimento host completato sul target; backup reale pronto per decisione

**Blocco host rimosso:**5timer e registry disabilitati/fermi,5runtimefontistabili;ricevutaVPS acquisita. Non ripeterequestofase. Nuovo fermoDocker+capture collegato al successo è qualificato run42310506109. [Pacchetto eseguibile](OUF_STORAGE_HOST_BOUND_COLD_PACKAGE_20261107.md):35policy,14stop,34fonti/interoPGcondiviso,archivioage;decisione sul singolonuovotentativo pendente. Originale tentativoDocker consumato conservato e3lettureaddebitate.

| Traguardo | Stato corrente |
| --- | --- |
| Contenimento writer host | Completato sul VPS,zero killforzati |
| Primo archivio cifrato target | Procedura collegata qualificata;approvazione/esecuzione pendenti |
| CopiaPC e restore isolato | In attesa archivio reale;recipient/decryptcrossplatform giàverificati |
| Migrazione e accettazione SeaweedFS | Ancora0/120migrati,0/8gate,0/21AT |

MiniPET39,78% invariato:il successo host è un blocco operativo rimosso,nonuncriteriocomplessivochiuso. Prossimorisultato concreto è ENCRYPTED_OFFLINE_RECOVERY_SET_CAPTURED sulVPS,poiWindows/restore;nessunfiloneIAM/DRindipendente.

## Decisione acquisita 2026-11-07 Europe/Rome — continuazione host sul VPS

Giovanni autorizza la singola continuazione proposta,GIOVANNI-NONPROD-HOST-CONTINUE-20261106-01. [Ricevuta](../evidence/storage-host-continuation-operator-decision-20261107.json). Comando pinned daeseguire una volta,JSONtargetpendente. Non richiedere di nuovo il consenso; nessunaesecuzione/archivio/gate giàdedotta. Le richieste precedenti sotto sono soddisfatte.

## Continuazione host qualificata — esecuzione reale ancora pendente

Readback VPS conferma19letture senzaintenti e causa sulle2sliceescaped. Continuazione qualificata run42308843588: riproduce vecchioHOLD,conserva21file,conteggia19letture/byteprecedenti ecompiecontenimento sufixture. [Pacchetto concreto](OUF_STORAGE_HOST_CONTINUATION_20261106.md). Serve decisione per singolacontinuazione conallowance600s separata;stesse6mutazioni configurazione e5timer+registry,scadenzaoriginaria invariata. Non ripetere reader/oldapply. Dopo ricevuta reale: nuova composizioneDockerstop/capture→archivioPC→restore→migrazione. MiniPET39,78%invariato,nessungatechiuso. Nessunanuovastima basata suquesticicli correttivi.

## Blocco host corrente — correzione qualificata, lettura journal pendente

Contenimento VPS HELD/SLICE_NAME_REQUIRED prima dei punti di mutazione nel codice; journal da confermare. Il validator e la prova precedente non coprivano le slice dei template. Correzione qualificata con2servizi istanziati reali,run42308152680 SUCCESS,5unit test e arresto naturale/TERM. [Prove](../evidence/storage-host-slice-qualified-20261106.json). Prossima consegna solo lettura3file locali per legare il tentativo; nessun replay o ripreparazione. Successivamente continuazione governata→archivio→PC/restore→SeaweedFS. Correzione dello stesso blocco,non nuovo creditoMiniPET;39,78% invariato.

## Decisione acquisita — esecuzione host sul VPS pendente

Giovanni ha approvato il pacchetto host esatto (GIOVANNI-NONPROD-HOST-CONTAIN-20261106-01). Consegnato il comando pinned; attendere ricevuta VPS. Nessun consenso da richiedere di nuovo per questo perimetro,nessun targetstop/capture già dichiarato. [Decisione](../evidence/storage-host-containment-operator-decision-20261106.json). Le richieste di decisione nelle sezioni storiche sono soddisfatte.

## Stato corrente — contenimento host pronto per decisione operativa

La bozza VPS è acquisita e l'executor è qualificato su processi systemd reali (run42306614307 SUCCESS). **Non rieseguire il preparatore**. [Pacchetto concreto](OUF_STORAGE_HOST_CONTAINMENT_OPERATION_20261106.md).

| Blocco verso la chiusura | Stato effettivo | Prossimo risultato verificabile |
| --- | --- | --- |
| File runtime riscritti durante preparazione backup | Correzione implementata e qualificata; applicazione VPS pendente | 5timer e registry disabilitati, servizi inattivi,5fonti stabili |
| Primo archivio target | Assente; vecchio tentativo consumato | Nuovo piano collegato alla ricevuta host,fermo/capture governati |
| Backup fuori host e restore | Cifratura cross-platform provata; dati target non copiati/ripristinati | Archivio sul PC e restore isolato verificato |
| Migrazione e accettazione SeaweedFS | 0/120copiati,0/8gate,0/21AT | Criteri originali soddisfatti con evidenze target |

Questa coppia acquisisce la bozza reale e qualifica la correzione del blocco host; **non chiude un gate MiniPET**.39,78% invariato. La vecchia stima12–18passi non è una previsione attendibile: niente nuovo conteggio basato su correzioni/test. L'applicazione host richiede la decisione aggiuntiva concreta; non richiedere nuovamente disponibilità del servizio o autorizzazione sviluppo. Dopo esito host completare la composizione stop/capture senza riaprire un filone IAM.

Le sezioni seguenti conservano lo storico e le istruzioni superate.

## Verifica del preparatore completata; prossima azione sul VPS

CI nativa42304356159SUCCESS: preparatore reale restituisce bozza con rilievi espliciti per symlink rifiutato e proprietà omesse,nessun servizio avviato/fermato.13unit test riusati per digest; qualifiche precedenti storage/crypto non ripetute. Ora eseguire soltanto il preparatore18228byte/SHAcaac2981... e acquisire JSONredatto per completare executorhost e nuova operazione collegata. [Prove e limiti](../evidence/storage-host-preparation-systemd-qualified-20261106.json). Nessun gateMiniPET chiuso,archivio target ancora assente.

## Correzione corrente: proprietà systemd e prova nativa del reader

Seconda preparazione respinta con PROPERTY_CARDINALITY prima delle scritture; campo effettivo non noto. Corretto show --all/valori sconosciuti/ExecStop multipli/diagnostica,13test localiPASS; ora qualifica contro systemd reale nel runner prima di nuova consegna. [Pacchetto](OUF_STORAGE_HOST_CONTAINMENT_PREPARATION_20261106.md). StessaAREA esclusiva,nessun vecchio stop/capture rilanciato o scope azzerato. Questa è ancora la correzione del medesimo blocco host; nessun avanzamento MiniPET attribuito.

## Correzione corrente del preparatore host

Prima preparazione HELD sul filtro percorso,prima di scrivere. Corretto il supporto ai frammenti systemd esterni mantenendo custodia e nofollow;9test localiPASS. Ora eseguire il preparatore corretto una volta; configurazioni illeggibili restano rilievi,non successi. [Dettagli e limiti](OUF_STORAGE_HOST_CONTAINMENT_PREPARATION_20261106.md). Nessun nuovo stop/capture,area cancellata o gate chiuso; questo corregge lo stesso blocco host,non aggiunge un filone o un nuovo traguardo MiniPET.

## Azione corrente — contenimento host prima del nuovo fermo

Cinque timer attivi hanno ReadWritePaths verso tutte cinque fonti runtime. È presente anche un service registry attivo: incluso conservativamente nel perimetro proposto; la coppia semantic mascherata resta invariata. [Ricevuta](../evidence/storage-runtime-writer-metadata-operator-20261106.json).

Ora: eseguire una sola preparazione privata delle configurazioni esatte, completare/qualificare executor host e nuova operazione collegata al vecchio tentativo, quindi decisione sul perimetro esteso e archivio reale. [Pacchetto preparatorio e limiti](OUF_STORAGE_HOST_CONTAINMENT_PREPARATION_20261106.md). Il preparatore non arresta servizi; executor non ancora implementato. Nessun altro probe crypto o test storage riuscito da ripetere. Questa è la correzione del fermo incompleto, non un nuovo traguardo MiniPET.

Dopo archivio: copiaPC/restore isolato, poi gate SeaweedFS. Le vecchie stime12–18passi non sono una previsione aggiornata: niente nuovo conteggio finché l'archivio target non è stato effettivamente prodotto. MiniPET39,78% e criteri invariati.

## Riscontro corrente — tentativo consumato e fonti runtime variabili

Il journal riportato daGiovanni è coerente con HOLD prima delle mutazioni (3comandi,0intenti); capture assente. Tutti5corpi runtime sono cambiati a parità di dimensione/custodia. [Ricevuta](../evidence/storage-cold-runtime-drift-operator-20261106.json). Nessun replay o semplice rinnovo hash del piano.

Il blocco da rimuovere è il contenimento degli eventuali writerhost delle credenziali runtime,non altro sviluppo generaleIAM. Trovati precedente contrattuale e collegamento esatto1dei5percorsi a un servizio/timer noto; statoattuale/attribuzione completa ancora da osservare. [Dossier e lettura raggruppata](OUF_STORAGE_RUNTIME_WRITERS_REVIEW_20261106.md). Dopo quell'output,preparare la correzione operativa concreta collegata al tentativo consumato. Primoarchivio reale,PC/restore e gateSeaweedFS restano la sequenza; nessun creditoMiniPET.

# Roadmap corrente MinIO → SeaweedFS — 6 novembre 2026

## Decisione corrente e coppia di lavoro

OUF è **non produttivo**, i dati applicativi sono **di test** e Giovanni accetta che resti indisponibile per tutto il tempo necessario. [Decisione](../evidence/storage-nonproduction-owner-context-20261106.json). Non chiedere nuovamente un orario di rientro. Conservare backup e restore come esercitazione riutilizzabile; credenziali e configurazioni rimangono private. Questa decisione non cancella dati, criteri MiniPET o gate operativi.

La coppia corrente:
1. **Rimossa la dipendenza dalla continuità di servizio:** prima copia di conservazione a servizi fermi, con lavoro applicativo eventualmente interrotto conservato per riconciliazione. Nessun drain applicativo o common-cut dichiarato per inferenza.
2. **Fermo e cattura resi eseguibili e verificabili:** driver delimitato, correzione dell'ordine dei mount Docker, qualifica nativa, pacchetto con comandi e hash. [Pacchetto corrente](OUF_STORAGE_COLD_STOP_PACKAGE_20261106.md). Giovanni ha autorizzato fermo e cattura con manutenzione esclusiva: [decisione](../evidence/storage-test-cold-operator-decision-20261106.json). Esecuzione target ancora da effettuare; non richiedere il consenso nuovamente.

Download, diagnosi, fixture e aggiornamenti documentali sono attività interne alla coppia, non nuovi “passi” di roadmap. La stima storica di 12–18 passi rimane ritirata: non rappresentava i blocchi effettivi. Il prossimo risultato da misurare è un archivio corrente con dimensione e SHA256, poi il suo recupero; non un nuovo conteggio di test.

## Percorso residuo con risultati verificabili

| Traguardo | Disponibile | Risultato ancora richiesto |
|---|---|---|
| Prima conservazione dello stato test | Piano 14 ruoli/34 fonti/5 directory runtime; recipient e VPS→Windows verificati; driver e produttore | Decisione sul comando esatto e manutenzione esclusiva dichiarate da Giovanni. Restano fermo e cattura cifrata con ricevuta; nessun backup target ancora prodotto |
| Copia indipendente e recupero | PC Windows scelto, SSH/SCP e decifratura verificati | Trasferire l'archivio corrente, confrontare hash, decifrare e ripristinare in ambiente isolato; verificare DB, oggetti, configurazioni, segreti e lavoro interrotto |
| Baseline e candidato G0–G2 | 120 corpi verificati; 18 rilievi tipizzati; coorte ricostruita; OCI33 e prove client | Accettare disposizioni/owner, accessi/custodia e censimento writer; chiudere licenze/provenienza/custodia del candidato e AT dei client applicabili |
| Esercizio e procedura G3–G4 | Qualifiche sintetiche e componenti, migratore e runbook | Recovery dell'insieme reale, TLS/rotazione, fault/reboot, capacità; rehearsal SeaweedFS su copie, parità completa, interruzioni e ritorno dopo scritture |
| Ammissione e passaggio G5–G6 | Nessun passaggio operativo ammesso | Pacchetto unico corrente, autorità applicabile, copia dei 120 oggetti e riferimenti, switch coordinato, percorso utenti e riapertura governata |
| Stabilizzazione G7 | Non iniziata | Osservazione proposta almeno 48 ore e cicli rappresentativi, backup/restore e manutenzione; ritiro MinIO deciso separatamente |

L'assenza di un vincolo di disponibilità vale per questa manutenzione non produttiva. Non attribuisce automaticamente obiettivi RPO/RTO soddisfatti a G3/G5 o qualifica produttiva. PET/Matrix in docs/baseline/v1.7 e MiniPET originale restano il contratto. Per il passaggio devono risultare conservate tutte le scritture confermate; un esito interrotto/ambiguo non diventa completato o rigiocabile.

## Evidenze da riusare senza nuove acquisizioni

- Raccolta G0 v2 tecnicamente completa: 145 container, 292 nuovi Engine GET / 345 cumulativi, 1.370 richieste S3, 3 export DB / 353 righe, 120 corpi verificati. Le due autorizzazioni di raccolta sono consumate.
- 18 rilievi: 10 owner non provati, 4 sample DB, 2 label diagnostiche, 2 payload con collegamento fisico ma proprietà non dimostrata. Nessun backfill automatico.
- Onboarding candidato d5155899; Ingestion4165b9e1 e UDP0d40da05. Qualifica componente HUMAN non equivale a percorso operativo HTTP/MCP/Gateway o grant.
- Preparazione backup v3 riuscita; piano 1c0bb62c, scadenza 7 novembre 2026 alle 20:53:39 Europe/Rome. Nessun rinnovo automatico. Correzione v4 deriva solo le impronte dei mount dal medesimo inventario conservato, mantenendo epoche, fonti, generazioni e budget.
- Cifratura VPS→Windows verificata su512byte. Non ripetere installazione age, scelta del PC, reader o prove della chiave.

Per le prove e i limiti puntuali: [dossier G0](OUF_STORAGE_G0_FINDINGS_DISPOSITION_20261106.md), [coorte](OUF_STORAGE_COHORT_DECISION_20261106.md), [qualifica nuova](../evidence/storage-test-cold-stop-qualified-20261106.json), [handoff](handoffs/OUF_STORAGE_CLOSURE_HANDOFF_20261105.md). La cronologia precedente resta in Git e nell'handoff; non costituisce una lista di azioni da rieseguire.

## Accettazione

**18,3/46 = 39,78%; 0/8 gate; 0/21 AT; 0/120 oggetti migrati.** Separatamente:120corpi reali verificati. Nessun credito aggiunto per questa qualifica. Nessun merge, deploy, grant, riapertura o modifica del source-lock. MinIO non viene cancellato né ritirato da questo pacchetto.
