## Aggiornamento corrente — natura dei rilievi acquisita

[Readback operatore](../evidence/storage-g0-sealed-findings-operator-20261106.json):120corpi/120riferimenti/120classificati,353righe;18rilievi=10campi tenant non valorizzati+4riferimenti aggiuntivi+4quarantena. Nessun rilievo missing/hash/size/unclassified/dangling nel breakdown.2ACL owner/grants non dimostrati;source/destination/backup stesso device. [Disposizione preliminare e contratti](OUF_STORAGE_G0_FINDINGS_DISPOSITION_20261106.md). Secondo passo in corso:classificazione locale esatta dei riferimenti e delle prove legacy,senza query o mutazioni;non presumere18riparazioni. Restano accessi/custodia/finestra/writer e accettazione capacità/funzioni/obiettivi. Numeri MiniPET invariati.

# Roadmap corrente MinIO → SeaweedFS — 6 novembre 2026

Questa roadmap sostituisce la stima conversazionale di **12–18 passi / 6–9 coppie** e il percorso successivo del riesame iniziale del 5 novembre. Non modifica criteri, gate, piano storico congelato o autorizzazioni. Base aggiornata: deploy `c4e3b4d2ca4be6b1860aee308ce62daedb662067`, Onboarding `d5155899b09dda298494b68cefa7e1f281167652`; PR54 entrambe draft/open.

## Correzione della pianificazione

La stima precedente era troppo ottimistica: trattava raccolta e integrazione operativa come attività già delimitate, senza aver verificato abbastanza le condizioni reali del VPS. Preparazioni, diagnosi, qualifiche e registrazioni sono poi state contate come “passi” senza aggiornare la previsione di chiusura. Non sono unità confrontabili con quei 12–18 passi. Non è possibile sottrarre le coppie svolte per ottenere un residuo attendibile.

Sono stati rimossi blocchi reali: pacchetto raccoglitore, connessioni private S3 e tre DB, binding di rete, percorsi di destinazione, consegna e preparazione sul VPS. Le qualifiche di copia/ritorno e dei client esistono, ma restano sintetiche. La raccolta target autorizzata si è arrestata in HOST_BEFORE dopo un Docker GET, senza raggiungere S3 o DB. Il limite di 64 container del pacchetto non era stato adeguatamente confrontato con l'host; il successivo riscontro locale mostra 145 directory, non un conteggio live provato. Il profilo192 corretto è stato poi autorizzato ed eseguito: la raccolta02 è SEALED con technicalCaptureComplete=true,120corpi verificati,3exportDB e145container osservati da Docker. Il risultato è HELD_RECONCILIATION_FINDINGS per18rilieviDB: la cattura è conclusa,la riconciliazione no. Fonte: output operatore registrato; breakdown locale acquisito;associazione semantica puntuale ancora da leggere.

**Stima 12–18 ritirata; nuova stima numerica non disponibile.** Non viene sostituita con un altro conteggio arbitrario. La raccolta corrente e la riconciliazione dei suoi rilievi permetteranno di stimare il lavoro residuo per criterio; eventuali incognite rimarranno esplicite. Non si promette che la raccolta, da sola, chiuda G0.

## Traguardi e prove di uscita

| Traguardo | Stato corrente | Prova necessaria per chiuderlo |
|---|---|---|
| G0 — baseline reale | Raccolta02 tecnicamente completa:120corpi,3exportDB,145container;18rilieviDB,2classificazioniACCESS da rivedere. Entrambi i tentativi consumati | Raccolta corrente verificata di oggetti/corpi e riferimenti DB; censimento writer/consumer e funzioni; riconciliazione delle otto sezioni incluse accessi, capacità, custodia e finestra. Eventuali rilievi devono essere risolti, non solo elencati |
| G1 — candidato mantenibile | Coorte OCI33 e scansioni al checkpoint qualificate; gate aperto | Inventario server/client/tool, review licenze e obblighi, custodia durevole verificata e scansioni valide all'ammissione |
| G2–G4 — compatibilità, esercizio e procedura | Prove sintetiche di client, copia/ritorno, recovery e restore disponibili | Matrice AT sulla coorte finale; topologia/TLS/segreti, backup indipendente e restore dell'insieme DB/oggetti/configurazioni/chiavi; writer realmente fermabili, parità DB/oggetti e rollback applicativo; capacità e RPO/RTO misurati rispetto a obiettivi accettati |
| G5 — consegna operativa ammessa | Non pronta: G0–G4 aperti | Unico pacchetto con binding, prove, runbook, hold/rollback, finestra e approvazioni effettivamente applicabili |
| G6 — migrazione e passaggio | Non iniziati; 0/120 oggetti reali migrati sul totale storico | Esecuzione autorizzata, quiescenza verificata, copia e parità integrale, percorso utenti sul target, switch e riapertura governati |
| G7 — osservazione e chiusura | Non iniziati; MinIO ancora attivo | Finestra concordata: MiniPET propone almeno 48h, con ciclo backup/restore e manutenzione, da estendere se non rappresentativi; decisione sul ritiro accessi MinIO e conservazione originali |

Per il volume storicamente ridotto, valutare prima la copia con fermo completo, sulla base dei dati correnti e della finestra accettabile. Non sviluppare delta online o collegamento HTTP/HUMAN senza una dipendenza dimostrata della procedura scelta. Il backup locale di staging non prova un backup indipendente; la domanda sul backup differita per la preparazione non equivale ad accettazione per il cutover.

## Prossima coppia operativa, senza nuovo lavoro preparatorio già riuscito

1. **COMPLETATO tecnicamente:** raccolta02 autorizzata ed eseguita;120corpi verificati,3exportDB,145container,zero scritture provider. Non ripetere acquisizione o preparazione. [Risultato operatore](../evidence/storage-g0-host192-collection-operator-20261106.json).
2. **IN CORSO:** leggere il riepilogo locale dei18rilieviDB e2classificazioniACCESS già conservati; assegnare una disposizione motivata e riconciliare le otto sezioni. ACCESS/CUSTODY/WINDOW/WRITERS restano mancanti (11percorsi writer); capacità osservata ma non accettata. Chiudere G0 solo con i criteri soddisfatti. Il numero18 non permette di stimare18riparazioni: può includere classificazioni,più riferimenti allo stesso oggetto o incongruenze effettive.

Questa coppia comprende acquisizione e valutazione delle evidenze: non sarà suddivisa artificialmente in download, lettura JSON, registrazione e aggiornamento PR. Un arresto reale può richiedere un intervento separato, che deve essere dichiarato come blocco e motivare la revisione della previsione.

Ogni aggiornamento successivo riporterà: criterio chiuso oppure blocco indispensabile rimosso, prova, residui e impatto sulla previsione. Registrazioni e documentazione di accompagnamento non saranno presentate come passi di migrazione. I test già riusciti si riusano; nuove prove solo per modifiche o lacune specifiche documentate.

## Riscontri e limiti

- [Riesame G0–G7 e 21 AT](OUF_STORAGE_CLOSURE_REVIEW_20261105.md).
- [Tentativo HELD](../evidence/storage-g0-held-operator-20261106.json) e [readback operatore](../evidence/storage-g0-held-readback-operator-20261106.json).
- [Qualifica host192](../evidence/storage-g0-host192-qualified-20261106.json): run42218997469; [preparazione VPS](../evidence/storage-g0-host192-preparation-operator-20261106.json). Gli esiti VPS sono riportati dall'operatore, non osservazioni dirette dell'agent.
- [Stato corrente strutturato](../releases/minio-seaweedfs-closure-status-20261105.json).

MiniPET invariato: **18,3/46 = 39,78%; 0/8 gate; 0/21 AT; 0/120 oggetti reali migrati**. Il 39,78% è una stima pesata di lavoro tecnico, non una misura del tempo residuo né accettazione. Questo aggiornamento registra una nuova evidenza target riportata dall'operatore, senza credito aggiunto:120corpi verificati e0migrati sono misure distinte.

La raccolta02 ha scritto soltanto evidenze locali e non ha mutato i provider. Ora è previsto esclusivamente il readback locale redatto,senza nuove query o verifica ripetuta dei corpi. Nessun merge,deploy,grant o riapertura. Basec4e3b4d2:CI49SUCCESS/3in corso al controllo; dedicata ingresso10/10SUCCESS. Pubblicazione con confronto dell'HEAD atteso,senza force.
