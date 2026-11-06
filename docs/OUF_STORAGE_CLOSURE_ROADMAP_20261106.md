# Roadmap corrente MinIO → SeaweedFS — 6 novembre 2026

**Raccolta tecnica e review dei dati disponibili concluse; G0 ancora aperto per evidenze operative e disposizioni non ancora accettate.** Fonte: [dossier](OUF_STORAGE_G0_FINDINGS_DISPOSITION_20261106.md) e [ricevuta finale](../evidence/storage-g0-final-local-review-operator-20261106.json). Base deploy f02ba458a7e536c848abca001154dbf5f665a16e; source d5155899b09dda298494b68cefa7e1f281167652, entrambePR54 draft/open.

## Risultato della coppia raccolta e riconciliazione

1. Raccolta02 completata tecnicamente:120corpi reali verificati/referenziati,3exportDB,145container,292GET nuovi/345cumulativi e1370richiesteS3,zero scritture target. Le due autorizzazioni sono consumate.
2. Review dei dati disponibili completata:18impronte associate,4sample DB e2label classificati,2payload collegati ad asset/hash/size/run. Restano10owner non provati e lacune ACCESS/CUSTODY/WINDOW/WRITERS/capacità/coorte. La riconciliazione G0 completa **non è conclusa**.

Download, helper, ricevute e aggiornamenti documentali non diventano altre coppie. Non ripetere le acquisizioni/qualifiche riuscite senza nuova modifica o motivo documentato.

## Coorte ricostruita e procedura delimitata

[Decisione coorte](OUF_STORAGE_COHORT_DECISION_20261106.md): le prove conservate collegano Onboarding7b9d3e91 ai sorgenti73498/9d19 (stesso tree),non alla label194b presa isolatamente. Confermata per lo sviluppo la candidata d515/OCI33/UDP0d40/Ingestion4165;delta58file/20Java/V39–V41. Membership live e interi servizi restano da qualificare.

Corretto il confronto MinIO:14cea493 root/native e69b2ec20 configuration sono collegati nella medesima prova conservata;69b2ec20 è già la sorgente della rehearsal. Non serve un nuovo test per una presunta immagine diversa.

Il [runbook](OUF_STORAGE_OFFLINE_CUTOVER_RUNBOOK_20261106.md) include la [matrice writer](../releases/storage-offline-writer-containment-20261106.json):9percorsi applicativi/3owner,2admin-esterni ancora da censire. Specifica drain,stop intero owner,inibizione restart/barriera DB-S3 e mantenimento fence durante V39 ACTIVE. Rimane DRAFT non eseguibile.

## Gate e prove residue

| Gate | Prova disponibile | Residuo per la chiusura |
|---|---|---|
| G0 baseline |120corpi verificati,18rilievi tipizzati con disposizioni, feature/runtime/capacità osservati |Accettare disposizioni, coorte e inventario completo; accessi/custodia,11percorsi writer e1container attivo fuori roster, funzioni/finestra/RPO/RTO |
| G1 candidato |OCI33 e qualifiche al checkpoint |Coorte finale server/client/tool, licenze, custodia durevole e sicurezza valida all'ammissione |
| G2 contratti |12casi client33 e mapping AT aperto |Binding rappresentativi della coorte scelta e tutti gli AT applicabili; niente trasferimento implicito della qualifica adapter al modulo completo |
| G3 recovery |Foundation/restore sintetici e backup storici parziali |Backup corrente DB+oggetti+config/chiavi, custodia indipendente, restore rappresentativo e obiettivi/capacità misurati |
| G4 procedura |Rehearsal copia/ritorno oggetti e runbook proposto |Writer realmente fermabili, common-cut e parità DB/oggetti, rollback applicativo dopo nuove scritture, comandi esatti qualificati |
| G5 ammissione |Non pronta |Pacchetto unico G0–G4, budget, binding, finestra e decisioni effettivamente applicabili |
| G6 passaggio |Non iniziato |Esecuzione autorizzata, copia reale/parità, percorso utenti, switch e riapertura governati |
| G7 osservazione |Non iniziata |Finestra proposta almeno48h, backup/restore e manutenzione rappresentativi; ritiro MinIO deciso separatamente |

Le prove di base restano quelle del MiniPET originale e PET/Matrix in docs/baseline/v1.7. Questa roadmap non le modifica.

## Coppia corrente: uscita acquisita e azione residua

1. **Origine, scelta e delta completati:** catena immagine/sorgente ricostruita dalle prove conservate;stesso tree73498/9d19 verificato;scelta di sviluppo d515 confermata,delta e limiti espliciti. Non è qualifica live o ammissione.
2. **Pacchetto operativo in corso:**9percorsi associati ai3owner e barriere proposte. Unica lettura locale preparata identifica il container attivo fuori roster e la copertura mount del JAR da2file già conservati. Esito operatore necessario;nessun nuovo accesso provider. Restano accessi effettivi,admin/esterni,backup indipendente/restore,finestra e comandi/budget esatti.

La lettura si esegue con scripts/read-storage-g0-unmapped-runtime-20261106.py al commit consegnato e SHA25640bf3fa351481b4f91af811418439556c716444c4d9dd2c80f67bdfe2ac13f5f. Non ripetere altri comandi. Il prossimo lavoro dopo l'esito risolve l'identità restante e completa gli input operativi;non riparte dal confronto della label o da test di componente già riusciti.

Nessuna nuova stima numerica: quella di12–18passi è ritirata perché non aveva delimitato le condizioni del VPS e i “passi” successivi erano stati frammentati senza aggiornare il residuo. La review ora riduce l'incertezza sui dati; restano coorte e procedura operativa. La prossima stima deve misurare questo residuo, non contare documenti o test.

## Stato di accettazione

MiniPET **18,3/46=39,78%**, **0/8gate**, **0/21AT**, **0/120oggetti reali migrati**. Separatamente:120corpi reali verificati. Nessun credito aggiunto per classificazione o runbook. MinIO,source-lock e piano congelato invariati; nessun merge/deploy/grant/riapertura.
