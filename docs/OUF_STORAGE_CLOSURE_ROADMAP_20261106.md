# Roadmap corrente MinIO → SeaweedFS — 6 novembre 2026

**Raccolta tecnica e review dei dati disponibili concluse; G0 ancora aperto per evidenze operative e disposizioni non ancora accettate.** Fonte: [dossier](OUF_STORAGE_G0_FINDINGS_DISPOSITION_20261106.md) e [ricevuta finale](../evidence/storage-g0-final-local-review-operator-20261106.json). Base deploy f02ba458a7e536c848abca001154dbf5f665a16e; source d5155899b09dda298494b68cefa7e1f281167652, entrambePR54 draft/open.

## Risultato della coppia raccolta e riconciliazione

1. Raccolta02 completata tecnicamente:120corpi reali verificati/referenziati,3exportDB,145container,292GET nuovi/345cumulativi e1370richiesteS3,zero scritture target. Le due autorizzazioni sono consumate.
2. Review dei dati disponibili completata:18impronte associate,4sample DB e2label classificati,2payload collegati ad asset/hash/size/run. Restano10owner non provati e lacune ACCESS/CUSTODY/WINDOW/WRITERS/capacità/coorte. La riconciliazione G0 completa **non è conclusa**.

Download, helper, ricevute e aggiornamenti documentali non diventano altre coppie. Non ripetere le acquisizioni/qualifiche riuscite senza nuova modifica o motivo documentato.

## Blocco concreto emerso e scelta della procedura

Onboarding osservato dichiara194b5865, mentre la qualifica client33 usa d5155899. I sorgenti differiscono in interfaccia di upload e policy timeout/retry; label e image ID non provano le classi effettivamente installate. Questa differenza va risolta prima della qualifica finale, senza estendere automaticamente il filone HUMAN/recovery.

Il [runbook offline](OUF_STORAGE_OFFLINE_CUTOVER_RUNBOOK_20261106.md) propone copia completa a scritture ferme e MinIO preservato. Specifica baseline DB/oggetti, backup indipendente, parità, switch, riapertura e ritorno prima/dopo nuove scritture. È DRAFT non eseguibile: binding finali, comandi, budget e decisioni ancora mancanti sono null nel [piano strutturato](../releases/storage-offline-cutover-plan-20261106.json). Non è una consegna ammessa.

## Gate e prove residue

| Gate | Prova disponibile | Residuo per la chiusura |
|---|---|---|
| G0 baseline |120corpi verificati,18rilievi tipizzati con disposizioni, feature/runtime/capacità osservati |Accettare disposizioni, coorte e inventario completo; accessi/custodia,11percorsi writer e1container attivo fuori roster, funzioni/finestra/RPO/RTO |
| G1 candidato |OCI33 e qualifiche al checkpoint |Coorte finale server/client/tool, licenze, custodia durevole e sicurezza valida all'ammissione |
| G2 contratti |12casi client33 e mapping AT aperto |Binding rappresentativi della coorte scelta e tutti gli AT applicabili; niente trasferimento implicito194b→d515 |
| G3 recovery |Foundation/restore sintetici e backup storici parziali |Backup corrente DB+oggetti+config/chiavi, custodia indipendente, restore rappresentativo e obiettivi/capacità misurati |
| G4 procedura |Rehearsal copia/ritorno oggetti e runbook proposto |Writer realmente fermabili, common-cut e parità DB/oggetti, rollback applicativo dopo nuove scritture, comandi esatti qualificati |
| G5 ammissione |Non pronta |Pacchetto unico G0–G4, budget, binding, finestra e decisioni effettivamente applicabili |
| G6 passaggio |Non iniziato |Esecuzione autorizzata, copia reale/parità, percorso utenti, switch e riapertura governati |
| G7 osservazione |Non iniziata |Finestra proposta almeno48h, backup/restore e manutenzione rappresentativi; ritiro MinIO deciso separatamente |

Le prove di base restano quelle del MiniPET originale e PET/Matrix in docs/baseline/v1.7. Questa roadmap non le modifica.

## Prossima coppia: due uscite verificabili

1. **Chiudere la scelta della coorte da qualificare.** Cercare nelle prove di consegna già conservate il legame sorgente/build/immagine/classi/binding della coorte installata. Produrre il delta esatto di compatibilità e la scelta motivata tra mantenimento e aggiornamento governato. Se manca una prova target, preparare una sola verifica delimitata del dato mancante, non un'altra raccolta G0 completa.
2. **Rendere concreto il pacchetto di fermo e ritorno.** Riunire censimento writer/accessi, backup indipendente/restore e finestra nel runbook con comandi e budget sui binding scelti. Distinguere il lavoro autonomo dalle poche attestazioni/azioni che Giovanni deve davvero fornire. Non chiedere approvazione al cutover finché il pacchetto non è reviewabile.

Nessuna nuova stima numerica: quella di12–18passi è ritirata perché non aveva delimitato le condizioni del VPS e i “passi” successivi erano stati frammentati senza aggiornare il residuo. La review ora riduce l'incertezza sui dati; restano coorte e procedura operativa. La prossima stima deve misurare questo residuo, non contare documenti o test.

## Stato di accettazione

MiniPET **18,3/46=39,78%**, **0/8gate**, **0/21AT**, **0/120oggetti reali migrati**. Separatamente:120corpi reali verificati. Nessun credito aggiunto per classificazione o runbook. MinIO,source-lock e piano congelato invariati; nessun merge/deploy/grant/riapertura.
