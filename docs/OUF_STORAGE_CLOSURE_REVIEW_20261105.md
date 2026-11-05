# Chiusura MinIO → SeaweedFS: riscontro dei criteri e percorso residuo

Riesame del 5 novembre 2026 richiesto da Giovanni. Priorità: completare la sostituzione storage; poi riprendere M2 file → onboarding → semantic registry → ingestion → reconciliation → UDP. Due passi sequenziali, nessun subagente.

Base esaminata: deploy `41431adaac06a85d9deeb31da70c156b3f955141`, Onboarding `d5155899b09dda298494b68cefa7e1f281167652`; entrambe PR54 draft/open. HEAD corrispondenti alla consegna. Le ultime 100 esecuzioni visibili per repository non mostrano run attivi: sul checkpoint deploy 50 workflow SUCCESS, source 8 SUCCESS. I check-run deploy sono 84 SUCCESS: workflow e check-run sono conteggi distinti. Nessuna attività concorrente dichiarata nelle discussioni PR restituite. Non è una prova dell'assenza di processi esterni non osservabili; l'aggiornamento del branch richiede expected SHA e nessun force.

## Primo passo: criteri contro implementazione e prove

Letture: AGENTS e checkpoint più recente, MiniPET §§4–11, handoff recovery, dossier/ricevuta HUMAN, contratti Onboarding HUMAN/PostgreSQL, policy resilienza, Matrix v1.7 §§1/4/7 e PET UDP §§81/109.4. La Matrix distingue contratto/integration da accettazione rappresentativa; il PET impone S3 come binding e riconciliazione DB/oggetti. RPO iniziale DB 900s e RTO core 14400s sono da validare; RPO del passaggio pianificato: zero scritture confermate perse. La finestra di fermo non ha ancora un valore accettato.

| Gate | Implementazione / qualifica già disponibile | Blocco effettivo di chiusura | Consegna necessaria |
|---|---|---|---|
| G0 baseline | Inventario privato16/17: 2 bucket, 120 record, 203743 byte; piano offline; mappa sorgente writer Onboarding/UDP/Ingestion | Nessun hash dei 120 corpi reali; ACL/publicAccessBlock non risolti; writer/consumer/DB non completi; capacità e binding non correnti; finestra non fissata | Unica raccolta governata corrente e riconciliazione di identità, writer, riferimenti, funzioni, capacità e obiettivi. Non rieseguire scope consumati |
| G1 candidato | OCI33 esatta, coorte e runtime sintetico verificati; raw scan HIGH/CRITICAL/UNKNOWN zero al checkpoint; SDKv1 e moduli archiviati del censimento29 rimossi | Inventario manutenzione complessivo ancora aperto; review licenze/redistribuzione, custodia durevole immagine/artifact e binding delle feature non conclusi | Dossier esatto di server/client/tool, lifecycle e review competente, custodia verificata e scansioni valide al momento dell'ammissione |
| G2 contratti | Client reali storici; prove OCI33 MIME, identità/TLS, isolamento laterale e rotazione in fixture | Nessun trasferimento automatico delle prove fra generazioni; matrice completa dei due client sulla coorte finale e sul binding target non conclusa | Tracciabilità AT per versione/client, chiusura delle differenze e riscontri target applicabili |
| G3 esercizio | Restore OCI33 da export su nuova esecuzione; PostgreSQL/PITR e common-cut di fixture; fault/compaction e rotazioni native; recovery Onboarding qualificato come componente | Topologia reale, custodia completa, writer OUF effettivi, restore/rebind governato, carico/capacità e RPO/RTO non accettati | Drill rappresentativo sull'intero insieme, preservando i test già riusciti e misurando gli obiettivi |
| G4 migrazione | Core Go con journal e copy-new su 120 corpi sintetici, hash/rilettura/CAS/crash; nuovo piano delta offline | Core vecchio usa due SeaweedFS di laboratorio, non MinIO→OCI33; nessun executor di replace/delete, delta finale, DB join o ritorno dopo nuove scritture qualificato | Rehearsal con sorgente MinIO isolata e OCI33 esatta, copie indipendenti, delta/inverse recovery e 100% byte/metadati/riferimenti confrontati |
| G5 pacchetto | Singoli deliverable e prove pubbliche | G0–G4 aperti; coorte/binding/custody/fence/backup/runbook/review/autorità non composti in una consegna ammessa | Pacchetto unico concreto, con hold/rollback e autorità corrente separata dallo sviluppo |
| G6 passaggio | Nessuna migrazione reale o switch | 0/120 oggetti reali; writer unico, parità e percorso utenti non osservati sul target | Esecuzione autorizzata, quiescenza/delta, switch e riapertura con prove correnti |
| G7 stabilizzazione | Nessuna osservazione post-switch | Finestra proposta ≥48h e ciclo backup/restore/manutenzione non iniziati; MinIO ancora attivo | Osservazione e decisione governata su ritiro accessi e conservazione originali |

Le prove di rotazione/isolamento/restore successive sono riportate nei loro dossier: i campi `syntheticRuntime` nella ricevuta iniziale OCI33 descrivono quella specifica esecuzione e non vanno riscritti come se avesse svolto i drill successivi. Tutti i gate restano OPEN.

## Matrice AT: nessun PASS target attribuito

| AT | Riscontro disponibile / residuo che impedisce PASS |
|---|---|
| 01 provenienza | Coorte OCI33 verificata; G1 complessivo, custodia, client/tool e review residui |
| 02 staging | Adapter/prove API storiche e Onboarding nuovo qualificato; percorso target con limite 10MiB e stessa URI da verificare |
| 03 UDP | Adapter S3 e contratti inventariati; PUT/HEAD/GET/LIST/DELETE e hash dei corpi su target da qualificare |
| 04 multipart | Fixture storiche; core di migrazione non implementa multipart/version history; applicabilità e binding finali aperti |
| 05 paginazione | Inventario sintetico storico >1000 record; client/pagine/escape sulla coorte finale da ricomporre |
| 06 namespace | Inventario metadata senza collisioni, guard e fixture; snapshot corrente e delete esatto da provare |
| 07 policy | Identità/prefissi/dinieghi sintetici; ACL reali, tenant e privilegi minimi target aperti |
| 08 rete/segreti | OCI33 TLS/rotazioni/isolamento laterale in fixture; topologia/custodia/rotazione target aperte |
| 09 metadati | Correzione MIME OCI33 qualificata; inventario funzionale corrente e conservazione di tutte le funzioni richieste aperti |
| 10 consistenza | CAS/copy e fault fixture; semantiche dei writer reali e concorrenza sul binding finale aperte |
| 11 errori/budget | Core copy e recovery owner con budget duraturi; percorso completo e disco pieno rappresentativo da ricomporre |
| 12 restart | Crash componenti OCI33 e restart owner/PG provati in laboratorio; reboot/host e deployment target non accettati |
| 13 restore | Restore nativo da soli export acquisito; intero insieme configurazioni/chiavi/DB applicativi e custodia target aperto |
| 14 interruzione copia | Tre crash reali del core copy-new; nuovo provider finale e delta mutativo non qualificati |
| 15 delta/fence | Common-cut fixture e owner Onboarding; census completo, fence di tutti i writer e delta target aperti |
| 16 parità | 120 corpi sintetici; 0 corpi reali verificati/copiati; join DB e confronto integrale reali aperti |
| 17 ritorno | Recovery fixture; nuove scritture/overwrite/delete dopo switch e ritorno senza perdita non qualificati |
| 18 Teatri/Farmacie | Identità preservate; letture governate di riferimenti esistenti sul candidato non eseguite |
| 19 utenti | Nessun percorso completo sui due client chatbot/MCP/Gateway del candidato storage |
| 20 capacità | Nessuna misura rappresentativa corrente di carico/risorse/throughput entro obiettivi concordati |
| 21 manutenzione | Export/restore sintetico; patch upgrade, export neutro e manutenzione finale da accettare |

Nessun N/A dedotto dall'assenza storica di versioni, marker o multipart. Le qualifiche citate non sostituiscono i requisiti del MiniPET.

## Secondo passo: delta finale nel modulo di pianificazione

Implementato [delta_manifest.py](../tools/storage_planning/delta_manifest.py), che riusa il compilatore inventario esistente e calcola hash da byte locali. Distingue ADD, REPLACE_BODY, REPLACE_METADATA, REMOVE, SOURCE_OBSERVATION_CHANGED e UNCHANGED. Produce intento privato vincolato ai due inventari, ai due profili e a tutti i corpi; riepilogo pubblico senza chiavi/hash/metadata privati. [Contratto e limiti](OUF_STORAGE_DELTA_PLAN_20261105.md).

**È un pianificatore offline, non un migratore operativo.** Le classificazioni di rimozione non autorizzano DELETE. Non osserva destinazione, origine autentica dei byte, fence, riferimenti DB o autorità; questi restano requisiti espliciti. Il core copy-new Go non è modificato, e non viene adattato tacitamente per eseguire il nuovo piano.

22 test locali PASS; workflow dedicato vincola i sorgenti e conserva il log. Nuove prove di componente, nessuna ripetizione dei precedenti drill nativi. MiniPET invariato **18,3/46 = 39,78%; 0/8 gate, 0/21 AT, 0/120 oggetti reali**.

## Percorso successivo delimitato

1. Comporre il rehearsal di migrazione su sorgente MinIO isolata e destinazione OCI33 esatta usando il core esistente, un'acquisizione autenticata/condizionale dei byte e il piano delta. Nessun trasferimento delle prove del vecchio binario al candidato nuovo. Decidere esplicitamente fra copia a sorgente interamente quiescente e precopia+delta; per il volume storicamente piccolo, valutare prima il percorso con fermo completo, previa misura corrente della finestra. Non aggiungere complessità di migrazione online senza necessità.
2. Qualificare le sole mutazioni richieste dal percorso scelto e la loro riconciliazione dopo risposta persa/crash; verificare insieme DB, oggetti e ritorno. In parallelo logico, senza subagenti, preparare il dossier unico per i residui G0/G1 da sottoporre quando concreto.

Il collegamento HTTP/HUMAN del resolver è **una dipendenza condizionale**: serve se la procedura scelta invoca quel comando. Non è automaticamente il prossimo passo né un prerequisito per ogni copia offline. Una procedura con fermo completo deve comunque dimostrare quiescenza reale, assenza di transazioni ambigue, custodia e autorità; non può cancellare latch o aggirare un owner incerto. La delega di sviluppo non vale come approvazione HUMAN.

Non sono effettuati merge, deploy, grant, nuove operazioni target o riapertura. Nessun reset di scope/budget o nuova acquisizione Teatri/Farmacie. Gli artifact storici restano nelle retention dichiarate: non è attestata una nuova custodia durevole.
