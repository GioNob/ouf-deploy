# Advisory GO-2026-5932: diniego storico e candidate correnti separate

Il run [41709442513](https://github.com/GioNob/ouf-deploy/actions/runs/41709442513), commit `63ae5b2a71873aad0586c9bb3b5819f054fa7c09`, rimane **FAIL** con `ADVISORY_CHANGED_REASSESSMENT_REQUIRED`. I nove test del classificatore passano; fallisce correttamente la rivalidazione contro l'advisory fresco. L'artefatto 13266117382 è conservato esatto: 1.059 byte, SHA256 `f22a4705c8213e6f206e190d5631c93d32c1997d009d1942c30febe2fe5cc096`. Non contiene una nuova assessment accettata.

La [fonte ufficiale](https://vuln.go.dev/ID/GO-2026-5932.json), riletta via HTTPS, è byte-identica a quella conservata dalla CI. Il nuovo hash canonico è `5e41013a01fdf0f434ce126d4e1a3a8d7b209accc112a00d8905ca0329605acb`, contro lo storico `26df709c385ffdb7845f0c94907d420136cbcd88c4e2a188032fe425a3ecb5a5`. Non è solo una variazione della data: l'aggiornamento del 2 novembre aggiunge il limite di correzione `golang.org/x/crypto@v0.58.1-0.20261009181718-2f1f834330b2`, una voce separata per il modulo `golang.org/x/crypto/openpgp` senza correzione e il riferimento all'issue 81227. I sette package vulnerabili restano gli stessi.

La decisione `OUF-SW-G1-20261102-01` appartiene esclusivamente al vecchio binario SeaweedFS 4.51 `bb9f768e…` e al suo advisory congelato. Decisione, VEX, snapshot e classificatore non vengono modificati. Il replay locale dello snapshot originale mantiene il precedente risultato; con l'advisory fresco il medesimo classificatore nega ancora l'uso della decisione. Il nuovo stato di freschezza è **STALE_NOT_ADMITTED**, non un nuovo consenso.

| Perimetro riletto | Prova | Risultato circoscritto |
|---|---|---|
| Generazione 29, binario `a0c74718…` | Build-info e grafo di 1.811 package della qualifica hosted | Pin crypto uguale alla versione corretta; modulo standalone assente; zero dei sette package importati |
| Sorgente/binario 30, `5b7e3dcf…` | Build-info e grafo locale di 1.740 package | Stesso pin corretto e stesse assenze |

Queste osservazioni tecniche non estendono la decisione HUMAN storica e non sostituiscono le scansioni fresche proprie delle nuove immagini. La generazione 31 non è stata valutata separatamente da questa ricevuta. Non occorre chiedere una nuova decisione per il vecchio hash per continuare lo sviluppo della candidata corrente; rivalutare l'eccezione storica sarebbe necessario solo se si volesse riutilizzare quella specifica disposizione.

Il workflow storico aveva un trigger troppo ampio, `tools/storage_security/**`, che include anche nuovi qualificatori indipendenti. La modifica proposta sostituisce quel glob con **48 percorsi esatti**, comprendenti classificatore, test, workflow, decisione/VEX/advisory/proposta, archivio, reader/verificatore e chiusura dei sorgenti storici: otto record del readback e 28 sorgenti della capsula. Tutti i precedenti trigger specifici restano inclusi. Permessi, job, comandi e comportamento del classificatore rimangono byte-identici; quando cambia un input storico il controllo continua a essere eseguito e a negare l'advisory mutato. Il fallimento già osservato non viene cancellato o convertito in successo. Nessun nuovo monitor è introdotto in questa patch.

Ricevuta: [audit con hash e limiti](../evidence/seaweedfs-historical-advisory-drift-20261103.json). Progresso invariato; nessuna ammissione release, nuova autorità, operazione target o modifica al piano corrente.
