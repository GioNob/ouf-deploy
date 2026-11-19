# Onboarding — consegna e revoca delle decisioni Authorization

## Due passi

1. Definito il contratto applicativo distinto per il recupero storage e collegato il registry Authorization esistente alla proiezione durevole dell'owner.
2. Qualificate preparazione/consegna idempotenti, conflitti di versione, revoca esplicita e cambio policy durante I/O, con audit e budget conservati.

Il repository ospita già `AuthorizationPolicyRegistry` e il ciclo di attivazione policy. L'integrazione è interna, per **Authorization e owner nello stesso PostgreSQL**; non è una consegna distribuita via rete e non abilita automaticamente un ingresso produttivo.

## Contratto e persistenza

La capability candidata `installation.storage.recovery` richiede EXECUTE, scope omonimo e attore HUMAN. Il descrittore non è aggiunto al bootstrap né ai descrittori di configurazione d'installazione. Il bundle deve dichiarare esattamente quei requisiti; stesso nome con scope/attori più deboli è negato.

Il server costruisce la risorsa `installation-storage-recovery` usando installazione e tenant fidati, `storageOwner=onboarding`, azione richiesta e dettaglio SECURITY_SENSITIVE. La decisione viene valutata dal registry/SDK esistente, con grant effettivo. Richiesti HUMAN fidato, autenticazione recente entro15minuti e scadenza positiva che non superi quella finestra.

V40 crea decisioni, proiezione singleton versione0 senza autorità e audit di consegna/azioni. Non registra capability o grant. La preparazione lega chiave, installazione, tenant, identità, runtime, epoch, azioni e deadline. Il fingerprint ordina gli insiemi per preservare l'idempotenza anche se cambia l'ordine di serializzazione. Chiave e contenuto uguali restituiscono lo stesso ID e scadenza; contenuto diverso è respinto.

La consegna richiede versione attesa e decisione corrente. Decisione DELIVERED, proiezione avanzata e audit sono atomici. Una risposta persa si riconcilia ripetendo la stessa consegna: torna la versione già pubblicata senza rinnovare nulla. Due decisioni concorrenti con la stessa versione attesa hanno un solo vincitore. La sostituzione revoca definitivamente la precedente; una decisione revocata non può essere riconsegnata. La revoca esplicita richiede a sua volta una decisione HUMAN corrente sull'azione REVOKE, conserva la storia ed è idempotente.

## Policy, revoca e pubblicazione

Ordine dei lock:controllo storage → lock policy741093 condiviso → proiezione → decisione → custodia/intento. L'attivazione policy esistente usa il lock esclusivo741093: non può attraversare una transazione owner che sta consumando l'autorità. La revoca esplicita confligge sui lock di proiezione/decisione.

GET resta fuori transazione. Dopo GET l'owner rivalida policy attiva fissata, decisione, revoca, runtime, epoch, custodia e scadenza. Cambiare policy o revocare durante GET impedisce l'ACK. L'audit owner è atomico con asset/ricevuta/ACK. Restano budget128/24h, transazione12s, lock2s, statement5s e controllo finale scadenza. Una nuova decisione non azzera il budget esaurito.

`StorageRecoveryCustody` rimane distinto: la decisione Authorization da sola permette il drain ma non prova la quiescenza richiesta per riconciliare o congelare. I test usano evidenze sintetiche bloccate; il verificatore produttivo di tutti i writer resta da collegare.

## Qualifica

Fonte qualificata `f909fbfbc3f060f2cb83238cb94c8d7b710f77dc`,[PR Onboarding54](https://github.com/GioNob/ouf-source-onboarding/pull/54).
- [Nativi42006721416](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42006721416)/job127175233217: **57scenari owner+8API/storage PASS**,zero failure/error/skip. Quindici nuovi casi rispetto al precedente c1d0dd22;il registry e i lock PostgreSQL sono quelli reali.
- [Fisico42006721313](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42006721313):producer127175233186 e readback127175977093 SUCCESS. **38membri/37checksum/270sorgenti/1695file backup**,nove negativi semantici respinti dopo ricalcolo dei checksum esterni. Le tabelle V40 sono incluse nella proiezione verificata ma restano vuote/senza grant in questo drill.
- System ID `7704624741742960681`,target `ouf_onboarding_upload_frozen_v39`,medesima immagine PostgreSQL acquisita e OCI33. Due oggetti/36byte,sei AccessDenied,dodici stop storage e due PostgreSQL puliti;restano riuscite le prove di autorità corrente esterna e JVM sopravvissuta al restore.
- **CI sorgente8/8SUCCESS**,incluse [PR42006730177](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42006730177) e [push42006721272](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42006721272),scansione bloccante e avvio container. Suite generale422riportati meno57native saltati=365eseguiti PASS;57native eseguiti nel job dedicato.
- Deploy precedente `18810180ca0e6db6dcf866b5fdc5ca49916abb82`:50/50workflow SUCCESS. I controlli del nuovo checkpoint documentale sono separati.

[Ricevuta completa](../evidence/storage-authorization-delivery-qualified-20261105.json).
- Artifact13404698522 (onboarding-common-cut-readback-42006721313):7145034byte,`sha256:c7ffa0e8c4d9c8263e98219e2ea525e81f3521760d987fe299cc2e9252ba7695`,custodia fino2027-02-03T09:57:56Z.
- Artifact13404369761 (onboarding-common-cut-42006721313):7148737byte,`sha256:854522df389c9d3e372e3953d798e373cd3cd71a75d6e95fd92dbd0d726c894d`,custodia fino2027-02-03T09:57:56Z.
- Artifact13404454808 (onboarding-upload-native-42006721416):99313byte,`sha256:9d888d2a0ccc21d4ce1a60c3d882b4921ee8c9e7f7dbcd01fdb4211ba39a755b`,custodia fino2027-02-03T09:57:56Z.

Qualifica riuscita alla prima esecuzione. Diff,sintassi Python e regressione placeholder WAL PASS locali. Java/PostgreSQL/S3 verificati sui runner Linux;nessun terzo download locale degli ZIP dichiarato. Tutte le prove precedenti preservate.

## Limiti e prossima coppia

Le classi non sono bean/endpoints e non è stato attivato alcun percorso produttivo. La capability è un contratto candidato nel codice, non una registrazione/grant già eseguita. Restano autenticazione Gateway/THS, validazione sessione, custodia completa, audit durevole dei dinieghi e revoca distribuita/acknowledgement remoti.

La regressione fisica comprende le nuove tabelle V40 ma ne richiede lo stato vuoto/senza autorità. Il recupero di una storia V40 popolata non è ancora qualificato. Un vecchio bundle Authorization ripristinato non diventa corrente per il solo fatto di essere valutabile: rimane necessario il fence indipendente da backup/generazione dell'installazione. Il precedente controllo runtime/postmaster e la prova di autorità esterna revocata restano preservati; rollback logico a postmaster invariato resta aperto.

Prossima coppia delimitata:integrare decisioni/consegne/audit V40 popolati nel common-cut;qualificare il ripristino con revoca successiva al taglio e blocco di ogni tentativo di riattestazione su policy/proiezioni obsolete, senza assegnare grant target. Prima riesaminare il confine di autorità corrente indipendente dal backup.

MinIO/source-lock e MiniPET18,3/46=39,78%,0/8gate,0/21AT,0/120oggetti reali invariati. Nessun merge/deploy/target/admission/replay/reset/grant. UDP/Ingestion,rollout misto,riapertura e RPO/RTO rappresentativi restano OPEN.
