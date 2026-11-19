# Onboarding — autorità e quiescenza nel recupero storage

## Due passi e limite operativo

1. Introdotto un ingresso interno obbligatorio per autorità corrente, azione, generazione e prova di quiescenza. Il costruttore senza adattatore ora rifiuta le operazioni.
2. Qualificati revoca durante I/O, concorrenza, scadenza, sostituzione della decisione, perdita della quiescenza, atomicità dell'audit e mancata riapertura, insieme al recupero fisico PostgreSQL/S3.

Il passo 1 consegna il confine di integrazione e il suo adattatore sintetico: **non un binding produttivo già installato**. Il riesame di Matrix v1.7, PET traceability e API recovery esistenti non attribuisce ai permessi HUMAN sui singoli file alcuna autorità sul controllo storage globale. Authorization resta owner delle decisioni; THS delle operazioni HUMAN protette; il backend applica il controllo. Backup/restore produttivo rimane delegato alla piattaforma.

## Implementazione

`StorageRecoveryGate` è una porta interna, senza bean, endpoint o migrazione di grant. Il futuro adattatore fidato deve leggere evidenze durevoli correnti nella stessa transazione PostgreSQL dell'owner e mantenerne i lock fino al commit. Revoca e modifiche di custodia devono confliggere con questi lock. Ordine: controllo storage, gate, intento. Nessun I/O di rete nell'adattatore sotto lock.

L'owner verifica lo scope globale fisso `onboarding:managed-file-storage`, azione, epoch, decisione non revocata, riferimenti e finestra positiva di autorità di massimo 24 ore, usando l'orologio PostgreSQL. Il drain può precedere la quiescenza; reconcile/freeze richiedono la relativa prova corrente. Il record restituito dall'adattatore non è un documento client né una firma verificata.

Prima del GET, una transazione riserva la lettura dal budget esistente 128/24h e salva READ_RESERVED. Dopo il GET, senza transazione aperta, l'owner rivalida l'autorità e richiede che l'intera evidenza coincida con quella della prenotazione. Una decisione nuova non può adottare un GET già avviato. ACK, asset, ricevuta e audit si salvano atomicamente; un errore audit annulla la pubblicazione, conservando la lettura già consumata.

Transazioni massime 12 secondi, attesa lock 2 secondi, statement SQL 5 secondi. Ulteriore controllo della scadenza dopo scritture/audit, prima del completamento: anche un ritardo nell'audit deve annullare l'ACK. Nessun reset del budget, nuovo PUT o comando di riapertura.

## Fixture e ripristino

`StorageRecoveryLabGate` esiste soltanto nei test. Tabelle sintetiche PostgreSQL, lock condivisi e audit nella stessa transazione sono esercitati realmente; non vengono installati da Flyway. Nella prova fisica il gate nasce senza quiescenza. Solo dopo stop dei quattro ruoli storage, restrizione Read/List della stessa identità e tre PUT AccessDenied viene registrata la quiescenza della fixture.

Il backup fisico ora include anche le due tabelle sintetiche di gate/audit. Dopo PITR al target nominato, controllo FROZEN, intenti, asset, ricevute e stato/audit sintetico coincidono byte per byte nelle proiezioni JSON. Il verificatore indipendente controlla anche la sequenza DRAINED → READ_RESERVED → ACKED → FROZEN e il relativo binding. Questo non qualifica la validità di grant produttivi dopo restore.

## Provenienza e verifiche

Fonte finale `5d9ba774b0d8b38c2acab36e1736803a1158059d`.
- [Run nativo41998933870](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41998933870)/job127148985529: **35 scenari owner + 8 test API/storage PASS**, zero failure/error/skip.
- [Run fisico41998934118](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41998934118): producer127148987556 e readback127149874682 SUCCESS. **32 membri, 31 checksum, 265 sorgenti, 1680 file backup** verificati; cinque negativi semantici respinti dopo ricalcolo dei checksum esterni.
- Due oggetti/36 byte, sei AccessDenied, dodici stop storage e due PostgreSQL puliti. System ID `7704610164890021928`, stesso target nominato e stessa immagine PostgreSQL acquisita della prova precedente; nessuna nuova scansione trasferita per analogia.
- **CI sorgente 8/8 SUCCESS**; [PR41998940250](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41998940250) e [push41998933767](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41998933767), inclusi scansione bloccante e avvio container. Suite generale400 riportati/35native saltati =365 eseguiti PASS; i35native sono eseguiti nel job dedicato.
- Deploy antecedente `fd5e774c48b00c410ba203bf407b9373640a3bb2`:50/50workflow SUCCESS. I controlli automatici del nuovo checkpoint documentale sono separati.

[Ricevuta completa](../evidence/onboarding-authority-gate-qualified-20261105.json).
- Artifact13401423124 (onboarding-common-cut-41998934118): 7098554 byte, `sha256:152d18c24f17805150f9f28c5da64e04174791c9691cb571da808e3da5135ac9`, custodia fino 2027-02-03T09:01:07Z.
- Artifact13401099296 (onboarding-common-cut-readback-41998934118): 7097031 byte, `sha256:563a849b6745ccd69669895088986e4a4237be50b4188740cec3959edd8ddbbf`, custodia fino 2027-02-03T09:01:07Z.
- Artifact13401552858 (onboarding-upload-native-41998933870): 80388 byte, `sha256:fb9dee43f9193a0c850abf73119452847e6ce7ebd894105ae7709e8f5a105661`, custodia fino 2027-02-03T09:01:07Z.

Il primo incremento `050a5a2aabba603234231275401bee7239126216` è conservato: [nativi41998540449](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41998540449), 33 scenari + 8 test API/storage PASS; [recupero41998540342](https://github.com/GioNob/ouf-source-onboarding/actions/runs/41998540342) e readback PASS, 265 sorgenti/1680 file backup. La revisione successiva aggiunge limiti transazionali e scadenza a fine audit, con due test dedicati. Non sostituisce né cancella la prova precedente.

Verifica locale: diff senza errori e sintassi Python PASS; test placeholder WAL PASS usando una directory temporanea del checkout. Il primo tentativo locale aveva fallito esclusivamente nella pulizia della directory temporanea Windows non scrivibile; non è stato dichiarato PASS. Java/PostgreSQL/S3 sono qualificati dai runner Linux. Nessun terzo download locale degli ZIP è dichiarato.

## Limiti e prossima coppia

Restano da definire/collegare il resource contract di piattaforma, identità di installazione, emissione e revoca delle decisioni tramite Authorization/THS/Gateway, prova corrente su tutti i writer, audit dei dinieghi e riqualifica dell'autorità dopo restart/restore. Restano aperti UDP/Ingestion, rollout misto, riapertura governata e RPO/RTO rappresentativi.

Prossimi due passi: definire il binding di piattaforma e la separazione fra backup e autorità corrente; poi qualificare che restart/restore non rendano riutilizzabili decisioni revocate o prove di quiescenza obsolete. Nessuna assegnazione di nuovi grant deriva dalla delega di sviluppo.

MinIO e source-lock invariati; MiniPET 18,3/46 = 39,78%, 0/8 gate, 0/21 AT, 0/120 oggetti reali. Nessun merge, deploy, operazione target, admission, replay/reset o grant.
