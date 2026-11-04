## Checkpoint storage 2026-11-04 — assunzione offset del test corretta, nuova qualifica PENDING

- Run 41878669053 / producer 87fc66ca: 183 test Linux PASS, dodici scenari PASS, inter-rename FAILED, marker-only SKIPPED. Readback 41878956434 fallito per receipt marker-only assente; originale e copia conservati (artifact 13348782049/13348816994).
- Diagnosi dai bytes originali: 1483 membri/1482 checksum verificati anche localmente. Il volume 2 contiene altri needle vivi prima del witness: offset 12583096→8388712, DAT 13631776→9437392, riduzione esatta 4194384. Il vecchio controllo new_offset==8 rifiutava questo layout valido. Body/ID/cookie integri nelle copie trattenute; non si promuove il run fallito a PASS.
- Corretto il controllo per richiedere offset allineato e riduzione esattamente uguale alla differenza delle lunghezze DAT, oltre a tutti i vincoli di fase/inode/hash/controllo del body. Tre regressioni per prefisso vivo, riduzione errata e indice errato. Diagnostica del controller distingue uscita osservatore da timeout; limiti e segnali non allentati. Cleanup failure del primo run preservata.
- 27 test puri inter-rename/marker-only PASS locali, due test Linux skipped; nuova suite attesa 186 test/14 scenari. Receipt negativa: evidence/storage-markeronly33-first-failure-diagnosis-20261104.json. Readback indipendente da aggiornare al nuovo producer/run/job, senza sovrascrivere il primo esito.
- MiniPET invariato 39,78%, 0/8 gate, 0/21 AT, 0/120 oggetti reali. Nessuna modifica a OCI/binario/MinIO/target, merge/deploy/admission/replay/reset/grant.


Il precedente riepilogo queued descriveva metadati ritardati: i log originali mostrano attività iniziata mentre le API continuavano a riportare coda. Non si attribuisce una causa di piattaforma non dimostrata. Il passo successivo resta completare il caso marker-only dopo la correzione del test; nessun nuovo passo di migrazione.

## Storia preservata

# Crash dopo le rinomine e prima della rimozione del marker33 — 2026-11-04

**IMPLEMENTED / NATIVE QUALIFICATION PENDING.**

Ripresa dal checkpoint `1a471e57c6073851918eea1d926cd76aca7180a9`, branch `feat/m2-discovery-complete-profile-20261029`, PR54 draft. Head verificato invariato; nessuna esecuzione in corso rilevata prima delle modifiche. I tredici scenari precedenti e tutte le evidenze restano conservati.

## Fase nuova

Quattordicesimo scenario, stessa OCI33/binario non strumentato. L'osservatore esterno riusa il trasporto ptrace qualificato e conserva tre stati: prima della rinomina DAT, prima della rinomina IDX e prima della cancellazione del marker. Richiede entrambe le syscall di rinomina con uscita 0, poi un fsync della directory con uscita 0, poi ingresso unlink/unlinkat del percorso .cpc esatto, non ripreso. Tutti i thread devono essere fermi, DAT/IDX devono coincidere esattamente con le copie iniziali anche per inode/device/blocchi, .cpd/.cpx devono essere assenti e il marker deve essere quello iniziale.

Quattro SIGKILL, radici conservate e nuovi processi dietro gate prima di exec. Il recupero deve eliminare il solo marker mantenendo identici DAT e IDX già promossi. La coppia viene controllata alla prima readiness prima delle riletture applicative e nuovamente dopo S3/metadati/witness e matrice 11 link/36 dinieghi. Nessun secondo vacuum, PUT di recupero o retry mutativo.

## Verifica e limiti

12 nuovi test puri PASS; il nuovo test Linux esegue realmente entrambe le rinomine e fsync prima di fermare unlink, conserva il marker dopo SIGKILL e verifica i thread creati dopo attach. Su Windows questo test è skipped, obbligatorio nel workflow Linux. Suite complessiva attesa **183 test / 14 scenari**; qualifica nativa e readback indipendente ancora PENDING.

Il readback dovrà verificare tutti i membri e i binding sorgenti, ricostruire le tre fasi dai bytes conservati, decodificare direttamente l'indice promosso e il body e confermare separatamente lo stato terminale del run originale. Nessun rerun nativo per sola verifica delle prove. Archivio originale e copia annidata con retention 90 giorni; nuova custodia durevole dei ZIP in Git non dichiarata.

L'osservazione modifica lo scheduling, non memoria/registri/storage/build. Non qualifica power loss, durabilità hardware, carico concorrente continuo o RPO/RTO. MiniPET invariato 18,3/46 = 39,78% (~40% ±10), 0/8 gate, 0/21 AT, 0/120 oggetti reali; MinIO invariato. Nessun VPS/merge/deploy/admission/replay/reset/grant/operazione target.

### Limite della verifica locale Windows

Il tentativo della suite completa si arresta nel primo modulo di isolamento: compilatore `cc` assente e probe socket con `errno=None` nel sandbox Windows (1 errore e 1 failure su 6 test eseguiti). Non è dichiarato PASS locale completo né vengono allentati i controlli Linux. Log locale conservato; la qualifica richiede tutti i 183 test senza skip sul runner Linux. Parsing YAML del workflow PASS.

## Esecuzione e readback vincolati

Producer `87fc66ca9a2b24fb55e983392f573c0c1f54d96c`, [run 41878669053](https://github.com/GioNob/ouf-deploy/actions/runs/41878669053), job 126745091191, attempt 1. Il readback verifica 40 binding sorgenti, 183 test senza skip, 14 scenari e 70 arresti finali puliti; conferma separata completed/success per il run e il job esatti. Nessuna seconda esecuzione nativa. 46 test puri delle quattro fasi PASS locali, 3 test Linux skipped sul sistema Windows. Il tentativo locale completo fallito è conservato in `evidence/storage-markeronly33-local-suite-attempt-20261104.txt` con percorsi locali oscurati.
