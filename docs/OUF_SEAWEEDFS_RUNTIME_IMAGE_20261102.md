# SeaweedFS — confezionamento della generazione runtime esatta

2 novembre 2026, Europe/Rome. Continuazione di SW-WP1/G1 sul checkpoint `f74d862142680503f90a5dfed44b4f9b2b40b11f`. Codice in `tools/storage_security/runtime_image.py`, workflow `storage-runtime-image.yml`.

## Risultato previsto e confine

Il packager produce un layout OCI e un archivio Docker deterministici dagli stessi byte del server SHA256 `bb9f768e5afca39c7fdc2113e5caafd9f911d4537917dd25c520ee4dbdab1f74`. Non ricompila il server e non estende la decisione OUF-SW-G1-20261102-01 a un altro binario. Rootfs scratch, utente10001:10001, binario0555, licenza upstream0444, nessuna shell, ENV, porta o destinazione ambientale incorporata. Trust, credenziali, rete, volumi e argomenti di ruolo richiedono ancora il profilo d'installazione validato. La directory /data richiede un volume con custody esplicita prima di un servizio reale.

La pipeline rilegge l'archivio originale esatto278756504byte, verifica4390Gitblob/mode e la provenienza del workflow OUF/source/ref/runner hosted prima del confezionamento. Non autentica una firma del publisher upstream. La scansione nuova dell'immagine include severità ignote e vulnerabilità senza correzione, con ignore vuoto. Soltanto lo stesso UNKNOWN GO-2026-5932 sul binario esatto può ricevere la disposizione già accettata; nuovi rilievi o advisory cambiato fermano la qualifica. I rapporti raw restano invariati.

SPDX2.3 è derivato dal medesimo report della scansione. Sono verificati digest dell'immagine e presenza di ogni coppia nome/versione inventariata. Le licenze dichiarate/concluse vengono riportate senza inventare assenza o accettazione per NOASSERTION. La licenza Apache2.0 upstream inclusa non sostituisce l'inventario e gli obblighi delle dipendenze. Nessuna accettazione legale è dichiarata dal packager.

L'avvio `version` sul runner usa utente non privilegiato, rootfs read-only, rete none, capability rimosse, no-new-privileges e limiti risorse. Prova caricamento/eseguibilità, non topologia, servizi S3/filer/volume/master o backup/recovery OUF. L'artefatto CI conserva layout, archivio, SBOM, scan, ricevute, hash e firma90giorni; non equivale ancora a custodia durevole della release.

## Verifiche e stato

12 test locali PASS: riproducibilità OCI/Docker, stesso config/layer, binario alterato, blob alterato, descriptor traversal, symlink, archivio alterato, falsa ammissione, output esistente non reinizializzato, immagine scansionata diversa, scan vuoto/target extra, dipendenza mancante da SPDX e licenze ancora aperte. Alcuni casi sono raggruppati nello stesso test. La suite separata di9test sull'applicabilità rimane la prova di quella policy; le nuove fixture di confine non la sostituiscono.

Qualifica reale CI: **PASS**,12test e tutti gli step di qualifica conclusi, sorgente `d4cfa1f08bb25dace29ed94946d4a7c97a729af0`, [run41527393253](https://github.com/GioNob/ouf-deploy/actions/runs/41527393253). Job125558545575. Scansione245pacchetti; SPDX247voci con247licenzeNOASSERTION. Byte originali186961604/SHA256459ef6d3b746cfd7387d10517949dcd30d507c33df9d4fedafe612cb31c5c98a riletti anche localmente:23checksum,5sorgenti,layoutOCI e archivioDocker ricostruiti identici,assessment riprodotto. Verifica indipendente [CI41527990598](https://github.com/GioNob/ouf-deploy/actions/runs/41527990598) **PASS**: firma esatta workflow/source/ref/runner hosted autenticata, assessment riprodotto senza eseguire binari, nessuna operazione target. [Archivio metadata conservato](../evidence/artifacts/storage-runtime-image-readback-41527990598.zip),103274byte/SHA256b93bfefbc1d3a1e19f2a1cdd9c4fbea992f2f72510199bcbaa28b96e59583d2f. Riletto anche localmente:27checksum metadata. Layer e archivio Docker sono verificati integralmente nell'originale ma esplicitamente esclusi dall'archivio metadata; non è custodia durevole degli eseguibili.

G1 complessivo rimane OPEN: review/completamento delle licenze, custodia durevole e coorte completa ancora aperti anche dopo un eventuale PASS dell'immagine. Tutti8gate e21AT rimangono OPEN. MinIO è ancora installato;120oggetti reali sono PLANNED_NOT_COPIED e nessun corpo reale è stato copiato o verificato.

## Avanzamento richiesto dall'owner

Il MiniPET storage non riportava un contatore percentuale accettato. La stima tecnica introdotta qui è circa30%, con incertezza di circa10punti; non misura collaudo, tempo consuntivato o dati migrati. Pesi: minimi delle stime originali del MiniPET (46ore complessive). Crediti stimati: G0=50%,G1=65%,G2=60%,G3=15%,G4=35%,G5–G7=0%. Somma pesata14,7/46≈32%, arrotondata prudenzialmente a circa30%. Sono giudizi di pianificazione, non nuove evidenze di chiusura. Le prove CI e le osservazioni target rimangono contatori distinti: gate0/8,AT0/21,oggetti reali copiati0/120.

Teatri/M1 resta tecnico8/8 e funzionale6/6; stessi26join/13identità/20proprietà/8Cinema. Stessa Farmacie61righe/10campiOPEN/codice ministerialeSTRING preservata. M2/G5–G7,61esitiUDP,dueclient,ripetibilità/fault e successivi search/verticali/API/scheduler/delta restano aperti. Nessun upload,profiling,grant,reset,replay,merge o effetto VPS;controllo17consumato e52EngineGET invariati.

## Autorità consultata

MiniPET storagev1.1 §4–5/8–11 e decisione esatta OUF-SW-G1-20261102-01. Testo PET UDPv1.3 dal repository al checkpointf74d: §46 supply chain, §81 recovery e §109.4–109.5 BOM/SBOM/configurazione/rete. Policy resilienzav3 consultata integralmente. Gli originali allegati baseline di questa conversazione non sono disponibili: non si attesta conformità completa agli allegati originali. Questa qualifica offline/CI non introduce retry runtime o nuova autorità.
