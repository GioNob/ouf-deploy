# Crash fra rinomina DAT e IDX33 — risultato qualificato, 2026-11-04

**PASS — esecuzione nativa e readback indipendente conclusi con successo.**

## Checkpoint storage 2026-11-04 — crash fra rinomine DAT/IDX33 PASS

- Producer `5ac67de14e4aaf17808b12f95040ed297aef37dc`, [run 41870302570](https://github.com/GioNob/ouf-deploy/actions/runs/41870302570), job 126715227789: **170 test / 13 scenari PASS**, attempt 1 completed/success. Verifier `15d6ac5b13c25866e61b8969c005dfe4355eb9e8`, [readback 41871254673](https://github.com/GioNob/ouf-deploy/actions/runs/41871254673), job 126718618427: completed/success; nessuna seconda esecuzione nativa.
- Volume 7, PID 31536/start 83283, TID 31808, nove thread in stato t. Dopo fsync marker/directory con ritorno 0, osservata uscita 0 della vera rinomina DAT; ingresso renameat 264 di .cpx→.idx fermato. DAT nuovo (inode 9961978), IDX vecchio (9961863), .cpd assente, .cpc/.cpx invariati. Vecchio offset 4194392 oltre DAT 1048688 byte; indice pendente valido a 8.
- Quattro SIGKILL, exit 137/non-OOM; radici conservate e nuovi servizi dietro gate. DAT invariato e IDX pendente promosso, coppia coerente già alla prima readiness prima delle riletture della fixture. Witness 1048593 byte/identità/hash/GET integri, baseline S3 e metadati integri al tentativo 1; 4194384 byte DAT e 4194304 byte allocati recuperati. Nessun vacuum aggiuntivo, PUT di recupero o retry mutativo; 11 link/36 dinieghi verificati.
- Readback: 1559 membri / 1558 checksum / 38 binding sorgenti; decodifica indipendente dei bytes IDX/cpx/DAT conservati. 65 stati finali puliti, 124 container distinti/59 morti intenzionali riportati, 13 reti rimosse. Receipt: `evidence/storage-interrename33-hosted-readback-20261104.json`; dossier: `docs/OUF_STORAGE_INTERRENAME_CRASH33_20261104.md`.
- Originale artifact 13345276270, 5727470 byte, SHA256 `a47304daa0ade0357972e714205fc70b01f02486773265011d70ae68b3cda73c`; copia originale annidata nel readback artifact 13345266273. Retention fino al 2027-02-02; receipt durevole in Git, nuova custodia durevole dei ZIP non dichiarata. Tutte le prove precedenti preservate.
- Prossimo singolo passo: Crash dopo entrambe le rinomine DAT/IDX e prima della rimozione del marker .cpc: verificare la finalizzazione idempotente dello stato con solo marker, senza nuovo vacuum. Questo caso resta OPEN, insieme a power loss, durabilità hardware, carico concorrente continuo e RPO/RTO.
- MiniPET invariato: **18,3/46 = 39,78% (~40% ±10)**; 0/8 gate, 0/21 AT, 0/120 oggetti reali. MinIO invariato; nessun VPS/merge/deploy/admission/replay/reset/grant/operazione target. I checkpoint PENDING e i “prossimi passi” sottostanti sono storia delle osservazioni precedenti.


## Fase osservata e recupero

L'osservatore esterno conserva i bytes prima della prima rinomina e poi lascia eseguire la vera syscall DAT fino all'uscita riuscita. Ferma la syscall IDX all'ingresso e tutti i nove thread prima del crash. Non scrive memoria, registri o storage del candidato; modifica lo scheduling. La build SeaweedFS 4.52 resta quella già qualificata, binary SHA256 `c301b4f487f17f4d9b8dfe1b26885ec4ea6141e1ace73b8dfaadff70bd714dfc`, OCI `sha256:5bfda2ef577b3c33216b82fb3eb1bed3ad76842ed13fc0a114ef94084b20da4d`; tutte le 33 patch e i cinque sorgenti upstream pertinenti sono verificati.

| File | Prima della rinomina DAT | Al crash fra rinomine |
| --- | --- | --- |
| DAT | 5243072 byte, inode 9961856 | 1048688 byte, inode 9961978, identico al precedente .cpd |
| IDX | 48 byte, inode 9961863 | Identico al vecchio IDX |
| .cpd | 1048688 byte, inode 9961978 | Assente |
| .cpx | 16 byte, inode 9961979 | Identico, indice nuovo pendente |
| .cpc | 0 byte, inode 9961980 | Identico, marker presente |

Il witness `7,0100000000002133aabbcc` ha body 1048593 byte, SHA256 `88750de893a15f19daabf07592666678d399ed4c10feba3bf1d93c2a1d10cd6c`. L'indice vecchio punta a 4194392, oltre la fine del DAT nuovo (1048688); il nuovo indice pendente punta a 8 e lega ID/cookie/dimensione/body esatti. Il readback decodifica autonomamente i bytes conservati: non si limita al booleano della receipt nativa.

Dopo quattro SIGKILL e la sostituzione dei processi dietro nuovi gate, il DAT già promosso resta identico e il solo IDX pendente viene promosso con la propria identità. Marker e temporanei sono rimossi. La coppia è verificata appena tutti i servizi sono pronti, **prima delle riletture applicative della fixture**, e ancora dopo il recupero completo. S3, metadati, witness e volumi non selezionati superano i controlli; topologia e dati recuperano al primo tentativo. Sono preservate le regressioni precommit e post-marker nei tredici scenari.

## Provenienza e conservazione

Receipt completa: [storage-interrename33-hosted-readback-20261104.json](../evidence/storage-interrename33-hosted-readback-20261104.json). Contiene risultati integrali, fasi/inventari, identità dei processi, sorgenti, manifest dei job, metadati degli artifact e conferma terminale separata.

| Artifact | Byte ZIP | SHA256 | Scadenza dichiarata |
| --- | ---: | --- | --- |
| [Originale 13345276270](https://github.com/GioNob/ouf-deploy/actions/runs/41870302570/artifacts/13345276270) | 5727470 | `a47304daa0ade0357972e714205fc70b01f02486773265011d70ae68b3cda73c` | 2027-02-02T16:43:36Z |
| [Readback 13345266273](https://github.com/GioNob/ouf-deploy/actions/runs/41871254673/artifacts/13345266273) | 5347132 | `54ef36099521563bc87ba75ebb200948eb7ab9112cd501c7962a2b0c555b223b` | 2027-02-02T16:48:53Z |

Il secondo ZIP contiene una copia inalterata del primo: il digest esterno è diverso perché comprende anche readback e osservazioni. Il digest del secondo ZIP è riportato dall'API GitHub; il readback indipendente verifica il contenuto dell'originale. Entrambi i run e i rispettivi job sono completed/success, attempt 1. La ricezione dell'artifact e la conferma terminale sono controlli separati, senza rilanciare il laboratorio. Nessuna nuova verifica locale dell'archivio o custodia durevole dei ZIP in Git viene dichiarata.

## Punto di ripresa

Crash dopo entrambe le rinomine DAT/IDX e prima della rimozione del marker .cpc: verificare la finalizzazione idempotente dello stato con solo marker, senza nuovo vacuum. Solo questa ulteriore finestra del commit sarà il prossimo caso; backup coordinato, restore su ambiente vuoto e obiettivi RPO/RTO restano lavoro successivo del MiniPET. Le tre fasi già qualificate sono precommit, post-marker/prima del DAT, e fra DAT/IDX. Questa prova di perdita processi non qualifica power loss o durabilità hardware.

## Storia dell'implementazione e delle osservazioni iniziali

Il testo sottostante è preservato integralmente come storia; i suoi stati PENDING sono superati dal risultato qualificato sopra.

---

# Crash fra rinomina DAT e IDX33 — 2026-11-04

**IMPLEMENTED / NATIVE QUALIFICATION PENDING.** Ripresa dal checkpointaa19c468
sul branch feat/m2-discovery-complete-profile-20261029, PR54 draft. Head invariato
prima della modifica; precedente verifica artifact41867565360 completed/success,
anche se l'elenco aggregato Actions la mostrava ancora in corso. Nessun nuovo
laboratorio precedente da duplicare. Tutte le prove gia acquisite conservate.

## Singolo scenario aggiunto

Tredicesimo caso sulla stessa OCI33/binario invariati. Riutilizza il trasporto
ptrace gia qualificato, in un osservatore separato: prima ferma l'ingresso della
rinomina DAT, verifica marker/fsync/copie/coppia precedente e conserva i bytes delle
copie e del vecchio IDX. Riprende l'esecuzione nativa dei thread preservando i segnali
reali; osserva l'uscita0 della prima rinomina e ferma l'ingresso della seconda
rinomina `.cpx→.idx`. Nessuna syscall, memoria, registro o file del server modificato.

La seconda fase richiede tutti i thread in ptrace-stop, `.cpd` assente, `.cpc/.cpx`
immutati, DAT identico alla copia iniziale anche per inode/device/blocchi, IDX ancora
vecchio. Il vecchio offset witness deve cadere oltre la lunghezza del nuovo DAT;
l'indice pendente deve invece puntare al body/ID/cookie esatti all'offset8. La coppia
mista e intenzionalmente conservata e confrontata come bytes grezzi, senza decodificare
il vecchio indice come se fosse coerente e senza riparazioni manuali.

Quattro SIGKILL e nuove generazioni dei servizi, directory conservate, namespace
nuovi e gate/firewall prima di exec. Richiesti DAT gia nuovo invariato, promozione
esatta del solo indice pendente, rimozione marker/temporanei, coppia coerente alla
prima verifica di readiness prima delle riletture applicative della fixture.
Poi baseline S3/metadati/witness, allocazione e volumi non selezionati; ripetizione
11link/36dinieghi e stabilita finale. Nessun secondo vacuum, PUT di recupero o retry
mutativo. I dodici scenari qualificati restano nella suite.

## Verifica iniziale e limiti

12 nuovi test puri PASS locali;22 test puri precommit/post-marker gia esistenti
PASS. I due test ptrace Linux (precedente e nuovo) sono skipped su Windows e richiesti
in CI prima del candidato. Parsing Python/YAML PASS. Suite attesa170test/13scenari;
nessun nuovo PASS nativo dichiarato prima di esecuzione e readback.

L'osservazione altera lo scheduling, non la build candidata. Non qualifica carico
concorrente continuo, power loss, durabilita hardware, RPO/RTO o migrazione target.
MiniPET invariato18,3/46=39,78% (~40% ±10),0/8gate/0/21AT/0/120oggetti reali.
Nessun VPS/merge/deploy/replay/reset/grant/admission; MinIO invariato.

## Producer e verifica indipendente

Producer`5ac67de14e4aaf17808b12f95040ed297aef37dc`,
[run41870302570](https://github.com/GioNob/ouf-deploy/actions/runs/41870302570),
job126715227789. Test Linux di entrambe le fasi ptrace PASS prima del laboratorio;
risultato completo nativo ancora PENDING a questa osservazione.

Il readback separato e vincolato a run/attempt1/producer esatti: acquisisce
l'archivio originale appena pubblicato, controlla digest API e tutti i membri,
38sorgenti contro checkout esatto,170test/13scenari/65arresti puliti. Decodifica
direttamente IDX/cpx/DAT conservati per provare vecchio offset invalido, nuovo body
integro e promozione esatta. Conserva anche le osservazioni dello stato remoto.
La conferma completed/success di run e job e un controllo separato obbligatorio,
con budget finito: nessun rilancio del laboratorio per ritardi del riepilogo Actions.
Originale e readback vengono conservati90giorni; custodia durevole dei nuovi ZIP
non dichiarata. Readback e conferma terminale devono entrambi passare.
