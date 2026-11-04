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
