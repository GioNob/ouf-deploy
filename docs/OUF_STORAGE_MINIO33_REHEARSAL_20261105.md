# Rehearsal MinIO → OCI33 e ritorno su storage vuoto

La coppia scelta per la chiusura della sostituzione storage collega il migratore esistente alla sorgente MinIO effettiva come versione software e alla destinazione SeaweedFS OCI33 esatta; qualifica poi interruzioni e ritorno dopo scritture. Non aggiunge un adapter recovery o un endpoint HUMAN. Sorgente e dati sono fixture isolate: nessuna operazione sull'installazione OUF.

Base: deploy `cdb65e1bd973edcb83fe49093c80bbb80d642f35`, 52/52 workflow SUCCESS; Onboarding `d5155899b09dda298494b68cefa7e1f281167652`, 8/8 SUCCESS. Nessuna esecuzione attiva osservata prima della modifica; aggiornamento del branch con expected SHA, PR54 draft/open. Nessun subagente.

## Due passi e criteri della prova

1. **Copia completa MinIO → OCI33.** Inventario S3 autenticato, compilatore privato e core Go originali, senza modifiche; 120 corpi sintetici/203743 byte, dieci senza hash annunciato. Nuova lettura integrale condizionale, verifica di rappresentazione e namespace esatti. Ritorno in un terzo MinIO indipendente e inizialmente vuoto, con confronto dei tre corpi per ciascun oggetto. Gli ETag e Last-Modified sono osservazioni provider, non identità portabili.
2. **Interruzioni e ritorno dopo nuove scritture.** Morte reale del processo nei tre punti BEFORE_PUT/AFTER_PUT/BEFORE_CHECKPOINT; risposta PUT riuscita sostituita da 503 e Retry-After, riconciliazione senza secondo PUT. Su un namespace distinto: sostituzione del corpo, sostituzione dei metadati, cancellazione e aggiunta confermate da OCI33; esportazione dell'insieme corrente in MinIO vuoto e confronto integrale. Oggetto cancellato assente e originali MinIO intatti. Restano incluse conservazione dei tag accettati da MinIO, encoding e negazioni If-Match/versioning. Il tag speciale storico viene provato come diniego sorgente senza mutazione, non riscritto durante la migrazione.

Il clock virtuale accelera solo Retry-After; crash, server, TLS, richieste e corpi sono reali. Non è un'interruzione di rete durata un'ora. La nuova fixture vive in `tests/fixtures/storage-minio33`, assemblata temporaneamente col modulo Go: il core copy-new e i test storici restano identici.

## Binding, isolamento e sicurezza

- MinIO linux/amd64 manifest `sha256:a1a8bd4ac40ad7881a245bab97323e18f971e4d4cba2c2007ec1bedd21cbaba2`, config `sha256:69b2ec208575b69597784255eec6fa6a2985ee9e1a47f4411a51f7f5fdd193a9`, mirror pubblico datalens-tech. **Non autentica il publisher originale**. La scansione storica HELD rimane HELD: questa esecuzione è soltanto una sorgente legacy usa-e-getta, non una nuova ammissione del server.
- SeaweedFS: lock OCI33 SHA256 `c2b30130b078a86ca440351980c3e745d4132e256591ec05fe98a9bdfc9058f8`, immagine config `sha256:3b972a3ca20f98b73554f0772a2df4f1a5ef4441298299a443f0e605f10ec9b6`. Archivio originale e coorte verificati con i verificatori esistenti; attestazione publisher della coorte vincolata al commit e workflow esatti.
- Tre container senza porte pubblicate, rootfs readonly, capabilities rimosse, no-new-privileges e limiti CPU/RAM/PID. Sorgente con network none, altre istanze nello stesso namespace: solo loopback, nessuna route esterna. Nessun socket Docker montato, nessun endpoint/credenziale/dato OUF, nessun mc. TLS con CA esplicita e SAN loopback; credenziali sintetiche.
- I client entrano nel namespace via nsenter e tornano all'UID del runner prima di aprire inventario/journal. Non si disabilitano protezione degli antenati, permessi o ownership. Gli oggetti iniziali restano quiescenti durante la copia; questa disciplina della fixture non dimostra il fence di tutti i writer OUF.
- Scansioni Trivy dei due moduli e degli eseguibili, tutte le severità/unfixed, senza ignore; HIGH/CRITICAL/UNKNOWN bloccanti per gli strumenti. Il raw HELD MinIO non viene trasformato in PASS. Chiavi private e dati delle directory persistenti non entrano nell'archivio pubblico.

## Qualifica

Candidato finale `4555f7dc2be2e44aa25277a22a35d7e2597c80ea`, [run42068964202](https://github.com/GioNob/ouf-deploy/actions/runs/42068964202)/job127391244238: **SUCCESS,12esiti nativi PASS inclusi subtest**. Archivio13435386238,369047byte,SHA256 `6d7b2953ad6e432b9a73c013593cfa679d488e2bd888092f767c308a6a6a596b`; readback locale27membri/26checksum/137sorgenti Git esatti,360corpi riletti condizionalmente sui tre provider, tre stop conexit0. Scan moduli/eseguibili: zero rilievi a tutte le severità. Copia iniziale con inventario/compilazione3,206591048s; inversa2,273352373s, fixture non rappresentativa del VPS. Scadenza artifact2027-02-03T16:52:41Z. Il readback non è una seconda esecuzione nativa.

Esito e riferimenti esatti sono nella ricevuta `evidence/storage-minio33-rehearsal-qualified-20261105.json`. Il primo candidato `adf87ccfe9aed0efecf5a037c6ae599f3e524c0c`, run42066811016/job127383049320, è fallito all'avvio dell'inventario: l'UID root ereditato da nsenter era incompatibile con l'ancestry posseduta dal runner. Readiness S3 riuscita; nessuna copia dichiarata. Correzione della fixture, controlli invariati. L'archivio fallito13434252761,29094byte,SHA256 `dbb906b455a07289417fa9ad165b184825514e8dce9dd2c272b2676d53ef9763` è conservato.

Il secondo candidato `44d359d94f54850067bf5506dba026edaa311339`, run42067463342/job127385476745, è fallito prima dei test perché `go tool test2json` cercava la cache sotto `/root` dopo il cambio UID. Il reporter viene ora compilato e scansionato prima di entrare nel namespace, senza cambiare HOME o permessi delle directory. Archivio13433424731,26672byte,SHA256 `8a6e2f6d989041f12087e9188526f1ec07cf90664f545e2b6f0e06b045fb2207`. Nessun PASS nativo attribuito a quel tentativo.

Il terzo candidato `fd90c93f5e34be681b5f4e3c8902e91dbbd9c119`, run42068130474/job127387978776, ha superato copia120, ritorno, quattro nuove mutazioni, tre crash e 503; è fallito perché MinIO risponde `InvalidTag` al tag speciale `fixture+clé` della fixture storica SeaweedFS. Il nuovo test conserva questo diniego e verifica che non alteri l’originale; usa poi un tag accettato dalla sorgente per la parità positiva, senza normalizzare o cambiare tag durante la copia. Il vecchio test SeaweedFS è invariato. Archivio13434639031,367135byte,SHA256 `392fe2e7fb46fdfcfb4eb78906552ac38ee42ee2e1c1b75ebad22105a067ef08`. Il rilancio completo qualifica il nuovo eseguibile integrato dopo questa modifica, non rinnova scope operativi consumati.

## Cosa chiude e cosa resta necessario

Questa prova elimina la lacuna di qualificazione del **percorso di copia fra i provider esatti**, distinta dalla vecchia prova SeaweedFS→SeaweedFS. Il ritorno copre lo stato degli oggetti dopo modifiche e cancellazioni; non ricostruisce i riferimenti PostgreSQL né dimostra il ritorno applicativo governato.

G4 resta aperto per riconciliazione DB/oggetti e procedura completa sul profilo rappresentativo. La copia con fermo completo è il percorso da valutare per primo; non richiede un motore replace/delete sulla destinazione vuota, ma richiede quiescenza reale, finestra accettata e inventario corrente. La precopia online con delta mutativo resta alternativa non qualificata, non prerequisito imposto senza necessità.

Prima del passaggio servono ancora: raccolta unica G0 dei corpi/ACL/writer/DB/capacità e binding correnti; dossier G1 di lifecycle/licenze/custodia; matrice finale G2 e recovery/capacità rappresentativi G3; pacchetto G5 ammesso, switch G6 e osservazione G7. La prossima coppia deve produrre il pacchetto concreto della raccolta G0 e la tracciabilità delle prove già disponibili alla coorte finale, evidenziando le sole azioni operatore realmente indispensabili. Non ripetere restore/rotazioni/crash già riusciti a sorgenti invariati.

MiniPET **18,3/46 = 39,78%; 0/8 gate, 0/21 AT, 0/120 oggetti reali**. Nessun credito target per la fixture. Nessun merge, deploy, grant, riapertura, reset di scope/budget o modifica al source-lock. HTTP/HUMAN del resolver resta una dipendenza condizionale della procedura scelta.
