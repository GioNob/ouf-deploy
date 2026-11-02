# SeaweedFS — inventario target acquisito e preparazione del piano privato

2 novembre 2026. Il controllo 16 ha completato l'inventario S3. È una raccolta di metadati non ammessa al cutover: tutti gli 8 gate e i 21 AT del MiniPET restano OPEN.

| Evidenza | Risultato | Implicazione |
|---|---:|---|
| Bucket / record oggetto | 2 / 120 | Insieme rilevato senza errore del reader; non è uno snapshot atomico |
| Byte logici delle versioni | 203743 | Circa 204 kB; non comprende allocazione SeaweedFS, filer, DB, backup o margini |
| Hash OUF dichiarati / assenti | 110 / 10 | Tutti i 120 corpi richiedono comunque SHA-256 alla lettura e alla rilettura destinazione |
| Versioni non-null / marker / multipart incompleti | 0 / 0 / 0 | Non rilevati nella raccolta; nessuna esclusione automatica delle prove future |
| Namespace | PASS | Nessuna collisione file-directory, chiave non sicura o slash finale rilevata |
| Risposte bucket non supportate | 2 | Nomi e valori non sono nel riepilogo: non equivale a funzione assente |
| Richieste della raccolta S3 | 265 GET/HEAD | Nessun corpo oggetto letto né scrittura S3 |
| Controlli / GET Docker cumulativi | 16 / 52 | Scope16 consumato; tutti i quattro vecchi comandi non vanno ripetuti |

La password è stata risolta da un file dichiarato regolare 0600, con singolo collegamento e dimensione ammessa, appartenente a un utente diverso da root. Il file letto era di 65 byte; il valore non è stato pubblicato o spooled. L'utente S3 proviene dall'ambiente esplicito. La fonte non è ammessa per la custodia operativa. NON_ROOT_OWNER è una violazione sufficiente del vecchio guard allo stato ora osservato; non possediamo i metadati del file al controllo 15 per una prova retrospettiva. Le 9 righe dei candidati corrispondono a 7 path distinti: non è una discrepanza del contatore.

RAM disponibile 11830857728 byte e spazio libero 293381369856 su 539792977920 byte appartengono al controllo 14. Le altre 12 configurazioni non sono state rinfrescate. Questi valori non ammettono capacità corrente, throughput, assenza di writer esterni o indipendenza del futuro storage.

## Differenze da risolvere nel piano di copia

I 10 oggetti senza hash dichiarato non sono classificati come persi o corrotti. I metadati originali vanno preservati; il nuovo hash calcolato dai corpi appartiene al manifest di migrazione, senza inventare hash storici o nuove revisioni semantiche. Anche i 110 hash dichiarati vanno confrontati con i byte effettivi.

Le due risposte NotImplemented vanno identificate per tipo dal manifest privato già raccolto. L'analisi distingue PRESENT, ABSENT e UNSUPPORTED, conserva policy, ACL, CORS e valori in area privata e segnala attributi per-oggetto di cifratura, KMS, retention e legal hold. Zero cifratura di default sui bucket non prova assenza di cifratura sui singoli oggetti.

La copia prevista mantiene bucket/key e i riferimenti object://managed-files esistenti. Preserva metadati, tag, versioni/marker se richiesti e la mappa degli ID originali. La LIST non è uno snapshot: prima del passaggio servono ancora censimento writer/consumer/DB, fence, delta finale e verifica integrale. I riferimenti nei 13 snapshot del14 sono osservazioni trattenute, non prova di writer correnti o di completezza dei consumer.

## Compilazione offline del piano privato

È qualificato un compilatore offline di manifest: 33 test Python in namespace rete isolato e verifica indipendente di firma, sorgenti e pubblicazione. Legge soltanto tre artifact della raccolta16 e lo snapshot host14, verificandone ricevuta/hash e stabilità. Non apre fonti delle credenziali, socket Docker, database o rete S3. Produce un nuovo migration-plan.private.json con modo 0600 con tutte le voci PLANNED_NOT_COPIED, zero copie e zero verifiche dei corpi già eseguite. Il riepilogo pubblico contiene solo conteggi e classi note, senza nomi degli oggetti, endpoint o valori delle policy.

Nuovo controllo 17 distinto, ancora NON eseguito:0 nuovi GET Docker/S3,52 GET Docker cumulativi invariati. Non riapre l'inventario e non modifica vecchi file. [Unico nuovo comando qualificato](OUF_SEAWEEDFS_OFFLINE_PLAN_20261102.md): eseguire una volta e restituire soltanto il JSON finale. Il manifest privato rimane sul VPS.

## Vincoli ancora aperti

SW-G0 resta OPEN per funzionalità private da riconciliare, writer, riferimenti DB, recovery e finestra. La build SeaweedFS corretta resta HELD per 1 UNKNOWN grezzo, con zero HIGH/CRITICAL e sola diagnostica sintetica ammessa; nessuna deroga o ammissione viene prodotta da questo risultato. Il motore di copia/ripresa non è ancora implementato: lo schema pianificato è il primo passo di SW-WP4, non una migrazione provata.

Nessuna nuova operazione VPS dopo la ricevuta16, nessuna copia, deploy, merge o grant. Le vulnerabilità del MinIO attuale restano presenti. Teatri/M1 rimane alle prove 8/8 tecniche e 6/6 funzionali già acquisite; la stessa Farmacie e i contratti congelati sono preservati, M2 non chiuso. MiniPET v1.0 §5–8 e introduzione della riconciliazione PET del 10 ottobre consultati; gli originali PET non sono disponibili in questa conversazione, quindi non viene attestata conformità completa né chiuso alcun gate.

[Ricevuta](../evidence/seaweedfs-private-baseline-target-20261102.json) · [Valutazione strutturata](../evidence/seaweedfs-private-baseline-assessment-20261102.json)
