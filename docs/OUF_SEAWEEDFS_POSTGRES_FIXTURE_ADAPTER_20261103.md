# Storage — adapter di snapshot PostgreSQL fixture

Stato: `PROCESS_BOUNDARY_VERIFIED_POSTGRES_EXECUTION_PENDING`.

`tools/storage_recovery/postgres_fixture.py` prepara ed esegue un comando `psql`
read-only per il solo database e schema `ouf_recovery_fixture`, via una directory
socket Unix esplicita. L'owner del laboratorio deve qualificare immagine,
eseguibile, socket e identità server. Il controllo del percorso non è una prova
di identità del DB. Non sono accettati SQL arbitrario, DSN, hostname TCP,
credenziali, nome DB o shell forniti dal chiamante.

Il comando usa `--no-psqlrc`, `--no-password`, `ON_ERROR_STOP` e ambiente nuovo:
non eredita PGHOST, PGPASSWORD, PGOPTIONS o PGSERVICE. La query fissa legge fence
e catalogo nella stessa transazione `REPEATABLE READ READ ONLY`, con timeout SQL
10 secondi, lock 2 secondi e inattività nella transazione 12 secondi. I valori
non sono parametri target né nuove decisioni RPO/RTO. Un massimo di due righe
generation e 4.097 righe object consente di rilevare cardinalità invalide senza
scambiare un risultato troncato per una lista completa. Il server può comunque
scansionare/ordinare più righe: la durata è limitata dal timeout SQL, non da un
budget di lavoro del planner.

Il processo ha deadline complessiva predefinita 15 secondi, mai oltre 30,
un solo tentativo, stdout massimo 4 MiB + 16 KiB e stderr massimo 64 KiB.
Entrambe le pipe vengono drenate con letture bounded. Timeout, overflow o errore
terminano l'intero process group, inclusi discendenti che trattengano una pipe;
il processo diretto viene raccolto. Nessun stderr raw entra nell'eccezione o
nella ricevuta. Anche un warning psql blocca questo profilo stretto. Codice di
uscita diverso da zero blocca un JSON altrimenti valido.

Il parser rifiuta campi duplicati/sconosciuti, output multipli, fence aperto,
writer attivi, ACK pendenti, generazioni miste, righe duplicate, scope non
fixture, hash/dimensioni invalidi e limiti superati. Produce gli input canonici
del reconciler esistente. Un test integrato conferma che un corpo corrotto a
metadati immutati rimane un errore dopo questo export.

## Ciò che la lettura non dimostra

Il valore `source_dump_sha256` è un riferimento fornito dal chiamante: non prova
che il DB letto sia nato da quel restore. La ricevuta conserva esplicitamente
`dumpRestoreOriginVerified=false`. Analogamente, leggere una riga fence chiusa
non impedisce a un writer di scrivere: `writerFenceEnforcedByAdapter=false`.
Il chiamante non deve promuovere questi input a prova di fencing o di restore.
Le cinque componenti di backup restano verificate dalla fondazione separata.

I test locali utilizzano processi peer reali, pipe, segnali e input sintetici;
non eseguono `psql`, PostgreSQL, SQL o un dump/restore. Le opzioni e il testo SQL
sono preparati ma richiedono esecuzione su PostgreSQL qualificato. Non si
attribuisce conformità PostgreSQL a un peer che restituisce JSON. Il risultato
non dichiara health, PITR, RPO/RTO, release o autorità runtime.

## Protocollo writer necessario al successivo laboratorio

Questo adapter è solo un lettore. Prima del drill coordinato, l'owner fixture
deve implementare e provare le seguenti operazioni con transazioni corte:

1. Claim: lock della riga generazione, verifica epoch e ammissione aperta,
   registrazione durevole dell'intento e della stessa idempotency key. Un claim
   già presente non genera una seconda mutazione. Commit prima dell'I/O S3.
2. Fence: stesso lock e chiusura durevole dell'ammissione. Un claim concorrente
   precede il fence ed è da drenare, oppure segue il fence ed è negato. Nessun
   contatore dichiarato a zero sostituisce l'insieme degli intenti durevoli.
3. ACK: solo dopo readback coerente e prova della durabilità richiesta, commit
   della riga catalogo e dello stato terminale dello stesso intento. Una
   risposta persa resta `RECONCILE_REQUIRED`; nessun nuovo PUT prima della
   riconciliazione. Nessun I/O remoto durante il lock/transazione DB.
4. Snapshot: ammissione ancora chiusa, tutti gli intenti riconciliati, nessun
   writer ammesso o ACK pendente, poi backup coerente e restore in ambiente
   vuoto. Vecchie generazioni rimangono negate anche dopo restart; questa
   lettura non riapre l'ammissione né azzera contatori/budget.

Questi punti sono specifica del prossimo adapter owner, **non implementazione
o qualifica** in questo lotto. La prova dovrà includere concorrenza, crash prima
e dopo PUT/ACK, restart, corpo alterato, database originale indisponibile e
recovery coordinato. Non è stato introdotto un backend SQLite alternativo.

Riferimenti normativi: PET UDP §81 (backup full + WAL/PITR e riconciliazione
DB–oggetti prima di healthy), Matrix 1.7 ownership/HUMAN/THS, policy resilienza
v3 regole 4–7, 10 e 15; MiniPET SW-G3/SW-AT13–16 restano OPEN. Opzioni psql:
[documentazione PostgreSQL](https://www.postgresql.org/docs/current/app-psql.html).

Nessuna operazione target. MinIO rimane attivo; Scope17/52, Teatri/M1 e Farmacie
restano invariati. Il workflow foundation conserva il proprio lock storico:
questa prova di adapter non qualifica né trasferisce una nuova immagine storage.
