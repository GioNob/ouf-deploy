# Diagnosi locale dei tre blocchi datasource G0

L'esito operatore acquisito in evidence/storage-g0-input-preparation-operator-20261106.json conferma la bozza S3 e tre dinieghi INPUTS_DATASOURCE_OVERRIDE_REQUIRES_REVIEW. Non dimostra ancora quale override sia presente: lo stesso codice include duplicati identici, valori discordi, parametri Hikari, configurazione esterna e opzioni JVM. Non rimuovere il controllo e non rilanciare il preparatore.

## Scopo del comando

scripts/review-storage-g0-datasource-20261106.py opera da root con python3 -I -B -S. Prima dell'import verifica l'esatto bundle input-tools-6c9de0f4 già installato, manifest SHA256541115aa70b073803ebe88a809a91a2f263bd7bd62d9708d297d37519e931bb2, sorgenti root0400 senza import aggiunti/symlink. Non scarica né reinstalla il bundle.

Richiede il risultato precedente S3-only con tre dinieghi. Crea soltanto inputs/datasource-review-20261106 root0700, claim e risultato0600; claim massimo1tentativo,3environment da131072byte e15secondi cooperativi. Legge il seed storico privato verificato per digest, che può contenere configurazione sensibile; verifica boot e generazioni dei tre processi prima/dopo ogni lettura. Non apre file di credenziali separati, passfile o i nuovi segreti S3. I byte sensibili restano in memoria locale.

Output: per Onboarding/UDP/Ingestion, presenza/non-vuoto e uguaglianza byte-per-byte delle coppie OUF_*_DB_URL/USER/PASSWORD e SPRING_DATASOURCE_URL/USERNAME/PASSWORD; placeholder esatto verso il corrispondente nome OUF; elenco di soli nomi noti fissi; conteggio degli altri nomi SPRING_DATASOURCE_*; presenza dei tre override di configurazione e menzione datasource nei tre JAVA_*. Nessun valore, nome arbitrario, hash di password o contenuto di configurazione. Un booleano uguale non dimostra la configurazione Spring effettiva: cmdline, file esterni, binding e stato DB non vengono osservati.

Se esiste già risultato, viene soltanto riletto. Scope parziale o errore: HELD, nessun reset o cancellazione automatica. Nessun Engine/S3/SQL, nsenter, check/collect, modifica di connessioni/permessi/volumi, grant o autorità. Il timeout cooperativo non è una qualifica di filesystem bloccato. La lettura diagnostica è un nuovo scopo limitato per i dinieghi appena osservati, non replay del vecchio preparatore o dei controlli13–17.

## Esito e seguito

Restituire soltanto il JSON stampato. DATASOURCE_OVERRIDE_METADATA_OBSERVED_REVIEW_REQUIRED consente di rivedere la causa, non di accettare o scegliere automaticamente credenziali. La continuazione DB deve preservare lo scope e S3 e gestire solo i casi realmente emersi; un override esterno o ambiguo resta in review. Non assumere innocui i parametri Hikari e non confondere alias JDBC storici con prova di configurazione corrente.

10test locali e workflow dedicato verificano redazione, input/import alterati, confronto valori/placeholder, drift, budget, ripetizione e area parziale. Lettori processo iniettati, nessuna nuova prova nativa/provider o accettazione. CI sul commit esatto registrata nella PR; non sommare locale e CI come casi distinti.

MiniPET18,3/46=39,78%,0/8gate,0/21AT,0/120oggetti reali. Il backup esterno non blocca questa preparazione; custodia/DR/capacità restano da dimostrare per i criteri applicabili.
