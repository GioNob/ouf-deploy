# Candidato di continuazione semantica: preparazione, non avvio

## 16 ottobre — review privata disponibile; candidato di continuazione da compilare sul target

Fasi tecniche8/8 conservate, funzionali0/6.
L'operatore ha completato la preparazione: review privata
/etc/ouf/deploy-snapshots/semantic-functional-session-review-e8ced3ui/review.json,
SHA256 beefc7f2ee79fa70c5b416d6d3efe68d3b08d15f9bb07c96c3e837995b627803.
Contatori precedenti69, limite proposto nuovi tentativi128/cumulativo197,
durata3600s. ENDcomplete=true, credentialFilesRead0, grantRequests0,
runtimeAuthorityIssued=false, humanApprovalGranted=false, readyForExecution=false.
Questo NON è un'autorizzazione di avvio, un nuovo budget concesso o un grant.

Sviluppo candidato (non installato): installed_owner.py aggiunge un compilatore
puro e un ramo di guardia per schema ouf.policy-token-governed-worker-session.v1.
Conserva i rami storici. Il totale deriva dai record hash-bound: base10+59=69;
verifica sessione/policy/first receipt/boot e il gap storico UNKNOWN, senza
dedurre contatori dalla versione schema o riaprire il vecchio journal.
Scope nuovo: cap197, policy finita, stessa chiave della proposta, reviewHash,
e fence persistente per logicalOwnerScopeHash nel parent del journal precedente.
Directory nuova deterministica dal reviewHash; la guardia nega senza il record
di fencing esatto. Il nuovo ramo scheduler controlla aritmetica e max attempts;
il vecchio profilo continua a rifiutare69. Nessuno di questi sorgenti è installato.

Sette test del contratto sui corpi AST candidati PASS, più due test di packaging/
compilazione e22 precedenti:31test locali PASS. Questi isolano le funzioni pure,
NON provano la composizione di firme, source-stage, installer e worker sul target.
Il publisher è invariato; la qualifica locale UID/GID resta simulata.
Mancano ancora composizione esecutore sigillato, qualifica completa firme/fencing,
decisione HUMAN corrente ed effettiva readiness policy Registry. Nessun apply
o domanda di approvazione runtime va emessa prima di chiudere questi gate.

Prossimo comando: scripts/prepare-chatbot-semantic-session-candidate-20261016.py.
Richiede la review privata ESATTA e gli stessi record hash-bound, legge anche la
ricevuta originale owner-first-grant.json, controlla hash input e generazione
Registry prima/dopo. Usa SOLO il compilatore puro estratto dai sorgenti hash-bound;
non importa né esegue il runtime owner. Compila un candidato root600/dir700
con source hashes, scope e pending gates, readyForExecution=false.
Sul solo scratch privato root crea una fixture temporanea root:10001/0750,
invoca il VERO AtomicTokenFile.publish su una stringa sintetica scaduta,
verifica file root:10001/0440 e readback, poi rimuove la fixture. Non tocca
output token live, directory/journal precedenti o permessi esistenti.
Nessuna credenziale, token live, firma, chiave privata, IAM/API/DB, grant,
unità o lifecycle viene usata. Due GET Docker metadata e due systemctlshow.
Massimo120s. Chown avviene SOLO nella nuova fixture temporanea.
Il launcher crea anche copie temporanee root600 dei sorgenti verificati, poi
le rimuove; producer originale invariato. Non eseguire file runtime direttamente.

L'output di compilazione target è necessario: la ricevuta privata originale
e i suoi valori completi non sono disponibili in questa chat. Non inventarli.
Se drift/contratto/custodia non corrispondono, STOP: non adattare contatori o
permessi e non riusare vecchi launcher/claim. Dopo la compilazione qualificare
la composizione firmata e l'esecutore prima di una nuova decisione HUMAN.
La review preliminare e il candidato non diventano mandato o accettazione THS.
Chiave teatri-semantic-draft-be74308e098aa3a6-20261016 conservata.
Preparatore candidato SHA256 ca9bd95d898e05109ef6f0277ce57f1625f18ce55a9a55d7979eb45882fc7506.

