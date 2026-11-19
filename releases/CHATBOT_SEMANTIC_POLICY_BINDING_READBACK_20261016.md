# Lettura metadati Authorization del Registry

## 16 ottobre — lettura VPS completata, diniego anche sulla ricevuta

Fasi tecniche 8/8 conservate; tappe funzionali 0/6, tappa 1 sospesa.
L'output operatore del reader v1 termina con complete=true. Delivery inattiva
(MainPID 0, Result success), authority scaduta; il record WORKER è CANCELLED /
CANCELLED_BY_OWNER, attempts=59 e controlledCumulativeGrantAttempts=69.
Il totale 69 è presente nel record, non inferito. SESSION e ADMISSION non
espongono il cumulativo; ADMISSION è BLOCKED. Queste letture successive non
costituiscono snapshot atomico né liveness o accettazione applicativa.
Il motivo preciso di termine del processo figlio resta non provato.

Campione Registry: exitCode 0, stdoutBytes 596, stderrBytes 0; tutti i marker
cercati assenti. Questo non prova salute, grant effettivi o causa del 403.
Una lettura semantic.proposal.read con ouf-admin e la chiave originale
teatri-semantic-draft-be74308e098aa3a6-20261016 restituisce 403
SEM_CAPABILITY_REQUIRED:ouf.semantic.proposal.read. Nessun retry; riconciliazione
ancora non eseguita, DRAFT e review THS non provate.

Nel sorgente Registry eccef11a97367f20e278db40b9ed6f45dd980c37,
SemanticAuthorizationBoundary converte più SecurityException nello stesso
codice SEM_CAPABILITY_REQUIRED. Questo spiega il limite diagnostico del codice,
non dimostra il bundle/configurazione della generazione target.
Il nuovo reader installation-specific legge due volte soltanto i metadati
Docker dell'esatto Registry, usando il socket custodito del prepared bundle.
Espone presenza dei riferimenti Authorization, interi configurati, uguaglianza
con l'hash policy40 già osservato e copertura dei path da mount readonly;
non apre policy o credenziali e non interroga owner API.
Segnala canali di override Spring/JVM: la configurazione esplicita non equivale
allo snapshot in memoria; eventuali valori assenti restano sconosciuti.

Cinque nuovi test locali PASS (redazione, assenza di inferenze, alias duplicati,
authority scaduta, drift della generazione); dieci test locali complessivi con
il precedente reader PASS. Nessuna qualifica target del nuovo reader ancora.
Nessun grant, rinnovo, retry della proposta, restart, modifica Gateway/DB/IAM,
reset o replay dei claim. HUMAN THS resta necessario per approvare/pubblicare.
Evidenza: evidence/chatbot-semantic-denial-retained-target-20261016.json.
Prossimo passo: launcher pinned di lettura metadati Authorization; serve output VPS.


Reader SHA256: 94554fb54cef10683cc4bde25b04542ffb5784599d6ad7a21a51af951130ed90.
Massimo 120 secondi, due GET Docker metadata; nessuna lettura di policy, token o chiavi.
L'identità della generazione è confrontata prima/dopo; drift impedisce di pubblicare la proiezione.
Il reader ammette la finestra scaduta perché non ne esercita l'autorità runtime.
