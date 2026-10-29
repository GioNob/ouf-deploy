# Sessione finita del solo token policy — consegna del 16 ottobre

Stato target conservato: **8/8 fasi tecniche, 0/6 risultati funzionali**.
Il candidato v2 è stato preparato con successo, ma non ha emesso autorità.
SHA256 candidato: `0f89461b7ec0d34078dbacc28d3281c935ca2f5c60dd185f2f763f4ffd3650b4`.
Revisione preliminare: `beefc7f2ee79fa70c5b416d6d3efe68d3b08d15f9bb07c96c3e837995b627803`.

## Comando disponibile e limiti

Launcher: `scripts/launch-chatbot-semantic-token-session-20261016.sh`, SHA256
`df509e9c44b7b1e08ce6acc3e4e0847aa18d0bcda7eadc525a808d3ba806f7ac`.
Il launcher scarica sette file dal commit immutabile
`c3e39aaf5783be6428fdb95dff1a3836748c0ce3` e verifica ogni hash prima di sudo.
Usa prima il client GitHub portabile già disponibile sul VPS; mantiene la sua
autenticazione, senza richiedere o mostrare token GitHub.

Questa è una continuazione **specifica dell'installazione e dello storico
vincolato**, non un nuovo installer generico. I riferimenti storici restano
controlli contro l'installazione sbagliata; endpoint, issuer, subject, trust,
socket Engine, credenziale e output derivano dai dati privati verificati.
Non si inventano nuovi endpoint, secret, grant o trasporti distribuiti.

Il comando resta in primo piano. Prima di qualsiasi grant workload:

1. Verifica review/autorità precedenti scadute, vecchia unit spenta, journal
   CANCELLED_BY_OWNER e tutti gli hash del candidato e della revisione privata.
2. Verifica la generazione corrente dell'esatto Registry tramite Engine GET.
3. Rilegge il bundle privato già consegnato, verifica loader e tutti i sorgenti,
   sostituisce solo sei moduli con i nuovi byte verificati e li carica da memoria
   in Python `-I -B -S`. I due moduli owner ouf-onboarding conservano i byte e il
   commit già approvati; nessun nuovo download owner o fallback su sorgenti disco.
4. Prepara un nuovo contesto privato e un nuovo journal, senza riusare directory
   di tentativi precedenti o claim consumate. Nessuna credenziale workload letta.
5. Esegue un nuovo login device HUMAN con il client esistente e la stessa
   selezione issuer/tenant/subject. Il login non approva la sessione. I token
   OAuth restano nei soli file privati del contesto, senza log dei bearer.
6. Verifica che la finestra proposta rientri nelle autorità dei ruoli esistenti;
   pubblica la revisione finale e richiede sul terminale `APPROVO <hash-esatto>`.
7. Solo dopo questa decisione e una sessione HUMAN ancora verificata consuma
   una claim di emissione; usa la chiave esistente per due firme distinte
   DEPLOYMENT_INTENT e FINAL_DEPLOYMENT_APPROVAL. Nessuna nuova chiave o
   CREATION_ATTESTATION. Il mandato infrastrutturale è finito e indipendente
   da un eventuale futuro login; non si rinnova automaticamente.
8. Ricompila gli scope, verifica nuovamente stato, custodia e generazione,
   consuma il fence globale O_EXCL e avvia il worker nella stessa invocazione.

Un evento di stop restringe anche la verifica temporale della stessa autorità
firmata: una risposta IAM arrivata dopo la cancellazione non può pubblicare
un token tardivo. Il tentativo consumato resta conteggiato.

Il processo termina la sessione entro **3600 secondi dalla decisione**; Ctrl-C,
TERM o HUP ne richiedono la cancellazione. Non registra servizi o timer e non
abilita restart o boot. Lasciare aperto il terminale dopo APPROVO. La procedura
di login ha il profilo finito preesistente, separato dalla finestra del worker.

Contabilità:69 tentativi workload controllati precedenti restano nello storico;
il primo nuovo tentativo sarà70. Massimo128 nuovi, cumulativo controllato massimo197.
Il gap di contabilità legacy resta UNKNOWN:69 non è una ricostruzione di tutta
la storia IAM. Backoff5/15/60/300/900, jitter20%, Retry-After e durata degli
attempt restano governati dal worker esistente; esiti ambigui non si ritentano.

Effetti consentiti: stage privato del codice owner, nuovo journal e rinnovo
finito del solo token policy nella destinazione già vincolata. Nessun primo
grant ripetuto, rotazione credenziale, modifica grant, lifecycle container,
scrittura DB o Gateway, ripetizione delle otto fasi tecniche o chiamata MCP.

Se compare STOP, conservare il log e riportarlo prima di qualsiasi nuovo
tentativo: preparazioni, firme o claim parziali richiedono riconciliazione.
Il comando non cancella il fence né azzera contatori o journal per ripartire.

## Evidenza di qualifica

[CI nativa del sorgente 38902222309](https://github.com/GioNob/ouf-deploy/actions/runs/38902222309),
job116976988186: **72 test PASS**. Sei prove di emissione/dispatch, quattro
di bootstrap/import, quindici di sessione OAuth e47regressioni composte owner,
contratto, firma e installazione. UID/GID, boot_id e socket Unix reali su Linux.

Le prove di dispatch simulano login e risposta del terminale; firme Ed25519,
custodia, IAM workload TLS e pubblicazione del token sono reali su fixture
locali sintetiche. Le quindici prove OAuth attraversano realmente una socket
loopback tramite un opener di test. Non sono un login HUMAN o un grant target.
La regressione di cancellazione avviene dopo una vera risposta IAM TLS: nessuna
nuova pubblicazione, contatore conservato e file precedente immutato.
La prova di import isolato usa tutti i moduli reali del repository e placeholder
per i soli due moduli owner esterni, importati senza invocarli. Il bootstrap
produttivo conserva invece i loro byte originali verificati, senza placeholder.

Due prove del launcher PASS localmente: corrispondenza di tutti i pin e wrapper
di copia privata realmente eseguito con figlio sintetico, più rifiuto della
manomissione prima del figlio. [Qualifica Linux del launcher 38902296302](https://github.com/GioNob/ouf-deploy/actions/runs/38902296302), job116977233087: **2 test PASS**.
Capsula di sviluppo aggiornata a
`3294e99e4fbe44dd2ff19f223a4b18d0b3e8ea41a1f7c0109e491312e12c1aa1`;
i vecchi launcher e commit già eseguiti restano storici, senza nuova esecuzione.

## Dopo l'avvio

Riportare `OUF_TOKEN_SESSION_STARTED` e il primo
`OUF_POLICY_TOKEN_OWNER_STATUS`, lasciando in esecuzione il comando.
ACTIVE dimostra il worker e la pubblicazione del token; non dimostra la policy
effettivamente caricata dal Registry né il completamento funzionale.

Resta necessaria una prova della policy effettiva e la riconciliazione della
receipt dello stesso `teatri-semantic-draft-be74308e098aa3a6-20261016` prima di
riprenderne l'intento. Nessun retry automatico di semantic.propose o dei403;
nessun cambio account. Le approvazioni semantiche restano nel THS.
Non dichiarare alcuno dei sei risultati funzionali sulla sola base del token.
