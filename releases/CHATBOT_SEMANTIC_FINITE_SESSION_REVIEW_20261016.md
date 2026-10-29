# Preparazione privata della review di sessione semantica

## 16 ottobre — diagnosi refresh completata; review di nuova sessione semantica da preparare

Fasi tecniche 8/8 conservate; funzionali 0/6.
Reader v3: tutti i vincoli endpoint e custodia PASS; file UID0/GID10001/0440,
regolare, singolo link, dimensione bounded. Un solo token letto senza stamparlo.
Metadato exp1792148493 = 2026-10-16 13:01:33 Europe/Rome; expiredAtRead=true.
La firma JWT non è verificata localmente. Un unico GET policy via binding HTTPS
approvato restituisce401; ENDcomplete=true, nessun retry o mutazione.
Questa è prova del rifiuto corrente sul percorso dal VPS con quel token.
È coerente con la scadenza del token dopo la cessazione del worker, ma non è
prova autonoma del motivo server del401, del trasporto JVM, dello snapshot
in memoria o della causa esatta del PRIMO403. Non forzare refresh con nuovi grant.

Il vecchio worker resta CANCELLED_BY_OWNER con cumulativo69 (59nel worker);
authority scaduta, admissionBLOCKED. Nessun rinnovo o replay autorizzato.
I componenti continued_owner/installed_owner sono vincolati a precedenti
specifici di recupero: NON usarli direttamente con count69 né cambiare i numeri
per adattarli. Serve un percorso distinto di nuova sessione finita con HUMAN
autenticato, stesso incidente/logical scope, nuova autorità e fencing,
preservando cancellazione e ogni journal precedente.

Preparatore nuovo: scripts/prepare-chatbot-semantic-session-review-20261016.py.
Scrive SOLO una nuova review privata root600 in directory root700.
Legge review/authority/bundle custoditi, i quattro record conservati
recovery/session/admission/status (hash canonici esatti già osservati), due GET
metadati dell'esatto Registry e due osservazioni dell'unità precedente ferma.
Non apre credenziali, non fa GET policy/IAM/MCP/DB, non prende claim di runtime
e non riavvia nulla. File o generazioni mutati bloccano la preparazione.
È readOnly=false esclusivamente perché crea il nuovo snapshot privato;
existingConfigurationWrites=0 e runtimeAuthorityIssued=false.

La review PROPOSTA contiene budget finito1ora/max128 nuovi tentativi di token
grant, massimo cumulativo197=69+128, interval60s, backoff5/15/60/300/900,
jitter20%, Retry-After, nessun rinnovo automatico.197 è un LIMITE PROPOSTO,
NON un contatore osservato. DecisionRef/timestamp/authority restano null,
readyForExecution=false. Richiede esplicita continuazione dopo cancellazione;
non riapre quel worker e non tratta la delega di sviluppo come autorità runtime.
Gli effetti proposti sono solo nuova sessione token e verifica readiness policy;
vietati primo-grant replay, fasi1–8, lifecycle applicativo, grant Authorization,
route Gateway, DB, reset e retry automatico della proposta semantica.
La chiave teatri-semantic-draft-be74308e098aa3a6-20261016 e il proposal hash
be74308e… sono conservati; riconciliare la ricevuta prima di una ripresa identica.
La review non è esecutore qualificato, autorità, approvazione THS o accettazione.

Quattro nuovi test locali PASS: nessuna autorità implicita, contatori non inferiti
e negativi, hash predecessori vincolati, scrittura/readback nativi root600/700 e
due snapshot esclusivi senza sovrascrittura. Totale22 PASS. Resta il limite
della qualifica precedente UID/GID10001 simulata, non accettazione target.
Evidenza: evidence/chatbot-semantic-policy-refresh-v3-target-20261016.json.
Reader/preparatore SHA256: 5fcf39579f2d81b9a916b0ed849d38896e9765b3b8c76f4320169f28553ab7f5.
Prossimo input esterno necessario: output del preparatore sul VPS; l'output
espone soltanto percorso/hash della review e limiti. Poi qualificare l'esecutore
e sottoporre l'esatto piano alla decisione HUMAN prevista; non attivare da questa
review non firmata. Non dichiarare la tappa1 completata.

