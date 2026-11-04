# Rotazione credenziali S3 — fixture33, 2026-11-04

## Contratto della prova

Una sola identità applicativa e la stessa policy prefix-scoped, con chiavi sintetiche pubbliche: OLD → OLD+NEW → NEW → riavvio NEW. L'identità bootstrap è invariata e non è il soggetto della rotazione. Si sostituisce solo il gateway S3, fermando/rimuovendo il precedente prima di avviare il successivo; master, volume e filer devono mantenere ID, StartedAt e RestartCount. Certificato e CA TLS restano identici, con verifica hostname e fingerprint su ogni richiesta.

Un solo seed iniziale: creazione bucket e oggetto binario. Prima della rotazione NEW deve essere rifiutata; durante overlap entrambe leggono gli stessi byte con GET/HEAD/LIST completo. Dopo revoca OLD deve ricevere HTTP403 InvalidAccessKeyId su GET, LIST, PUT nuovo, overwrite e DELETE; HEAD richiede HTTP403 e corpo vuoto, senza inventare un codice XML assente. NEW deve scrivere una sola volta un secondo oggetto, rileggerlo e conservare il precedente; DELETE e PUT fuori prefisso restano AccessDenied, secret errato SignatureDoesNotMatch. Dopo ulteriore restart tutti i dinieghi e le letture devono essere identici, senza ripetere seed o scrittura NEW.

Sette container distinti complessivi, massimo quattro simultanei, un solo gateway attivo; tre sostituzioni bounded. Nessun retry mutativo. Il solo materiale credenziale salvato nelle evidenze è pubblico e sintetico; il workflow rifiuta chiavi private TLS.

## Verifica

22 test locali PASS: 12 nuovi e 10 regressioni TLS esistenti. Esito nativo PENDING sul workflow dedicato, legato al lock/coorte/OCI33 esatti. Gli altri cinque scenari storage già verificati restano al checkpoint320827d2, senza trasferire il loro risultato a questo nuovo test.

## Limiti e avanzamento

Non è hot reload, zero downtime, rotazione owner/admin, STS/session token, test di richieste in-flight o custodia segreti produttivi. Le chiavi sono fixture dichiarate pubbliche; nessun segreto target, VPS o servizio reale viene modificato. Non prova revoca su gateway multipli, né ammissione target. MiniPET invariato 18,3/46, circa40% ±10; 0/8 gate, 0/21 AT, 0/120 oggetti reali.
