# OUF — politica predefinita di resilienza v1

Decisione utente: 11 ottobre 2026, 03:28:33 CEST. Si applica di default a tutti i moduli OUF e a ogni nuovo lavoro nel progetto. È una politica di implementazione e operatività coerente con i PET, non un'estensione di grant o una modifica implicita dei contratti di dominio.

## Regole obbligatorie

1. Un'indisponibilità temporanea sospende il lavoro dipendente e pianifica retry finiti con backoff incrementale e jitter. Il processo mantiene stato e osservabilità; non termina o si riavvia solo perché l'interlocutore manca. Le funzioni indipendenti possono continuare.
2. Default versionato: attese base 5s, 15s, 60s, 300s, poi 900s; jitter fino al20%; massimo128 tentativi e24ore per episodio/operazione, inclusi il primo tentativo e la sua durata. Il limite raggiunto per primo sospende ulteriori retry automatici e apre un'issue richiedente intervento. Attesa indefinita per intervento non significa retry infinito.
3. I profili per operazione/errore possono cambiare questi valori con motivazione e budget finito versionati. Un tentativo ha un proprio timeout realistico, distinto dalla durata complessiva di recupero. Retry-After viene rispettato: mai anticiparlo per farlo rientrare nel cap del backoff; se supera il budget residuo si sospende.
4. Le attese non trattengono lock condivisi, transazioni DB o richieste remote aperte. Lo stato di retry/checkpoint/evidence è persistito dall'owner con transazioni corte. Restart non azzera budget, contatori, dedupKey, idempotency key o storico.
5. Si ritentano automaticamente soltanto classi esplicitamente transitorie e operazioni read-only/idempotenti, o mutazioni protette da una idempotency key con deduplicazione owner provata. Un esito mutativo ambiguo richiede riconciliazione prima di rispedire; nessuna duplicazione o avanzamento checkpoint/watermark senza ACK durabile.
6. Revoca esplicita, integrità/identità/configurazione non verificabile, errore permanente e classe sconosciuta bloccano l'operazione e richiedono intervento. Il retry non aggira IAM, HUMAN/THS, secret custody, allowlist o policy di rete. Incertezza sul controllo produce deny.
7. Durante una pausa scadono o vengono revocate lease e aperture non più verificabili. Ripresa automatica solo con nuova evidenza fresca, generazioni e autorità ancora valide, sotto una chiusura runtime nuova che autorizzi espressamente tale recupero. Mai estendere TTLzero, importare risoluzioni storiche, rigiocare un claim consumato o riavviare R9/R10.
8. Liveness distinta da readiness: vivo/in pausa non equivale a pronto o traffico autorizzato. Stati osservabili includono ACTIVE, RETRY_WAIT, PAUSED_EXHAUSTED, BLOCKED, RECONCILE_REQUIRED e CANCELLED. Questi sono stati operativi, non nuovi stati di dominio.
9. Eventi/issue persistenti e deduplicati espongono codice sicuro, tentativo, prossimo tentativo, budget residuo, correlazione e risoluzione. Niente raw token, credenziali o payload privati. Un retry non crea un incidente distinto per ogni tentativo.
10. Prove obbligatorie per nuova integrazione: indisponibilità di ore con tempo simulato, ripresa senza duplicazioni, budget/Retry-After/jitter, stop/revoca/cambio generazione durante la pausa, timeout e crash durante una mutazione, persistenza/ripartenza e nessun lock tenuto nelle attese. Per la rete servono anche nft/DNS reali e negazioni native.

## Riferimenti PET

Ingestion Runtime1.3 §15: exponential backoff+jitter, idempotenza e nessun avanzamento committed checkpoint; §24: worker persistente, transazioni corte e niente I/O remoto dentro TX DB; operational awareness: incidenti deduplicati e budget finito per categorie retryable. Gateway1.5 T11/T11.3: retry governati, operazioni idempotenti/safe-to-retry, allowlist/default-deny indipendenti dalle route e protezione DNS/redirect. Authorization1.5: default-deny e audit senza segreti. Semantic1.3: owner enforcement, HUMAN-only governance e secretRef.

## Applicazione e stato reale

Questa politica è obbligatoria per sviluppo/revisione. Non dichiara che tutti i runtime esistenti siano già conformi. Il primo intervento riguarda il provider lease worker; R10 resta fallito/QUIESCED/consumato, set vuoti all'ultima lettura. Sono sospesi i precedenti launcher di recupero/preflight: prima va completata e qualificata la chiusura resiliente. Nessun deploy/restart o nuovo grant è effettuato dalla pubblicazione di questo documento.

Per gli altri moduli la conformità runtime va verificata contro i rispettivi PET e meccanismi di retry/checkpoint già esistenti, conservando owner, contratti, idempotenza e storage. Nessun framework/broker nuovo è introdotto per imporre questa politica.
