# Onboarding — lease legata alla transazione PostgreSQL ed esito COMMIT incerto

## Due passi completati

1. Binding persistente alla transazione owner effettiva: XID completo, identità del cluster, OID del database e istante di avvio PostgreSQL registrati prima di concedere la lease.
2. Resolver PostgreSQL dell'esito incerto, qualificato con interruzioni reali TCP durante COMMIT, transazioni preparate e riavvio del database. L'esito non è fornito dall'oracolo dei test.

Sorgente `529aca458ea7c3699d1437934ea7cd4379d70870`, [PR Onboarding54](https://github.com/GioNob/ouf-source-onboarding/pull/54). [Contratto sorgente](https://github.com/GioNob/ouf-source-onboarding/blob/529aca458ea7c3699d1437934ea7cd4379d70870/docs/STORAGE_RECOVERY_POSTGRES_OUTCOME.md).

## Binding e protezione dal riavvio

`PostgresRecoveryTransactions` cattura `pg_current_xact_id()` sulla stessa connessione già associata alla transazione Spring dell'owner. Un'altra DataSource, autocommit, connessione read-only o identità diversa vengono respinti. L'istanza deve essere un primary PostgreSQL17 con synchronous_commit=on. La cattura non chiude la connessione owner.

Il provisioning esplicito di uno store vuoto persiste `owner.database` privato e con checksum prima dello stato corrente. Lo schema bound è `ouf.platform-storage-authority.pg.v2`; il marker contiene UUID, generazione, identità database e xid8, entro 2.048 byte. Non esiste aggiornamento implicito degli store legacy. La rimozione del file di ammissione non permette il ritorno al formato unbound.

L'ammissione conserva l'avvio del postmaster: il riavvio reale del container è stato verificato, con stesso system identifier ma nuovo istante di avvio. Vecchia risoluzione e vecchia ammissione restano negate. Non si ricava una nuova ammissione dalla sola disponibilità di una connessione.

## Esito reale e confine dell'approvazione

`PostgresRecoveryOutcomeResolver.prepare` legge il marker esatto, rilascia il guard, verifica la lease di approvazione del comando e interroga PostgreSQL fuori dalla transazione owner e dal lock del file. Solo `committed` e `aborted` producono una prova terminale opaca; `in progress`, stato non più conservato/NULL, errore SQL o identità diversa bloccano. Righe ACTIVE/DRAINING e PID non sono usati per indovinare l'esito.

La prova dura al massimo 30 secondi e non supera la scadenza dell'approvazione, limitata a cinque minuti. Il provider accetta soltanto il tipo Prepared costruito dal resolver per i marker bound. Sotto il guard confronta nuovamente comando, marker e transazione, e controlla l'approvazione senza eseguire altre query SQL. Restano ricevuta persistente, generazione successiva revocata e cancellazione/fsync del marker esatto.

**L'approvazione HUMAN autenticata e il collegamento operativo restano da integrare.** I test usano approvazioni sintetiche, mentre l'esito della transazione è letto dal PostgreSQL reale. Nessun endpoint, bean, grant, privilege SQL o ammissione operativa è installato. Il resolver non riapre il traffico né compensa gli effetti applicativi già conclusi.

Le query e il socket hanno limite di due secondi; la DataSource iniettata deve avere un proprio timeout finito di acquisizione/login/pool. Nessun retry è aggiunto. La qualifica dei privilegi minimi e del binding operativo è separata; le funzioni di identità amministrative non ricevono nuovi grant in questo blocco.

## Qualifica

| Verifica | Esito |
|---|---|
| [Native owner 42043116716](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42043116716), job 127298832353 | **97 scenari nativi + 8 API/storage = 105 PASS**, zero fallimenti/errori/skip |
| Nuovi casi | 8; complessivamente 26 ricevute provider, 17 log JVM e 5 ricevute di esito PostgreSQL |
| Readback locale nativo | **174 membri, 173 checksum, 278 blob Git esatti**; nessuna ripetizione dell'esecuzione nativa locale |
| [Regressione fisica 42043116701](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42043116701) | producer 127298832712 e readback 127300103902 SUCCESS; 39 membri, 38 checksum, 281 sorgenti, 1.695 file backup e 15 alterazioni semantiche respinte |
| CI sorgente | **8/8 SUCCESS**; suite generale 462 riportati − 97 skip nativi = 365 eseguiti PASS; scan bloccante immagine e boot container riusciti |
| Checkpoint deploy precedente a9a8fb1 | **50/50 SUCCESS**; i controlli del nuovo commit documentale sono distinti |

[Ricevuta completa](../evidence/storage-postgres-owner-outcome-qualified-20261105.json), [verificatore](../scripts/readback-postgres-authority-native-20261105.py). Eseguire Python senza -O dal checkout Onboarding al commit esatto, passando il percorso dello ZIP nativo scaricato. Artifact Actions conservati fino al 3 febbraio 2027; digest, dimensioni e identificativi sono nella ricevuta.

La regressione fisica resta il driver sequenziale precedente: non integra questo resolver e il readback non esegue un secondo restore nativo. In questo turno è stato verificato localmente lo ZIP nativo, non nuovamente lo ZIP fisico. I dieci file sorgente modificati sono stati riletti integralmente dopo la pubblicazione.

## Casi PostgreSQL verificati

| Caso | Evidenza |
|---|---|
| Binding della connessione | XID del marker uguale a quello della transazione owner; stesso binding dopo riapertura; altra DataSource, vecchio gate e metadata assente negati |
| Risposta COMMIT persa | Il proxy inoltra COMMIT, osserva CommandComplete e scarta la risposta; l'owner riceve errore reale, il marker resta, una JVM nuova risolve COMMITTED e conserva DRAINED |
| COMMIT non inoltrato | Connessione chiusa prima dell'invio; PostgreSQL abortisce, resolver ROLLED_BACK, ACTIVE e nessun audit di drain prima della nuova ammissione separata |
| COMMIT ritardato | Client disconnesso con transazione server ancora aperta: risoluzione negata; dopo inoltro e completamento effettivo, COMMITTED |
| Transazioni preparate | PREPARE TRANSACTION resta bloccata; COMMIT PREPARED e ROLLBACK PREPARED vengono distinti dal resolver |
| Binding/approvazione errati | Altro database sullo stesso cluster e approvazione invalida/scaduta negati, marker conservato |
| Riavvio PostgreSQL | Restart reale del container, nuovo postmaster, vecchio binding negato senza rebind automatico |
| Prova preparata superata | Revoca dell'approvazione dopo preflight e vecchia prova contro una nuova lease respinte |

Le tre prove TCP generano errori JDBC reali e non iniettano notifiche Spring UNKNOWN; le precedenti prove di UNKNOWN iniettato rimangono distinte. Il proxy è solo loopback, usa il protocollo simple-query senza SSL/GSS nella fixture e non registra frame di autenticazione o dati. Il parametro max_prepared_transactions=10 riguarda esclusivamente PostgreSQL usa-e-getta della CI.

## Limiti e prossima coppia

Qualifica same-host/local POSIX, ext4 e PostgreSQL17. Restano aperti TLS fault, power loss, failover/restore e rebind governato, esaurimento reale della storia XID, custodia dello store, privilegi minimi, timeout della DataSource operativa, osservabilità owner/Gateway/MCP e approvazione HUMAN live. La storia business ripristinata e i budget dopo rollback completo owner non vengono ricostruiti dal solo esito XID. Nessun nuovo credito di accettazione target è attribuito a queste prove.

Prossima coppia proposta: collegare l'approvazione autenticata/revocabile al fingerprint esatto del comando; qualificare quel collegamento con un profilo PostgreSQL a privilegi minimi e limiti finiti, mantenendo negato il rebind dopo restart finché non ha prove governate dedicate.

MinIO/source-lock invariati; MiniPET **18,3/46 = 39,78%, 0/8 gate, 0/21 AT, 0/120 oggetti reali**. Nessun merge, deploy, target, grant o riapertura del traffico. UDP/Ingestion, rollout misto e RPO/RTO restano aperti. Entrambe le PR54 sono draft/open.
