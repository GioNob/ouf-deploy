# Storage — riconciliatore coordinato sintetico

Stato: `PURE_LIBRARY_PREPARED_LIVE_POSTGRES_PENDING`.

La libreria `tools/storage_recovery/coordinated.py` confronta uno snapshot
completo di righe SQL fixture con un elenco completo di oggetti e i corpi GET
forniti come stream dal chiamante. Ricalcola SHA256 sui byte: un metadato hash
immutato non può nascondere un corpo alterato. Controlla conteggi, dimensioni,
insiemi, metadati e generazioni. Ogni stream è chiuso, anche in errore.

Riusa il validatore del manifest/profile della fondazione recovery, senza
introdurre una seconda identità del candidato o un nuovo schema di backup.
Il manifest conserva le cinque componenti obbligatorie. Lo snapshot SQL è
vincolato all'unico hash `postgres_dump`; la ricevuta fence fornita è vincolata
all'hash e alla generazione del manifest. Questo è un collegamento degli input,
non una prova che un DB live sia stato ripristinato da quel dump.

Prima di leggere i corpi richiede snapshot dichiarati completi, generazione
unica, writer dichiarati fermi, ammissione chiusa e nessun ACK pendente.
Il guard `admit_fixture_write` nega epoch superati e fence chiusi, ma è una
funzione pura: un futuro adapter dovrà applicare atomicamente il protocollo
nel proprio owner. Questa libreria non arresta né impedisce da sola writer reali.

## Limiti di risorse e risultati

Massimo 4.096 oggetti, 16 MiB per oggetto, 64 MiB di byte attesi totali,
snapshot SQL di 4 MiB e ricevuta fence di 16 KiB. Le letture sono blocchi di
massimo 64 KiB. Ogni corpo consuma al massimo la lunghezza attesa più un byte
sentinella, che rileva dati extra; un backend che restituisce più byte del
richiesto è rifiutato. Il massimo payload letto è quindi 64 MiB + 4.096 byte.
I timeout I/O sono responsabilità dell'adapter: una libreria sincrona non può
interrompere un metodo `read` bloccato. Non sono introdotti retry.
Se uno stream fallisce dopo una lettura parziale, `bodyByteCountComplete=false`:
il totale conserva soltanto i readback completati, non inventa il conteggio
dei byte del readback interrotto. Il digest di un corpo intero viene esposto
solo quando è stato osservato EOF.

Input incompleto, duplicato, non fixture o incoerente causa eccezione fail-closed.
Missing, extra, corruzione o errore GET produce `SYNTHETIC_RECONCILIATION_BLOCKED`.
Solo verifica completa senza findings produce
`SYNTHETIC_FIXTURE_RECONCILED_NOT_ACCEPTANCE`. Anche allora `runtimeHealthyClaimed`,
`livePostgresRecoveryQualified`, `pitrQualified`, RPO/RTO, release e autorità
runtime restano false. Il controllo dei byte dei cinque artefatti backup resta
alla funzione foundation `verify_restore`, non viene simulato dal reconciler.

## SQL e integrazione futura

`tests/fixtures/storage-recovery/catalog.sql` descrive esclusivamente lo schema
`ouf_recovery_fixture`, separato da UDP e dagli altri owner. Non viene applicato
in questo lotto; i test usano stream reali in memoria con errori controllati.
Sono provati corpi alterati a metadati invariati, missing/extra, lunghezze
errate, generazioni miste, dump differente, writer stale, ACK pendenti, lista
incompleta, errori read e limiti di byte/conteggi.

Restano PENDING: qualifica dell'immagine PostgreSQL fissata, esecuzione SQL,
dump/restore live, adapter GET con timeout, fence concorrente transazionale,
perdita degli originali, PITR/WAL, TLS e workload rappresentativo. Il PET UDP
§81 e MiniPET SW-G3/SW-AT13–16 non sono chiusi da questo lotto. Nessuna operazione
target; MinIO, Scope17/52, Teatri/M1 e Farmacie invariati.
