# Onboarding — autorità durevole locale e revoca fra JVM

## Due passi

1. Implementato `FilePlatformRecoveryAuthority`, provider della porta già esistente per una directory protetta fuori dal set di backup/restore owner e Authorization.
2. Qualificati riapertura dopo restart, revoca fra JVM, morte del detentore del lock, pubblicazione con risposta persa e replay logico Authorization mentre la revoca esterna resta durevole.

Sorgente `bf8bb65cf353dc60c9482dd6fe50e4416b2eefe6`, [PR Onboarding54](https://github.com/GioNob/ouf-source-onboarding/pull/54). [Contratto completo](https://github.com/GioNob/ouf-source-onboarding/blob/bf8bb65cf353dc60c9482dd6fe50e4416b2eefe6/docs/STORAGE_RECOVERY_DURABLE_LOCAL_AUTHORITY.md).

## Persistenza e protocollo

Il provider è interno e costruito esplicitamente: non è un bean, endpoint, nuovo issuer o grant. Riceve prove già autorizzate dagli owner piattaforma/Authorization; autenticazione Gateway/THS, grant e audit approvativo non sono sostituiti da un file.

Directory canonica0700, file0600 regolari e dello stesso owner; filesystem locale POSIX ammesso (ext4/xfs/tmpfs/overlay). Guard e percorso devono restare stabili e protetti. Provisioning una tantum soltanto su directory vuota, guard CREATE_NEW; stato corrente assente non viene ricreato automaticamente. Un provisioning interrotto resta bloccato per riconciliazione esplicita.

Lettori e publisher condividono un lock OS esclusivo con tryLock, senza attesa. La lease rimane fino al completamento della transazione tramite l'adattatore precedente. Una JVM distinta non può pubblicare mentre l'owner sta committando. Le operazioni di controllo vengono serializzate per store; una transazione indipendente annidata può essere respinta per contesa.

Stato JSON versionato, tipi/forma rigorosi, checksum SHA256 e massimo4096byte. Pubblicazione con generazione attesa e incremento esatto; stessa prova riconciliata senza cambiare la scadenza. Una prova differente sulla stessa versione non sovrascrive il vincitore. Il pending privato viene forzato su disco, rinominato atomicamente e seguito da fsync della directory. Pending incompleto non autorizza e viene riscritto solo sotto lock; esito incerto richiede riconciliazione della prova esatta.

L'adattatore continua a verificare ammissione/installazione/tenant/generazione. Il registry reale mantiene policy/HUMAN/scadenza; il provider non riammette worker né rinnova budget. Prima di concedere una lease, il provider forza su disco un indicatore privato `lease.active` e la directory. Soltanto un completamento DB noto (commit o rollback) lo cancella e forza, prima di rilasciare il lock. Morte del processo o completamento UNKNOWN lasciano l'indicatore: lettori e publisher rimangono bloccati anche dopo restart. Nessun timeout, PID check o nuovo provisioning lo cancella. Questo evita di usare il rilascio OS come prova che un COMMIT già inviato a PostgreSQL sia concluso.

## Casi nuovi

- Lettura da una JVM nuova, pubblicazione della revoca, riapertura, ripetizione identica e rifiuto della versione obsoleta.
- Publisher figlio respinto nell'intervallo post-audit/pre-commit del vero owner; pubblicazione riuscita dopo commit e blocco successivo del worker precedente.
- Detentore figlio terminato forzatamente: durante il lock l'owner è negato; dopo la morte l'indicatore durevole continua a bloccare owner e publisher, anche dopo riapertura del provider, senza regrant automatico.
- Publisher termina con halt86 dopo persistenza ma prima della risposta. Il processo riaperto riconcilia lo stesso risultato; il replay logico riporta DELIVERED, ma prepare/deliver/owner restano bloccati dalla revoca durevole con postmaster invariato.
- Due publisher con la stessa generazione attesa hanno un solo vincitore.
- Corruzione, payload eccessivo, stato mancante, reprovision automatico e symlink vengono respinti.
- Pending sintetico incompleto ignorato; istanza vecchia respinta dopo sostituzione del guard.
- Prova scaduta, pubblicazione dentro transazione owner e permessi insicuri negati.
- Notifica UNKNOWN di completamento transazione iniettata nel test: l'indicatore resta durevole e non viene cancellato automaticamente da una successiva riapertura. Non è dichiarato un guasto reale di database/rete per questo caso.

## Qualifica del commit finale

| Verifica | Risultato |
|---|---|
| [Native owner 42024429070](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42024429070), job 127234955805 | 80 scenari owner + 8 API/storage = **88 PASS**, zero errori/fallimenti/skip |
| Nuovi casi provider | 9 ricevute PASS; 8 log di JVM figlie; filesystem effettivo ext4 |
| Readback locale dell'archivio nativo | 125 membri, 124 checksum e **273 blob Git esatti**; non ripete l'esecuzione nativa |
| [Regressione fisica 42024429052](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42024429052) | producer 127234955228 e readback 127236034764 SUCCESS; 39 membri, 38 checksum, 276 binding sorgente, 1.695 file backup, 15 alterazioni semantiche respinte |
| CI sorgente | **8/8 SUCCESS**; suite generale 445 riportati − 80 nativi saltati = 365 eseguiti PASS; scan bloccante immagine e avvio container riusciti |
| Checkpoint deploy precedente ee2d208 | **50/50 SUCCESS**; non attribuiti al nuovo commit documentale |

La regressione fisica conserva il driver sequenziale esterno precedente: non dimostra l'integrazione del nuovo provider nel drill fisico né un restore nativo indipendente del readback. Il readback locale di questo turno riguarda soltanto l'archivio nativo. La [ricevuta](../evidence/storage-durable-local-authority-qualified-20261105.json) contiene identificativi, digest e risultati; gli artifact Actions scadono il 3 febbraio 2027.

[Verificatore riproducibile](../scripts/readback-durable-authority-native-20261105.py): eseguire da un checkout Onboarding esattamente a bf8bb65, passando il percorso dello ZIP nativo scaricato; Python standard library, nessun Java/DB/S3 o target richiesto. Non usare Python con ottimizzazioni (-O), perché le verifiche usano assert.

La prima versione ba18f0c aveva già superato 79 + 8 test e tutti gli 8 workflow. La revisione ha individuato che il rilascio OS dopo la morte JVM può precedere la risoluzione di un COMMIT già inviato. Il commit finale aggiunge l'indicatore durevole non risolto e la gestione UNKNOWN, cambia il caso kill in diniego persistente e aggiunge il nono test. Non si presenta la prima versione come qualifica finale; identificativi e risultati sono conservati nella ricevuta.

## Confini effettivi

La qualifica è **fra processi sullo stesso host e filesystem locale**, non multi-host o NFS/CIFS. I tipi ammessi non sostituiscono la qualifica del mount operativo. Lock acquisition non attende, ma non si promette una latenza massima sotto stallo del kernel/disco. Windows non è ammesso dal provider.

Halt/kill provano crash di processo, non perdita di alimentazione host. Il pending interrotto è costruito dal test e non viene presentato come crash strumentato in un punto preciso della scrittura. La protezione assume guard permanente e directory esterna integra: rollback della directory di autorità stessa o manipolazione privilegiata non sono qualificati.

Non viene aggiunto un audit storico approvativo alternativo; questa è una proiezione corrente. Non sono installati percorso produttivo, grant, ammissione Gateway/THS, custodia completa writer o nuovo deployment. Restano aperti startup/recovery operativo, audit dinieghi, ricostruzione budget dopo rollback owner completo, revoca fra host, UDP/Ingestion, rollout misto, riapertura e RPO/RTO.

Prossima coppia proposta: rendere osservabile lo stato durevole non risolto e definire la riconciliazione dell'esito owner; qualificare la ripresa governata soltanto dopo verifica del commit/quiescenza e nuova generazione, senza cancellazioni basate sul solo PID o timeout.

MinIO/source-lock e MiniPET18,3/46=39,78%,0/8gate,0/21AT,0/120oggetti reali invariati. Nessun merge/deploy/target/admission/grant. Tutte le evidenze precedenti restano preservate.
