# Onboarding — autorità corrente separata dal ripristino

## Due passi

1. Definito il contratto interno di binding alla piattaforma e implementato il vincolo a installazione, sessione di esecuzione e avvio PostgreSQL. Un nuovo avvio non può adottare automaticamente una decisione o una prova di quiescenza salvata nel backup.
2. Estesa la qualifica nativa: nuovo processo, autorità revocata dopo il taglio, fonte corrente assente e processo mantenuto vivo attraverso il ripristino fisico devono restare bloccati.

È un contratto di integrazione e una qualifica del controllo owner con adattatore sintetico. Non è installato un emettitore/adattatore produttivo Authorization/THS/Gateway, né sono stati riutilizzati permessi HUMAN sui singoli file.

## Implementazione

`StorageRecoveryRuntime.start(installationRef, db)` genera una nuova sessione casuale fuori dal database e campiona `pg_postmaster_start_time()`. Costruttore privato, nessun ingresso di deserializzazione o ripristino del nonce. L'istanza va mantenuta per la vita del worker, non ruotata per aggirare i limiti.

Ogni transazione owner verifica il medesimo avvio PostgreSQL prima di leggere il gate. Una JVM sopravvissuta al riavvio/ripristino del database deve quindi fermarsi, anche se il vecchio record ripristinato appare valido. Installazione e sessione della decisione devono coincidere con il runtime. La quiescenza ha un binding separato alla stessa sessione: rinnovare il collegamento dell'autorità non rende corrente una vecchia prova di custodia.

Restano invariati controllo epoch/fase, esatto binding prima/dopo GET, budget128/24h degli intenti, limiti transazionali12s/lock2s/statement5s, audit atomico e scadenza ricontrollata dopo audit. Il nuovo runtime non riapre FROZEN, non cambia epoch, non azzera budget e non prolunga decisioni.

Il contratto dettaglia identità di installazione, decisione corrente, custodia, responsabilità dei proprietari e protocollo ancora necessario per la revoca esterna concorrente. Il solo accesso una tantum a una fonte remota non viene presentato come revoca coordinata.

## Prova fisica

La fonte corrente della decisione è modellata da un file test-only esterno a tutte le directory di export/restore dell'owner. Prima della riconciliazione, una nuova JVM rifiuta il binding del processo precedente senza consumare letture; una nuova attestazione sintetica dell'esistente decisione corrente conserva la scadenza e non abilita la quiescenza. Questa viene registrata soltanto dopo i tre dinieghi S3 nativi già previsti.

Dopo il punto PostgreSQL nominato, la fixture revoca sia la decisione corrente esterna sia la proiezione locale. Il ripristino al punto precedente restituisce intenzionalmente una proiezione locale NON revocata. Una nuova JVM rifiuta quel runtime; il tentativo di attestazione fresca contro la decisione corrente revocata è respinto. Anche nascondere temporaneamente il file corrente deve produrre un diniego, mantenendo inalterati owner e audit. Il file corrente non viene estratto dagli archivi.

Un'altra JVM resta viva prima della distruzione del database originale e fino alla promozione del ripristino positivo. Il diverso avvio PostgreSQL deve essere rilevato prima dell'accesso al gate e del completamento del freeze. Il watchdog è finito e non tiene transazioni aperte mentre attende.

Il verificatore indipendente lega sessioni dei processi, audit, budget invariato sui dinieghi, byte della decisione corrente, revoca locale successiva al taglio e proiezione precedente recuperata. Le nuove mutazioni semantiche del pacchetto sono respinte anche ricalcolando i checksum esterni. Non è un secondo restore nativo su un altro runner.

## Qualifica

Fonte qualificata `c1d0dd22eebbd27565ccbc86a225ea4a69c8a1f9`,[PR Onboarding54](https://github.com/GioNob/ouf-source-onboarding/pull/54).
- [Nativi42003559195](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42003559195)/job127164563518: **42scenari owner+8API/storage PASS**,zero failure/error/skip. Sette nuovi casi rispetto al checkpoint5d9ba774.
- [Fisico42003559164](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42003559164):producer127164563597 e readback127165487012 **SUCCESS**,inclusa JVM mantenuta viva attraverso il restore. **38membri/37checksum/266sorgenti/1680file backup**,nove negativi semantici respinti.
- System ID `7704618884206514216`,target `ouf_onboarding_upload_frozen_v39`,stessa immagine PostgreSQL acquisita e OCI33 già qualificata. Due oggetti/36byte,sei AccessDenied,dodici arresti storage e due PostgreSQL puliti. Nessuna nuova scansione immagine attribuita per analogia.
- **CI sorgente8/8SUCCESS**,incluse [PR42003566793](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42003566793) e [push42003559325](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42003559325),scansione bloccante e avvio container. Suite generale407riportati meno42native saltati=365eseguiti PASS;42native eseguiti separatamente.
- Deploy precedente `8f210c07fd1673eec20a49cf73911dede9540047`:50/50workflow SUCCESS. I controlli del nuovo checkpoint documentale sono separati.

[Ricevuta completa](../evidence/onboarding-runtime-binding-qualified-20261105.json).
- Artifact13403337484 (onboarding-common-cut-readback-42003559164):7106525byte,`sha256:ad62bcad183649bd19125f00102ce475fa46275fff0a5d1c8c7418321c72b076`,custodia fino2027-02-03T09:34:58Z.
- Artifact13403058364 (onboarding-common-cut-42003559164):7109639byte,`sha256:0ba25f6901c4f77739eee08f335b692403bf7eccf4df2ef37ed5c8c361e5ff9f`,custodia fino2027-02-03T09:34:58Z.
- Artifact13404530154 (onboarding-upload-native-42003559195):86927byte,`sha256:7b1cd8d55c78cbe8c345d6a9a685a508c97e05726d37f42a21f7221e86eb14f4`,custodia fino2027-02-03T09:34:58Z.

Qualifica riuscita alla prima esecuzione. Verifiche locali:diff senza errori,sintassi Python e regressione placeholder WAL PASS. Java/PostgreSQL/S3 verificati sui runner Linux; nessun terzo download locale degli ZIP dichiarato. Prove e descrizioni PR precedenti conservate integralmente.


## Limiti e prosecuzione

La fixture del file corrente non è un servizio Authorization produttivo e non qualifica una revoca distribuita concorrente. Restano aperti capability/resource contract approvato, attestazione autenticata, collegamento Authorization/THS/Gateway, custodia di tutti i writer, audit dei dinieghi e revoca esterna coordinata con le proiezioni locali.

Il controllo dell'avvio PostgreSQL copre restart/restore fisico. Un rollback logico a postmaster invariato richiede un fence della generazione di installazione distinto e non è qualificato qui. UDP/Ingestion, rollout misto, riapertura e RPO/RTO rappresentativi restano aperti.

Prossima coppia: predisporre il contratto applicativo di recovery storage nell'owner Authorization/piattaforma, senza assegnare grant runtime; poi qualificare la consegna e revoca della decisione fra autorità e proiezione owner, inclusi esiti ambigui e generazioni obsolete. Prima verificare i contratti originali e lo stato dei repository coinvolti.

MinIO/source-lock e MiniPET18,3/46=39,78% invariati;0/8gate,0/21AT,0/120oggetti reali. Nessun merge/deploy/target/admission/replay/reset/grant. Prove precedenti preservate.
