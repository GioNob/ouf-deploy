# Fase 6: Ingestion creato, Gateway completato e nove grant conservati

**Superato dal fix del preflight**: vedere CHATBOT_INGESTION_ARCHIVE_BINDING_FIX_20261016.md. Il runtime qui descritto ha incontrato AttributeError nel primo tentativo target, prima di nuova autorità.

## Stato VPS confermato

Fasi tecniche 1–5 complete, fase 6 sospesa, 7–8 pendenti, CSV 0/6.
La diagnosi qualificata legge il journal delle 28 nuove modifiche Gateway tutte
APPLIED e due mappe stabili identiche al piano finale: 74 route totali, incluse
quelle estranee preservate. Non confondere 74 route con 37 modifiche complessive.
APISIX ha otto passi conservati. UDP e Onboarding restano nelle stesse generazioni
senza restart. Quattro backup COMPLETE e migrazioni MCP COMPLETE/audit CLEAN.

Container Ingestion cbf3067d946cf21a8f4abbb03ed47a217f2f39624ed1a5fb23a642325129ee35,
status created, PID zero, mai avviato, zero restart. Journal: 11 effetti APPLIED,
ingestion.create CLAIMED, nessuno start. Env è l'unico campo differente: 8 voci
richieste, 11 osservate, composizione esatta dei 6 default dell'immagine e della
richiesta. Nessuna chiave o valore estraneo. MCP applicativo è ancora la vecchia
generazione fermata. Il worker è CANCELLED con 9 tentativi grant cumulativi,
8 precedenti +1, una pubblicazione, admission BLOCKED. La storia legacy resta UNKNOWN.

## Correzione

CohortContainers.candidate legge i default dell'immagine richiesta per ID esatto
e confronta la mappa Env effettiva con default più override richiesti. Duplicati,
chiavi mancanti, valori cambiati e aggiunte estranee bloccano. Una rimozione
esplicita non può essere reintrodotta dai default. Gli altri campi Config restano
confronti esatti; nessuna Env/label privata viene stampata. La richiesta di
creazione, la sua hash e gli intenti già consumati rimangono identici.

La nuova ricevuta tipizzata, dentro lo stesso profilo Gateway già qualificato,
lega review/authority precedenti, journal e worker, container esatto, binding
nativo e mappa finale. La catena privata completa è riletta e congelata, comprese
le due precedenti continuazioni e i claim consumati. L'identità firmata di
Ingestion viene controllata anche dopo l'adozione, per escludere la sostituzione
concorrente con un'altra generazione apparentemente uguale.

Il nuovo journal conserva 11 APPLIED e il create CLAIMED. Solo l'osservazione
in sola lettura può chiudere quel claim; non viene emesso un secondo create o
rename. Seguono una sola prenotazione di start, readiness e verifica schema,
con i budget persistenti già previsti. Esiti ambigui richiedono riconciliazione.
Il Gateway adotta anche il journal delle 28 modifiche completate e verifica
la mappa finale prima/dopo: zero nuove scritture, zero sostituzioni APISIX.
Duplicati, drift, revoca e claim già consumati bloccano; i journal precedenti
non vengono modificati. I quattro archivi validi sono verificati e copiati,
mai rigenerati; nessun restore, bootstrap audit o replay delle dieci fasi Registry.

La nuova revisione HUMAN autorizza una nuova finestra finita di massimo 128
nuovi tentativi e 3600 secondi, entro la scadenza umana, mantenendo i nove
precedenti. Il prossimo nuovo tentativo sarà il decimo cumulativo. Nessun nuovo
primo grant, reset storico o rinnovo automatico. Sono mantenuti jitter,
Retry-After, cancellazione e revoca; le letture dell'autorizzazione ricostruiscono
i ruoli solo dalla ricevuta immutabile con policy owner attuale identica.
Dopo l'avvio di MCP una nuova lettura MCP reale è obbligatoria prima di rilasciare
i produttori. Le approvazioni applicative HUMAN restano nel THS.

## Configurazione e limite della qualifica

Domini, route, endpoint, trust, chiavi, reti e storage restano nei piani approvati.
I pin storici di questo incidente non sono default per altri Enti. Questo
adattatore Docker/netns non dimostra una distribuzione multi-host o multi-rete.
Le prove native usano fixture dichiarate: non avanzano la roadmap del VPS e
non dimostrano il CSV end-to-end.

## Versioni operative

Sorgente runtime: a2132d7ee330f9f0ce7d4fc9316dd880acad4f3f.
Capsula: 130 membri, SHA256 b27731fb30b545d1c42751f0c6f92384501a46937b9cbf071d2db1ed780c3d04.
Delivery SHA256: 48c5e2d3ca39b73b8d528e5f44cb1f5bd2713b82af784ea7d284a887868c49dd.
Launcher scripts/launch-chatbot-ingestion-created-20261016.sh,
SHA256 86cda068263765704834ec6cb442fddb8c6164f78976f1da74d7d515da604dd9.
Qualifiche concluse; launcher operativo pubblicato per una nuova revisione HUMAN finita.


## Qualifiche specifiche concluse

CI nativa 38877206131, sorgente fixture f09e6838ae27efbd2e525ad7348d1ed5a64af1c5:
job 116895011078 PASS: APISIX reale e adozione delle 28 modifiche senza nuove
scritture o cicli di vita; Docker reale riproduce 8 Env richieste, 6 default
immagine, 11 osservate, due letture della stessa generazione creata e un solo
start di quel container. Le immagini scratch sono fixture con binario statico;
non provano la readiness dell'applicazione Ingestion target.
Job 116895011470 PASS: 20 test in sei suite, inclusi 9 grant TLS conservati e
10° effettivo, review di fase 6, cinque test di custodia/adozione, budget duraturi,
jitter/Retry-After, revoca e nessun replay. Il flusso di adozione container usa
signer, journal privati e socket Unix reali con gli effetti Docker simulati;
la prova fisica Env/identità/start è separata e dichiarata.

La sorgente runtime a2132d7ee330f9f0ce7d4fc9316dd880acad4f3f è identica nel
contenuto eseguibile e nella capsula a f09e6838ae27efbd2e525ad7348d1ed5a64af1c5:
la comparazione GitHub contiene soltanto la fixture e il filtro del workflow.
I due precedenti fallimenti CI erano fixture (UID, mandato corrotto per prova
negativa e PATH implicito), non nuovi tentativi sul VPS. Nessuna qualifica viene
presentata come avanzamento dell'installazione o accettazione end-to-end.

## Qualifica generale conclusa

CI generale 38876888992, job 116894441077, runtime a2132d7ee330f9f0ce7d4fc9316dd880acad4f3f: PASS, 494 test in 67 suite. Comprende le prove PostgreSQL native sui quattro archivi, migrazioni e revoca, oltre ai journal e alle riconciliazioni. CI backup 38876889037, job 116893970691: PASS. Gli errori PostgreSQL attesi nelle prove negative di permessi e sola lettura non sono fallimenti della suite.

La pubblicazione non esegue il launcher sul VPS: stato target ancora fase 6/8 sospesa, fasi 1–5 conservate e CSV 0/6. Nessuna nuova autorità runtime emessa dalla qualifica CI.
