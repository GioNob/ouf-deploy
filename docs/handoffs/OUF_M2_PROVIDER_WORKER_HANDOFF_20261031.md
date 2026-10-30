# M2 — Passaggio iniziale provider ammesso → worker distinto

31 ottobre2026, Europe/Rome. Incremento PR54. Sorgente iniziale4d3965a9,
successore09930619 PASS su push41144149193/job124365161963 e
PR41144156259/job124365184371, entrambi i report finali letti.
Ammissione iniziale misurata2.526s/2.113s.4test del compilatore broker PASS
in ciascun job; prova provider isolata e nuova prova congiunta entrambe PASS.

## Prova concreta

La prova provider già esistente continua a eseguire broker, attestor, driver,
wrapper CAS, ammissione v4, OCI/rootfs/NIC runc e firme reali. Mantiene il caso
start con risposta persa, riconciliato senza un secondo avvio, e il gate Registry
chiuso e paused. La modalità CI aggiuntiva --worker-handoff consuma l’ammissione
MaterializedProviderAdmission reale dello stesso candidato per un processo worker
distinto. Usa build_worker/DiscoveryRecovery, DNS, nft e lo stesso kernel/binding/
lock; crea un journal di coordinazione separato e conserva quello del provider.

L’ammissione iniziale completa produce una prova verificata dei cinque record
protocollo e dell’adapter. Il fixture conserva byte e identità dei record e dei
journal finiti, controlla scadenza firmata, parent/child correnti e generazioni
runc effettive. Non ricalcola l’intera installazione ad ogni controllo. Il codice
di questo guard è solo CI e finito: non sostituisce il contratto di fiducia e
vita operativa del servizio installato, già qualificato separatamente.

Il processo distinto esercita pubblicazione e rinnovo sulle due famiglie nft,
DNS non cacheabile → revoca → backoff persistito senza nuove query/tentativi,
ripresa con clock originali e contatori cumulativi, invocazione concorrente
negata e pause reale del provider → worker BLOCKED. Il ritorno del provider non
deve riarmare il worker bloccato. Il Registry resta paused; nessun producer viene
rilasciato. Le query DNS e le attese devono trovare liberi lock comune e lock
breve del journal; il lock di invocazione resta dedicato al processo.

## Fallimento iniziale conservato

Push41143707713/job124363746484 e PR41143712908/job124363763535 falliscono
nella nuova prova: primo tick circa25secondi, RETRY_WAIT/DNS_WINDOW_TOO_SHORT,
1tentativo e0pubblicazioni. Il provider isolato passa in entrambi. Il fixture
richiamava l’intera ricompilazione/verifica installativa ad ogni guard.
Il successore consuma la prova iniziale e ne verifica i sigilli correnti;
timeout, TTL e policy di produzione restano invariati. Il budget CI è dichiarato
nel sorgente, non è una concessione o un reset sul target. Le fixture di ogni run
sono nuove e isolate. Nessun tentativo precedente viene rigiocato.

## Confini di accettazione

Il confine Docker del fixture provider resta modellato, immagini/review e
predecessore applicativo Registry sono sintetici. runc/PID/namespace/OCI/rootfs/
NIC, protocollo Ed25519, processo worker, DNS/nft, lock e journal sono reali.
Questa prova non esegue WorkerMaterialization, firma/pubblicazione/registrazione
e avvio della unit systemd sigillata con questi due peer. La precedente prova
systemd/Docker con ammissione applicativa sintetica rimane separata.

Non è coorte Docker completa, vita operativa indefinita, boot/rotazione,
pubblicazione delle capability o Farmacie→UDP. Nessun modulo di produzione o
capsule congelato è modificato.13test locali della factory/accounting/guard
worker PASS0.115s; qualifica432test/50suite del codice produzione conservata.

[Evidenza](../../evidence/m2-provider-worker-native-handoff-qualified-20261031.json).
Prossimo: comporre il confine Docker reale con la stessa ammissione v4 e la
materializzazione/attestazione/pubblicazione/registrazione/avvio del worker
sigillato, poi coorte completa/TLS/IAM/DB/fencing/trust e compilatore/review/CLI
privati. Soltanto dopo: pubblicazione coordinata e vere capability Farmacie.

Teatri M1/G4 e tecnico8/8/funzionale6/6 acquisiti a passi singoli. Farmacie conserva
stesso profilo SUCCEEDED61righe/10colonne, codice ministeriale STRING e10campi
OPEN. G5–G7/M2,24AT,8UX,8stabilità e due client restano OPEN. Nessun nuovo
upload/profiling/acquisizione, target apply, authority/grant/budget/reset/replay,
merge o release acceptance; nessun nuovo comando operatore pronto.
