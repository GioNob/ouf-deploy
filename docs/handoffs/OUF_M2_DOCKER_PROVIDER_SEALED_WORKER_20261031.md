# M2 — Provider Docker ammesso e worker sigillato

31 ottobre 2026, Europe/Rome. Incremento della PR54. Teatri resta il caso
completato a passi singoli: M1/G4, tecnico8/8 e funzionale6/6 acquisiti. Farmacie
conserva lo stesso profilo SUCCEEDED61righe/10colonne, codice ministeriale STRING
e tutti10campi OPEN. Nessun nuovo upload, profiling o acquisizione.
M2/G5–G7,24AT,8UX,8stabilità e due client restano aperti.

## Risultato certo

Il passaggio iniziale con Docker reale è PASS nella PR a sorgente
`f6ace16126a9abfd314f3b11b9d35df968ae821f`, run41152208212,
job124391072474, report finali letti. Un solo create e un solo start del provider
tramite Engine e runtime v4 registrato; risposta start realmente persa, poi
riconciliata. Broker, attestor, installer e driver verificano fullOCI indipendente,
rootfs, generazione e NIC. Il sigillo rootfs deriva da un peer di controllo
separato, qualificato prima del candidato e della review; il suo OCI non viene
usato come policy del candidato. Immagini/review e predecessore di ammissione
completa del Registry sono fixture esplicite.

Lo stesso provider ammesso alimenta un worker distinto con DNS/nft reali,
pubblicazione e rinnovo delle due famiglie, errore DNS/cacheTTLzero, revoca,
backoff senza query/tentativi prematuri e ripresa con clock e contatori originali.
L'arresto reale del provider tramite l'operazione kill supportata blocca il worker,
revoca le lease e non produce restart/riarmo. Il Registry rimane paused al gate.
Il precedente runc pause/resume resta una prova distinta: l'adapter ammesso
intenzionalmente non supporta Docker pause/unpause.

## Correzione di composizione

Il broker usava il lettore privato0600 anche per il config.json del peer Registry,
che containerd crea root:root0644. La revisione pura e fissata a hash
`repair_peer_bundle_sources.py` specializza soltanto la lettura OCI del peer:
config.json nel CID esatto restituito dal runtime autenticato, antenati root non
scrivibili da altri, file regolare root:root0644, un link, dimensione finita,
metadati del descriptor/percorso stabili e hash fullOCI atteso firmato. Le due
osservazioni di OCI/generazione/NIC restano obbligatorie. Errori sconosciuti non
vengono riclassificati o ritentati. Chiavi, credenziali, authority, policy e journal
conservano i lettori privati. Il profilo discovery richiede l'esatto nuovo hash.
Draft originale, riparazioni storiche e capsule congelati restano immutati.

Il fixture iniziale registrava inoltre un runtime ancora assente al momento
della discovery delle feature Docker: i mount risultavano diversi e l'ammissione
li negava. Un bootstrap CI solo features/version, che nega ogni lifecycle, ora
precede il daemon. Il wrapper di profilo viene preparato prima della review;
il vero owner mantiene il singolo CAS. I mount attesi non vengono copiati dall'OCI
osservato. La prova successiva passa l'ammissione nativa completa.

## Unit sigillata: prova congiunta PASS nel fixture, stabilità generale aperta

La nuova modalità --sealed-worker usa lo stesso MaterializedProviderAdmission,
Registry/provider/Engine/parent/child/kernel/lock, con WorkerMaterialization reale,
firme, pubblicazione create-only, registrazione e avvio systemd. Il predecessore
Registry completo è ancora modellato, esplicitamente. Un kernel-lock in una
directory dedicata impedisce al sandbox readonly di esporre la chiave del signer.

Il tentativo a f6ace161 ha raggiunto il worker ACTIVE ma la riconciliazione finale
è stata negata per scadenza del child sintetico90s. Il successore assegna la nuova
autorità iniziale CI alla finestra parent120s, prima di creare i due candidati;
non prolunga authority già in uso, non rinnova budget e non modifica limiti/guard
produttivi. Elimina una ricostruzione duplicata del materializer e riconcilia lo
start appena c'è la prima pubblicazione; il rinnovo operativo viene verificato
dopo il readback installativo. Sorgente attuale
`5870e73f8d9fd13ed115f3aa7aced541cb7d4ccf`: passaggio finito PASS,
osservazione della unit UNKNOWN. Successore diagnostico
`7d124c9c967c5a5f43945e2f183ff8b68ffb6406`: entrambi i job PASS nella
PR41152837404, finite124393038001 e sealed124393038158; report finali letti.
Nella stessa prova sealed il provider Docker è ammesso v4 e il vero worker viene
materializzato, attestato/pubblicato/registrato/avviato e osservato positivamente.
Risposte provider/systemd perse senza secondo start; SIGKILL/reentry conserva
clock/contatori. L'arresto provider revoca/blocca senza restart o riarmo.
Firma privata nascosta, soloCAP_NET_ADMIN e NoNewPrivileges verificati.
Il precedente UNKNOWN non si è riprodotto con la diagnostica: causa ancora
ignota, nessuna guardia allentata, nessuna accettazione generale di stabilità.
I due modi usano runner indipendenti e non riutilizzano fixture consumati.

## Validazione e residuo

PASS locali completati:13worker,8profili provider,7lettore OCI pubblico,
1composizione anticipata;7test degli artefatti immutabili in19.773s.
La suite runtime locale è stata interrotta dopo tre casi stampati PASS:
nessuna nuova qualifica di suite completa. CI estesa e48e3fd7 PASS:440test/52suite/zero skip, PR41151383885/
job124388475217, report finale letto. I commit successivi fino a7d124c9c cambiano fixture native
e workflow. Il successore produttivo07734a75 conserva diagnostica sicura delle
letture UNKNOWN e viene qualificato separatamente. La qualifica432test/50suite del
precedente05456554 resta acquisita nel suo perimetro. Cause delle precedenti anomalie locali MCP/worker non risolte.

[Evidenza e fallimenti conservati](../../evidence/m2-provider-docker-worker-20261031.json).
Restano: causa UNKNOWN/stabilità, coorte corrente completa/TLS/IAM/DB/fencing/trust,
compilatore/review/CLI privati, pubblicazione coordinata delle capability, reale
Farmacie→Ingestion→UDP con tutti61esiti, reimport invariato, fault/recovery,
continuità chat/boot/rotazione e due client. Search sugli oggetti rimane separata
dal caricamento; verticali/API/scheduler/delta seguono il flusso file completo.
Nessun nuovo comando operatore pronto, apply target, grant/authority di produzione,
reset/replay, merge o accettazione di rilascio.


## Successore diagnostico07734a75

La lettura privilegiata negata perdeva la causa nella conversione UNKNOWN del
LeaseStartAdapter; la sequenza perdeva inoltre l'evidenza del sottopasso pendente.
Ora conserva una categoria di lettura e un codice da vocabolario finito;
nessun testo arbitrario, percorso, errno, argv o output processo viene esportato.
Il sottopasso START resta consumato: nessun nuovo avvio, retry, ricevuta positiva,
reset di contatori o nuovo permesso. Il ripristino in un processo di test dei
soli due metodi precedenti riproduce entrambi i dettagli mancanti. Il successore
passa9test start in6.760s e15test sequenza in173.703s, inclusa la conservazione
byte per byte dei journal durante la lettura UNKNOWN e la successiva lettura
positiva senza altro start. Non è la riproduzione del vecchio UNKNOWN nativo.

Sorgente07734a75: Docker PR41153678783, finite124395660746 e
sealed124395660459 entrambi PASS; report finali letti. Passano inoltre worker
PR41153678754/job124395660081 e lifecycle MCP PR41153678861/job124395660872,
con i rispettivi limiti di fixture. Protocollo esteso PR41153678695/
job124395659985 PASS443test/52suite/0errori/0skip, report finale letto e
tutti3nuovi casi di regressione eseguiti.
[Evidenza diagnostica](../../evidence/m2-worker-observation-diagnostics-20261031.json).
Le cause UNKNOWN/stabilità, coorte completa e percorso Farmacie→UDP restano aperti.
