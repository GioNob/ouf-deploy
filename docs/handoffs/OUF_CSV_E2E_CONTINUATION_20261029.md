# CURRENT — Composizione selezionata qualificata; Farmacie conserva il profilo

30 ottobre2026, Europe/Rome. Teatri è completata a passi singoli: riusarne
componenti e prove per il flusso completo, ripetibile e resiliente di ogni file.
M1/G4,tecnico8/8,funzionale6/6 restano acquisiti per Teatri; M2 generale rimane
aperto. Farmacie conserva lo stesso asset/job/profilo SUCCEEDED61righe/10colonne,
codice ministeriale STRING e10campi OPEN. Nessun nuovo upload/profiling o terza
acquisizione Teatri. La sequenza ordinaria termina in UDP con esiti per riga;
search sugli oggetti e verticali/API/scheduler/delta restano successivi.

[PR54](https://github.com/GioNob/ouf-deploy/pull/54), sorgente05456554:
il coordinatore riusa immagini selezionate, Registry/provider/worker fino alla
barriera, Gateway e MCP. Stessi parent/child/Engine/transizione/review obbligatori.
Il lock dedicato della transizione impedisce un rilascio concorrente dei producer
durante Gateway/MCP; le pause si propagano e lo rilasciano senza dormire.
Prove finali in sola lettura e cronologia Registry invariata. Nessun nuovo motore
retry, inizializzazione journal o metodo di rilascio. Barriera logica, non una
nuova attestazione fisica di quiescenza o dell'intera coorte.

Gateway discovery v2 consuma ogni dispatch con marker esclusivo/fsynced separato
dal journal mutabile; riprodotta la regressione precedente del secondo connect,
poi testata la correzione e la ricostruzione dopo start con risposta persa.
Executor discovery vincola i due campi runtime del child al parent corrente
autenticato; campi sconosciuti sono negati prima del claim. Il percorso constructor
è testato con firme/journal reali. La CI intermedia4b71 ha rilevato il byte drift
dell'executor condiviso rispetto all'artefatto immutabile: file ripristinato
esattamente, specializzazione solo discovery, artefatto/test/pin intatti.
Tutti142moduli congelati coincidono; esecuzione/CAS/riconciliazione ereditati.

Protocollo05456554 PASS432test/50suite/zero skip per evento:
push41133846758/job124331281185 e PR41133853136/job124331301342;
entrambi i report finali letti. Qualifica dei componenti/composizione, non E2E target.
65test locali pertinenti più7test artefatti PASS. Immagini native PR41133852958/
job124331301145 e MCP PR41133853046/job124331301207 PASS/report finali letti:
Docker29.8.1, due load senza replay, start perso riconciliato dopo ricostruzione,
503/RetryAfter→204/backoff e tentativi originali. App MCP HTTP statica e
parent/package/admission sintetici: non prova del vero MCP/coorte/composizione
nativa completa. CI recovery41133852937 PASS586test/64suite con2skipTLS
esplicitamente subordinati a scope nativo; altri2testDB e3paused-generation
PASS; tutti report finali letti. Anomalie locali MCP/worker precedenti restano
senza causa dimostrata, nessuna guardia indebolita.

[Evidenza](../../evidence/m2-discovery-selected-runtime-qualified-20261030.json)
e [checkpoint e prossimo lavoro](OUF_M2_SELECTED_RUNTIME_20261030.md).
Prossima prova concreta: provider v4 e worker distinto reali insieme sullo stesso
Registry/Engine/parent/child; poi coorte corrente completa e TLS/IAM/DB/fencing/
trust, compiler/review privata/CLI sigillati e pubblicazione coordinata.
Restano discovery reale Farmacie, mapping pinned/THS, Ingestion/UDP/esiti61righe,
reimport invariato, fault/ripresa/cambio chat, boot/rotazione e due client.
M2/G5–G7/24AT/8UX/8stabilità OPEN. Nessun comando operatore nuovo pronto:
scope/input precedenti consumati. Nessuna nuova authority/grant/budget/reset/
replay/merge/accettazione o effetto target dedotti. Header seguenti storici.

# CURRENT — Teatri riusata per il flusso generale; Farmacie corrente; recupero MCP qualificato

30 ottobre 2026, Europe/Rome. L'owner chiarisce: Teatri è completata a passi
singoli; riusare quanto realizzato per un flusso completo, ripetibile e resiliente
per ogni file. Farmacie è il caso attuale. M1/G4, tecnico8/8 e funzionale6/6
rimangono acquisiti per Teatri; non equivalgono all'accettazione generale M2.
Nessuna terza acquisizione Teatri e nessun nuovo upload/profiling Farmacie:
stesso profilo SUCCEEDED61righe/10colonne, codice ministeriale STRING e10campi
OPEN già confermati.

La sequenza ordinaria riusa asset/job, proposta e compiler, semantica locale
pubblicata ed eventuale discovery OntoPiA governata, review/onboarding,
Ingestion e riconciliazione/materializzazione UDP con esiti di tutte le righe.
Search sugli oggetti caricati resta separata; verticali/API/scheduler/delta seguono
questo percorso file. Non riscrivere pipeline o motori già esistenti.

Nuovo incremento [PR54](https://github.com/GioNob/ouf-deploy/pull/54):
test di risposta persa più rigoroso, che richiede errore Engine esatto e prova
del dispatch; qualifica nativa del solo MCP con Docker29.8.1, Engine, HTTP,
Ed25519 e journal reali. Risposta di start persa riconciliata dopo ricostruzione,
nessun secondo avvio, montaggi/restart policy preservati, repeat senza cambi e
revoca bloccante. Successore dc16fa46 prova davvero503/Retry-After→204:
backoff persistito senza nuovi health/lifecycle, start e tentativi cumulativi
conservati attraverso un'altra ricostruzione. Push41123600168/job124296302282 e
PR41123610248/job124296342265 PASS; entrambi report finali letti.
Protocollo d4410db9:391test/46suite/zero skip per evento, push41123284691/
job124295154658 e PR41123296096/job124295188542 PASS/report finali letti.

[Evidenze](../../evidence/m2-discovery-mcp-native-qualified-20261030.json) e
[checkpoint di riuso e limiti](OUF_M2_SINGLE_MCP_NATIVE_20261030.md).
L'app del fixture è HTTP statica; parent/pacchetti/ammissione Registry sintetici.
Non prova il vero binario MCP, coorte completa, capability installate o CSV→UDP.
Le due anomalie locali MCP_INVOKING_RECORD_DRIFT e DETACHED_VERIFICATION_UNPROVEN
restano senza causa dimostrata; CI positiva non le cancella, guardie invariate.

Sole letture live ouf-admin: MCP HEALTHY; Farmacia CLASS search [] per quella
query; ingestion.status DENY permanente non ritentato, non regressione Teatri.
Discovery non ancora esposta nel plugin installato. Prossimo: composizione
provider/worker e coorte corrente, TLS/IAM/DB/fencing/trust, compilatore/review
privata/CLI sigillati, pubblicazione coordinata; poi vera discovery Farmacie,
mapping pinned, Ingestion/UDP, reimport invariato/fault/ripresa/cambio chat,
boot/rotazione e due client. M2/G5–G7/24AT/8UX/8stabilità restano OPEN.
Nessun nuovo comando operatore pronto o effetto target/authority/grant/reset/
replay/merge/accettazione dedotto. Input/scope precedenti restano consumati.
Header seguenti storici.

# Caricamento CSV → UDP e capabilities sugli oggetti caricati

# CURRENT — Go 1.27.3 e pacchetto MCP qualificati; import immagini nativo PASS

30 ottobre 2026, Europe/Rome. L’owner approva l’ultima Go stabile/supportata:
«Va benissimo usare l'ultima versione di go. Anzi, direi che è auspicabile.»
[Decisione acquisita](../decisions/OUF_MCP_GO_BASELINE_ALIGNMENT_DECISION_20261030.md) supera il vincolo minor1.25 di Matrix1.7/MCP1.4 §65.
Versione corrente risolta nei tag/VERSION ufficiali:1.27.3, commit2aae1000.
Pin esatto/checksum e tutti i gate restano obbligatori, SDK1.7.0/contratti invariati;
originali DOCX/checksum intatti. Non chiedere nuovamente approvazione per la sola
versione Go. Pacchetto MCP09d1f521/12882394596 Go1.26.10 conservato storico:
nuovo candidato/build/pacchetto1.27.3 acquisiti nel perimetro documentato seguente.
MCP9539cbb4/PR81 qualificato: full CI push41088404381/job124175536886 e
PR41088414424/job124175572636 PASS, report finali letti. Go1.27.3/checksum
ufficiale/SDK1.7.0, race/DB/pairwise/build, Staticcheck2026.2.2+nilness e
Govulncheck ufficiale pinnato: nessuna vulnerabilità rilevata. Le due precedenti
incompatibilità degli analizzatori sono conservate e corrette senza suppression.
Pacchetto12993233270 producer6aad7448/run41090381338/job124182417709 PASS:
262blob/10payload/modi644-755/config/layer/binario verificati indipendentemente;
ELF Go1.27.3/SDK1.7.0, SBOM36componenti, report tutte le severità0.
Immagine2321c66f…; prima build12993555804 esclusa per tar664/775, mantenuta storica.
Evidenze: evidence/mcp-go127-source-and-package-qualified-20261030.json e
readback associato. La qualifica non è trust del publisher/ammissione target.
Nessun grant/replay/reset/autorità runtime o accettazione M2 dedotti.

Deploy54 sourcec62d0b2156e43943a50e13995092566c9fc99fb3:365test/43suite PASS
su push41039846376/job124009671934 e PR41039855443/job124009703393,
zero skip, tutti i report finali letti. Include6test import Registry+MCP con
archivi/firme/journal reali e Engine/CLI modellati, anche regressione deliberata
record senza seconda dispatch. Nativo worker PR41039855426/job124009703075 e
provider PR41039855535/job124009704662 PASS separati, report letti; ammissioni
applicative worker sintetiche/confine Docker provider modellato. Nessuna prova
combinata/coorte target/E2E o8stabilità; cause UNKNOWN/drift storico non stabilite.
M1/G4,technical8/8,functional6/6 e Farmacie61righe/10colonne/STRING/OPEN conservati.
M2/G5–G7/24AT/8UX/8stabilità/due client OPEN. CSV→UDP/esiti per riga;
capabilities UDP separate sugli oggetti caricati, search fuori dal caricamento.
Import Registry+MCP su Docker29.8.1 reale PASS a source9c93274f: push41090657018/
job124183350825 e PR41090667765/job124183389246, report letti. Una load ciascuno,
risposta persa riconciliata via GET, seconda apply senza cambi di journal, revoca
bloccante; parent/review/package/applicazioni sintetici, nessun container applicativo
avviato. Coorte completa e CSV→UDP target ancora OPEN.
Nessun comando operatore pronto; scope precedenti consumati. Proseguire autonomamente.
Header CURRENT successivi sono cronologia, non richieste di nuova approvazione Go.

# CURRENT — provider e worker qualificati separatamente; composizione e coorte M2 ancora aperte

30 ottobre 2026, Europe/Rome. [Deploy54](https://github.com/GioNob/ouf-deploy/pull/54):
provider v4 nativo PASS su push/PR; cutover/worker356test/42suite PASS su push/PR,
zero skip e report finali letti. Worker tardivo nativo PASS su entrambi gli eventi:
cattura Docker reale, nuovo fence, firme/file/registrazione/start, risposta persa
riconciliata senza secondo avvio, systemd/DNS/nft e capsule37moduli invariata.
Le ammissioni applicative del fixture worker sono sintetiche; il confine Docker
del fixture provider è modellato. NON è ancora la prova comune di provider v4
reale+worker, coorte completa o target CSV→UDP. Un primo test nativo ha restituito
UNKNOWN con worker ACTIVE: causa non stabilita, fallimento conservato; i PASS
successivi e la diagnostica CI non provano da soli la stabilità.

Source921212074a901b514794118083b37f0f60fe3e63 aggiunge uguaglianza esatta
provider/worker di kernel,DNS,binding,nft e lock, oltre alla ricetta
Registry, e rifiuta il riuso su boot diverso. Journal provider conservato e
ledger worker nuovo/distinto: il vincolo iniziale sullo stesso path è stato corretto
prima di ogni consegna target.16casi locali PASS; CI successore
ancora in corso. [Evidenze e limiti](https://github.com/GioNob/ouf-deploy/blob/feat/m2-discovery-complete-profile-20261029/evidence/m2-discovery-installation-composition-qualified-20261030.json).
[Selezione pacchetti corrente](../../releases/m2-discovery-cohort-selection-20261030.json):
Registry4f8fb581/MCP09d1f521/Gatewayc666c0f0; Gateway607 è storico. Selezione e
qualifica sorgenti NON sono review privata eseguibile, installazione o authority.

Technical8/8,functional6/6,M1/G4 acquisiti per il caso conservato; M2/G5–G7,
24AT,8UX,8criteri stabili e due client reali restano OPEN e nel denominatore.
Farmacie stesso profilo SUCCEEDED61righe/10colonne, STRING/OPEN già confermati.
Caricamento termina con oggetti UDP ed esiti di tutte le righe; capabilities UDP
sugli oggetti carichi qualificate separatamente, search non è una fase.
Receipt1868/runtime contract CONSUMATI, provider target osservato fermo; nessun
nuovo effetto target o lettura indipendente. Nessun comando operatore pronto.
NEXT prova comune provider/worker e coorte corrente, binding/review privata,
TLS/IAM/DB/fencing/trust, boot/rotation/pubblicazione e vero collaudo CSV→UDP.
Continuare autonomamente; no replay/reset/grant/budget/upload/job/acquisizione/
merge/subagenti/automazioni. Header successivi storici per il prossimo passo.



> **30 ottobre — runtime contract osservato, scope consumato.** [Ricevuta](../../evidence/m2-provider-runtime-contract-target-20261030.json) e [footer forniti dall’owner](../../evidence/m2-provider-runtime-contract-target-20261030.log): adapterv4/Brokerv1/profili attesi, provider ancora fermo,4GET/18metadata/zero lifecycle/chiavi/firme, exit0. Nessuna lettura indipendente del VPS; non è ammissione. Non rilanciare il vecchio comando. Prosegue autonomamente la composizione del provider child; nessun nuovo comando target pronto.

## Obiettivo confermato dall’owner

Il percorso ordinario deve essere integralmente governato da chatbot tramite le
capability OUF: upload CSV, profiling, proposta semantica e mapping, review HUMAN,
onboarding, Ingestion e materializzazione UDP con esiti verificabili per ogni riga.
Le capabilities UDP devono essere utilizzabili via chatbot sugli oggetti caricati.
Search non è una fase del caricamento: è una capability UDP da qualificare nel
suo perimetro, separatamente dalla sequenza di ingestion. Il completamento del
caricamento non dipende dall’invocazione di search; un diniego o guasto della
consultazione non annulla gli oggetti persistiti e non riavvia l’acquisizione.
Deve essere ripetibile, resiliente e fluido. Installazione/manutenzione sono un
percorso operatore distinto, da non ripetere a ogni caricamento.

Riferimenti: mini-PET CSV E2E1.1 (24 requisiti/24 test), mini-PET M2v1.3
(8 criteri UX) e gli 8 criteri M2-DISC-STABLE. Tutti rimangono nel denominatore.
Una ricerca semantica riuscita o un import singolo non chiudono M2.

## Stato verificato

- Tecniche8/8 e funzionali6/6 del caso conservato: M1/G4 acquisiti; nessuna terza
  acquisizione Teatri. M2/G5–G7 e accettazione finale restano OPEN.
- Farmacie conserva lo stesso asset/job/profilo: SUCCEEDED,61righe/10colonne;
  codice ministeriale STRING e10campi OPEN già confermati. Nessun nuovo upload,
  profiling o conferma di quelle scelte.
- Nuove sole letture live ouf-admin: `ouf.system.status` HEALTHY/actionRequiredfalse;
  `semantic.search(q=Farmacia,type=CLASS,limit=5)` restituisce `[]`, senza errore.
  Questo non prova assenza di ogni semantica equivalente, disponibilità discovery,
  readiness applicativa o E2E. Non crea/adotta un’ontologia sostitutiva.
- Discovery deve seguire chatbot→MCP→Gateway→Registry→OntoPiA. Le tre capability
  candidate MCP81 sono ancora non pubblicate al checkpoint; il provider target
  resta fermo nell’ultima ricevuta conservata, non riosservato da questa ripresa.

## Incremento implementato

[Deploy54/cb6f2da6](https://github.com/GioNob/ouf-deploy/commit/cb6f2da62f5974ca1a9eaee0352f21e4a7cfaccb)
introduce il compilatore e la transazione create-only dei file del worker:

1. Template/capsule/configurazione/ricetta/unità e ledger iniziali esatti;
   policy, clock iniziali e hash sono coperti da un seal da attestare.
2. Tre attestazioni CREATION_ATTESTATION già emesse e correnti: seal,
   installazione e ammissione della generazione. Il componente non firma,
   non trasforma un’osservazione in ammissione e non contiene CLI di consegna.
3. Stesso parent/child/fase e lock logico; claim durevole esclusivo prima delle
   scritture. File e directory nuovi, nessuna sovrascrittura o adozione di ledger.
4. `installed.json` come ultimo marker visibile al runtime. Reconciliation
   iniziale prima dello start: solo lettura, inode posseduti/custody/hash/byte;
   risposta finale persa riconciliabile, partial write conservata senza replay.
5. Scope parent unico per pubblicazione e start distinto. Vecchio scope start-only
   conservato per file già installati e firmati; capsule37moduli invariata.

Prove locali complete:13nuovi+59regressioni=72PASS/0skip, eseguite per suite in
processi distinti. File, Ed25519,fsync/flock e guard runtime sono reali; ammissioni
applicative, probe delle due generazioni e boot del fixture sono sintetici.
Il primo avvio multi-suite non ha prodotto un riepilogo completo: non è contato;
si usano soltanto i report completi delle otto suite separate e della nuova.
CI del commit:248test selezionati per push/PR, zero skip; entrambi job SUCCESS.
Anche frame OCI e sandbox Docker29.8.1/systemd/DNS/nft passano per push/PR;
sei log letti direttamente. Il fixture sandbox nativo continua a creare i file
manuali: non è ancora la prova nativa del nuovo publisher composto con il
controller completo. [Evidenza e job esatti](../../evidence/m2-discovery-worker-file-publication-qualified-20261029.json).
Nessuna nuova prova target è inferita.

Baseline originale effettivamente consultata: Matrix1.7 DOCX §§1,7 e Registry1.3
DOCX §26/26.3, oltre alle repliche testuali; mini-PET CSV1.1 §§1–6 e mini-PET M2
con criteri di stabilità. Non è una dichiarazione di conformità completa.

## Continuazione: issuer finito e ammissione conservata del provider

[Deploy54/f2dfa9c2](https://github.com/GioNob/ouf-deploy/commit/f2dfa9c2be348cfdfdeb4581228b3d1b1612d763)
collega il reader di ammissione provider al signer esistente e al publisher:

- Il reader riusa il protocollo deployment firmato, la creazione v2 con frame
  autenticato, il mandato firmato di accettazione/rootfs e il registro di consumo
  STARTED. Confronta ricetta indipendente, immagine, artifact, trasporto, runtime,
  OCI applicativo, PID/startTicks/namespace con il peer del worker. Non crea o
  ammette un provider e non ne prova la readiness.
- Lo scope parent separato lega chiave esistente isolata e tre payload esatti.
  Registry owner e probe nativo delle due generazioni sono ricontrollati prima
  della firma; uno snapshot non firmato non raggiunge da solo il signer.
- Claim esclusivo e dispatch per payload precedono ogni uso della chiave. Esiti
  persi/parziali restano consumati; la reconciliation legge soltanto prove attuali,
  firme e inode posseduti. Directory/chiave/scope cambiati bloccano la firma.
- La prova composta arriva da contratti provider firmati a tre attestazioni reali
  e pubblicazione tramite il componente precedente, senza un secondo signer.
  Capsule37moduli invariata; nessun nuovo engine di ammissione o lifecycle.

15nuovi test e72regressioni locali PASS/0skip, report completi. CI263test per
push/PR PASS/0skip; sandbox/frame nativi passati, sei log letti. Ed25519, protocollo,
file/fsync/flock e publisher sono reali; le prove della creazione applicativa e
le osservazioni native/boot del fixture sono sintetiche. Il reader richiede i
contratti di ammissione esistenti: averlo implementato non dimostra che un nuovo
provider li abbia prodotti sul target. La qualifica CI corrente e i suoi limiti
sono nel [record di evidenza](../../evidence/m2-discovery-worker-attestation-qualified-20261029.json).

Lo slot provider del parent copre ora la lettura dell’ammissione conservata.
Il futuro controller deve comporre esplicitamente anche lo scope della propria
installazione: create/start non possono essere nascosti dentro questo reader.
L’issuer è finito e iniziale; boot, rotazione e rinnovo ordinario restano separati.

## Continuazione: un’unica fase iniziale del worker

La fase ATTEST → FILES → REGISTER → START ha ora scope parent unico, claim e
dispatch persistenti per ogni sottopasso. Registrazione manager create-only e un
solo daemon-reload; avvio singolo separato. Una risposta persa viene riconciliata
senza rieseguire il comando. La continuazione esplicita può invocare solo un
sottopasso mai tentato; un effetto parziale/ambiguo blocca il resto. Ogni commit
richiede rilettura esatta, ogni dispatch ricontrolla il proprio record e la stessa
invocazione rifiuta una regressione rispetto al suo ultimo stato conservato.

Lo start richiede le tre prove iniziali; il suo hash coincide con quello
conservato nel NativeEvidenceStore. Dopo l’avvio, l’osservazione mantiene la prova
iniziale e legge il worker corrente senza pretendere il ledger iniziale o
ripristinarlo. Gli osservatori read-only verificano l’inode del lock senza
acquisirne il flock di durata del worker; le mutazioni conservano il fence esclusivo.

CI del sorgente finale:287 test/33 suite per push e PR, zero skip; entrambi
SUCCESS, log completi letti. La prova nativa esercita davvero issuer/Ed25519,
publisher, registrazione, systemd,
Docker29.8.1, DNS/nft, risposta start persa, SIGKILL/rientro e revoca della trust.
Il seed manuale inutilizzato è conservato prima dell’installazione in destinazioni
nuove. I contratti di ammissione applicativa Registry/provider del fixture restano
sintetici: non equivale a provider ammesso sul target, installer completo o E2E.
[Qualifica e limiti](../../evidence/m2-discovery-worker-sequence-qualified-20261029.json).

Il contratto runtime effettivo del provider non è negli input storici e non è
accessibile via MCP. La [lettura target qualificata](OUF_M2_PROVIDER_RUNTIME_CONTRACT_20261029.md) è
stata eseguita e consumata il30ottobre,
con quattro GET Engine e metadata selezionati, senza chiavi/credenziali/lifecycle.
L’esito è acquisito e si prosegue sul provider child. Non ripetere il comando.
Questa manutenzione non entra nel caricamento ordinario CSV.

## Residuo, in ordine di dipendenza

- Comporre e qualificare nativamente il nuovo provider nella finestra gate-only,
  il suo percorso reale di ammissione/consumo e la ripausa prima di Registry ATTEST.
  Collegare quelle prove reali al nuovo issuer; nessun vecchio provider o mandato
  scaduto può sostituirle.
- Completare il coordinatore/installazione attorno alla fase worker ora qualificata:
  13peer/TLS/IAM/DB/fencing/trust, boot/rotazione con continuità di budget e storia.
  La lettura metadata è riuscita e consumata; nessun nuovo comando target pronto.
- Installazione governata e pubblicazione coordinata delle capability, grant
  di uso ordinario e rinnovi persistenti; verificare tutti8 M2-DISC-STABLE.
- Eseguire la vera discovery OntoPiA, confronto/adozione/pubblicazione approvati,
  mapping pinned del CSV, Ingestion/UDP con contabilizzazione di ogni riga,
  provenienza ed esiti per riga. Qualificare separatamente le capabilities UDP
  sugli oggetti caricati, compresa la ricerca tipizzata prevista dai contratti.
- Completare vocaboli/relazioni managed, reimport invariato senza duplicati,
  fault/ripresa/cambio chat, due client reali e dossier HUMAN M2.

Input1868b57c e predecessori rimangono consumati. Nessun replay/reset, nuovo
budget/grant/upload/job/acquisizione, authority runtime, target apply, merge,
subagente o automazione. Repository aggiornati nell’autorizzazione esistente.
