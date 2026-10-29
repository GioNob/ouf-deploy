# Ripresa del lavoro OUF dopo la perdita della chat — 29 ottobre 2026

Questo è un indice di ripresa ricostruito da GitHub. La vecchia chat non è stata
recuperata: il servizio Personal Context risulta disabilitato. Le ricevute target
citate restano osservazioni storiche documentate, non nuove letture del VPS.
L'owner ha rinnovato l'autorizzazione a leggere/scrivere i repository GioNob e a
tenere aggiornata la documentazione. Le decisioni runtime HUMAN/THS restano quelle
previste dai contratti; nessun comando operatore è pronto a questo checkpoint.

## Dove ripartire

`main` di Deploy è fermo a `5d114e3973667dd26dde407a70d6718263ad1840`
(14 ottobre). Non usarne il README come sequenza operativa corrente.
Il checkpoint documentale corrente è nel ramo
`fix/registry-bound-owner-lineage-20261023`, PR50, osservato a
`94defb3828ad356897747426ad4b982e00468061`.
Il codice discovery corrente è nel ramo della PR54. Le PR sono DRAFT e non
costituiscono una release installata; la ripresa non richiede di fonderle.

| Repository / PR | Riferimento osservato | Ruolo nella ripresa |
| --- | --- | --- |
| [Deploy 50](https://github.com/GioNob/ouf-deploy/pull/50) | `94defb3828ad356897747426ad4b982e00468061` | Checkpoint, baseline PET e ricevute target |
| [Deploy 54](https://github.com/GioNob/ouf-deploy/pull/54) | `5e3f0f3e860dab7a3d2e04c551e33e315f684444` | Composizione discovery, worker, gate e trasporto |
| [Registry 41](https://github.com/GioNob/ouf-semantic-registry/pull/41) | `1086f7ea5a3281dc7731ea28d258f8fead403d07` | Discovery durabile composta con il file owner |
| [Gateway 84](https://github.com/GioNob/ouf-api-gateway/pull/84) | `c666c0f0080b8802fc71daa27c32a0af2ed98544` | Route discovery e correzione contratto CAPABILITIES |
| [MCP 81](https://github.com/GioNob/ouf-mcp-server/pull/81) | `09d1f521703f2e896398c751b41008f22c6dca0d` | Tre capability discovery candidate, ancora INACTIVE |

Sono accessibili anche `ouf-source-onboarding`, `ouf-ingestion-runtime` e
`ouf-udp-object-resolution`. I permessi GitHub riportano pull/push per tutti i
sette repository OUF. Questo inventario non è un audit completo del loro codice.

## Stato di prodotto da preservare

- M1/G4 acquisiti. M2, G5–G7, D5–D7, due client reali ed E2E restano aperti.
- Farmacie: stesso asset `9c502da5-b5d8-405e-b3f5-60eb31ecb513`, job
  `677480c8-3d10-44fd-9dad-f72ddeed20a4`, profilo
  `f3061699-4fde-4085-89c8-bc8703f65686`: profiling SUCCEEDED e preview
  61 righe/10 colonne già acquisiti. Policy59 pubblicata secondo il checkpoint.
  Codice ministeriale come chiave STRING e dieci campi OPEN già confermati.
  Non richiedere nuovamente queste scelte o ripetere upload/profiling/recovery.
- Il percorso richiesto è chatbot → MCP OUF → Gateway → Registry → OntoPiA.
  Nessuna discovery reale completa è provata; import web/Turtle manuale e
  ontologie inventate non sostituiscono questo percorso.
- Ultimi input installativi target
  `1868b57c9fbbb3f05b6f8b2eedeb2f1afe14c0ad4cf15cc7f3e039bbedd6d083`:
  riusciti e consumati; provider fermo nell'osservazione conservata, launcher
  ritirato. Conservare scope, log, store, contatori e predecessori.

## Ultimo risultato tecnico e suo limite

La [qualifica parent/gate/worker](../../evidence/m2-discovery-parent-gate-worker-source-qualified-20261029.json)
documenta 235 test selezionati per job, firme reali e prove native separate di
Docker29.8.1/systemd/DNS/nft. La risposta persa dopo un vero start manager è
riconciliata senza un secondo start. La finestra gate-only ripausa la stessa
generazione prima di Registry ATTEST. I predecessori e le ammissioni applicative
dei fixture restano sintetici: non provano installazione o authority sul VPS.

Il pacchetto Gateway corretto è artifact `12930098785`, ZIP SHA256
`22cd26a29460de69d9aae9392cebad2a3eca28b3b6bc0153bbaab7b68aa24441`.
Il readback conservato confronta 380 blob GitHub, sette payload e dieci
materializer. Non prova route, publisher trust o ammissione target.

## Prossimo incremento implementativo

Completare la transazione unica dei byte e del ledger iniziale firmato del worker.
`LeaseStartAdapter` avvia soltanto file già installati e firmati; non è l'installer.
Lavorare nel ramo PR54, conservando il checkpoint documentale nel ramo PR50.

1. Legare l'installazione al template statico revisionato, all'intento parent
   corrente, alla capsule esatta e alle due ammissioni native indipendenti.
   La materializzazione dei PID/CID non concede authority.
2. Consumare durevolmente un solo intento prima delle scritture. Pubblicare solo
   byte revisionati, firme/receipt, custody e ledger iniziale della nuova
   operazione; non inizializzare sopra ledger esistenti o migrare R12.
3. Riconciliare crash/esito ambiguo con osservazione dei file, identità, hash e
   journal posseduti. Nessun overwrite, firma ripetuta o reset implicito.
   Qualificare concorrenza, drift, partial write e replay prima della consegna.
4. Comporre l'installer con lo start singolo già qualificato e il nuovo provider
   ammesso nella finestra gate-only, poi ripausa prima dell'attestazione Registry.

Restano inoltre aperti coordinatore completo dei tredici peer, trust autorevole,
TLS/IAM/DB/fencing, boot/rotazione con contatori cumulativi, pubblicazione
coordinata e prove OntoPiA/E2E su due client. Tutti gli otto criteri
[M2-DISC-STABLE](../OUF_M2_DISCOVERY_STABLE_OPERATION_20261029.md) restano OPEN.
Non aprire una finestra/token prima che il percorso completo sia qualificato.

## Baseline e verifica di questa ripresa

I PET sono già nel [pacchetto baseline1.7](../baseline/v1.7/README.md), sul ramo
PR50; non occorre richiedere nuovamente l'allegato. Per questa ricostruzione sono
state consultate le copie testuali della Matrix1.7 §§1,4,7 e del Registry1.3
§§11,17,26, incluso OntoPiA §26.3; MiniPET M2v1.3, criteri di stabilità e
AGENTS.md. Sono ausili degli originali, non attestazioni di conformità integrale.

Sul codice PR54 esatto sono stati rieseguiti localmente i sette test del template
installativo e i sei test del compilatore unità: 13 PASS, zero skip. Sono test
di proposte sintetiche e isolamento della configurazione; nessun nuovo test
nativo, accesso VPS o risultato E2E è rivendicato. I 235 test rimangono evidenza
CI preesistente, non una suite rieseguita in questa ripresa.

Questo incremento modifica soltanto documentazione e collegamenti di ripresa.
Nessun nuovo installer implementato, merge, grant, budget, upload, job, resume,
firma runtime, attivazione o release acceptance. Gli header sottostanti degli
indici conservano la storia: per la sequenza corrente partire da questo documento
e dal checkpoint più recente di AGENTS, verificando eventuali nuovi commit.
