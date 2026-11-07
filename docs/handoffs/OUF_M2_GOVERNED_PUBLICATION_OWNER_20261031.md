# OUF — Owner della pubblicazione Discovery e chiarimento delle letture VPS

31 ottobre 2026, Europe/Rome. Sorgente `e61d06fa81a0b89bf8a1e441938d39d748e0a732`, [PR54](https://github.com/GioNob/ouf-deploy/pull/54) in bozza, non unita. Questo componente non è un installer eseguibile sul target.

## Letture dell'operatore

[Evidenza minimizzata](../../evidence/m2-vps-diagnostic-metadata-20261031.json). L'operatore ha eseguito i comandi di sola lettura systemctl/Docker e incollato l'output. I dati non sono stati letti indipendentemente sul server.

Il boot guard è `oneshot`, `RemainAfterExit=yes`, uscita0, `Result=success`, `active/exited`. Il token owner è attivo. Le unità storiche R8/R9 risultano `not-found`. Registry `790c62742c92...`, image `b61bc39c...`, è `running=true`, `paused=false` e dichiara entrambi i flag `OUF_DISCOVERY_WORKER_ENABLED=false` e `OUF_SCHEMA_GOV_ENABLED=false`. CID/image Registry e immagini MCP/Onboarding coincidono con i riferimenti del29ottobre; questo non prova identità della generazione di processo, configurazione effettiva o ammissione nativa. I provider storici v2 sono fermi da13giorni; il solo codice137 non attribuisce una causa alla terminazione.

Queste letture non documentano un incidente `QUIESCED` corrente sul VPS. La correzione causale qualificata nella CI rimane distinta. Per questo chiarimento non occorrono altri comandi operatore. Non abilitare flag né riavviare container storici o worker consumati per prova.

## Componente implementato

`publication_owner.py` ricompila i piani con gli stessi helper pubblici qualificati della review, poi confronta l'esatta sezione `capabilityPublication` con il parent autenticato. Richiede gli effettivi tipi `DiscoverySelectedRuntime`, `DiscoveryApplication`, `DiscoveryExecutor`, parent e child correnti. Il nuovo owner riusa le macchine a stati autorizzative e Gateway esistenti; il child Registry a13fasi conserva i byte e non riceve sezioni legacy proiettate o nuove firme.

`DiscoveryPublicationWindow` usa il checkpoint dell'effettivo executor dell'applicazione con fase `RELEASE_PRODUCERS` e punto **`BEFORE_DISCOVERY_CAPABILITY_PUBLICATION`**. Il contratto pretende ricevuta esatta di schema/fase/punto/versione/intento/child/source ed evidence hash; un booleano o un oggetto generico viene respinto. La stessa storia Registry deve restare ferma prima e dopo il controllo. Questo è un punto che il controller nativo M2 deve ancora implementare e qualificare: il controllo della forma della ricevuta non è una prova di coorte completa.

Il coordinatore mantiene il fence reale dell'invocazione Registry attraverso autorizzazione, tre route e verifica finale. La conferma dei ruoli resta l'operazione HUMAN del rispettivo owner; una proposta in attesa esce immediatamente, conserva gli effetti e libera il fence. Nessun wait, approvazione automatica o rilascio dei producer è aggiunto.

Ogni journal ha un binding iniziale create-only con parent, child, componente, piano, tipo di owner e directory. Ogni effetto remoto ha un ulteriore marker create-only/fsynced prima dell'I/O, indipendente dal journal mutabile. Una regressione del JSON viene quindi respinta prima di un nuovo dispatch. Risposte perse di registrazione/PUT vengono riconciliate in lettura; anche una proposta ruoli con deduplicazione mantiene il massimo parent di un dispatch e, se ambigua, richiede riconciliazione esplicita. Directory già inizializzate o parziali non vengono completate o adottate da `initialize`.

Il trasporto Gateway ha un proprio tipo M2 e verifica l'effettivo owner runtime, generazione, eseguibile e binding della credenziale admin già selezionati. Accetta una PUT soltanto per la route/corpo del claim corrente. Riusa il trasporto namespace originale; non modifica il namespace del processo principale. Una revoca dopo il marker persistente interrompe l'operazione prima della mutazione remota.

La ricevuta finale attesta soltanto la riconciliazione del delta osservato. `producerReleaseDispatched`, `fullCohortProven`, `currentNativeAdmissionProven`, `targetApplyAuthorized`, `runtimeAuthorityIssued`, `applicationE2EProven` e `releaseAcceptance` restano false. Il componente non ha CLI di applicazione o firma.

## Verifica e limiti

Locale: suite13test PASS173.131s; nuovo caso di revoca dopo il dispatch-claim PASS1test3.739s; verifica aggiuntiva dell'inizializzazione parziale PASS1test2.802s. Sono14casi distinti. Le firme parent/child Ed25519, custody, file, fsync e journal sono effettivi; checkpoint nativo, selected-runtime, I/O HTTP/IAM/Gateway e transizione HUMAN sono fixture esplicite. La verifica Java dei vincoli dei ruoli rimane nella suite Discovery autorizzativa precedente; questa suite non finge di eseguirla.

CI unificata dei14casi: [run41210128164](https://github.com/GioNob/ouf-deploy/actions/runs/41210128164), job124563188217, PASS14test/1suite/0errori/0saltati in131.293s. Log finale letto direttamente, inclusi tutti i14esiti. Il checkpoint nativo e le chiamate owner rimangono fixture; nessuna accettazione del target è acquisita.

Regressione del compilatore parent sulla stessa sorgente: run41210128124/job124563188370, PASS8test0.610s e12test11.186s, zero errori/saltati, log finale letto. Nessuna nuova verifica dell'artefatto generato da questa esecuzione viene qui dichiarata; la precedente capsule136moduli qualificata rimane la consegna già verificata nel dossier della review.

Le closure/pin precedenti da37worker/108review/128infrastruttura/136parent restano immutate e verificate. Il nuovo owner è una libreria separata: il compilatore isolato precedente non lo carica né lo rende eseguibile sul VPS. Sono ancora necessari controller/checkpoint nativi completi, ammissione corrente di coorte/custody/TLS/IAM/DB/trust/fencing, confezionamento e review concreta prima di una consegna target.

L'integrazione deve verificare che l'owner autorizzativo HUMAN sia effettivamente raggiungibile nella fase tenuta dal fence. Un piano che abbia già fermato quel control plane richiede una composizione/ordinazione governata coerente; questo componente non riavvia producer né allenta il fence per renderlo raggiungibile.

M2/G5–G7/24AT/8UX/8stabilità/boot/rotazione/due client restano aperti. Teatri M1/G4 tecnico8/8 e funzionale6/6 acquisiti. Farmacie resta la stessa acquisizione SUCCEEDED61righe/10colonne, ministeriale STRING/tutte10aperte; nessun upload/profiling/acquisizione da ripetere. Nessun grant, apply, reset, replay, merge o accettazione del rilascio.
