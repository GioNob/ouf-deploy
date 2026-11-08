# Regola permanente sui frame MAC e sul lifecycle dei container

Questa regola nasce da errori ripetuti dell’assistente nel riutilizzare lo storico OUF. Deve essere letta prima di ogni lavoro su create, stop, detach, rename, replacement, recovery o confronto Config/NetworkSettings. Non basta aver corretto il planner se executor, guard e fixture non coprono lo stesso lifecycle.

## Precedenti realmente consultati

- 8ottobre2026, ouf-deploy d8b5309487eeaee2d879b9b525e3203b36799a7a: prova native dei binding MAC/IP/interfaccia espliciti, stessoCID e frame congelato; 18f1cf2797d76b221e4b2e9fa3f18ce7c49df121: pin dei soli endpoint propri fermi e claim durevole. Sono prove di gestione nominativa, non una concessione a ignorare Config.
- 20ottobre2026, docs/handoffs/OUF_CLOUD_MAC_FRAME_RECONCILIATION_HANDOFF_20261020.md e evidence/ingestion-frame-mac-stop-target-20261020.json: STOP ENDPOINT_MAC_ONLY_PROFILE_REQUIRED. Il compilatore richiedeva erroneamente Config.MacAddress vuoto; correzione per legacyMAC nonvuota SOLO se uguale a un endpoint osservato, campo legacy omesso nelle nuove richieste e binding endpoint preservati. Storia e contatori mantenuti.
- 25ottobre2026, a421e821d1d522de85aec1d3558f61076cceab99: Config.MacAddress riconosciuta nel planner, replica READ con MAC allocata distinta e replacement con MAC endpoint conservata SOLO dopo STOP/DETACH. tests/qualify_acquisition_mac_engine.py prova il trasferimento endpoint, ma NON pretende né verifica Config.MacAddress legacy presente inizialmente.
- 25ottobre2026, continuazione a21f5bda sul VPS:13stage applicati; al guard RENAME_OLD_MCP Config.MacAddress è ASSENTE dopo detach, mentre prima era stringa presente/nondefault e uguale alla MAC dell’endpoint. Image/mounts/StartedAt coincidono. L’assistente aveva mantenuto l’uguaglianza cieca del Config completo nel guard successivo, e la fixture generica non copriva il profilo legacy reale. Responsabilità dell’implementazione/qualificazione dell’assistente, non dell’operatore.

## Regole obbligatorie per le prossime modifiche

1. Distinguere MAC della NIC fisica, Config.MacAddress legacy e NetworkSettings/EndpointSettings per rete. Nessuna equivalenza implicita. Valori e policy di allocazione provengono dal profilo Ente validato o da osservazioni autenticate per quel deployment; mai valori storici come default riusabili.
2. Consultare questi precedenti PRIMA di scrivere un nuovo confronto Config e riusare le primitive pertinenti. Seguire il campo attraverso compiler, richiesta CREATE, inspect prima/dopo start, stop, detach, rename e replacement. Coprire gli stessi profili nel codice e nel CI.
3. Config.MacAddress non è un campo da ignorare globalmente. Il delta osservato nel caso attuale è precisamente PRESENTE/stringa/coerente → ASSENTE, solo sullo stesso vecchioCID fermo e senza endpoint dopo STOP/DETACH provati. Empty string, null, valore diverso o variazioni di altri campi non sono quella prova. Image, mount, StartedAt e HostConfig restano esatti; vecchi hash e originali non vengono riscritti.
4. Le fixture native per un rilascio che tocca questo lifecycle DEVONO includere esplicitamente il vecchio Config con legacyMAC presente, oltre al caso endpoint-only. Il test deve affermare quella precondizione e fallire se il runner non la riproduce; vietato saltarla o convertire una fixture endpoint-only in prova del caso legacy.
5. Il ciclo native richiesto è create/start → inspect → stop → detach → inspect → rename → replacement/start → inspect. Verificare preservazione della MAC sull’endpoint del sostituto, vecchio container trattenuto fermo e stessa identità/generazione/mount del vecchio. Qualificare i backend Engine pertinenti (classic/containerd). Un green generico non copre un profilo assente.
6. Matrice negativa obbligatoria: legacy assente/null/vuota/malformata/multicast/zero/non coerente all’origine; legacy nuova/null/vuota anziché assente dopo detach; CID/image/mounts/StartedAt/HostConfig/Env/Hostname diversi; vecchio ancora running o con endpoint. Fallire senza normalizzazioni generiche.
7. Usare la primitiva comune tools/acquisition_read_native/retained_mac.py per il profilo stretto corrente. Un nuovo caso diverso richiede evidenza e policy esplicita, non una tolleranza aggiunta a posteriori al guard. Il helper non autorizza lifecycle, non genera MAC e non modifica input/runtime.
8. Se STOP: mantenere scope/journal/candidati/log e contatori; prima leggere solo le prove necessarie. Nessun rilancio, reset, reimport, secondaCREATE, vecchio restart o nuova acquisizione per compensare un difetto del guard. Un recupero residuo richiede nuova review concreta e mandato cumulativo esplicito prima di effetti o nuove letture credenziale.

## Gate di consegna

Non chiamare un controller pronto per il VPS finché i test legacy di cui sopra non passano senza skip, con log diretti letti e profili realmente presenti nelle fixture. Registrare limiti e differenze fra dati/chiavi/owner sintetici CI e prove server. Il superamento del gate non implica E2E o release acceptance.

Questa regola resta in AGENTS.md e nel repository per le chat successive. Non si basa sulla promessa di memoria dell’assistente. I test e la review del codice devono impedirne la regressione.

## Richiamo del 7 novembre 2026 — confronto dei sostituti SeaweedFS

Giovanni ha segnalato nuovamente il precedente. Il documento era ancora presente, ma il richiamo non compare negli AGENTS dei due rami correnti prima di questa correzione (operativo `de8e048b`, documentazione `738a8792`). Il nuovo avviatore `scripts/ouf-runtime-20261107.py` confronta il Config completo e segnala soltanto il nome del campo diverso: questo non basta a distinguere una transizione legacy nota da un cambiamento reale. Il precedente non è stato consultato prima di quel controllo: omissione dell'assistente.

La ricevuta del 7 novembre identifica `Config.MacAddress` come unico campo Config diverso per i sostituti Onboarding e UDP; non espone presenza, tipo o valore prima/dopo né confronto corrente degli endpoint. Gli script di cambio conservano `replacement-container.private.json` **dopo** avvio e readiness, non prima di start. La regola del vecchio container fermo/detached del 25 ottobre non può essere trasferita automaticamente a questi sostituti running.

Ripristinato il richiamo esplicito negli AGENTS di entrambi i rami. Prima di correggere il guard, leggere dai riferimenti già conservati la forma precisa del delta e la corrispondenza degli endpoint per rete; riusare la primitiva solo se il profilo coincide. Nessuna esclusione globale di MacAddress, normalizzazione generica, modifica runtime o riscrittura delle impronte effettuata. Il controllo della policy Semantic già consegnato resta valido e il suo comando pinned non cambia.

## Osservazione corrente dell'8 novembre 2026

La [ricevuta delle 09:11 CET](../evidence/analysis-discovery-runtime-operator-20261108.json) precisa il caso attuale. Onboarding e UDP hanno Config/HostConfig/mount/NetworkSettings identici alla cattura dei sostituti; Config.MacAddress è STRING unicast nonzero, coincidente con un endpoint, in entrambe le osservazioni. Il precedente delta dei sostituti non è presente in questa lettura.

Per MCP, Semantic, APISIX, Gateway owner e Ingestion, la cattura ha legacy ABSENT e la lettura corrente STRING valida/unicast/nonzero e coincidente con un endpoint. Solo MacAddress differisce nel Config; differisce anche NetworkSettings. Non è il profilo PRESENT→ABSENT dopo detach del vecchio container. Non dedurre una causa del cambiamento o una regola lifecycle da due snapshot: non è stata introdotta esclusione globale, né modificato alcun guard o hash storico. Il lettore delle dipendenze usa esplicitamente i frame correnti della ricevuta dell'8 novembre.

## Qualifica Onboarding a due reti — 8 novembre 2026

Il profilo `TWO_NETWORK_BACKEND_LEGACY_MAC_DETACH_LAST_V1` è qualificato in [CI42518570091](https://github.com/GioNob/ouf-deploy/actions/runs/42518570091), source e5bec2ee, Docker29.8.1 classic/containerd. Due reti reali, legacy inizialmente presente sia nella fixture esplicita sia nella fixture endpoint-only; zero skip. Il campo deve coincidere con l'endpoint backend, distinto da quello privato. Dopo STOP: detach privato conserva legacy e il restante endpoint esatti; detach backend finale produce legacy ASSENTE e zero endpoint. CID, immagine, generazione, mount, HostConfig, ENV e altri campi Config restano esatti; poi rename e sostituto con entrambi gli IP/MAC/alias originari.

Il controller `scripts/upgrade-onboarding-wide-20261108.py` implementa questa policy separata; riusa soltanto validazione e digest del helper comune, senza proiettare falsamente due reti su una. La matrice negativa rifiuta forme MAC non ammesse e mutazioni del vecchio/sostituto. Non modifica il profilo singola rete già qualificato né ammette differenze generiche sui sostituti running. [Prove e limiti](../evidence/onboarding-wide-upgrade-qualification-20261108.json). La [ricevuta VPS delle21:16CET](../evidence/onboarding-wide-ready-operator-20261108.json) conferma poi il successo del medesimo profilo a due reti: vecchio trattenuto spento, entrambi gli endpoint conservati e nuovo Onboarding pronto. Qualifica e ricevuta target restano prove distinte; non rigiocare il controller.


## Qualifica Ingestion a una rete — 8 novembre 2026

[CI42522348023](https://github.com/GioNob/ouf-deploy/actions/runs/42522348023), source5d926783: archivio candidato Ingestion avviato su Docker29.8.1 classic/containerd. Entrambi i profili EXPLICIT_LEGACY_CONFIG e ENDPOINT_ONLY_COMPAT_CONFIG hanno realmente Config.MacAddress presente all’origine e assente dopo STOP/DETACH; segue rename e sostituto con IP/MAC/alias conservati, vecchio trattenuto spento. Sei test guard e due cicli nativi per backend, zero skip; log letti. Il controller riusa `retained_mac.verify_detached`, aggiunge il controllo Path/Args e non introduce una nuova eccezione generica. V18, stato sintetico, configurazione esterna e Gateway-read key esercitati. [Prove e limiti](../evidence/ingestion-wide-upgrade-qualification-20261108.json). Ricevuta installazione VPS ancora attesa; non confondere questa qualifica con un successo target.


## Confronto API1.44 e CLI nel lettore Ingestion — 8 novembre 2026

La ricevuta22:20CET riporta Config/rete differenti nel vecchio fermo, stessa generazione, un nome di rete e nessun detach nel journal. Il lettore `read-ingestion-wide-held-state-20261108.py` confrontava un inspect CLI senza API fissata con gli snapshot del controller API1.44: difetto del confronto, non prova di una nuova transizione lifecycle. Il successivo lettore `read-ingestion-resume-prerequisites-20261108.py` usa API1.44 per il confronto primario e affianca la CLI per distinguere le viste. Nessuna normalizzazione MAC o eccezione ai guard introdotta. Risultato target ancora atteso. [Stato corrente](OUF_INGESTION_WIDE_UPGRADE_20261108.md).
