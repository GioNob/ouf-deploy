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
