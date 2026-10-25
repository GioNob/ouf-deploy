# MAC: regola appresa e stato retained — 25 ottobre 2026

## Errore ripetuto e correzione verificata

L'owner ha contestato la ripetizione dello stesso errore. L'assistente aveva consultato il caso legacy nel planner, ma lasciato nel guard successivo un confronto cieco dell'intero Config. Il test generico di trasferimento MAC non dimostrava la presenza iniziale di Config.MacAddress legacy. La responsabilità è dell'implementazione e della qualificazione dell'assistente.

La regola permanente è ora in testa ad AGENTS.md e in [OUF_LEARNED_CONTAINER_MAC_INVARIANTS.md](../OUF_LEARNED_CONTAINER_MAC_INVARIANTS.md), con i precedenti realmente consultati dell'8,20,25 ottobre. Distingue NIC fisica, MAC legacy di Config e MAC degli endpoint per rete. Non introduce valori Ente predefiniti.

La primitiva comune `tools/acquisition_read_native/retained_mac.py` ammette esclusivamente Config originale meno il campo MacAddress, che deve essere ASSENTE dopo il detach. All'origine il valore deve essere una MAC unicast valida coerente con l'unico endpoint osservato. Stesso CID/image/nome atteso, vecchio fermo/PID0/senza endpoint, stessa StartedAt, mount esatti e HostConfig originale con la sola RestartPolicy approvata. Null, stringa vuota, altri valori/campi, generazioni e binding differenti falliscono. Input e vecchi hash non vengono riscritti.

Nel guard `ports.NativePorts.old_guard` questa transizione richiede anche STOP e DETACH entrambi APPLIED con le prove attese e una policy esatta inclusa nella review firmata. Prima di quel prefisso resta il confronto Config esatto. Nessuna esclusione globale del campo.

## Qualificazione del codice, separata dal VPS

Commit sorgente [1141e89d69ad974b9c5ae6b6262d4cb6883d3575](https://github.com/GioNob/ouf-deploy/commit/1141e89d69ad974b9c5ae6b6262d4cb6883d3575).

- [Lifecycle legacy obbligatorio,40210134105](https://github.com/GioNob/ouf-deploy/actions/runs/40210134105): job121219388422 classic e121219388590 containerd PASS. Ciascuno esegue6 test puri con casi negativi e2 cicli native API1.44: EXPLICIT_LEGACY_CONFIG e ENDPOINT_ONLY_COMPAT_CONFIG. In entrambi, Config.MacAddress iniziale è realmente presente e dopo STOP/DETACH è ASSENTE; seguono rename e replacement/start con MAC endpoint preservata e vecchioCID trattenuto fermo.
- [Protocollo e operator nativi,40210134055](https://github.com/GioNob/ouf-deploy/actions/runs/40210134055): job121219388574,18 test protocollo PASS; job121219388620 containerd e121219388652 classic,2 test operator originale più2 continuazione PASS ciascuno. Il percorso positivo supera il guard RENAME, crea il replacement, aggiunge le2 rotte e completa l'attestazione. Il caso negativo prova la quarantena dei soli candidati propri.
- Log diretti di tutti i job citati letti; zero skip in questi test. Engine esatto Docker29.8.1, archivio SHA256 d8db66739d2e28d4933786d73e918d9be643a67fbd835db1bf740d650a259e70. È la versione già usata nel precedente CI del20ottobre, non una nuova installazione sul VPS.
- I runner Docker generici iniziali non riproducevano l'assenza del campo dopo detach: run40208966109/40208970534 e40209410223/40209413312 falliti e conservati. Il test non è stato saltato o allentato.
- Dati, chiavi, owner e decisioni CI sono sintetici. Nessun accesso production, nessuna approvazione dell'owner simulata sul VPS. I PASS non sono risultati server né E2E.
- La suite generale non è tutta verde: run40210133992, job121219388349 fallisce su PROTECTED_METADATA_ANCESTRY_REQUIRED (560test,3failure/11error/2skip); gli altri due suoi job passano. Non occultare quel risultato né attribuirlo alla correzione MAC senza ulteriore prova.

## Ultima ricevuta VPS: diagnostica conclusa, child consumato

`RETAINED_OLD_MCP_GUARD_DIFFERENCE_OBSERVED`, complete=true, Exit0/DeliveryExit0. La ricevuta pubblica integrale è in [acquisition-old-mcp-guard-observed-target-20261025.json](../../evidence/acquisition-old-mcp-guard-observed-target-20261025.json).

Solo Config differisce: prima campo presente/stringa/nondefault/uguale alla MAC endpoint originale; dopo campo assente, tipo NoneType. Image, mounts e StartedAt coincidono. 13 stage APPLIED, successivo RENAME_OLD_MCP, renameClaimed=false, newMcpCreated=false. Vecchio MCP fermo/senza endpoint e nome preservato nelle risposte trattenute. Negativa APPLIED, entrambi i READ ingestion/udp fermati e restart disabilitato. Nessuna nuova osservazione runtime corrente; non inferire che lo stato sia rimasto immutato.

129 letture di metadata privati; zero nuove richieste Engine/admin/credenziali/chiavi/SQL/OAuth. Ultimi contatori cumulativi:

| Contatore | Consumato | Massimo precedente |
|---|---:|---:|
| Engine GET |128|500|
| Engine writes |14|22|
| image load |3|3|
| owner configuration read |42|64|
| readiness GET |2|128|
| admin GET |2|32|
| admin PUT |0|2|
| service credential file read |2|2|
| quarantine stop |2|3|

Review7fcbce1f43fd99b4add8db9913b3dc2fe215836f16eecd8e8191f9e344e54aa9; authority496dda9a7057f67c4ffb10e6ae4606d101479c905cad6a731907eaf4010d56a4; journal1fb1159ada9d78123d1a90985e8c6ba23a18648bd3b3f621406c43dc9f57817d; privateEvidencee6b8642e1c04f510eabdddc6d038a87c9575e65be060928bf9981bd631eb4af2.

Root originale:
`/etc/ouf/deploy-snapshots/acquisition-read-apply-5fa62e4f6869a6f40fb512878dcf65dcb6ffaf941be487e4189826f418046591`.
Continuazione consumata: `terminal-continuation-v1`.
Diagnostica consumata al suo interno: `retained-old-mcp-guard-v1`.
Log diagnostica: `/home/oufadmin/ouf-acquisition-old-mcp-guard.IGg90nG5/operator.log`.
Log delivery: `/home/oufadmin/ouf-old-mcp-guard-delivery.4Wh4YU1m/bootstrap.log`.

Il digest canonico della ricevuta ricostruita dal testo owner è7db79ea88e7f4ecf72dec889a8753afb40a53890573615bcebbf0b2fbc67e0f9: deve essere verificato sul file retained prima di usarlo come binding; l'agente non ha letto direttamente quel file VPS.

## Passo successivo consentito

Non rilanciare i vecchi wrapper o il lettore diagnostico. Il codice corretto NON autorizza a ripartire dall'inizio. Vecchio MCP fermo/scollegato: non riavviare/ricollegare. Nessun nuovo MCP o routePUT è provato sul VPS.

Il prossimo lavoro è una recovery residua distinta e ancora da qualificare, che conservi history, file, hash e contatori, adotti soltanto i due CID READ già creati/propri/quarantinati e verifichi freschi binding e generazioni. Non ripetere import, READ CREATE o vecchio STOP/DETACH. La nuova review deve esporre limiti cumulativi ed eventuale estensione finita prima di credenziali/effetti, con APPROVO e hash freschi su riga isolata da vero terminale. Nessuna autorità è già concessa per questi effetti. Dopo STOP: prove conservate, nessun rilancio automatico.

Un prototipo locale non qualificato della recovery è stato separato dai sorgenti di consegna; nessun wrapper né comando runtime di recovery è pubblicato. Il checkpoint qualifica la correzione del guard, non quel prototipo.

Dopo installazione VPS provata: letture governate delle sole due acquisizioni esistenti; policy48 scaduta. Nessuna terza acquisizione, nessun grant o budgetfonte dedotto dall'autorizzazione allo sviluppo. E2E/G4/F5/F6 restano aperti, tecnico8/8 e funzionale4/6; Supervisor dopo E2E. Nessun merge o release acceptance.

## Catena precedente

Leggere integralmente [STOP prima della diagnostica](OUF_ACQUISITION_OLD_MCP_GUARD_STOP_20261025.md), [continuazione dopo review non approvata](OUF_ACQUISITION_RECONCILED_CONTINUATION_20261025.md), [handoff evidenze acquisition](OUF_ACQUISITION_EVIDENCE_READ_HANDOFF_20261025.md), [proiezione Registry/network](OUF_REGISTRY_NETWORK_PROJECTION_HANDOFF_20261024.md), [resume24ottobre](OUF_RESUME_PROMPT_20261024.md), seguendo i loro riferimenti. Le istruzioni di eseguire scope successivamente consumati sono storiche.
