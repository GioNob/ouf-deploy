# OUF CSV E2E — cronostoria effettiva

Baseline congelata: [Mini-PET v1.1](OUF_CSV_E2E_COMPLETION_MINIPET_v1_1_20261020.md), commit d190193773116c9a59403aa42ccc9f89423eb959. Il [registro eventi](../evidence/csv-e2e-execution-timeline-20261020.json) è append-only nella successione dei commit e conserva timestamp/provider, intervalli e prove. La baseline non viene riscritta.

Origine di riferimento: **20 ottobre2026,11:07:49Europe/Rome**, timestamp della richiesta di avvio, non misura esatta della prima operazione. Tracciamento dedicato da **20/10/2026, 11:16:46**. Gli avvii precedenti senza una marcatura hanno estremi noti, non un orario inventato. Le chiusure CI sotto sono timestamp effettivi di GitHub, mostrati in Europe/Rome.

| Evento / obiettivo | Ora effettiva o checkpoint | Risultato |
| --- | --- | --- |
| G0 selezione/baseline |20/10/2026,11:16:46|PASS;6branch owner corrispondenti, contesti conservati; nessun gate runtime|
| WP1 Ingestion, CI39399340219 |20/10/2026,11:18:04|PASS:186test,0failure/error;2testLua condizionali esclusi qui e coperti da gate intermodulo conservato; supply-chain/ripristino PASS|
| WP1 capsule immutabile, CI39399647915 |20/10/2026,11:18:04|15test PASS,0skip; pin storici invariati|
| WP1 MCP, CI39399343702 |20/10/2026,11:18:30|PASS;80misure,p95=2,755161ms sotto25ms; suite normale e race PASS|
| Regressione coorte39399655535 |20/10/2026,11:35:05|CANCELLED dal workflow cancel-in-progress dopo il nuovo commit; non è PASS|
| WP2 componente lifecycle/key, CI39401710478 |20/10/2026,11:35:14|16regressioni+7nuovi test PASS,0skip; firme/custodia/CAS reali, Engine sintetico|
| Branch di lavoro isolata |20/10/2026, 11:38:46|feat/csv-e2e-native-completion-20261020, per non interrompere la regressione suPR41|
| G1 complessivo |Non chiuso|Attesa regressione coorte39401717480 sui byte af1172; gli altri risultati restano distinti|
| G2/G3 |Non chiusi|Componente WP2 qualificato, non Ports/issuer/closure completi; nessuna ammissione target|
| F5/F6/M1/M2 |Aperti|Nessuna nuova acquisizione o accettazione finale|

## Confronto con il piano

Previsioni centrali conservate:G0 H+0,5;G1 H+3;G2 H+14;G3 H+19;F5 H+22;F6/M1 H+24;G5 H+35;G6 H+46;G7/M2 H+55. La data di osservazione non sostituisce la prova del gate.

Il primo intervallo misurato è durato **22.00minuti**, con lavoro WP1 e preparazione WP2 intercalati; la suddivisione esatta fra i due WP non è stata inventata. L'intervallo iniziale non segmentato dura **8.96minuti** e resta esplicito. Il successivo intervallo attivo WP2 è aperto dalle **20/10/2026, 11:38:46**. Il registro conserva il tempo trascorso, l'effort misurato, la precisione e le eventuali attese su assi distinti.

Nessuna attesa passiva è stata finora imputata: mentre le CI lavoravano, proseguiva la preparazione indipendente. La cancellazione della vecchia CI è una perdita di tempo di calendario/computazione del runner, non una seconda spesa dell'effort dell'agent nello stesso intervallo. Ogni ulteriore attesa e intervento HUMAN avrà una registrazione propria quando misurabile.

## Codice e limiti delle prove

- [Ingestion PR44](https://github.com/GioNob/ouf-ingestion-runtime/pull/44): isolamento transazionale dei fixture senza modificare scheduler/tenant production.
- [MCP PR76](https://github.com/GioNob/ouf-mcp-server/pull/76): profilo LAN obbligatorio distinto dalla strumentazione race, soglia25ms invariata.
- Deploy b6da28026102f2739088e05723122deeda077159: snapshot HUMAN esatto45b78c e confronto capsule; nessun pin/claim storico riscritto.
- Deploy af1172ba4127a78cb42a812a90bab3c3c60cb159: journal dei tentativi nativi, CID persistito prima del readback e sigillo metadata della chiave. Il test locale fchown(10002,10002) ha restituitoEINVAL; la qualifica reale è quella del runnerroot, non una simulazione del proprietario.
- I2skipped Ingestion riguardano vettori Lua: prova intermodulo39304985543 su663faa giàPASS. Il confronto663faa→8a15d8 modifica soltanto readiness/startup, il test scheduler e documentazione; nessun file del confine autenticato è cambiato. Questa è evidenza riusata, distinta dalla nuova suite.

Stato: **tecniche8/8,funzionali4/6**. Nessuna operazione target, login/refresh/reset, replay di Owner7/projection7, subagente o automazione operativa.
