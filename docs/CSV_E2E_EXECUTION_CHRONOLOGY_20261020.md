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
| WP1 regressione coorte39401717480 |20/10/2026,11:35:07–11:51:37|PASS sul commit af1172; precedente run cancellata conservata come tale|
| WP2 trasporto Gateway, primo tentativo39403466107 |20/10/2026,11:49:19–11:50:01|23regressioni+13/14nuovi testPASS; una aspettativa errata dopo claim conservato, scenari separati senza rilassare il codice|
| WP2 trasporto Gateway corretto39403673060 |20/10/2026,11:51:01–11:51:46|38testPASS,0skip; firme/CAS/custodia reali, generazione/HTTP sintetici|
| G1 decisione complessiva |20/10/2026,11:53:01|PASS; tutte le evidenze WP1 pertinenti riconciliate sui rispettivi byte; nessuna authority target|
| WP2 policy snapshot DB |Checkpoint20/10/2026,11:58:52|9testlocaliPASS; nessuna nuova sessione SQL target o ammissione DB|
| G2/G3 |Non chiusi|Componente WP2 qualificato, non Ports/issuer/closure completi; nessuna ammissione target|
| F5/F6/M1/M2 |Aperti|Nessuna nuova acquisizione o accettazione finale|

## Confronto con il piano

Previsioni centrali conservate:G0 H+0,5;G1 H+3;G2 H+14;G3 H+19;F5 H+22;F6/M1 H+24;G5 H+35;G6 H+46;G7/M2 H+55. La data di osservazione non sostituisce la prova del gate.

Il primo intervallo misurato è durato **22.00minuti**, con lavoro WP1 e preparazione WP2 intercalati; la suddivisione esatta fra i due WP non è stata inventata. L'intervallo iniziale non segmentato dura **8.96minuti** e resta esplicito. Il secondo intervallo misurato va dalle **11:38:46 alle11:53:01**. Un terzo intervallo attivo WP2 è aperto dalle **11:53:01**. Il registro conserva il tempo trascorso, l'effort misurato, la precisione e le eventuali attese su assi distinti.

Nessuna attesa passiva è stata finora imputata: mentre le CI lavoravano, proseguiva la preparazione indipendente. La cancellazione della vecchia CI è una perdita di tempo di calendario/computazione del runner, non una seconda spesa dell'effort dell'agent nello stesso intervallo. Ogni ulteriore attesa e intervento HUMAN avrà una registrazione propria quando misurabile.

## Codice e limiti delle prove

- [Ingestion PR44](https://github.com/GioNob/ouf-ingestion-runtime/pull/44): isolamento transazionale dei fixture senza modificare scheduler/tenant production.
- [MCP PR76](https://github.com/GioNob/ouf-mcp-server/pull/76): profilo LAN obbligatorio distinto dalla strumentazione race, soglia25ms invariata.
- Deploy b6da28026102f2739088e05723122deeda077159: snapshot HUMAN esatto45b78c e confronto capsule; nessun pin/claim storico riscritto.
- Deploy af1172ba4127a78cb42a812a90bab3c3c60cb159: journal dei tentativi nativi, CID persistito prima del readback e sigillo metadata della chiave. Il test locale fchown(10002,10002) ha restituitoEINVAL; la qualifica reale è quella del runnerroot, non una simulazione del proprietario.
- I2skipped Ingestion riguardano vettori Lua: prova intermodulo39304985543 su663faa giàPASS. Il confronto663faa→8a15d8 modifica soltanto readiness/startup, il test scheduler e documentazione; nessun file del confine autenticato è cambiato. Questa è evidenza riusata, distinta dalla nuova suite.

Stato: **tecniche8/8,funzionali4/6**. Nessuna operazione target, login/refresh/reset, replay di Owner7/projection7, subagente o automazione operativa.

### Checkpoint G1

Decisione osservata **20/10/2026,11:53:01Europe/Rome**; ultima dipendenzaCI
terminata11:51:37. Effort tecnico cumulativo misurato al checkpoint:
**36.24minuti**, più l'intervallo iniziale
non segmentato di8,96minuti: intervallo cumulativo **0.604–0.753ore**.
Include preparazione WP2 durante le CI; non è un consuntivo esclusivo WP1.
Rispetto a G1 centraleH+3 il raggiungimento è anticipato, ma questa singola
misura non giustifica ancora una riduzione automatica delle55ore complessive.

G1 non richiede merge o distribuzione delle sole correzioni di fixture:
Ingestion8a15d8 e MCPe7e9d9 conservano i byte production selezionati; Deployaf1172
contiene la correzione della capsule storica. Restano distinti i pin delle
immagini target e i nuovi commit di qualifica. Il rientro intermoduloLua è
quello conservato e verificato per confronto dei file, non due test inventati.

[PR42](https://github.com/GioNob/ouf-deploy/pull/42) conserva i deltaWP2 e questa
cronologia sulla branch isolata. Per il DB sono riusati i18SQL e il digest di
catalogo già qualificati; la nuova policy esige ruolo completo, righe privilegio
univoche, freshness massima5secondi, identità/porta esplicite e contatori completi.
I test positivi su catalogo sintetico sono dichiarati unitari e non provano DB
reale, startup, currentOwner o HUMAN. WP2 resta aperto fino al G2 completo.

Prima revisione del forecast aG1: intervalliM1 **18–30h** eM2 **40–70h**, centrali24/55h, conservati fino al checkpointG2. Motivo: l'effortWP1 non è separabile con precisione dalla preparazioneWP2 e il componente nativo completo non è ancora qualificato. Nessun moltiplicatore di produttività applicato una seconda volta.

Checkpoint 20/10/2026, 12:08:55: CI39404688204 terminata **20/10/2026,12:00:19Europe/Rome**;47testPASS,0skip. Componenti nuovi Owner/SQL:10+8testlocaliPASS, osservati a questo checkpoint; backend/processi simulati, firme/CAS reali. G2rimaneaperto.

Checkpoint20/10/2026, 12:15:14: CI39405867174 terminata **12:09:46Europe/Rome**,65testPASS,0skip. Importazione daFD verificato:11testlocaliPASS con loaderDocker sintetico. IntervalloWP2 2026-10-20T09:53:01.026Z–2026-10-20T10:15:14.724Z: **22.23minuti**. Nuova attività di composizione NativePorts avviata esattamente a questo checkpoint; non è aperturaG2. Totale tecnico misurato chiuso: **58.47minuti**, più8,96iniziali non segmentati; nessuna attesa passiva o effortHUMAN inventato.

Checkpoint20/10/2026, 12:30:51: CI39406640241 terminata **12:16:10Europe/Rome**,76testPASS,0skip. Composizione NativePorts ancora in corso: corretta l'interazione CAS fra contatori dei componenti e statoRunner;8testlocaliPASS,7testguardruntimePASS,3testprofiloreadinessPASS. Cinque casi namespace/HTTP Linux attendonoCI. NessunG2 o admissiontarget anticipato.

Checkpoint20/10/2026, 12:45:39: CI39408488591 terminata **12:32:27Europe/Rome**,99testPASS,0skip; inclusi namespace/HTTP Linux reali con osservazioniEngine simulate. G2aperto. Dopo l'avviso utente12:41:55, branch/head/evidenze sono riconciliati senza replay. L'intervallo **12:34:57–12:42:11** (7.24minuti) è marcato **continuità non verificata** ed escluso dall'effort misurato, senza chiamarlo attesaHUMAN. Il nuovo intervallo attivo riparte dalla prima operazione verificata12:42:11. Quattro test locali del confine Gateway conservato sonoPASS; nessuna nuova lettura o mutazione target.
