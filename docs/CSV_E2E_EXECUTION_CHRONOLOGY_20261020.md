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

Il primo intervallo misurato è durato **22.00minuti**, con lavoro WP1 e preparazione WP2 intercalati; la suddivisione esatta fra i due WP non è stata inventata. L'intervallo iniziale non segmentato dura **8.96minuti** e resta esplicito. Il secondo intervallo misurato va dalle **11:38:46 alle11:53:01**. Gli intervalli WP2 successivi e le relative chiusure sono conservati nel registro eventi; i checkpoint sotto aggiornano il consuntivo. Il registro conserva il tempo trascorso, l'effort misurato, la precisione e le eventuali attese su assi distinti.

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


Checkpoint20/10/2026,12:54:20: CI39410225377 terminata **12:47:07Europe/Rome**,104testPASS,0skip. Successivi31testlocali binding/Owner/DB/Gateway e7test di composizione profiliPASS. Il nuovo compilatore verifica Engine unico, canaleDocker esplicito senza credenziali, stessa generazione Onboarding/Owner, payload e riferimento chiave del piano Owner già concluso, config Gateway prima/dopo e budget finiti. È preparazione privata: G2 resta aperto, nessuna authority o operazione target.

Consuntivo prudente misurato chiuso: **86.16minuti (1.436ore)**, più8,96minuti iniziali non segmentati. Anche12:47:51–12:52:01 è escluso dalla misura: contiene lavoro locale e risposte di stato, ma il momento esatto di fine attività precedente non fu marcato. Non viene classificato come attesaHUMAN. Nuovo intervallo attivo dal checkpoint12:54:20.

| Gate | Baseline centrale cumulativa | Consuntivo confrontabile | Stato |
| --- | --- | --- | --- |
| G1 |3h|0,604–0,753h, inclusa preparazioneWP2|PASS11:53:01|
| G2 |14h|1.436h misurate cumulative al checkpoint, lavoro ancora aperto|Nessuna varianza finale finché il gate non è provato|
| G3 / M1 |19h /24h|Non raggiunti|Gate runtime e accettazione ancora necessari|
| M2 |55h centrale;40–70h intervallo|Non raggiunto|Forecast invariato fino al riesameG2|

I timestamp di inizio/fine attività sono separati da quelli di completamentoCI e decisione dei gate. Nessun tempo di calendario non verificato viene trasformato in effort; il rapporto fra ore spese e55h previste non equivale alla percentuale funzionale completata.


Checkpoint20/10/2026,13:03:17: CI39411288606 terminata **12:56:36Europe/Rome**,113testPASS,0skip. Nuovi testlocali:6canaleEngine+7composizioneNativePorts+9policyDB PASS. La query nuova usa floor(epoch) per non generare osservazioni future per arrotondamento: nessuna tolleranza aggiunta alla freschezza5s, nessun replay del preflight storico. Composizione completa scritta, ma issuer/chiusura/entrypoint e qualifica rappresentativa ancora aperti; G2NONPASS.

Effort cumulativo chiuso **95.11minuti (1.585h)**, più8,96minuti iniziali non segmentati e con i due intervalli incerti esclusi. Nuova attività issuer/chiusura/qualifica dal checkpoint13:03:17. Baseline centrali immutate: G2H+14, G3H+19, M1H+24, M2H+55. Nessuna percentuale di completamento derivata dal rapporto delle ore.


Checkpoint20/10/2026,13:13:10: composizioneCI39412298239PASS, completata13:05:20. Prima qualifica PostgreSQL reale39412833943 **FAILED13:08:54**,3erroriCAS: i GETEngine con budget condiviso rendevano obsoleta la versione restituita dai controlliDB/Owner. Corretto il riaggancio della sola versione/contatoreGET; nessuna modifica a fencing, claim, scadenze o budgetSQL.28testlocaliPASS (8Engine+9DB+11Owner). La nuova qualifica PostgreSQL è necessaria: la run fallita non diventaPASS per una correzione locale.

Totale tecnico misurato chiuso **105.00minuti (1.750h)**, più8,96iniziali non segmentati; intervalli incerti sempre esclusi. G2aperto controH+14; nessuna varianza finale o nuova previsione di accettazione. Nuovo intervallo attivo13:13:10. Nessuna operazioneVPS/login/refresh/reset/replay.


Checkpoint20/10/2026,13:18:23: qualifica PostgreSQL reale39413446807 **PASS13:14:20**,3test,0skip, catalogo0ae9e4f3fda6fd7f4432c1816139a53eba471077730badf2beb61712585ed209. Query nuova ripetuta, checksum alterato e membership broad verificati, tentativi conservati. Prima run fallita39412833943 resta registrata. Regressione componenti39413446767PASS13:15:06.

Issuer/entrypoint/chiusura scritti:6testissuer con firmeEd25519reali di fixture;4testletturaautorità;5testloader con importisolato reale di113moduli, nessun fallback disco. Ricevutequalifica/HUMAN dei test sono sintetiche: **non provanoG2néautoritàtarget**. L'issuer rifiuta qualifica rappresentativa mancante/incompleta e consuma il claim prima delle firme; l'entrypoint separa initialize/step/reconcile senza autenticazione o loop. RestanoAPISIX/JVM e avversariali sull'executor completo.

Effort misurato chiuso **110.21minuti (1.837h)**, più8,96iniziali non segmentati; intervalli incerti esclusi. Nuova attività13:18:23. G1chiuso, G2aperto rispettoH+14; M1centrale24h/M2centrale55h non riscritti. Tecniche8/8, funzionali4/6.


Checkpoint20/10/2026,13:32:01: CI39414076923 **PASS13:20:44**, compresi issuer/entrypoint/importisolato113moduli; anchePG39414076927PASS. Preparata la sequenza completa suDocker29, APISIX/etcd,PG17 e immagineJVMqualificata, con perdita della rispostaCREATE giàeffettuata e bearerpubblicatoscaduto. Il serverOwnerGET e l'identitàHUMAN sono fixture sintetiche dichiarate; gli oggetti/firme/journal/custodia e i runtime sono reali diCI. G3 dovrà verificareHUMAN/Owner attuali deltarget; nessuna acquisizioneF5/F6 dichiarata.

Effort cumulativo chiuso **123.85minuti (2.064h)** contro baseline cumulativaG2 **14h**. Il gate è ancora aperto: la differenza dalle14h è budget teorico non ancora consumato, non una stima certificata del residuo. M1centrale24h/M2centrale55h restano le previsioni congelate fino al riesameG2. Ulteriore intervallo attivo dal13:32:01;8,96min iniziali non segmentati e intervalli incerti separati.


Checkpoint20/10/2026,13:44:35: setup della prova completa fallito due volte per escape del workflow introdotti nella nuova fixture:39415803840/job118604385287 (printf,13:33:49) e39416140228/job118605505203 (continuazioneenv,13:37:02). Sono fallimentiCI conservati, non prove di runtime. Checksumartefatto invariato; tutti i blocchishell verificati conbash-n e doppi escape rimossi. Il tarDocker29 è ora fissato anche alloSHA256 osservatod8db66739d2e28d4933786d73e918d9be643a67fbd835db1bf740d650a259e70. Regressioni componenti ePG17 delle rispettive run restanoPASS.

Aggiunta la pausa persistente dei GETOwner429/502/503/504:Retry-After, budgetcumulativo e assenza di probe duranteattesa. Un effetto conclaim consente solo riconciliazione, maiapplyautomatico.5nuovi testlocaliPASS;8regressioniRunner+7NativePorts+5loaderPASS;3testHTTPnamespace attendonoCI. La suitecore16 ha15PASS e il noto errorelocale fchown(10002,10002)=EINVAL: non è stata indebolita; il test devepassare sulrunnerroot reale.

Consuntivo tecnico chiuso **136.42minuti (2.274h)**, più8,96iniziali nonsegmentati; intervalliincerti esclusi. G2aperto contro14hcentrali;M1H+24/M2H+55immutati. Ulteriore intervalloattivo13:44:35. Nessun targetcall/login/refresh/reset/replay.


## Checkpoint 2026-10-20T12:22:36.152Z

Effort tecnico misurato cumulativo: **2.763 h**; baseline cumulativa G2 **14 h**, gate ancora aperto: scostamento finale non determinabile. L’intervallo non verificato 12:12:28–12:21:06.540 UTC è escluso. WP5: sola ricognizione dei contratti intercalata, nessuna allocazione oraria inventata.

Le prove PostgreSQL17 restano PASS. La sequenza reale Docker29/APISIX/JVM ha superato i precedenti confini e si arresta alla creazione Gateway per un campo di configurazione ereditato non coincidente; run39419681503, completato12:12:29Z. I casi di risposta CREATE persa e bearer scaduto passano. G2 non superato. Diagnostica limitata al nome del campo, senza valori privati. Il nuovo lettore HUMAN conserva contatori e ricevuta governata senza eseguire login/rinnovo; 5 test sintetici PASS. Nessuna autorità o operazione sul target.


## G2 PASS — 2026-10-20T12:51:39.940Z

Il gate G2 è superato sul sorgente24c2d9b8c7b3f4f8a4a61125b86877ffbd635dba:162test componenti,3PG17,3sequenza/adversariali reali, inclusa esecuzione tramite closure114moduli, issuer e entrypoint isolato. Dossier: CSV_E2E_G2_NATIVE_EXECUTOR_QUALIFICATION_20261020.md. Qualifica completata dal provider12:49:12Z, decisione12:51:39.940Z. Nessuna operazione o autorità target.

Effort cumulativo misurato al gate:3.160557h; limite conservativo includendo ogni intervallo iniziale/non verificato:3.730817h; baseline14h. Differenza cumulativa tra−10.839443 e−10.269183h. Include WP5 intercalato, non è il solo effort WP2 e non è una previsione del tempo residuo. Baseline immutata.

WP5: Ingestionbcc1354, CI39423704214 PASS197test,2skip; Onboarding17a68ae, CI39425216528 PASS273test,0skip; UDPdf1f4c3, CI39424531492 PASS267test,2skip. I casi di conversione, compatibilità/outbox/quarantine e datatype owner sono verdi nei moduli. G5 resta aperto: manca prova composta dei nuovi pin, vocabolari/relazione. WP3 attende HUMAN/THS corrente ed executor target qualificato; si prosegue nelle attività indipendenti. Tecniche8/8, funzionali4/6.
