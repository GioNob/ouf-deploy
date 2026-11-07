# Onboarding — osservabilità e riconciliazione governata dell'autorità

## Due passi completati nel perimetro interno

1. Proiezione diagnostica read-only dello store: CURRENT, CONTENDED, RECONCILE_REQUIRED, REVOKED, EXPIRED, FENCED, UNAVAILABLE. UUID e digest del marker correlano la stessa pausa dopo restart. Contesa e dati illeggibili non diventano pronti; un binding installazione/tenant diverso non riceve dettagli.
2. Protocollo interno di riconciliazione dell'esatta lease, con gate fidato dell'esito owner, ricevuta persistente, generazione successiva revocata e ripetizione idempotente. Qualifica nativa con PostgreSQL e JVM separate.

Fonte: `6eb268070ca9c96743cb399b51558016fdc96aa5`, [PR Onboarding54](https://github.com/GioNob/ouf-source-onboarding/pull/54). [Contratto completo](https://github.com/GioNob/ouf-source-onboarding/blob/6eb268070ca9c96743cb399b51558016fdc96aa5/docs/STORAGE_RECOVERY_DURABLE_LOCAL_AUTHORITY.md).

## Cosa viene provato, e chi conserva l'autorità

`inspect(binding)` non crea lease, non cancella file e non concede lavoro. CURRENT descrive soltanto lo store corrente: readiness, validità policy e ammissione richiedono ancora gli owner esistenti. Gli errori di costruzione dello store devono essere proiettati come indisponibilità dal futuro adattatore operativo.

`PlatformAuthorityReconciliation.Gate` è una porta interna fidata. La futura implementazione operativa deve autenticare la decisione, associare il marker alla transazione/database ammessi, verificare COMMITTED oppure ROLLED_BACK ed escludere ogni transazione precedente fino alla chiusura. PID assente, timeout, lock OS libero e righe ripristinate non bastano. **Il gate operativo non è implementato in questo blocco**: i test usano un oracolo sintetico che conosce l'esito della propria transazione e un vero lock PostgreSQL NOWAIT sulla riga di controllo owner.

Il provider convalida fingerprint dell'intero comando, UUID/digest/generazione della lease, identità installazione/tenant, riferimenti actor/reason/decision e prova fresca di durata massima cinque minuti. Ricontrolla la stessa prova immediatamente prima della rimozione del blocco. Non introduce issuer, endpoint, bean, capability, grant o decisioni HUMAN ricavate dalla delega di sviluppo.

## Ordine persistente e ripresa

La transizione, sotto il guard OS esclusivo e l'esclusione owner del gate, è:

1. Ricevuta immutabile per command UUID, con checksum, file privato, staging, fsync e rename atomico.
2. Prova corrente alla generazione successiva, obbligatoriamente **revocata**, persistita e forzata.
3. Nuova verifica del gate e rimozione/fsync del marker esatto.

Un crash prima del punto 3 conserva la pausa. Ripetere il comando identico richiede nuova prova/esclusione e mantiene database, esito e riferimento owner della prima ricevuta. Dopo completamento, il replay identico restituisce la ricevuta storica senza rinnovare scadenze o richiedere un'altra mutazione. Un altro intento con lo stesso command ID, una generazione superata o una nuova lease pendente non vengono cancellati dal comando precedente.

La conclusione della riconciliazione non riapre il traffico. Nei test una pubblicazione separata alla generazione 3, nuova ammissione e nuova decisione/delivery permettono il drain; worker e decisione precedenti restano negati. Un budget già esaurito a 128 letture resta esaurito: zero GET e nessun nuovo asset.

Le ricevute hanno limite 8.192 byte e capacità 128 per store. Saturazione o corruzione bloccano; nessuna cancellazione automatica di storico. La ricevuta tecnica non sostituisce l'audit autorizzativo piattaforma. La rimozione governata dei blocchi resta subordinata alla custodia dello store e alla correttezza del futuro gate operativo.

## Qualifica

| Verifica | Esito |
|---|---|
| [Native owner 42037715612](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42037715612), job 127280796561 | **89 scenari nativi + 8 API/storage = 97 PASS**, zero fallimenti/errori/skip |
| Nuovi casi | 9; complessivamente 18 ricevute provider e 16 log di JVM figlie |
| Readback locale archivio nativo | **151 membri, 150 checksum, 275 blob Git esatti**; nessuna ripetizione nativa locale |
| [Regressione fisica 42037715655](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42037715655) | producer 127280094977 e readback 127281077240 SUCCESS; 39 membri, 38 checksum, 278 binding sorgenti, 1.695 file backup, 15 alterazioni semantiche respinte |
| CI sorgente | **8/8 SUCCESS**; suite generale 454 riportati − 89 skip nativi = 365 eseguiti PASS; scan bloccante immagine e boot container riusciti |
| Precedente checkpoint deploy 105a35c | **50/50 SUCCESS**; non attribuiti al nuovo commit documentale |

[Ricevuta completa](../evidence/storage-governed-authority-reconciliation-qualified-20261105.json), [verificatore riproducibile](../scripts/readback-governed-authority-native-20261105.py). Eseguire il verificatore con Python standard library, senza -O, dal checkout Onboarding al commit esatto e passare il percorso dello ZIP nativo scaricato. Gli artifact Actions scadono il 3 febbraio 2027; la ricevuta conserva digest, dimensioni e identificativi. Il readback fisico non è una seconda esecuzione di restore nativo, e lo ZIP fisico non è stato nuovamente verificato sul computer locale.

I nove casi aggiunti coprono:

- Osservazione senza scritture, correlazione stabile dopo restart, contesa non pronta e redazione del binding errato.
- Diniego per gate assente/conteso, prova scaduta/prestata/senza esito, generazione attiva, lease errata e transazione ambientale.
- UNKNOWN iniettato dopo il vero audit owner ma prima del commit: il lock PostgreSQL nega una risoluzione anticipata; dopo commit resta DRAINED e la generazione vecchia è revocata.
- Rollback effettivo, nuova ammissione separata e budget esaurito preservato.
- JVM terminata con halt87 dopo pubblicazione revocata/prima della cancellazione e halt86 dopo completamento/prima della risposta; replay da JVM nuova senza doppia ricevuta o rinnovo.
- Due comandi concorrenti: un solo vincitore, una sola ricevuta.
- Comando modificato e vecchio comando contro una lease successiva respinti.
- Saturazione a 128 ricevute e ricevuta corrotta: marker conservato.
- Prova scaduta al controllo finale: stato già revocato, marker ancora presente; nuova riconciliazione valida conclude.

La prima pubblicazione `297b7ed611ce312b385d59bc21cc74128a43927f` aveva il file dei test troncato nel trasferimento: la compilazione l'ha respinta. Il file locale integro è stato ripubblicato in `1b1dc75fd9bf03ca343c8d0fc95e6191c8ddb06d`, con rilettura integrale degli otto file cambiati e 97 test PASS. Il commit finale include anche i file di test condivisi nel filtro della regressione fisica, affinché cambiamenti di queste dipendenze ne riattivino la compilazione. Nessuna qualifica è attribuita al primo tentativo fallito; riferimenti e motivo sono conservati nella ricevuta.

## Confini e prossima coppia

Resta una qualifica same-host/local POSIX, con filesystem effettivo ext4. UNKNOWN è iniettato; il lock e il commit/rollback PostgreSQL sono reali, ma non si dichiara un COMMIT ambiguo causato da guasto reale di rete. I crash sono di processo, non power loss. La regressione fisica usa il driver sequenziale precedente e non integra il nuovo percorso di riconciliazione.

Mancano gate operativo con autenticazione e correlazione esatta lease/transazione, verifica della storia dopo restore, prepared transaction e perdita di custodia, pubblicazione/autorizzazione live, osservabilità via owner/Gateway/MCP, retention governata, mount produttivo, multi-host e budget dopo rollback completo owner. UDP/Ingestion, rollout misto, riapertura traffico, RPO/RTO ed E2E target restano aperti.

Prossima coppia proposta: collegare durevolmente la lease all'identità della transazione e del database ammessi; implementare e qualificare il resolver PostgreSQL su esito incerto reale, senza affidarsi all'oracolo di test o a un semplice flag. Non riaprire traffico né cancellare marker per solo timeout/PID.

MinIO/source-lock invariati; MiniPET **18,3/46 = 39,78%, 0/8 gate, 0/21 AT, 0/120 oggetti reali**. Nessun merge, deploy, target, grant o ammissione operativa. Entrambe le PR54 restano draft/open.
