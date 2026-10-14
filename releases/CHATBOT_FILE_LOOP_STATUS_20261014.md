# Ciclo file-chatbot: stato unico della ricomposizione

Aggiornamento del 14 ottobre 2026. Obiettivo: file → profilazione → semantica
assistita → approvazione HUMAN → configurazione/attivazione → ingestion →
risoluzione/commit con dati preesistenti → UDP → ricerca dal chatbot.

**L'end-to-end Teatri sul VPS non è ancora dimostrato.** Le precedenti stime
brevi non erano fondate su una verifica della combinazione da installare.
Le CI dei componenti non bastavano a sostenere quelle stime.

## Problema riscontrato e correzione concreta

La comparazione dei tree Git ha trovato funzionalità esistenti disperse tra
main, rami di integrazione e pacchetti live. Nuovi candidati verdi nelle loro
prove isolate perdevano capacità necessarie al flusso. Non era corretto
considerare queste capacità già conservate senza controllare il pacchetto.

| Modulo | Divario riscontrato | Intervento |
| --- | --- | --- |
| MCP | File upload/profile/preview, create source, semantic read e urban search assenti nel candidato nuovo | Ricomporre la linea funzionante con main; preservare operational awareness e aggiungere prepare/read della review owner |
| Gateway | Route file/owner/read perse; materializer proposal ricostruiva il documento azzerando le altre route | Ripristino e composizione additiva con controllo delle collisioni |
| Registry | IAM/consultation e delegazione mancanti nel candidato | Recupero delle classi qualificate e prova JWT reale in CI; import RDF nella proposta idempotente esistente |
| Onboarding | Main non comprendeva la linea già integrata picker, managed file, identity gate, THS | Riutilizzo del commit 6340d5bf120e09b47c32177656e2c377a4c03640, completamento della review browser per Source e semantica |
| Ingestion/UDP | Limite locale 20 contro 32 riferimenti ammessi dal canale file | Correzione circoscritta, CI verde e merge PR40/PR39 |
| Rilascio Registry | Profilo a 13 fasi imponeva nuovo trasporto/worker discovery non usati dal ciclo file | Profilo esplicito firmato a 11 fasi, senza no-op o riuso improprio delle autorizzazioni precedenti |

Il ramo integrato Onboarding è stato ritrovato prima di riscrivere la sua
funzionalità. La ricomposizione preserva il lavoro utile già fatto. Non si
deve installare la vecchia combinazione a tre pacchetti del mattino come
se queste regressioni non esistessero.

## Che cosa è già osservato e va riusato

- Il profilo Teatri esistente del file autorizzato è ancora leggibile via
  MCP: 13 righe, 20 colonne. Non ripetere upload o profilazione.
- La ricerca UDP via MCP del 14 ottobre restituisce gli otto Cinema ACTIVE,
  `nextCursor=null`, `partial=false`. È un readback attuale, non una nuova
  esecuzione dell'ingestion Cinema.
- Le tre radici create il 13 ottobre rimangono evidenza da riusare tramite
  il ledger completato; non ripetere le claim consumate.
- La review target 92b3276992b3b3ec459e734196671728b8a49a99a02185e2c6f7c1da87ce82a1
  e lo staging già eseguito restano storici validi dei loro byte. Non
  autorizzano immagini corrette diverse o operazioni ulteriori.
- La mutazione IAM del caller audience è già APPLIED_RECONCILED. Non ripeterla.
- Il gap storico di accounting rimane UNKNOWN/OPEN. Nessun azzeramento del
  budget è implicito nella ricomposizione.

## Prova composta superata e combinazione congelata

Il [run 38534861649](https://github.com/GioNob/ouf-ingestion-runtime/actions/runs/38534861649)
ha superato **36 verifiche sul percorso composto**, con quattro applicazioni
Java reali, server MCP Go reale, PostgreSQL e MinIO. Ha attraversato proposta
semantica, review e pubblicazione owner, consultazione del pin attivo,
creazione/review delle due sorgenti, readiness e attestazione, attivazione,
poller, MATCH con nuova revisione di un oggetto esistente, NEW, tre ACK
durevoli, ricerca MCP e provenienza di entrambe le sorgenti. Il CAP `00123`
rimane una stringa e l'identità dell'oggetto preesistente è conservata.

Il corpus CSV è sintetico. Autenticazione, mediazione Gateway, sign-in e
decisioni HUMAN sono fixture dichiarate; le API owner sono reali. La prova
non dimostra il VPS né l'esecuzione sui 13 Teatri. I dettagli e tutti i limiti
sono conservati in [chatbot-composed-pass-20261014.json](chatbot-composed-pass-20261014.json).

| Modulo | Commit main del pacchetto |
| --- | --- |
| Registry | `eccef11a97367f20e278db40b9ed6f45dd980c37` |
| Onboarding | `84828f74ac586bae09a78f0fb197b75b1a3d98d1` |
| Ingestion | `c48ee4b1873a474e81c6e1be70d393854021e2c1` |
| UDP | `b49c0d6f50c574c11684361ce4e8040e9cbddee2` |
| MCP | `f7ecaeb210d8fcead478b90c62645db13a7d8226` |
| Gateway | `bf179e96200deb84942ad32507edef52a4284cd0` |

La verifica indipendente via GitHub dei sei tree completi conferma che ogni
merge main è identico al relativo commit qualificato. La ricevuta
[chatbot-cohort-release-evidence-20261014.json](chatbot-cohort-release-evidence-20261014.json)
riporta i tree SHA, i run, i digest e il confine tra prova e autorizzazione.

Il [run pacchetto 38536134146](https://github.com/GioNob/ouf-deploy/actions/runs/38536134146)
ha completato build, scansione, export, boot Registry con quattro mount,
assemblaggio dei sei moduli e firma/verifica del publisher. Nessuna immagine
è stata applicata al VPS da questo run.

## Ripresa del pacchetto dopo lo sblocco Actions

Il run [38584614991, tentativo 2](https://github.com/GioNob/ouf-deploy/actions/runs/38584614991/attempts/2)
ha completato source-lock, i sei moduli, scansioni, assemblaggio e firma/verifica
del publisher. L’archivio completo è l’artefatto `11907557440`, SHA256
`144699ab7756c8312d49783967cfbb64acc02a617015ad89f5adf51e25a10300`.

Questa variante sostituisce soltanto il pin MCP della tabella storica con
`f249b3dcc58c2a96742092d90fa09fd90b705bd0` ([MCP PR69](https://github.com/GioNob/ouf-mcp-server/pull/69)):
conserva gli esatti byte delle migrazioni VPS 1–9 e aggiunge le migrazioni 10–12.
Non va integrata in main finché le altre cronologie installate non sono osservate.
Il lock corrente riporta questo overlay; la prova composta precedente rimane
qualificata per i propri sorgenti, non diventa una nuova prova composta dell’overlay.

[Deploy PR29](https://github.com/GioNob/ouf-deploy/pull/29), sorgente consegna
`f9b42b8cd4358a908c7a0e88777f9e55b8400258`, lega launcher, ingresso root,
manifesto dei sorgenti e qualificazione dell’estrattore allo stesso archivio.
Il controllo del manifesto confronta tutti i sorgenti effettivi e impedisce una
consegna con hash precedenti alle modifiche. I quattro check push/PR del nuovo
commit sono SUCCESS: il job nativo esegue 163 test in 22 suite; il job archivio
scarica e verifica il digest, estrae i sei pacchetti e i tre source archive.
[Ricevuta](chatbot-file-cohort-resumption-evidence-20261014.json). La migrazione rimane dietro
preflight amministrativo corrente, quattro backup, quiescenza e revisione
completa al terminale. Cleanup verificato delle abilitazioni temporanee prima
dell’avvio; nessun replay mutativo o restore automatico.

La ricerca MCP corrente del 14 ottobre conferma gli otto Cinema ACTIVE,
revisioni e proprietà della baseline invariati, `partial=false` e nessuna
pagina ulteriore. Non è una riesecuzione ingestion. La conferma corrente del
profilo Teatri resta da acquisire; non ripetere upload o profilazione.
Nessuna migrazione, sostituzione di servizi o nuova decisione HUMAN è stata
eseguita sul VPS da questa ripresa. Il ciclo reale resta OPEN.

## Arresto della preparazione sul VPS e diagnosi corrente

L'operatore ha eseguito la consegna qualificata e riportato l'output il
14 ottobre 2026 alle 18:27 CEST. Digest dell'archivio e sorgenti verificati;
estrazione privata avviata; login amministrativo IAM riuscito. Il programma
ha superato il controllo dell'asset/profilo esistente prima del login HUMAN:
questo dimostra i metadati richiesti (ownership, 13 righe, 20 colonne, versione
e hash), non una nuova lettura MCP dell'anteprima né l'ingestion.

Dopo CURRENT_HUMAN_OWNER_AUTHORIZATION_REVIEW la preparazione ha prodotto
BLOCKED / PG_STATEMENT_DENIED / runtimeAuthorityIssued=false. Il motivo è
un EOF del canale psql e non identifica da solo permessi, tabella, SQLSTATE
o guasto di connessione. La causa precisa resta UNKNOWN; nessun retry
automatico, grant correttivo o nuova migrazione è autorizzato da questa
diagnosi. Nessuna autorità di rollout è stata emessa da questa invocazione.

Il prossimo passo operatore è solo la diagnosi
[scripts/diagnose-file-cohort-postgres.py](../scripts/diagnose-file-cohort-postgres.py),
pubblicata al commit `5aec5cda89bac9a32b8111611288548b31439788`, SHA256
`c0ee2b57cea5147a19319748b6543e8948a48c51e21236a55144fb2ec14255d2`.
Controlla i quattro binding correnti, le query identità/storia e il preflight
amministrativo MCP in transazioni READ ONLY, con timeout; stampa solo controllo,
modulo, conteggio, fatti ammessi e SQLSTATE classificato. Non esegue
installer, restart, migrazioni, grant, restore, rinnovi di budget o token.
Cinque test locali verificano redazione, classi sconosciute e identità;
non sono prova PostgreSQL target. Nessuna conformità globale è dichiarata.

Conservare l'archivio da 1,7 GB già scaricato. Non rilanciare l'installatore
prima del risultato diagnostico. Un'eventuale consegna corretta riutilizzerà
i byte verificati, conservando storico, journal e vincoli di resilienza.

### Risultato della diagnosi operatore e controllo amministratore

Output riportato dall'operatore il 14 ottobre 2026 alle 19:14 CEST:
DATABASE_IDENTITY e MIGRATION_HISTORY PASS per UDP (35), Onboarding (32),
Ingestion (15) e MCP (9). Solo ADMIN_OWNERSHIP MCP è BLOCKED:
exitCode=2, sqlstate=null, UNCLASSIFIED_CHANNEL_FAILURE.
La lettura è completata; non è una prova positiva del preflight amministrativo.

Il codice di installazione e la prima diagnosi usano un nome amministratore
costante, `postgres`. La presenza e utilizzabilità di quel ruolo sul target
non è dimostrata. Gli errori di connessione possono precedere l'esecuzione
dell'impostazione VERBOSITY di psql: SQLSTATE assente non dimostra un
errore SQL né una mancanza di permesso su una tabella.

La diagnosi aggiornata, commit `286493fc68cf3b29dd8b559ac976495959ab8729`,
SHA256 `a9cc6d2f7ab4dcb905bc45d1e916d51eb8f571c048127690899799117876eaa8`,
legge soltanto il selettore POSTGRES_USER del container corrente e confronta
la sua esistenza/superuser con pg_roles tramite il caller applicativo MCP.
Prova poi la query amministrativa in READ ONLY con quel selettore esplicito.
Nessun default implicito, ricerca indiscriminata di superuser o credential file.
Classifica solo pattern FATAL fissi e redatti; errori sconosciuti restano BLOCKED,
senza retry automatico. Otto test locali PASS, non prova target.
Nessuna correzione di grant o installazione è stata eseguita.

Il prossimo passo è questa lettura diagnostica. La correzione del preparatore
dovrà legare selettore e identità/superuser osservati al piano firmato,
usando lo stesso amministratore per preflight, bootstrap e cleanup, e
preservando hash, backup e journal monouso. Conservare il pacchetto scaricato.

### Correzione dopo la diagnosi amministrativa positiva

L'output operatore delle 19:19 CEST del 14 ottobre 2026 dimostra che il ruolo
`postgres` non esiste, mentre il selettore POSTGRES_USER identifica un ruolo
esistente e superuser. La query amministrativa selezionata riesce:
PostgreSQL 170011; schema, audit_event, tool_attempt e sequenza hanno owner
authority per il workload; audit owner ancora assente. Per security_incident
la owner authority del workload è false. Non è una query fallita e non dimostra
di per sé l'assenza del privilegio TRIGGER.

La migrazione 4 già crea security_incident; la 12 richiede TRIGGER per
agganciare l'osservatore. Il preparatore corretto seleziona POSTGRES_USER,
prova current_user/superuser e vincola lo stesso amministratore al piano
privato e a bootstrap/cleanup. Richiede presenza/OID/owner/ACL della tabella
incidenti, senza imporre che il workload ne sia proprietario.
Se TRIGGER manca, la revisione completa include una concessione temporanea
non delegabile, limitata a quella tabella e a quel workload, con revoca prima
dell'avvio. OID e owner rimangono invariati; ACL normalizzata confrontata con
la baseline, anche dopo cleanup. Drift di altri privilegi blocca l'azione.
Controlli sotto lock di tabella in transazioni corte con lock_timeout; nessun
lock durante retry/wait, replay di mutazioni ambigue o cambio di ownership.

Il pacchetto rimane quello già verificato. La capsula aggiornata SHA256 è
`c83e9022e803d715c02de7f145c80c0e6ff39a7aee7ab4236c19510947bd2eb8`;
launcher SHA256 `058f188fed166b44cff717577658a8c0f1eb7fc6ba44357e6424f7e73a79e43f`.
Test locali: database 17, preparazione 7, launcher 13 PASS.
La CI deve qualificare PostgreSQL reale con amministratore non convenzionale,
security_incident di altro owner, migrazione 12 esatta, drift ACL,
trigger funzionante dopo cleanup e privilegi originali preservati.
Non consegnare la nuova azione prima del successo di questa prova.

La revisione privata include anche database, workload, amministratore e delta
TRIGGER effettivo con il preflight e il relativo hash; non si limita ai digest
contenuti nel bundle. La decisione al terminale vincola questi dettagli esatti.

Nessuna migrazione, grant operativo o rollout target eseguito da questi
cambiamenti. Ripresa tramite nuovo piano/revisione e riuso esplicito
dell'archivio già scaricato; storico e journal conservati.

### Consegna qualificata: stato target aggiornato sotto

Sorgente eseguibile immutabile `dca15f41bab8ddd254febb72f2a6008f94628ea1`.
[CI nativa 38608036495](https://github.com/GioNob/ouf-deploy/actions/runs/38608036495):
**176 test in 23 suite, PASS**, incluso il caso PostgreSQL reale con
amministratore dal nome diverso da postgres e tabella incidenti di altro owner.
Migrazione audit 12 esatta; grant TRIGGER limitato e revocato; ACL e owner
iniziali ripristinati, drift di altri privilegi negato, trigger funzionante
dopo cleanup, membership SET e CREATE temporanei revocati. La review concreta
dei delta è qualificata; non è un'accettazione sul VPS.

[Archivio 38608036351](https://github.com/GioNob/ouf-deploy/actions/runs/38608036351):
digest originale, sei pacchetti e tre source archive PASS.
La [consegna operatore corrente](chatbot-file-cohort-vps-20261014.sh) sostituisce
la prima consegna f9b42b8. Usa il gh portabile esistente e l'archivio
già presente nella directory della capsula iniziale 126e49f3830667934bf8f8d7.
Nessun nuovo download da 1,7 GB, upload Teatri o profilazione.
Se l'archivio manca o non è quello esatto, arresto prima di sudo/apply;
nessuna ricerca indiscriminata o sostituzione automatica.

Il comando opera con nuovo preflight e piano, login richiesti e revisione
completa al terminale. Prima della conferma dell'hash non emette autorità.
Le approvazioni applicative restano nel THS e la finestra è un'ora.
Nessuna migrazione o mutazione di servizi target è stata eseguita da questa
qualificazione. Prossimo passo: operatore esegue la consegna e riporta soltanto
gli stati redatti. End-to-end reale resta OPEN.

### Stato target corrente: blocco runc prima della revisione

L'operatore ha eseguito la sorgente qualificata dca15f41 usando l'archivio
esistente e riportato l'output il 14 ottobre 2026 alle 19:49 CEST.
Preparazione e login IAM riusciti; il precedente preflight DB è stato
superato. Il collector Registry si è fermato con
RETAINED_REAL_RUNC_GENERATION_AND_LAYOUT_REQUIRED e
runtimeAuthorityIssued=false. Non è stata raggiunta la conferma finale.
Nessuna migrazione, bootstrap audit role o nuova azione lifecycle target
è stata eseguita da questa invocazione.

La condizione richiede id, PID, status runc=running e un bundle con prefisso
esatto /run/docker/containerd/daemon/io.containerd.runtime.v2.task/moby.
Il caller prova Running=true per il Registry precedente, ma non distingue
Paused. Pausa o layout/alias sono ipotesi da discriminare: nessuna è ancora
un fatto target. Non relabel, unpause, restart, nuovo grant o ampliamento
della policy deriva dall'errore; nessun retry automatico di esito sconosciuto.

Il prossimo passo è il solo read
[scripts/diagnose-file-cohort-runc.py](../scripts/diagnose-file-cohort-runc.py),
SHA256 `7ebfa2816427073ed8398bf38f864dc3f06911445a739fdba6182a78b7cbf464`.
Usa le esatte binding retained e i loro hash, legge il container selezionato
e il comando runc state due volte; stampa soltanto booleane/profili e stati
redatti. Nessun login IAM, token, config.json OCI, pause/unpause, restart,
firma, migrazione o tentativo di apply. Cinque test locali qualificano
separazione running/paused, drift PID/generazione, layout distinti e redazione;
non sono un'osservazione del VPS.

Conservare pacchetto e capsule precedenti. Non rilanciare la consegna apply
prima di acquisire questi fatti. La prova CI rimane valida per i propri
sorgenti; il ciclo reale resta OPEN.

### Correzione layout e preflight aggregato prima dei login

L'output operatore delle 19:58 CEST del 14 ottobre 2026 identifica il divario:
container, PID, stato running e generazioni Engine/runc sono stabili;
bundleUsesSystemContainerd=true, bundleExactExpected=false.
La causa è il solo parent del bundle: /run/containerd/io.containerd.runtime.v2.task/moby.
Non è un container paused né una nuova generazione da adottare.

La correzione supporta due profili espliciti nel sorgente, Docker-managed e
system-containerd, selezionando esattamente il parent del container corrente.
Nessun glob o path arbitrario deriva dall'OCI. Il singolo parent scelto è
vincolato al recipe e alla revisione, riusato nelle successive osservazioni
paused, peer e full frame. Runtime root rimane quello già osservato /run/docker.
Il namespace /var/run/docker/netns è accettato solo come alias del parent
canonico /run/docker/netns, con custodia del parent e inode coincidente con
/proc/PID/ns/net. Parent ignoti, drift PID/id e stato paused restano negati.

Un nuovo preflight read-only precede entrambi i login IAM. Raccoglie nello
stesso report vincoli retained, generazione, baseline Engine (versione/driver/
cgroup/storage), custodia della chiave di consultazione (solo metadati),
runtime/layout, namespace, NIC e stabilità. I controlli indipendenti continuano
dopo un diniego, quelli dipendenti non fanno probe con selettori non verificati.
Fatti e codici redatti; nessuna autorità o credenziale viene concessa da PASS.
Il collector completo ripete i controlli e le route IAM prima della review.

La review privata include anche il contesto runtime Registry concreto e
l'expected rootfs seal indipendente. Capsule 112 sorgenti:
SHA256 `931746225f7043a8267073f93436ebb3ef87e05536ad125adaad6c8f92390321`.
Launcher SHA256 `eadb7093d04fcfad9c8f2e1baa95676ea32d76a763604f0267e682ce3ece674e`.
Localmente runtime layout 7 e launcher 13 test PASS.
CI completa e prova native runc/bundle/namespace ancora da completare per
questi sorgenti. Non consegnare questa variante prima del successo.

Nessun riavvio/unpause, nuovo grant target o replay. L'archivio originale
è conservato e verrà riutilizzato. Il prossimo comando sostituisce la vecchia
consegna; non richiede una nuova diagnosi per ogni singolo controllo nativo.

## Prova che manca per dichiarare il risultato

La combinazione completa deve essere installata tramite un ingresso operativo
unico, con revisione dell'azione, diagnosi e riconciliazione degli esiti ambigui.
Le approvazioni applicative HUMAN avvengono nel browser con gli esatti
contenuti e riferimenti; lo sviluppo non le sostituisce.

La prova sul VPS deve riportare asset, configurazione e pubblicazione,
run/correlation, esito di ogni riga, ACK durevole, decisioni di risoluzione,
commit/revisioni/lineage e ricerca autorizzata dal chatbot. Il conteggio degli
oggetti nuovi non viene assunto uguale alle righe. I Cinema preesistenti
devono risultare preservati. Una prova positiva di merge richiede record
realmente corrispondenti, non l'unificazione artificiale di Cinema e Teatri.
La ripetizione come seconda sorgente degli stessi Teatri può produrre MATCH
con nuova provenienza e NOOP canonico: una revisione numerica crescente non è
obbligatoria quando il contenuto e l'autorità vincente rimangono identici.
Le corrispondenze ambigue richiedono la review HUMAN esistente; non saranno
trasformate in MATCH automatici per fare passare la prova.

L'azione operativa in preparazione ha una finestra finita di un'ora, vincolata
al mandato corrente. La sua eventuale riuscita non certifica da sola un
servizio permanente 24/7.

La proposta semantica unica è descritta in
[TEATRI_SEMANTIC_REUSE_REVIEW_20261014.md](TEATRI_SEMANTIC_REUSE_REVIEW_20261014.md).
È preparazione non registrata: nessun pin di revisione/pubblicazione viene
inventato e nessun valore inferito viene spacciato per conversione eseguita.

## Regola di continuità

Aggiornare questo stato e i pin della combinazione, senza sovrapporre nuove
milestone che nascondano il percorso incompleto. Una prova di modulo è una
prova di modulo; una prova sul runner è una prova sul runner. La conclusione
richiesta dall'utente resta il ciclo reale utilizzabile dal chatbot.
