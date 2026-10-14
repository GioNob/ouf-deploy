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
