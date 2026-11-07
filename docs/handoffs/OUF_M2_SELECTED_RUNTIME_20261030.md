# M2 — Composizione degli owner selezionati, prima del rilascio

30 ottobre 2026, Europe/Rome. Incremento PR54, sorgente
`05456554165d73731f8a259c35d9f2f5d696cb19`. CI qualificata su push e PR:432test/50suite per evento, zero skip;
entrambi i report finali letti.

## Obiettivo conservato

Teatri è completata a passi singoli. Riusarne componenti e prove per il flusso
completo, ripetibile e resiliente di ogni file. M1/G4, tecnico8/8 e funzionale6/6
sono acquisiti per Teatri, non accettazione generale M2. Farmacie conserva lo
stesso asset/job/profilo SUCCEEDED, 61 righe/10 colonne, codice ministeriale
STRING e tutti i 10 campi OPEN. Nessun nuovo upload/profiling/acquisizione.
La sequenza resta chatbot/onboarding, Registry locale, eventuale OntoPiA,
Ingestion, riconciliazione/materializzazione UDP con esito per ogni riga.
Search sugli oggetti e verticali/API/scheduler/delta seguono il percorso file.

## Modifiche concrete

`DiscoverySelectedRuntime` compone import immagini selezionate, Registry/provider/
worker fino alla barriera di verifica, Gateway e MCP. Richiede gli stessi oggetti
parent/child, Engine, transizione, window e componenti della review. Riusa gli
owner esistenti e i loro journal/budget; non inizializza journal, inventa retry o
fornisce un metodo di rilascio. Le pause dei componenti si propagano.

Durante Gateway/MCP mantiene il lock dedicato della transizione Registry:
un executor concorrente non può rilasciare i producer. Non è il lock condiviso
di rete/lease. Nessuna attesa persistita dorme sotto il lock: la pausa solleva
un’eccezione e lo rilascia. Verifica nuovamente cronologia Registry, immagini,
generazioni e prove di completamento prima del receipt. La barriera è logica;
non costituisce da sola una nuova attestazione fisica di quiescenza.

Il wrapper discovery Gateway v2 introduce marker esclusivi/fsynced per ogni
singolo dispatch lifecycle. La regressione controllata del journal mutabile
prima permetteva un secondo connect: test fallito sul sorgente precedente,
poi passato con i marker indipendenti. Anche risposta start persa e owner
ricostruito non autorizzano una seconda mutazione. Il Gateway storico è intatto.
`DiscoveryImages.verify()` controlla solo un import già VERIFIED senza caricare.

`DiscoveryExecutor` valida i due campi aggiuntivi del child contro gli esatti
componenti del parent corrente, autenticato e non revocato. Campi sconosciuti,
parent differente e scope discordante sono negati prima del claim. Non proietta
o rifirma il child. `DiscoveryApplication(discovery_parent=...)` usa questo
executor; il percorso storico continua a rifiutare le estensioni.

La CI intermedia `4b71eada` ha scoperto che un hook nell’executor condiviso rompeva
il confronto con un artefatto pubblicato immutabile. Il successore ripristina
esattamente quel file, conserva artefatto/test/pin e specializza solo la validazione
v1/13 fasi nella sottoclasse discovery. Esecuzione, CAS, lock e riconciliazione
rimangono ereditati. Questo fallimento e la correzione restano nell’evidenza.

## Verifica e limiti

65 test locali pertinenti passati: Gateway13, immagini7, composizione9,
executor discovery6, executor storico9, file-only10, application11. La
composizione usa owner leaves modellati; executor/application verificano firme
Ed25519 e journal reali con effetti nativi sintetici. Il primo incremento
`17cb553f` ha superato push e PR:405test/47suite, zero skip, report finali letti.
Il successore05456554 passa432test/50suite/zero skip per evento:
push41133846758/job124331281185 e PR41133853136/job124331301342;
entrambi i report finali letti.
Anche7test locali sugli artefatti pubblicati PASS20.983s:142moduli del capsule
corrente coincidono byte per byte. CI recovery586test/64suite PASS con2skip
TLS esplicitamente subordinati a uno scope nativo dedicato; altri2testDB e
3test della generazione paused PASS, tutti i report finali letti.

[Evidenza](../../evidence/m2-discovery-selected-runtime-qualified-20261030.json).
Le prove Docker di immagini e MCP sono separate, con package/parent/admission
sintetici e applicazione MCP HTTP statica. Non equivalgono a eseguire insieme
questo coordinatore o il binario MCP reale. Le precedenti anomalie locali MCP
restano senza causa dimostrata; nessuna guardia è stata indebolita.

## Prossima prova necessaria

Eseguire una composizione nativa comune degli owner reali, iniziando da provider
v4 e worker distinto sullo stesso Registry/Engine/parent/child, conservando i
confini di ammissione espliciti. Poi qualificare coorte corrente completa e
TLS/IAM/DB/fencing/trust, compiler/review privata e CLI sigillati, pubblicazione
coordinata delle capability. Discovery reale Farmacie, mapping pinned e THS,
Ingestion/UDP e rendiconto61righe devono ancora essere eseguiti e verificati.
Reimport invariato, fault/ripresa/cambio chat, boot/rotazione, due client e tutte
le24AT/8UX/8stabilità restano richiesti. M2/G5–G7 restano OPEN.

Nessun nuovo comando operatore è pronto. Gli scope precedenti restano consumati.
Nessuna authority/grant/budget/reset/replay/merge o accettazione target è dedotta
dalle prove CI; le modifiche di questo incremento sono solo di sorgente.
