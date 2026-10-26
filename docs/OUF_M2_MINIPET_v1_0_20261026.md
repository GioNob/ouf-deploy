# OUF — Mini-PET M2: CSV autoguidato fino a UDP

**ID:** OUF-MP-CSV-M2 · **Versione:** 1.1 (percorso file conservato per i link esistenti) · **Data:** 26 ottobre 2026, Europe/Rome  
**Stato:** piano del residuo M2; M1 acquisito, M2 aperto.  
**Accettazione di prodotto:** Giovanni / HUMAN autorizzato. **Esecuzione:** agent principale, sequenziale, senza subagenti o automazioni operative.  
**Stima residua:** da ricostruire sui delta verificati. Le 34–58 ore, centrale 46, e la relativa riserva della versione 1.0 sono ritirate come forecast corrente.  
**Roadmap:** [sequenza e checkpoint](OUF_M2_ROADMAP_20261026.md). **Registro:** [piano strutturato](../releases/csv-m2-plan-20261026.json).

## 0. Rettifica: M2 riusa M1, non lo ricostruisce

La versione 1.0 mescolava componenti già realizzati, prove già acquisite, nuove prove e possibili lacune implementative dentro sei blocchi con ore assegnate. La separazione non era sufficiente a sostenere la stima residua. La versione 1.1 conserva i criteri di accettazione, distingue il riuso e ritira il forecast numerico fino a un inventario puntuale dei delta. **Un requisito M2 non ancora accettato non significa che il relativo componente sia da costruire.**

| Area | Già acquisito / riusabile | Solo residuo M2 |
| --- | --- | --- |
| Pipeline Ingestion → UDP | Esecuzione e materializzazione provate sulle due run Teatri; ACK, intake e lineage letti dagli owner | Esercitare il percorso sul nuovo CSV/configurazione; correggere solo differenze osservate |
| Identità | Stessi 13 oggetti anche per riga/contenuto sulle due run | Provare configurazione invariata/no revisione gratuita; configurazioni M1 differenti non coprono questo test |
| Proprietà e provenienza | 20 proprietà correnti selezionate per oggetto, contributi di entrambe le run; omissioni della nuova run tutte EMPTY_STRING | Verificare i casi specifici non coperti: fonti distinte, autorità/conflitto, altri null/vuoti e relazioni. Prima censire i test esistenti |
| Letture governate | Owner READ installate e riuscite, controlli di label e provenienza utilizzati per M1 | Comporle in un resoconto utente automatico e completo; nessuna nuova installazione READ presunta |
| Governance / deployment | Pubblicazione/review native e controller finiti già sviluppati e qualificati nei rispettivi perimetri | Riutilizzarli; una nuova qualifica o azione target solo se un delta effettivo la richiede |
| Ricerca | Serving Teatri/Cinema già utilizzato; tool tipizzati presenti | Collegare risultati del nuovo percorso alla consultazione; test specifici di autorizzazione/paginazione impattati |
| Farmacie | Upload completato e asset conservato; job di profiling FAILED | Causa reale e fix/recovery circoscritto, senza ricominciare upload o pipeline |
| Flusso autoguidato | Capability, stati e review esistenti da comporre | Eliminare passaggi manuali, rendere leggibile la diagnosi e verificare recupero senza ID copiati |
| Semantica generale | Mapping e parte dei delta tipizzati già presenti/qualificati storicamente | Audit per vocabolari, gap e relazione semplice: riuso, test mancante o fix effettivo distinti |
| Resilienza e due client | Primitive e prove pregresse da riusare con i relativi limiti | Collaudo specifico CSV invariato/fault/nuova chat e due client; non riscrivere un recovery engine |

Fonte per le prove M1: [dossier owner](../evidence/csv-m1-f5-f6-owner-verification-20261026.json). La tabella non attribuisce alle prove Teatri coperture più ampie di quelle osservate.

Prima di imputare ore a una voce residua, compilare: requisito → componente/commit esistente → prova riusabile → limite → delta concreto → nuovo test necessario → stima. Se manca solo una prova, la voce è **collaudo**, non sviluppo. Se il codice esiste ma non è collegato al percorso, è **integrazione**. Solo una lacuna dimostrata è **implementazione**. Una regressione su prova valida si riesegue soltanto per impatto motivato.

## 1. Risultato da ottenere

Un utente autorizzato porta un nuovo CSV, come Farmacie, fino agli oggetti UDP attraverso un percorso fluido e autoguidato: carica il file una volta, comprende e corregge la proposta, decide sulle ambiguità reali, approva gli effetti nel percorso fiduciario e riceve un risultato verificato. Il sistema gestisce avanzamento, attese ammesse, contesto e recupero. L'utente ordinario non deve conoscere job ID, endpoint, log, comandi VPS, SQL o sequenze interne.

M2 è completo quando questo percorso funziona su **due client MCP indipendenti**, almeno uno senza UI incorporata, con un nuovo CSV, semantica dichiarata, riconciliazione UDP, reimport invariato, guasti controllati e ripresa dopo cambio chat. Il chatbot accompagna il processo; gli owner conservano stato, autorizzazioni e decisioni. Non si introduce un agent interno a OUF.

Il caso Farmacie è la prima prova rappresentativa. Una correzione diagnostica o l'import riuscito di quel solo file non bastano a chiudere M2.

## 2. Baseline, fonti e stato certo

Questo mini-PET dettaglia il residuo WP5/WP6/WP7 del [mini-PET CSV 1.1](OUF_CSV_E2E_COMPLETION_MINIPET_v1_1_20261020.md). Conserva i suoi 24 requisiti CSV-R01…24, 24 test CSV-AT-01…24 e gate G5/G6/G7; aggiunge criteri espliciti di fluidità. La baseline del 20 ottobre resta storica: le sue indicazioni di ripartenza e stati OPEN di M1 non sono lo stato corrente.

Precedenza: istruzioni attuali dell'owner; Matrix/PET/contratti originali; [policy di resilienza v3](OUF_RESILIENCE_POLICY.md); questo piano per sequenza e stima. Non sono cambiate ownership o semantiche di accettazione. Riferimenti riletti: Blueprint 0.3 §§9–10, Matrix 1.7 §7, Onboarding 1.6 §§7.3–7.6, MCP 1.4 §§33–35 e catalogo E2E 0.3 nell'allegato OUF Reality Baseline Package 1.7. Restano applicabili UDP 1.3, Semantic Registry 1.3 e contratti 1.0.0-rc3-coherence secondo la tracciabilità del mini-PET precedente. Gli originali pertinenti si rileggono prima del relativo delta implementativo.

| Elemento | Evidenza disponibile | Limite / lavoro residuo |
| --- | --- | --- |
| M1 / G4 | [Handoff M1](handoffs/OUF_M1_COMPLETED_20261026.md), [dossier](../evidence/csv-m1-f5-f6-owner-verification-20261026.json): due run Teatri, 26 join di evidenza, 13 identità conservate, 20 proprietà correnti selezionate per oggetto, 8 Cinema preservati | Prova del caso conservato. Le configurazioni delle due run differiscono: non certifica reimport a configurazione invariata né M2 |
| Nuovo CSV Farmacie | Upload completato, asset conservato; un solo job di profiling arrivato a FAILED / ONB_FILE_PROFILE_FAILED | Causa server non ancora dimostrata; nessun profilo, fonte o acquisizione Farmacie completati |
| Originale allegato | 13.903 byte, UTF-8 con BOM, separatore punto e virgola, 61 righe dati / 10 colonne, forma regolare e header unici; verifica Python CSV strict positiva | Non prova uguaglianza con i byte server né esecuzione del parser Java installato. Java locale indisponibile per libjli.so |
| Diagnosi owner | PR draft [Onboarding #52](https://github.com/GioNob/ouf-source-onboarding/pull/52), commit a5ed8b05c264a8221783a6e323ba00117aed891d: categoria minimizzata del FAILED senza nuovo profiling | Candidato CI, non installato; categoria live e causa ancora sconosciute. UNCLASSIFIED resta possibile |
| Qualifica del candidato | CI push 40363732930 e PR 40363741161 concluse; log diretti: 283 test di modulo, 0 failure/error/skip; prove mirate e build/scan/boot in CI | Non equivale a readiness VPS, correzione Farmacie o nuova autorità runtime. [Checkpoint diagnostico](../evidence/managed-profile-diagnostic-ci-checkpoint-20261026.json) |
| Consultazione | Catalogo con semantic.search, urban.object.search, urban.object.related_search e letture di acquisizione | Presenza nel catalogo non prova grant attuale o successo. La search oggetti esposta oggi accetta tipo canonico esatto e paginazione, non filtri arbitrari |
| Accessi temporanei | Policy 54 documentata per upload/profile/preview fino alle 19:34:29 Europe/Rome del 26 ottobre | Osservazione storica, non grant permanente o autorizzazione ad acquisire; nessun rinnovo automatico |

Contesto Farmacie da preservare: handoff `4da5410e-98de-472c-89b6-bc1cdae8ecf1`; asset `9c502da5-b5d8-405e-b3f5-60eb31ecb513`; job `677480c8-3d10-44fd-9dad-f72ddeed20a4`; SHA256 dell'allegato `f670059bb524832aa9cd78fbe5e907be053244248ff1ef4d7962b14fcd72c311`. Gli identificativi servono alla tracciabilità tecnica; l'utente deve poter riprendere dicendo «riprendi il caricamento Farmacie» e scegliere solo se vi sono più lavori compatibili.

Il link al picker non è una pagina di diagnosi. Il tentativo autorizzato di lettura browser della API del job ha restituito 401: non dimostra la causa del profiling. Non esiste in questa evidenza una pagina THS verificata da proporre per leggere il dettaglio del job.

## 3. Perimetro e confini

| Incluso in M2 | Criterio |
| --- | --- |
| CSV nuovo e profilo dichiarato | UTF-8 con/senza BOM, virgola/punto e virgola, quoting/newline, limiti espliciti e diagnosi; niente reinterpretazioni silenziose |
| Onboarding autoguidato | Profiling, proposta di classe/campi, INCLUDE/EXCLUDE e classificazione, identità, tipi, vocabolari, temporalità e relazione semplice |
| Governance | Review concreta, hash/versione attuali, effetti di pubblicazione e acquisizione espliciti, decisione HUMAN in THS |
| UDP | MATCH / NEW / REVIEW, contributi complementari, conflitti e provenienza, esiti per ogni riga |
| Ripetibilità | Stessi byte e configurazione/semantica fissate: niente duplicati o revisioni canoniche gratuite; retry tecnico distinto da nuova acquisizione |
| Resilienza del percorso | Stato persistente, retry finiti ammessi, claim ambigui riconciliati, scadenza/revoca, ripresa da chat/client e quarantena governata |
| Consultazione minima | Ritrovare tipo e oggetti prodotti, pagine autorizzate, provenienza e relazione semplice usando capability realmente esposte |
| Qualifica rappresentativa | Due client reali, UI fiduciaria utilizzabile anche da mobile, ambiente isolato per fault, secondo profilo di installazione isolato |

Restano separati: fusione di **due oggetti canonici già esistenti** con survivor/alias/storia (OUF-E2E-014), ricerca avanzata per nome/indirizzo/prossimità, grafi multi-hop, motore analitico, altri formati, streaming, installer universale e Supervisor. La riconciliazione multi-fonte su un unico oggetto è invece obbligatoria in M2. La loro esclusione non elimina i requisiti PET più ampi: saranno mini-PET successivi, senza PASS implicito.

Il presente piano autorizza zero effetti runtime, acquisizioni, nuovi grant o pubblicazioni. Nessuna terza acquisizione del caso Teatri conservato. Le future prove con file nuovi o fixture sono intenzioni distinte, ammesse solo attraverso la governance prevista.

## 4. Esperienza utente e contratto di fluidità

| Momento | Il sistema fa | L'utente fa | Evidenza di uscita |
| --- | --- | --- | --- |
| Avvio | Verifica capability/accessi necessari e apre il corretto upload governato; conserva il riferimento del lavoro | Sceglie il file; autentica la propria sessione quando necessario | Un asset owner e una receipt, recuperabili |
| Analisi | Avvia una sola profilazione ammessa, segue lo stato in modo bounded, mostra colonne/anomalie e distingue attesa da errore | Non impartisce comandi «prosegui» per ogni fase tecnica | Profilo completo oppure motivo sicuro e azione consentita |
| Proposta | Presenta tipo, mapping, campi esclusi, label, chiave e trasformazioni con motivi e punti incerti | Conferma/corregge le sole scelte di dominio mancanti | Configurazione validata e riferimenti semantici esatti |
| Revisione | Mostra riepilogo unico degli effetti; riusa scelte già confermate finché valide; collega la review giusta | Approva/rifiuta nel Trusted Approval Workspace | Decisione vincolata alla versione corrente |
| Esecuzione | Pubblica/ammette esclusivamente gli effetti approvati, segue Ingestion e UDP, conserva il contesto se la chat termina | Può allontanarsi e tornare senza copiare identificativi | Stato owner durevole e progresso verificabile |
| Eccezioni | Raccoglie le righe ambigue e spiega causa/opzioni/effetti; recupera automaticamente solo i transitori ammessi | Decide sui casi che richiedono realmente giudizio o nuova autorità | Decisione consumata una volta; resto del lavoro conservato |
| Risultato | Riepiloga tutte le righe, mostra oggetti/variazioni/provenienza e capacità di ricerca disponibili | Consulta e verifica il risultato | Materializzazione owner, non solo ACK o container ready |

Le fasi sono un modello di presentazione. Non impongono nuovi enum o un motore di workflow parallelo. Autoguidato significa che il backend procede entro l'intento già autorizzato e il client propone il prossimo passo valido. Non significa che la chat esegua in background dopo la sua chiusura o che il modello approvi al posto dell'utente.

Per una fonte senza ambiguità: una selezione del file, una proposta consolidata e le sole decisioni HUMAN richieste dai contratti. Obiettivo di UX: un unico percorso di review, anche quando contiene più decisioni owner; non promettere una singola firma che sostituisca atti distinti. Un grant mancante produce una richiesta amministrativa chiara, non una catena di errori dopo l'upload.

**Criteri aggiuntivi obbligatori** (namespace locale UX, non nuovi scenari E2E canonici):

| ID | Criterio verificabile | WP |
| --- | --- | --- |
| M2-UX-01 | Nel percorso positivo zero comandi terminale/SQL, zero copia-incolla di ID/hash/log, zero «prosegui» usati soltanto per avanzare una fase tecnica | 2,6 |
| M2-UX-02 | Un solo upload/profiling per l'intento iniziale; risposta persa e doppio click non producono duplicati. Ogni rifiuto indica causa sicura, stato conservato e azione valida, oppure blocco operativo esplicito | 1,2,5 |
| M2-UX-03 | Proposta leggibile: ogni colonna ha destinazione o esclusione motivata; chiave/label/trasformazioni esplicite; nessun IRI o significato inventato | 3 |
| M2-UX-04 | Link THS verificato per la decisione esatta, login e ritorno preservano contesto; telefono/desktop, scadenza e versione obsoleta hanno recupero comprensibile | 2,6 |
| M2-UX-05 | Nuova chat ritrova il lavoro dagli owner con accessi correnti; nessuna dipendenza da memoria del modello o receipt browser scaduta; più lavori richiedono selezione breve | 2,5,6 |
| M2-UX-06 | Ogni riga è contabilizzata; nessun «completato» con righe invisibili, in attesa, redatte senza copertura dichiarata o solo ACK ricevuto | 4,6 |
| M2-UX-07 | Oggetti ritrovabili con la ricerca tipizzata disponibile; pagine/cursori/parzialità dichiarati, zero accessi a proprietà o conteggi non autorizzati | 4,6 |
| M2-UX-08 | Attesa mostra ultimo stato osservato e prossimo controllo previsto; errore non transitorio non entra in loop. Guasto di una dipendenza non genera un incidente per ogni riga | 1,2,5 |

Nel collaudo si registrano azioni umane, round-trip THS, richieste di chiarimento, tempo attivo dell'utente, attese e interventi operatore. I criteri a zero sopra sono bloccanti. Tempi di profilazione/import e p50/p95 si misurano sul profilo finale; non si inventa oggi uno SLA. Soglie prestazionali contrattuali esistenti restano obbligatorie.

## 5. Mapping Farmacie da proporre e validare

Questa tabella è un'ipotesi di lavoro da verificare sui dati e sul Registry, non una configurazione approvata.

| Colonna | Trattamento proposto | Decisione / controllo |
| --- | --- | --- |
| nome_denominazione | Nome dell'oggetto | Proprietà pubblicata esatta; normalizzazione esplicita |
| indirizzo | Stringa indirizzo conservata | Nessuna geocodifica o separazione arbitraria |
| latitudine, longitudine | Numeri secondo formato dichiarato | Ordine assi, range, coppia completa e CRS; niente inversione silenziosa |
| sistema_coordinate | Riferimento al CRS dichiarato | Verificarne valore e coerenza; non assumere EPSG dal nome della colonna |
| cap | Stringa | Conservare zeri iniziali e formato |
| codice_ministeriale | Candidato per sourceObjectId | Verificare unicità, completezza, stabilità e namespace; non è urbanObjectId |
| tipologia | Candidato mapping codice/valore → concetto | Usare vocabolario pubblicato; unknown genera gap o trattamento approvato |
| inizio_validita_anagrafica | Data con formato esplicito | Verificare significato di dominio; nessuna fine validità inventata |
| note | Testo facoltativo | Valutare INCLUDE/EXCLUDE e classificazione; nessuna label OPEN automatica |

Per tutte le colonne: obbligatorietà, null/vuoto, errori, label e provenienza devono essere dichiarati. La classe Farmacia e gli IRI delle proprietà si risolvono dal Registry; se mancano, il flusso guida la proposta semantica e la relativa decisione HUMAN. Non si forza una classe simile.

La presenza di 61 righe non implica 61 nuovi oggetti: identità duplicate, match esistenti, righe rifiutate o in review determinano l'esito. Qualunque anteprima di match è etichettata come previsione; solo UDP decide l'identità canonica e il risultato definitivo.

## 6. Ownership, implementazione e riuso

| Owner | Responsabilità M2 | Riuso / delta da verificare |
| --- | --- | --- |
| Onboarding / THS | Asset, profiling, classificazione, mapping, versioni, review e bundle | ManagedFile*, SourceRevisionService, workflow e review esistenti; aggiungere solo diagnosi/recupero/proiezioni mancanti |
| Semantic Registry | Classi, proprietà, vocabolari, concetti e publication set | Discovery e governance esistenti; nessun restart/reinstall del worker o nuova attivazione tecnica implicita |
| Ingestion | Parser e trasformazioni approvate, source identity, run, handoff e watermark | ManagedTabularAdapter, CanonicalRecordPipeline, RunExecutionWorker, outbox e checkpoint |
| UDP | MATCH/NEW/REVIEW, materializzazione, conflitti, revisioni, relazioni e provenance | GovernedIdentity*, LinkedPropertyReconciler, PublishedResolutionLoop, recovery e API owner |
| MCP / Gateway | Capability tipizzate, mediazione, riepilogo e recupero | Manifest/kernel, routing e proiezioni owner; nessun accesso diretto ai DB o endpoint arbitrari |
| Authorization / IAM | Principal, scope, grant, label e decisioni correnti | Enforcement owner prima della serializzazione; nessuna concessione implicita dal catalogo tool |
| Deploy | Coorte esatta, delta governati, native qualification e ricevute | Executor/custody/journal già qualificati, analisi d'impatto e nuove azioni finite per i soli effetti necessari |

Ogni patch deve collegare requisito → owner → riuso → delta → test → prova. Il piano non introduce broker, datastore di workflow, nuovo identity engine o servizi centrali autoritativi degli incidenti. Le capability umane rimangono channel-neutral e mediate dal Gateway; nessuna scorciatoia MCP locale.

## 7. Work package del residuo

I sei WP sono contenitori di verifica e dei soli delta residui, non sei componenti da sviluppare da zero. Le ore della versione 1.0 sono ritirate. Prima si riusano implementazioni/prove esistenti; si stima separatamente integrazione, collaudo e fix effettivo. Le attività già svolte non vengono ricontate.

| WP | Risultato | Owner principale | Dipendenze di uscita | Natura del residuo | Baseline |
| --- | --- | --- | --- | --- | --- |
| M2-WP1 | Causa Farmacie osservabile e rimossa; profiling recuperabile | Onboarding, Gateway, Deploy | Contesto retained e nuova autorità se servono effetti | Diagnosi/fix da determinare | WP6 + integrazione WP7 |
| M2-WP2 | Percorso autoguidato e contesto durevole | MCP, Onboarding, THS | WP1 per prova positiva | Integrazione + UX | WP6 |
| M2-WP3 | Semantica CSV generale e configurazione validata | Onboarding, Registry, Ingestion | Contratti correnti; WP2 per UX finale | Audit del delta + collaudo | WP5 |
| M2-WP4 | Farmacie fino a UDP e risultato consultabile | UDP, Ingestion, MCP | WP1–3 e ammissione HUMAN specifica | Prova verticale + eventuali fix | WP5/WP6 + prova verticale WP7 |
| M2-WP5 | Ripetibilità e recupero senza duplicazioni | Owner del singolo effetto, MCP | WP2–4 per integrazione finale | Riuso prove + collaudo mancante | WP6 + fault WP7 |
| M2-WP6 | Coorte finale, due client, dossier e accettazione | Cross-module, HUMAN | Tutti i WP precedenti | Qualifica finale + dossier | WP7 |


### M2-WP1 — Rimuovere il blocco reale, conservando il lavoro

1. Conservare FAILED, asset, job, ricevute e contatori. Leggere il dettaglio minimizzato dello stesso job attraverso un canale owner governato; PR52 è il candidato disponibile, non una diagnosi già acquisita.
2. Se serve installare il delta, preparare e qualificare un aggiornamento Onboarding circoscritto con immagine CI esatta, ammissione corrente e review concreta. Nessun replay del vecchio rollout V35. Questa manutenzione resta distinta dal percorso utente ordinario.
3. Separare accesso all'oggetto, integrità/size/hash, parser e persistenza. Una categoria UNCLASSIFIED non autorizza a indovinare o ritentare; richiede un ulteriore dettaglio sicuro mirato.
4. Riprodurre la causa, correggerla presso l'owner e verificare il recupero su fixture prima del target. Implementare la prosecuzione governata richiesta dopo esaurimento: storia conservata, nuova autorità finita quando necessaria, stessa identità logica per la stessa operazione.
5. Ottenere il profilo del file conservato; un nuovo file corretto è ammesso solo se la diagnosi dimostra un difetto nei byte e l'utente sceglie la correzione, con nuova versione e lineage.

**Output:** causa con evidenza, fix e regressione pertinente, categoria/azione leggibile, recupero qualificato, profilo Farmacie oppure blocco specifico. **Checkpoint M2.0:** diagnosi provata e percorso di recupero disponibile. Ristima della sola diagnosi/correzione appena nota la causa, combinata con l'inventario del riuso prima di un nuovo totale M2. La CI diagnostica attuale non chiude WP1.

### M2-WP2 — Comporre il percorso autoguidato

1. Inventariare capability e letture owner già presenti per ritrovare asset/review/run; colmare solo le lacune. Definire una proiezione di avanzamento con stato osservato, copertura, azione umana necessaria e prossimo passo consentito.
2. Rendere durevoli i riferimenti e risolvibile «riprendi Farmacie» con ownership e visibilità correnti. Gestire più lavori senza selezione arbitraria e senza esporre quelli altrui.
3. Collegare upload → profilo → proposta → THS → run → risultato con tool/schema/link verificati. Poll finiti e risposta asincrona; nessuna richiesta HTTP tenuta aperta fino all'import completo.
4. Review leggibile e recuperabile: diff, effetti, versione, scadenza, esito rifiuto/cancel, rientro da mobile. Nessun nuovo login o consenso ripetuto quando l'autorità corrente è sufficiente; nessun rinnovo automatico quando non lo è.
5. Anticipare i controlli di eleggibilità e permesso osservabili prima del passo dipendente, senza promettere autorizzazione futura: revoca e scadenza restano controllate dagli owner.

**Output:** proiezioni/tool minimi, percorso chat/THS, guida breve e test UX01/02/04/05/08. **Checkpoint M2.1:** navigazione e recupero funzionano; stato di business finale ancora da provare in WP4. Un prompt ben scritto da solo non chiude WP2.

### M2-WP3 — Significato dei dati e configurazione eseguibile

1. Coprire il profilo CSV della baseline: encoding, delimitatori, quoting, header, righe irregolari e limiti. Allineare i limiti di profiler e compilatore; 10 colonne Farmacie non giustificano l'aumento dei limiti generali.
2. Proporre classe/campi/label/chiave e validare tutte le righe rispetto alla configurazione. Conservare stringhe con zeri iniziali, tipi/decimali/date, valori originali e regole versionate.
3. Completare mapping codice→concetto, gestione unknown e semantic gap con pubblicazioni esatte; riusare i delta già qualificati dopo verifica d'impatto.
4. Comporre la relazione semplice su fixture: target presente, assente e ambiguo. Non inventare una relazione nel CSV Farmacie per far passare il test.
5. Provare la compatibilità fra proposta, validazione, bundle pubblicato e consumer Ingestion/UDP, inclusa la retrocompatibilità dei profili IDENTITY conservati.

**Output:** profilo Farmacie proposto, fixture generale, mapping/contratti e test. **Gate G5:** semantica generale qualificata; nessun riferimento mancante sostituito con latest o con una scelta del modello.

### M2-WP4 — Materializzazione e riconciliazione UDP verificabili

1. Attraverso le decisioni HUMAN pertinenti, pubblicare la configurazione esatta e ammettere una sola acquisizione Farmacie prevista. Nessuna acquisizione di prova nascosta dentro il profiling o una pubblicazione.
2. Verificare run/bundle/pubblicazione e la catena riga → handoff → ACK durevole → intake → materializzazione → oggetto/revisione/provenienza. ACK e commit restano distinti.
3. Provare su fixture deterministiche MATCH/NEW/REVIEW e due fonti distinte sullo stesso oggetto; contributi complementari, autorità, equivalenza, null/vuoto, conflitto, multivalore e cancellazione esplicita. La priorità è decisa dalla policy, non dal chatbot.
4. Presentare resoconto completo, righe da decidere e collegamenti autorizzati. Verificare la ricerca tipizzata per ritrovare gli oggetti e la relazione semplice senza query arbitrarie o risultati troncati spacciati per completi.

**Output:** primo dossier Farmacie e test UDP; confronto con expected fissati prima dell'esecuzione. **Checkpoint M2.3:** Farmacie arrivato a UDP con tutte le righe rendicontate. Non è ancora M2: mancano ripetibilità, fault e prova completa sui due client.

### M2-WP5 — Ripetibilità, resilienza e ripresa

1. Distinguere duplicato della stessa richiesta, risposta persa, retry tecnico, nuova acquisizione deliberata, nuova configurazione e recovery dopo STOP. Conservare identità, fencing, contatori e incidenti fra sessioni.
2. Provare reimport invariato su fixture: stessa fonte, byte/configurazione/schema/semantica fissati, nuova run ammessa; stessi ID e revisioni canoniche quando il contenuto canonico non cambia, nuova evidenza run presente.
3. In ambiente isolato: crash prima/dopo effetto e prima/dopo ACK, dipendenza temporaneamente indisponibile, risposta tardiva, restart, doppio comando concorrente, vecchio worker fenced, revoca/scadenza e budget esaurito. Nessun fault sui worker di produzione conservati.
4. Applicare resilienza v3 al percorso: classi transitorie esplicite, backoff/jitter/Retry-After, budget persistente, nessun lock nelle attese. Errori permanenti/sconosciuti e mutazioni ambigue richiedono STOP/riconciliazione. I default della policy non concedono un budget al job esistente.
5. Collegare diagnosi e incidenti alle proiezioni operative esistenti. Un outage condiviso ha incidente aggregato e conteggio dei lavori; isolare il minimo scope indipendente, proteggere controllo/diagnosi e recuperare gradualmente. Alert e Supervisor globali restano fuori da questa accettazione.
6. Dopo chat interrotta, l'owner prosegue solo il lavoro già ammesso; al ritorno il client rilegge stato e decisioni correnti. Se serve un nuovo budget HUMAN, la UI propone una nuova sessione finita collegata senza cancellare il passato.

**Output:** matrice fault, contatori prima/dopo, idempotenza, stato e recupero. **Checkpoint M2.4:** ripetibilità e recovery provati; G6 richiede anche il collaudo dei due client in WP6. Non si certifica da questi test l'intera adozione multi-modulo della policy v3.

### M2-WP6 — Qualifica finale e accettazione

1. Fissare coorte effettiva, immagini e contratti; riusare prove compatibili con motivazione. Qualificare e distribuire solo ulteriori delta necessari con nuova ammissione/review pertinente; i rollout già conclusi nei WP precedenti non si ricontano né si ripetono.
2. Eseguire il percorso su client A e B reali, registrando nomi/versioni/trasporto e UI disponibili; almeno B funziona con soli tool e link web. B usa un'intenzione di test distinta, non il replay del job Farmacie. Stesso livello di sicurezza e stessi risultati attesi.
3. Completare tutte le prove richieste, incluso secondo profilo di installazione isolato; registrare i casi canonici completi e le suite di modulo impattate. Nessun obbligatorio SKIPPED/BLOCKED viene trasformato in PASS.
4. Consolidare guida utente, runbook operatore separato, risultati per riga, limiti, regressioni e residual risks. Verificare baseline M1 e oggetti estranei senza nuove acquisizioni Teatri.
5. Presentare il dossier all'owner. **G6:** percorso e due client qualificati. **G7/M2:** tutti gli obblighi soddisfatti e accettazione esplicita del miniprogetto registrata. Nessun merge o release acceptance incluso.

## 8. Dati e collaudo

| Fixture / ambiente | Scopo e expected da congelare prima dell'esecuzione |
| --- | --- |
| Farmacie retained | 61 righe dati del file originale; hash server da verificare con evidenza owner. Expected di identità/proprietà stabiliti dopo profiling e review; nessuna ipotesi «61 nuovi» |
| DS0 Teatri/Cinema | Riuso dossier M1 e regressioni READ motivate; nessuna terza acquisizione o replay di decisioni |
| CSV-DS1 / DS1R | Baseline: 3 record, scope con U1/U2/U3; due match e un nuovo → 4 oggetti; reimport invariato conserva ID e revisioni, U3 immutato |
| DS-MULTI | Due fonti indipendenti rappresentano lo stesso oggetto, identità sorgente distinte e autorità dichiarata → un urbanObjectId, due source binding e provenance per proprietà; completa E2E-006 |
| CSV-DS2 | Chiavi duplicate, schema errato, vocabolario unknown, match ambiguo e conflitto pari autorità → rifiuto/review attesi, nessuna scelta inventata |
| CSV-DS3 | Codici 01/02, stringa con zero iniziale, decimale/data, relazione semplice → tipi/concept/versioni/edge corretti; negativi espliciti |
| ENV-A/B | Profili isolati con reti/path/binding differenti, stesso codice. Non prova installer universale o multi-provider IAM |
| FAULT | Runtime e persistenza reali isolati; fault controllato e tempo simulato dove pertinente; contatori/dedup/fencing ispezionabili |
| CLIENT-A/B | IAM/Gateway/THS e owner reali del profilo selezionato. Nome/versione e disponibilità del secondo client da fissare in WP2; sua assenza blocca G6/G7 |

Ogni expected viene versionato prima del test. Non si modifica il denominatore per ottenere successo. Per Farmacie: le 61 righe devono ricadere in categorie mutuamente esclusive di materializzata, rifiutata, in review, in attesa o errore; la loro somma resta 61. I conteggi di oggetti creati/aggiornati/invariati sono separati, perché più righe possono contribuire allo stesso oggetto. Una riga in review può essere un esito corretto del test negativo, ma non si dichiara «importazione tutta completata» finché quella decisione resta aperta.

## 9. Tracciabilità dell'accettazione

I 24 test originari restano obbligatori nel livello previsto. I=integrazione isolata; T=target con binding reali; C=client reale. Il registro JSON conserva procedure, requisiti e tracciabilità canonica originali, con stato finale separato dalle prove storiche.

| Test | Criterio sintetico | Livello | WP responsabile |
| --- | --- | --- | --- |
| CSV-AT-01 | Discovery, scope/owner/route e deny senza dispatch | I+T+C | 2,6 |
| CSV-AT-02 | Upload/profiling e risposta persa senza duplicati | I+T+C | 1,2,5 |
| CSV-AT-03 | Formato CSV, limiti, errore strutturato e originale conservato | I | 1,3 |
| CSV-AT-04 | Identità stabile al riordino; chiave duplicata esplicita | I+T | 3,4 |
| CSV-AT-05 | Vocabolari/tipi/originali/versioni; unknown non valido | I+T+C | 3 |
| CSV-AT-06 | Gap semantico → governance → stessa fonte ripresa | I+T+C | 3,6 |
| CSV-AT-07 | Review corrente accettata, hash/versione obsoleti respinti | I+T | 2,6 |
| CSV-AT-08 | Preparazione senza acquisizione; intenzione ammessa una volta | I+T | 2,4,5 |
| CSV-AT-09 | Cambio ACTIVE durante run: riferimenti fissati preservati | I | 3,5 |
| CSV-AT-10 | ACK durevole e watermark; commit UDP verificato separatamente | I+T readback | 4,5 |
| CSV-AT-11 | MATCH/NEW/REVIEW e decisione consumata una volta | I+T+C | 4 |
| CSV-AT-12 | Complementi/conflitti/null/vuoti/autorità/multivalore/delete | I+T | 4 |
| CSV-AT-13 | Relazione presente/assente/ambigua, dedup e provenance | I+T | 3,4 |
| CSV-AT-14 | Tutte le righe, catena delle evidenze e parzialità | T+C | 4,6 |
| CSV-AT-15 | Nuova run invariata e retry distinti; zero revisioni gratuite | I+T+C | 5,6 |
| CSV-AT-16 | M1 conservato: 13 Teatri, 20 proprietà, due run, 8 Cinema | T+C retained | 6 |
| CSV-AT-17 | Crash/restart/esaurimento/claim incerto senza replay o reset | I | 5 |
| CSV-AT-18 | Revoca/scadenza/tenant/label; deny prima della serializzazione | I+T | 2,5,6 |
| CSV-AT-19 | Nuova chat riprende senza nuovo job implicito | T+C | 2,5,6 |
| CSV-AT-20 | Due client indipendenti, almeno uno senza UI incorporata | T+C | 6 |
| CSV-AT-21 | Due profili isolati, stesso codice, nessun default Ente nascosto | I | 6 |
| CSV-AT-22 | Delta executor: effetti/identità/namespace/no-replay qualificati | I | 1,6 |
| CSV-AT-23 | Ammissione corrente DB/HUMAN/owner/readiness e preservazione route | I+T | 1,6 |
| CSV-AT-24 | Dossier, coorte, guida, baseline e accettazione HUMAN | T+C | 6 |

AT16 è prova retained da riusare dopo analisi d'impatto, non ordine di riesecuzione. Per AT23 i numeri di route del rollout storico descrivono quella prova: il nuovo delta congela il proprio inventario corrente e dimostra tutte le rotte estranee preservate. Non si forza il runtime attuale a un conteggio storico.

Scenari canonici minimi completi, già richiesti dalla baseline: **OUF-E2E-002, 003, 006, 017, 018, 019, 020, 022, 025**. Per 001/009/010/016/021/023/024 si riusano qualifiche pertinenti e si eseguono regressioni impattate senza attribuire PASS completo a un sottotest. Le suite MCP-A/THS-A/PET applicabili restano obbligatorie. I nuovi UX non sostituiscono gli scenari canonici.

| Scenario canonico | Prova completa da allegare | WP |
| --- | --- | --- |
| OUF-E2E-002 | Guasto prima della persistenza UDP, watermark fermo, recupero con stesso handoff, avanzamento solo dopo evidenza durevole | 5 |
| OUF-E2E-003 | Due FULL_SNAPSHOT invariati e medesimi riferimenti fissati; nuova run con lineage completa, nessuna revisione canonica gratuita | 5 |
| OUF-E2E-006 | Due fonti distinte, un urbanObjectId, entrambi i source binding, autorità e provenance per proprietà | 4 |
| OUF-E2E-017 | Decisione HUMAN, bundle immutabile consumato senza ricostruzione da tabelle Onboarding, binding Gateway, prima run e UDP con correlation conservata | 4,6 |
| OUF-E2E-018 | Route coarse ALLOW e owner fine-grained DENY prima della serializzazione; policy/versione ed errore preservati | 5,6 |
| OUF-E2E-019 | Pubblicazione B durante una run fissata su A in ambiente isolato; ripresa e provenance restano su A | 3,5 |
| OUF-E2E-020 | Due record con identità sorgente stabile; canonical ID assegnato solo da UDP e distinto dalla provenance identity | 3,4 |
| OUF-E2E-022 | Stessa capability/versione/owner/operation/I-O fra proiezioni; binding logico, tools/list non grant, tools/call riautorizzata | 2,6 |
| OUF-E2E-025 | Errore backend controllato attraverso Gateway/MCP: ProblemDetails e correlationId preservati; traccia/log di test ispezionati senza segreti | 1,5,6 |

Per ciascuno si eseguono tutte le precondizioni, i passi e le asserzioni del catalogo originale; la tabella ne indica l'allocazione, non ne riduce il contenuto. L'ispezione dei log del test isolato non introduce una capability MCP per raw log di produzione.

## 10. Gate, evidenze e definizione di completato

| Gate / checkpoint | Condizione | Stato iniziale |
| --- | --- | --- |
| G0–G4 / M1 | Prove storiche e dossier del caso conservato | ACQUISITO; non riaperto dal piano |
| M2.0 | Causa Farmacie provata e recupero governato qualificato | OPEN |
| M2.1 | Flusso guidato e contesto recuperabile | OPEN |
| G5 / M2.2 | Semantica generale e compatibilità validate | OPEN |
| M2.3 | Farmacie materializzato e tutte le righe rendicontate | OPEN |
| M2.4 | Reimport invariato e fault/recovery provati | OPEN |
| G6 | Due client reali e requisiti UX/ripresa soddisfatti | OPEN |
| G7 / M2 | Coorte finale, tutti i test obbligatori, dossier e accettazione M2 | OPEN |

Ogni evidenza riporta requisito/test, scenario canonico quando applicabile, timestamp, ambiente, input/expected/hash, commit, immagini reali, profilo/contratti/pubblicazioni, assertion PASS/FAIL/BLOCKED, artifact, correlation e limiti. Per runtime aggiunge riferimenti decisione/authority/claim e postcondizioni, mai credenziali. Gli E2E usano il formato evidence-record-v1 della baseline.

**Done M2:** CSV nuovo attraversa davvero chat → upload → semantica/review → Ingestion → UDP → consultazione; stessa configurazione invariata non duplica; errori/attese e ripresa sono gestiti; due client qualificati; tutte le righe e gli effetti spiegabili; nessun passo ordinario richiede terminale o intervento tecnico; G5/G6/G7 PASS e decisione finale HUMAN registrata. Una deroga a un obbligo richiede cambio esplicito del perimetro, non una nota che lo trasformi in PASS.

## 11. Stima ritirata e metodo di ristima

La baseline del 20 ottobre stimava 40–70 ore complessive fino a M2, centrale 55, di cui M1 18–30 (centrale 24) e WP5–7 22–40 (centrale 31). Questi valori restano il preventivo storico, non il residuo corrente. M1 è acquisito e il consuntivo storico è incompleto.

**Le 34–58 ore residue, centrale 46, la riserva 8–16 e il calendario derivato della versione 1.0 non sono più il forecast corrente.** Erano una ripartizione preliminare dei sei WP senza inventario sufficientemente puntuale del codice e delle prove già riusabili. Non è dimostrato che tutti quei blocchi richiedano nuovo sviluppo; non si giustifica quindi lo scostamento numerico dalla baseline come lavoro nuovo certo.

La prossima stima deve coprire esclusivamente:
1. causa e correzione Farmacie, dopo diagnosi;
2. collegamenti mancanti del percorso autoguidato, dopo inventario delle capability/stati/review;
3. specifici delta semantici/UDP dimostrati mancanti;
4. prove non già coperte: configurazione invariata, fault/ripresa, due client e dossier finale;
5. eventuale distribuzione del solo codice realmente modificato, senza ripetere installazioni acquisite.

Per ogni voce: evidenza del riuso, delta, test necessario e ore residue separati. Tempo già svolto o sola presenza di un requisito non genera nuove ore. Nessuna stima sostitutiva viene inventata prima dell'inventario. La correzione del preventivo non riduce i criteri M2 né riapre M1.

Ogni checkpoint registra ore effettive note, attese e residuo aggiornato; quantità non note restano null. Le attese esterne e la partecipazione HUMAN si contabilizzano separatamente, senza doppio conteggio. I contatori di progetto non modificano budget runtime. Nessuna data target viene dedotta dalle ore ritirate.

## 12. Rischi, decisioni e controlli

| Rischio / dipendenza | Azione | Effetto sul piano |
| --- | --- | --- |
| Causa Farmacie ignota; categoria eventualmente UNCLASSIFIED | Diagnosi minimizzata owner prima del fix e ristima WP1 | Blocca recupero/prova positiva, non progettazione indipendente |
| Stato non ritrovabile senza ID | Inventario API owner, delta minimo di discovery/read e ACL | Blocca UX05/G6 |
| Review/link/login non coerenti | Test della decisione esatta, scadenza, mobile e ritorno | Blocca UX04; nessun link diagnostico inventato |
| Grant temporaneo o workload non valido | Distinguere eleggibilità, scope OAuth, policy/label e stato runtime; diagnosi prima di proposta mirata | Nessun grant largo o rinnovo automatico |
| Semantica/chiave non definite | Proposta motivata e scelta di dominio; gap esplicito | Blocca G5 o ammissione, non si forza il mapping |
| No-op produce revisioni o conflitto silenzioso | Expected invariati e prove UDP; correggere owner | Blocca AT12/15 e M2 |
| Recovery non esposto o non qualificato | Stato durevole, fencing e nuova sessione consentita dai contratti | Niente nuovo job per aggirare esaurimento |
| Secondo client o ambiente fault non disponibili | Identificarli presto in WP2; proseguire attività indipendenti | G6/G7 restano BLOCKED, mai simulati come reali |
| Delta oltre il riuso previsto | Analisi d'impatto e ristima del solo delta | Nuova stima; nessuna riduzione nascosta dei test |
| Confusione M1/M2/release | Stato distinto nel registro e nelle PR | M1 conservato; M2 e release non accettati da CI o da questo piano |

## 13. Governance e consegna

Sviluppo, documentazione e GitHub proseguono nel mandato esistente. La pubblicazione di questo mini-PET non richiede una nuova approvazione di lavoro. Per gli effetti di dominio si usa THS con revisione corrente; per eventuale manutenzione runtime serve la review concreta e la reale decisione dell'operatore prevista dal controller. L'agent non invia APPROVO, non rinnova authority e non usa credenziali estratte. Le review di manutenzione devono essere rare, motivate e separate dall'import ordinario.

STOP conserva prove e contatori; prima riconciliare l'effetto ambiguo, mai ripetere il wrapper consumato. Nessuna reinstallazione/riavvio Registry, reset, attivazione tecnica implicita, merge o release acceptance. Non cambiare classificazioni per aggirare una redazione. Autorizzazione a leggere repository e capability non equivale a grant runtime corrente.

Deliverable finali: coorte/delta con pin; profilo CSV e fixture; percorso chat/THS e recovery; dossier per riga e ricerca minima; matrice test/canonici; guida utente breve; runbook operativo separato; consuntivo e registro residui. I file originali, dati e log privati non si pubblicano in GitHub.

## 14. Primo tratto operativo

1. Ripartire da **M2-WP1**, stesso FAILED Farmacie: acquisire la causa owner minimizzata senza nuovo upload/profiling.
2. Se la diagnostica richiede distribuzione, qualificare un delta Onboarding nuovo e circoscritto, poi presentare la review concreta. PR52 e la sua CI sono il punto di partenza, non un'APPLY già pronta.
3. Ristimare dopo la causa e completare il percorso di recupero; in parallelo logico, durante attese, definire proiezione dello stato e inventario per WP2 senza azioni runtime.
4. Procedere secondo la [roadmap](OUF_M2_ROADMAP_20261026.md); aggiornare un solo stato corrente nel registro, conservando gli snapshot precedenti.

Nessun effetto runtime è stato eseguito per redigere questo piano. M1 resta acquisito; M2/G5/G6/G7 e accettazione release restano aperti.
