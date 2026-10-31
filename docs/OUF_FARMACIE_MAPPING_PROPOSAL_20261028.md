# Farmacie — proposta di mapping da completare con le decisioni di dominio

28 ottobre 2026, Europe/Rome. Riferimento: [miniPET M2 v1.2](OUF_M2_MINIPET_v1_0_20261026.md), §5 e WP3. [Evidenza owner](../evidence/farmacie-profile-preview-policy59-20261028.json).

**Stato: scelte di dominio confermate dall’utente; semantica pubblicata e configurazione eseguibile ancora da completare.** Nessun nuovo IRI è presentato come termine pubblicato. Nessuna fonte, acquisizione o attivazione è stata creata.

## Profilo letto attraverso MCP

Policy 59 è confermata PUBLISHED dalla receipt owner della stessa proposta autorizzativa. Anteprima del profilo esistente riuscita: versione 1, CSV, 61 righe/10 colonne, UTF-8, separatore punto e virgola, header 1. L'owner ha restituito un campione redatto di 5 righe, che qui non viene ripubblicato.

La proposta automatica sceglie nome_denominazione come chiave perché è il primo candidato. I candidati sono nome_denominazione,indirizzo,codice_ministeriale. L'unicità nel file non prova stabilità nel tempo: l’utente ha confermato codice_ministeriale come chiave stabile della fonte, mantenendolo come stringa lessicale.

## Trattamento proposto delle 10 colonne

| Colonna | Profilo owner | Trattamento proposto, da validare |
| --- | --- | --- |
| nome_denominazione | STRING, non nullable,61 distinti | Denominazione della farmacia; non chiave di default |
| indirizzo | STRING, non nullable,61 distinti | Indirizzo conservato; niente geocodifica o suddivisioni inventate |
| latitudine | DECIMAL, nullable,58 distinti | Latitudine della fonte; preservare null e precisione; controllare range e coppia |
| longitudine | DECIMAL, nullable,58 distinti | Longitudine della fonte; controllare range e coppia, senza inversioni silenziose |
| sistema_coordinate | STRING, non nullable,1 distinto | CRS dichiarato dalla fonte; nel campione WGS 84/EPSG:4326. Verifica coerente su tutte le righe prima dell'esecuzione |
| cap | LONG inferito, non nullable,28 distinti | STRING lessicale: CAP è un codice; preservare eventuali zeri iniziali |
| codice_ministeriale | LONG inferito, non nullable,61 distinti | STRING lessicale; chiave sorgente proposta, con namespace della fonte e stabilità da confermare |
| tipologia | STRING, non nullable,1 distinto | Tipologia della fonte; nel campione Ordinaria. Se mappata a un concetto, richiede vocabolario/versione pubblicati e policy unknown esplicita |
| inizio_validita_anagrafica | DATE, non nullable,30 distinti | Data anagrafica come dichiarata; non trasformarla in data di apertura o fine validità. Formato/semantica da validare nel percorso owner |
| note | STRING, non nullable,4 distinti | Note della fonte, con significato/provenienza conservati; nessun dato da ricostruire dal nome o indirizzo redatti |

**Classificazione e inclusione confermate il 28 ottobre 2026:** tutte le dieci colonne sono incluse con label OPEN. Il codice ministeriale è confermato come chiave stabile della fonte e rimane stringa. CAP rimane stringa. Queste scelte devono essere vincolate alla futura configurazione e review; non autorizzano a rimuovere retroattivamente redazioni o controlli delle API esistenti.

**Coordinate:** nullable e58valori distinti non dimostrano quante righe manchino di coordinate né la precisione geografica. Eventuali coordinate condivise non sono prova di identità urbana. La qualità deve restare visibile e il comportamento su coppie incomplete/valori fuori range deve essere esplicito.

## Semantica da risolvere tramite discovery OUF su OntoPiA

Richiesta esplicita dell’utente: usare le capability OUF sul percorso chatbot → MCP → Gateway → Registry → OntoPiA. La connessione corrente non espone ancora la discovery esterna. [Composizione qualificata e gate residui](handoffs/OUF_M2_ONTOPIA_DISCOVERY_COMPOSITION_20261028.md). Non creare un’ontologia locale o un import manuale per sostituire la ricerca nazionale richiesta.

Le ricerche autorizzate CLASS per farmacia e pharm sono vuote. La ricerca ONTOLOGY per ouf ha restituito Cinema e Teatri con publicationSet9fe7d1ee-9e13-40bc-ad50-53e36ea0076b. Un'altra ricerca è stata negata per budget MCP esaurito e non è stata ritentata. Questo non prova assenza globale di una classe Farmacia o completezza del catalogo.

Prima di source.onboarding.create servono riferimenti pubblicati esatti di classe, proprietà e vocabolario dove applicabile. Se mancano, il percorso prepara una nuova bozza semantica esplicitamente da rivedere in THS; nessuna adozione/pubblicazione dal modello. Non riusare classe Teatro o Cinema per sbloccare la configurazione. Le ricerche successive devono rispettare admission/budget correnti, senza reset o nuovi commandKey che aggirino il limite.

D5 rimane aperto: il collegamento dei mapping vocabolario/relazione nel compiler managed va completato e qualificato, riusando i motori esistenti. La riuscita di questo profiling non qualifica D5.

## Decisioni acquisite e sequenza successiva

1. Acquisito: codice_ministeriale è confermato come identificativo stabile della fonte, mantenuto stringa.
2. Acquisito: tutti i dieci campi sono confermati inclusi e OPEN.
3. Completare discovery/proposta semantica e ottenere i relativi riferimenti pubblicati attraverso la governance.
4. Preparare la bozza di onboarding con le scelte confermate; validare l'intero file attraverso l'owner, poi review HUMAN degli effetti di pubblicazione e acquisizione.
5. Rendicontare tutte61 righe fino aUDP:61 righe non significa61 nuovi oggetti. Reimport,fault,dueclient e accettazione restano obblighi separati del miniPET.

L'originale/hashing completo lato storage non è esposto dalla sola preview; non dichiararlo verificato indipendentemente. Non servono nuovo upload,profiling,budget oresume del job completato.
