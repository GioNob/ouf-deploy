# Teatri: proposta semantica unica da revisionare

Stato: preparazione, nessuna adozione, pubblicazione o attivazione. Sostituisce
la proposta non registrata del 13 ottobre; non modifica artefatti ACTIVE.

Il file e il profilo già presenti si riusano. Lettura MCP del 14 ottobre:
asset `6609b245-86ed-4315-8ce0-73f2a8555bf3`, profilo
`7984c39c-7396-4248-ab0a-f2efc390b49c` versione 1, 13 righe e 20 colonne.
Le ricerche autorizzate `teatro`, `Theater` e `PerformingArtsTheater` non
hanno restituito risultati. È una ricerca mirata, non la prova di assenza
da ogni voce del Registry. La consultazione esatta dell'ontologia Cinema
ACTIVE ha restituito 17 asserzioni, con dominio Cinema e sottoclasse
`schema:MovieTheater`: non giustifica classificare i teatri come cinema.

## Riuso, allineamento ed estensioni

La scelta segue Semantic PET v1.3 §6.1. Le definizioni ufficiali consultate
il 14 ottobre 2026 sono riferimenti da sottoporre all'owner, non pin OUF
già pubblicati e non prova di discovery runtime attiva.

| Elemento | Scelta proposta e ragione |
| --- | --- |
| Classe | Riusare [schema:PerformingArtsTheater](https://schema.org/PerformingArtsTheater), pertinente ai luoghi per arti performative. Nessuna nuova classe Teatro duplicata. |
| Nome | Riusare [schema:name](https://schema.org/name). |
| Tipologia testuale | Riusare [schema:additionalType](https://schema.org/additionalType), che ammette classificazioni testuali aggiuntive; non inventare URI di un vocabolario controllato. |
| Componenti dell'indirizzo | Conservare i componenti distinti del file. [PostalAddress](https://schema.org/PostalAddress) descrive una risorsa indirizzo strutturata: una proprietà applicata direttamente al teatro non deve fingere di aver creato quella risorsa. CAP lessicale. |
| Coordinate e qualificazioni | Conservare i valori dichiarati con sistema e precisione. [GeoCoordinates](https://schema.org/GeoCoordinates) e latitude/longitude standard non autorizzano a supporre che tutte le righe siano già normalizzate/verificate. |
| Capienza | Proprietà qualificata della fonte: il campione segnala esplicitamente una capienza riferita a una sala, non all'intero teatro. Non equiparare a maximumAttendeeCapacity del luogo. |
| Spettacoli e stagione | Misura e periodo restano associati; non sono un numero senza periodo o un elenco di eventi individuali. |
| Fonti, note e verifica | Conservare l'ambito della provenienza per indirizzo, coordinate e altri dati. Non trattare i collegamenti come identità sameAs, siti ufficiali o richieste di fetch. |

Il [Turtle proposto](teatri-reuse-20261014.ttl) contiene realmente la classe
e tutte le 20 proprietà utilizzate. Un'unica ontologia da approvare è
sufficiente soltanto se il Registry pubblica questo contenuto esatto e
i consumer verificano i termini nella revisione e nel publication set
contenitore. Non si comprimono 21 riferimenti fingendo appartenenze RDF.

## Cosa conserva l'esecuzione CSV disponibile

L'adapter CSV conserva le celle come testo. La pipeline esistente supporta
`IDENTITY`, non conversioni numeriche o di data. Questa proposta dichiara
quindi valori lessicali `xsd:string`: il CAP mantiene gli zeri iniziali e
le coordinate mantengono precisione testuale e valori mancanti. I tipi
inferiti dal profiler restano informazioni per la revisione. Il presente
percorso non promette confronti numerici o spaziali su stringhe.

L'owner deve verificare mapping, rappresentazione dei valori assenti,
classificazione dei dati, chiave e politica di risoluzione. `RESTRICTED`
è una proposta prudente visibile alla revisione, non una classificazione
attribuita automaticamente alla fonte. `nome_teatro` è una chiave locale
proposta: un cambio di nome non prova identità invariata tra fonti.

## Criterio di esito

La proposta non costituisce ancora prova end-to-end. Occorrono l'approvazione
HUMAN autentica, i pin pubblicati, l'attivazione della configurazione completa,
l'esito durevole di ogni riga e il readback autorizzato dal chatbot. Il conteggio
di oggetti nuovi può differire dalle 13 righe: vanno riconciliati gli esiti
di risoluzione/commit, conservando i dati preesistenti. Un MATCH positivo
richiede dati realmente corrispondenti e una politica approvata; non un
merge forzato Teatro/Cinema.
