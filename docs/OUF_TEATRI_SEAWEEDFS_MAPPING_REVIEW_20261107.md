# Mapping del CSV Teatri già caricato su SeaweedFS

Stato: **proposta pronta; scelta dell'owner sul nuovo asset ancora necessaria**. Nessuna bozza applicativa, approvazione o acquisizione inviata.

Asset `c51745c5-1fc0-4d36-bdcf-1e9a8a049c94`, profilo `da3f17a2-5cbc-4d7d-9ed8-7f4b39a00342`: 13 righe, 20 colonne, CSV UTF-8 separato da `;`. Preview attuale letta via MCP. La corrispondenza delle colonne non dimostra identità byte per byte col vecchio file: l'hash non è esposto dalla preview.

## Proposta da scegliere

Riutilizzare il mapping Teatri: **tutte le 20 colonne incluse, accesso RESTRICTED e trasformazione IDENTITY**. Classe `https://schema.org/PerformingArtsTheater`; chiave sorgente `nome_teatro`, proposta dal profiler, con 13 valori distinti. La stabilità dell'identità dipende dalla stabilità di questa chiave.

Tutte le celle rimangono stringhe del CSV, anche CAP, capienza e coordinate. `4.565.094`/`1.376.850` non vengono convertiti o dichiarati coordinate geografiche numeriche valide. Si conservano sistema di riferimento, precisione, fonti e note. La capienza può riferirsi a una sala secondo le note. Nessuna equivalenza con Cinema.

Prefisso `teatri:` = `https://api.ouf-lab.it/semantic/teatri#`; prefisso `schema:` = `https://schema.org/`.

| Colonna | Proprietà |
| --- | --- |
| `nome_teatro` | `schema:name` |
| `tipologia` | `schema:additionalType` |
| `toponimo` | `teatri:toponimo` |
| `nome_indirizzo` | `teatri:nome_indirizzo` |
| `civico` | `teatri:civico` |
| `cap` | `teatri:cap` |
| `citta` | `teatri:citta` |
| `provincia` | `teatri:provincia` |
| `latitudine` | `teatri:latitudine` |
| `longitudine` | `teatri:longitudine` |
| `sistema_riferimento` | `teatri:sistema_riferimento` |
| `precisione_coordinate` | `teatri:precisione_coordinate` |
| `capienza_posti` | `teatri:capienza_posti` |
| `spettacoli_stagione` | `teatri:spettacoli_stagione` |
| `stagione_riferimento` | `teatri:stagione_riferimento` |
| `note` | `teatri:note` |
| `fonte_indirizzo` | `teatri:fonte_indirizzo` |
| `fonte_coordinate` | `teatri:fonte_coordinate` |
| `fonte_altri_dati` | `teatri:fonte_altri_dati` |
| `data_verifica` | `teatri:data_verifica` |

## Semantica verificata

Il registro locale restituisce Teatri 1.0.0 ACTIVE. Lettura esatta: revisione `a1db3912-2b72-42eb-af88-a775fcd0e2ab`, publication set `9fe7d1ee-9e13-40bc-ad50-53e36ea0076b`. Snapshot completo: 105 statement. Classe e 20 proprietà presenti; le 18 proprietà locali dichiarano dominio PerformingArtsTheater e range string. I due termini schema.org sono dichiarati rdf:Property senza range/domain nello snapshot: non si attribuiscono loro dichiarazioni assenti.

Non occorre nuova pubblicazione semantica per questa proposta. La precedente approvazione della sorgente storica non vale come approvazione del nuovo asset.

## Passo successivo

[Payload completo pronto](../releases/TEATRI_SEAWEEDFS_MAPPING_REVIEW_20261107.json). Alla scelta dell'owner: creare la bozza idempotente `teatri-seaweedfs-c51745c5`, leggere versione/hash e preparare la review nativa THS. Il contratto MCP di creazione richiede profilo rivisto, riferimenti semantici scelti e decisioni di accesso sui campi. L'execution proposal per Ingestion/UDP e l'approvazione HUMAN restano passi successivi; nessuna compatibilità viene presunta da questo documento.

La sorgente storica `teatri-csv-6609b245` non è modificata né riacquisita. Il nuovo asset non viene ricaricato o riprofilato.

[Esiti MCP e verifica](../evidence/semantic-recovery-functional-read-20261107.json) · [Stato operativo](STATE.md).
