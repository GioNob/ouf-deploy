# M2 — Direzione dello storage a oggetti: decisione owner necessaria

**Stato: PROPOSTA, nessuna scelta effettuata.** 1 novembre 2026, Europe/Rome.
Questa decisione riguarda il prodotto/licenza dello storage. Non costituisce
approvazione THS, autorità runtime o autorizzazione a migrare dati.

## Evidenza che impedisce di ammettere lo storage conservato

L'indice MinIO `14cea493`, il manifesto amd64 `a1a8bd4a` e la configurazione
`69b2ec20` sono quelli già collegati alla cattura privata consumata. Una copia
pubblica esplicitamente distinta, `ghcr.io/datalens-tech/minio`, rende disponibili
gli stessi byte. Sono verificati tutti i nove layer compressi e i nove diff ID
espansi. Il registry originale rimane indisponibile; la copia non autentica il
publisher originale e non viene adottata come dipendenza runtime.

La scansione OS e due binari Go, a tutte le severità e unfixed inclusi, produce:

| Componente | CRITICAL | HIGH | UNKNOWN |
|---|---:|---:|---:|
| OS Red Hat9.6 | 0 | 8 | 0 |
| Client `mc` | 2 | 50 | 4 |
| Server `minio` | 7 | 69 | 4 |
| Totale rilievi | 9 | 127 | 8 |

Sono rilievi di immagine, con possibili CVE ripetuti tra componenti; non sono
144 CVE distinti né una prova di sfruttabilità sulla configurazione installata.
Il gate HIGH/CRITICAL/UNKNOWN è correttamente HELD. Le vulnerabilità delle
dipendenze e del sistema operativo hanno in gran parte versioni corrette;
aggiornarle da sole non risolve i difetti di autenticazione del server.

Il [README upstream al commit7aac2a2c](https://github.com/minio/minio/blob/7aac2a2c5b7c882e68c1ce017d8256be2feea27f/README.md)
dichiara il progetto non più mantenuto. Gli avvisi ufficiali
[GHSA-9c4q-hq6p-c237](https://github.com/minio/minio/security/advisories/GHSA-9c4q-hq6p-c237)
e [GHSA-hv4r-mvr4-25vw](https://github.com/minio/minio/security/advisories/GHSA-hv4r-mvr4-25vw)
indicano che i bypass di firma interessano tutte le release fino all'ultima
open source e rimandano ai fix AIStor2026-04-11. Non è una normale patch di
versione del pacchetto Community già approvato.

Qualifica effettiva: sorgente `46e9ce6a`, run41352708811/job124986151771. Recupero
e scanner completati; il job fallisce al gate sicurezza. L'intero artifact
13101916659,270.309byte,SHA256 `59786c63…`, è conservato in
`evidence/artifacts/m2-minio-exact-copy-security-41352708811.zip`.
Nessuna esecuzione dell'immagine, credenziale utente letta o operazione target.

## Alternative concrete da scegliere

| Percorso | Cosa autorizzerebbe la scelta | Requisiti prima di qualunque uso reale |
|---|---|---|
| MinIO AIStor con licenza adeguata | Qualificare il prodotto supportato dal vendor come nuovo candidato | Licenza ottenuta dall'owner; profilo funzionale e di cifratura/HA compatibile; digest/publisher/scan; canary e backup verificati; review runtime distinta |
| Sostituzione con storage S3 mantenuto e open source | Selezionare e qualificare un nuovo backend senza assumere un contratto proprietario | Confronto funzionale/supporto; test dei client OUF reali; copia verificata di oggetti/metadata/policy; canary e piano di rientro; nuovo profilo e review |

La documentazione [licenze AIStor](https://docs.min.io/aistor/operations/licenses/)
richiede una licenza. Il piano Free è limitato a singolo nodo e non ammette
cifratura server-side a riposo né varie funzioni enterprise; non è una
sostituzione automaticamente compatibile con qualsiasi installazione OUF.
L'[accordo Free](https://www.min.io/legal/aistor-free-agreement) è proprietario
e contiene restrizioni di redistribuzione. Nessun accordo è stato accettato,
account registrato o binario AIStor scaricato/installato in questo lavoro.

La [procedura ufficiale di upgrade](https://docs.min.io/aistor/administration/upgrade-aistor-server/open-source-minio/linux/)
dichiara irreversibile la conversione in-place verso AIStor. Perciò la proposta
OUF richiede prima un canary su copia indipendente, preservando originale e
backup, e una verifica concreta di ripristino. Non si promette un rollback
ottenuto rimettendo semplicemente il vecchio container sul volume convertito.

Un fork Community manutenuto da OUF sarebbe una terza responsabilità permanente,
con patch applicative, test di regressione delle vulnerabilità e supply chain
propri. Non viene assunto implicitamente come soluzione del blocco M2.

## Perché serve l'owner

Le autorizzazioni di sviluppo e di uso delle capabilities restano valide.
Mancano però una scelta tra prodotto proprietario e vincolo open source, e
l'eventuale licenza del prodotto scelto. L'agente non può attribuire una
preferenza non espressa né assumere l'accettazione di una licenza o una
migrazione irreversibile. La sola scelta di direzione abiliterà il lavoro sul
candidato, non gli effetti sul VPS.

Sono preservati Semantic corretto, candidati di riparazione Ingestion/UDP,
Teatri/M1 e stessa Farmacie. Lo sviluppo indipendente della correzione Gateway
prosegue fino alla sua qualifica prima di richiedere la decisione. M2 resta
OPEN. Scope12 consumato,12controlli/35GET; nessun replay/reset/grant/authority.
