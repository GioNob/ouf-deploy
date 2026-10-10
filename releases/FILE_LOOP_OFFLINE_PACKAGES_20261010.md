# File-loop offline candidate packages — 10 ottobre 2026

Pipeline [38069730894](https://github.com/GioNob/ouf-deploy/actions/runs/38069730894): tutti e tre i moduli PASS. [Manifest e pin](file-loop-qualified-cohort-20261010.json).

Questi sono pacchetti di staging unsigned. Ogni archivio contiene sorgenti Git esatti, ricetta Docker con basi esterne risolte a digest, JAR estratto dall'immagine, immagine Docker-save, inventario sorgente, scan legato all'image ID e SHA256SUMS. Il builder non avvia l'applicazione, non contatta provider, non legge chiavi, non firma e non tocca il VPS. La prova SQLite/XLSX è ripetuta nel nuovo container Ingestion prima dell'export; le scansioni HIGH/CRITICAL/UNKNOWN includono unfixed e non hanno eccezioni.

Il gate di continuità conserva 34 SQL UDP e 14 SQL Ingestion. I main riconciliati hanno tutti i workflow PASS; i pacchetti usano i candidati qualificati immutabili e non latest.

| Modulo | Artifact ID | ZIP SHA-256 |
| --- | --- | --- |
| ingestion | 11676720102 | sha256:29a981ddfaed56265ed1061bdf9a59088e87cd0cac46d5844a7fe9255a7d9c32 |
| udp | 11676625220 | sha256:36de53a045bbe94c3cdda80cf6599adfd014c595da1720c817f2aeb586ef14cd |
| semantic | 11676412613 | sha256:a0c30bbb7d44d3e6405bae28ad80b6c5dcfc28ed2f078d387cf4e26d179e28c3 |

I digest dell'archivio attestano i byte consegnati da Actions, non una firma dell'autorità d'installazione. Le attestazioni/trust dell'immagine Semantic precedente non sono riutilizzabili per questa nuova immagine. Digest base fissati non garantiscono da soli futuri JAR identici: Maven e apk upgrade richiedono ulteriore congelamento della dependency closure per riproducibilità futura byte per byte. Il pacchetto presente ha hash verificati.

Prima di apply: custodia e firma d'installazione; nuovi trust pubblici legati all'immagine; inventario OCI host completo e peer reciproco correnti; readiness/backup/restore/fence di migrazione; transizione HUMAN nella superficie diretta. Nessun reset/replay di claim R9 o del run Cinema. L'archivio Docker non è la dichiarazione OCI completa del container host.

La ricerca corrente degli otto Cinema è verificata nella natura pubblicata cinema#Cinema su tre pagine (3/3/2); [ricevuta limitata](../evidence/current-canonical-search-read-20261010.json). I controlli negativi/audit/multi-file e R-INSTALL restano aperti.
