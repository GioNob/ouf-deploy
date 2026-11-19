# Composizione della coppia successore — 9 novembre 2026

**Codice e prove isolate completati; nessuna installazione VPS.** La [ricevuta delle 12:25:29 CET](../evidence/discovery-generation-sources-read-operator-20261109.json) chiude la lettura delle fonti: ricette indipendenti coincidenti con le policy installate, peer reciproci coerenti, nessuna osservazione live.

Il [compilatore](../tools/semantic_cohort_admission/compose_successor_cohort.py) riusa il compilatore OCI e il validatore peer della versione cohort che supporta leaseGuard. I sorgenti runtime congelati e i protocolli esistenti non cambiano. La nuova funzione produce soltanto una proposta in memoria, a partire da ricevuta, input storici, ricette indipendenti, due nuovi CID/transazioni e dichiarazione completa del Semantic atteso.

## Delta consentito

| Flusso | Dichiarazione nella proposta |
| --- | --- |
| Adapter: 172.21.0.2→172.21.0.3:9443/tcp | Nuovo CID southbound, hash OCI ricompilato, tutte le sue tre NIC |
| Southbound: 172.21.0.2→172.21.0.3:9443/tcp | Nuovo CID adapter, hash OCI ricompilato, entrambe le sue NIC |
| Southbound: 172.18.0.6→172.18.0.14:10443/tcp | Dichiarazione Semantic completa al posto di BRIDGE_PORT 1377; nessun indice inventato |

NIC/MAC, indirizzi, porte, protocolli, purpose, authorityRef e nomi delle tabelle rimangono quelli degli input. Il contesto Docker dei nuovi ruoli è ricompilato con i loro CID e namespace privato nuovo. Viene selezionato lo stesso coordinatore successore per entrambi; kernel, DNS e lock restano quelli conservati. Identità storiche, transazioni riutilizzate, coordinatori misti, namespace presi dal predecessore, flussi aggiunti e indice storico diverso sono rifiutati.

La dichiarazione Semantic deve contenere CID, hash completo dell'OCI attesa e NIC backend. Questa funzione verifica forma e perimetro, **non autenticità, provenienza indipendente o generazione live**. I CID forniti dal chiamante non provano proprietà delle creazioni. Custodia delle fonti, nuove aspettative rootfs, firma e ammissione rimangono obblighi dell'installer. I sigilli storici della ricevuta non sono selezionati o copiati nell'output. Tutti i relativi indicatori di autorità/ammissione/start restano false; nessun CLI o comando operativo è consegnato per questo modulo.

## Prove e limiti

Sorgente `33f05f1159da7a04396ded70be0d60f6b26dc2a1`, modulo SHA256 `823aa871055fcb7e6f53c7bcd27208914fbf02e604d9ee062e5240f647c2f6b1`. [CI 42610077499](https://github.com/GioNob/ouf-deploy/actions/runs/42610077499), job 129135939384: **11 test PASS, zero skip**, log diretti letti.

Le prove usano la topologia della ricevuta, baseline Engine indipendenti conservate e documenti/identità sintetici. Verificano ricompilazione, collegamento reciproco, sostituzione del peer numerico, preservazione degli input e rifiuti per alterazione. Non verificano un nuovo container VPS, la compatibilità native del suo frame, la provenienza del peer Semantic o l'autorità target.

Il binding file della ricevuta operatore usa SHA256 `8a0ed83e6cbbcd4f46802d610c5382a57605381242896a0145174f7fe2a31d3d` sui 7.224 byte del produttore, inclusa LF finale. Il campo `sourceReceiptHash` della proposta usa il digest canonico senza LF, `adfa9d9da7b389712f3e6af995909313d5f91e637edd5dbe96b9c0bfdbefafc6`; non confondere il digest del documento con quello del file.

## Prossima integrazione

Il sorgente della riparazione Semantic conserva la richiesta prima della CREATE in `/var/lib/ouf-storage-migration/semantic-discovery-key-repair-20261108/request.private.json`. È un punto di partenza per la ricetta indipendente del peer; disponibilità, custodia, corrispondenza alla ricevuta e validità corrente non sono state osservate qui. La OCI descrive l'argv iniziale del gate: non sostituirla con il cmdline Java osservato dopo il segnale USR1.

Completare quell'aspettativa e la raccolta native del peer, poi collegare proprietà delle nuove creazioni, sigilli rootfs e nuovi mandati ai componenti esistenti di profili, pubblicazione e switch. Considerare nella stessa integrazione le modifiche Semantic necessarie a credenziale/provider, perché un successivo cambio di container o generazione richiede binding coerenti. Non rigiocare i vecchi CID/journal o il lettore concluso. F2–F6 restano aperti.
