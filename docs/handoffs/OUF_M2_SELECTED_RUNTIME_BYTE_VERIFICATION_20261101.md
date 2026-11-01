# M2 — verifica del ramo runtime dopo la diagnosi esatta

1 novembre 2026, Europe/Rome. Sorgente IN QUALIFICA; nessun nuovo comando pronto.
[Diagnosi operatore](../../evidence/m2-image-graph-target-20261101.json), Exit0,
risultato canonico 95e66e217be370477f7bece3a3ac7313857c92d73dd7d6fabd41c2200f67cea7,
prova privata f54c14e334545054a4c6d3f56d51c3ad9d8c4038653dd2c813b4408dabc295ea.
13 archivi/2.774.726.144 byte, 13 match classico→OCI univoci, nessun membro classico
mancante. 22 manifesti assenti: 13 di altre piattaforme, 9 ausiliari unknown;
ordinali 0,1,5,7 interessati. Tutti i 9 scope precedenti preservati, 10 controlli/
35 GET. Diagnostico, cattura e vecchi verificatori sono CONSUMATI. Non rilanciarli.

## Perimetro della nuova prova

La diagnosi prova struttura e hash degli archivi, non i digest delle configurazioni,
i layer o i diff ID. La nuova verifica richiede la ricevuta e la prova privata
esatte della diagnosi, i suoi claim/profilo, entrambi gli STOP precedenti e tutti
i dieci scope originali, con ownership/mode/no-link/metadata e generazioni stabili.
I byte restano privati sul VPS; l'agente ha solo il JSON pubblico, non shell o file.

Verifica ogni documento OCI presente per digest, raggiungibilità dal digest nativo
richiesto e limiti. Entro quel ramo richiede UN SOLO manifesto runtime che uguagli
config e lista ordinata di layer del manifest.json classico, a sua volta unico e
completo. La piattaforma del descrittore, se presente, e quella della configurazione
devono concordare col profilo. Questo recupero installativo resta vincolato alla
linux/amd64 già qualificata per la coorte; non è un default di installer generico.
Nessun tag/label/URL fornito dal chiamante seleziona immagini o amplia il profilo.

Un manifesto assente può restare FUORI dall'ammissione solo se è esplicitamente
di altra piattaforma oppure è un ausiliario marcato unknown/unknown, con marker
attestation e target nonausiliario coerente e dichiarato nello stesso ramo nativo.
Indici assenti, piattaforma richiesta assente/indefinita, marker/target incongrui
e ambiguità restano STOP. Presenti altri manifesti della piattaforma richiesta
non corrispondenti al binding classico non vengono scelti implicitamente.
Ogni assenza deve riconciliare esattamente i conteggi/contesti della diagnosi.

Config e ciascun layer selezionato sono OBBLIGATORI: media type, digest, size,
compressione e diff ID espanso, con rootfs e ordine esatti. Il ciclo di verifica
dei layer è lo stesso AST del verificatore precedente, con prova di uguaglianza;
si confrontano inoltre config/manifesto/layerHash reali su export già qualificati.
Niente estrazione, import, tag, lifecycle, Engine o fetch di contenuti assenti.
La configurazione privata si legge solo nell'archivio per la prova; valori e hash
individuali non vengono esportati. File di credenziali e mount host non aperti.

Il risultato ammette solo la PROVA dei byte del runtime selezionato: non indice
completo, altri rami, attestazioni/publisher, scan PASS, appartenenza dell'intera
coorte o authority/esecuzione. Nessun salto di gate installativo o applicativo.

## Controllo finito e custodia

Nuovo scope fisso /etc/ouf/deploy-snapshots/m2-selected-runtime-bytes-fa95a719-20261101-v1,
root0700/file0600/create-only/fsync. Massimo 1 controllo/600s; cumulativi 11/35,
zero nuovi GET Engine. Stessi 13 archivi, nessuna ricattura o duplicazione.
Limiti preservati: 2GiB per archivio/8GiB set, espansi 8GiB per immagine/32GiB set,
2048 membri, 64 descrittori d'indice, profondità4, 256 layer, 16MiB metadata per
immagine; prova precedente e report nuovi ciascuno entro2MiB. Timeout esterno635s,
kill dopo5s. STOP/interruzione conserva tutto: nessun retry, riarmo, reset o grant.
La shell isolata è manutenzione distinta dal flusso ordinario chatbot/MCP.

## Teatri e baseline consultati

Riletti [handoff M1](OUF_M1_COMPLETED_20261026.md),
[dossier owner: 26 join/13 identità/20 proprietà/8 Cinema](../../evidence/csv-m1-f5-f6-owner-verification-20261026.json)
e [audit M2: generazioni, riuso e lacune](../OUF_M2_CODE_EVIDENCE_GAP_AUDIT_20261026.md).
Si conservano contratti owner/provenance/identity/property/recovery, senza terza
acquisizione o nuovi motori. MiniPET M2v1.3 WP2/WP6/§10; policy resilienza v3
regole3–9/14–18; GatewayPET1.5 T11/T11.3 e principi AuthorizationPET1.5.
Fonti di formato: [OCI index1.1.1](https://specs.opencontainers.org/image-spec/image-index/?v=v1.1.1),
[layout](https://specs.opencontainers.org/image-spec/image-layout/) e
[Docker save](https://docs.docker.com/reference/cli/docker/image/save/).
La scelta riduce la prova al runtime univoco; nessuna conformità completa si
ricava dai soli hash. I 235 sorgenti congelati, 19 della diagnosi e 17 del vecchio
verificatore devono restare esatti; la capsula separata non è l'esecuzione M2 completa.

M1 resta tecnico8/8 e funzionale6/6, stessa Farmacie SUCCEEDED61righe/10colonne/
10OPEN e ministeriale STRING. M2/G5/G6/G7/dueclient ancora OPEN. Dopo questa prova
restano source/publisher/membership, Gateway proposal, owner/policy/custody/bearer,
coorte/pacchetto/review/authority correnti e Farmacie fino a UDP con ogni riga.
Poi grafo/search e verticali/API scheduler/delta. Nessuna acquisizione/attivazione,
merge, release acceptance, subagente o automazione autorizzata da questo passo.
