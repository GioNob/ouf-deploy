# M2 — diagnosi della struttura degli archivi conservati

1 novembre 2026, Europe/Rome. IN QUALIFICA; nessun comando operatore pronto.
[Secondo STOP](../../evidence/m2-image-byte-reconciliation-target-stop-20261101.json):
ImageByteReconciliationExit=1, PRIVATE_IMAGE_BLOB_OR_EXACT_CANONICAL_EMPTY_CONFIG_REQUIRED,
risultato canonico8bec830155b26ee665298b6e35f8bb53d41e1ee8ba0333e4e2209829dfea1380,
9controlli/35GET. Entrambi i verificatori sono consumati; non rieseguirli.

## Dato certo e ipotesi da distinguere

Il ramo fallito richiede un blob presente oppure la sola configempty canonica
ammessa. La ricevuta non espone se manchi un manifesto, una config o altro.
La correzione del data opzionale è valida ma non risolve il caso privato.
Le prove precedenti usavano tredici immagini locali linux/amd64; mancava un
export multipiattaforma con varianti non presenti nello store.

La [specifica OCI layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md#blobs)
ammette riferimenti a blob assenti dal layout. Il contratto [Docker save](https://docs.docker.com/reference/cli/docker/image/save/)
esporta le varianti presenti nello store. Questo rende plausibile un indice
parziale ma NON prova la causa VPS e NON autorizza skip indiscriminato o fetch.

## Controllo diagnostico distinto

Confronta tutti i nove scope esistenti, i due risultati esatti e i profili/claim,
root0700/file0600/no link/metadata stabili. Rilegge i tredici archivi della stessa
catturafa95a719/receipt9733fa7c; autentica ogni archivio con hash e dimensione
originali. Poi apre solo TARheaders e JSON indice/manifesti bounded. Config e
layer NON vengono aperti come membri né espansi: i loro byte attraversano
soltanto lo streaming indifferenziato per l'hash integrale dell'archivio.

Enumera presenza/assenza dei riferimenti, contesto e classe piattaforma:
INDEX_MEMBER, RUNTIME_CONFIG/LAYER, ATTESTATION_CONFIG/LAYER, SUBJECT e classic
member. Verifica digest dei documenti presenti; gli altri membri sono soltanto
presenza/dimensione, non prova dei loro digest/diffID o dell'identità eseguibile.
Confronta il manifest.json classico con le configurazioni/liste layer dichiarate
nei manifesti OCI presenti, senza selezionare un candidato o ammetterlo.
Sotto-grafi di manifesti assenti restano esplicitamente non osservati.

Il report completo rimane privato sul VPS. Pubblico: ordinali non nominativi,
conteggi/classi enum e hash aggregato della prova; niente path, nomi/tag, valori,
descrittori, hash individuali o configurazioni. Nessuna sintesi o ammissione dei
blob mancanti, fetch esterno, Engine, mount host, credenziali, SQL/OAuth, import,
estrazione, processo applicativo o lifecycle. Zero authority/budget runtime.

Nuovo scope fisso /etc/ouf/deploy-snapshots/m2-image-graph-diagnostic-fa95a719-20261101-v1,
root0700/file0600/create-only/fsync. Massimo1controllo/600s; cumulativi10controlli/
35GET. È diagnosi diversa, non nuovo tentativo di verifica o riarmo. STOP e
interruzione conservano ogni file; nessun rilancio o directory alternativa.
Limiti:2GiB/archivio,8GiBset,2048membri,256documenti/1024riferimenti,2MiB/documento,
16MiBmetadata/immagine,profondità4,64KiBJSONpubblico. Tutto bounded senza retry.

## Riuso Teatri e baseline consultata

Riletti [handoffM1](OUF_M1_COMPLETED_20261026.md),
[dossier26join/13identità/20proprietà/8Cinema](../../evidence/csv-m1-f5-f6-owner-verification-20261026.json)
e [auditM2: metodo, generazioni e riuso concreto](../OUF_M2_CODE_EVIDENCE_GAP_AUDIT_20261026.md).
Si riusano owner/provenance/riconciliazione/recovery; nessuna terza acquisizione
Teatri o riscrittura dei motori. Il contratto specifico del formato Docker è
qualificato separatamente, senza dedurre l'installazione da prove del caso M1.
MiniPETM2v1.3 WP2/WP6/§10; policyresilienzav3 regole3–9/14–18;
GatewayPET1.5 T11/T11.3; AuthorizationPET1.5 separazione attori/human-only.
La diagnosi è manutenzione, non il normale percorso file MCP→Gateway→owner.

M1tecnico8/8 e funzionale6/6 acquisiti, stessa Farmacie61righe/10colonne10OPEN/
ministerialeSTRING. M2/G5/G6/G7 e dueclient restano OPEN; nessun upload/profiling/
acquisizione/attivazione/releaseacceptance. Pipeline fino a UDP con ogni riga,
poi grafo/search e verticali/API scheduler/delta. Publisher/source/membership,
Gatewayproposal, owner/policy/custody/bearer, coorte/pacchetto/review/authority
correnti rimangono distinti e aperti.
