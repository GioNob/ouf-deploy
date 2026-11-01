# M2 — riconciliare lo STOP sul descrittore OCI empty

1 novembre 2026, Europe/Rome. Stato: sorgente e consegna QUALIFICATI;
nuova riconciliazione VPS NON eseguita. [Ricevuta pubblica esatta](../../evidence/m2-image-byte-verification-target-stop-20261101.json),
SHA canonico d1e98ad391ccc5d339ce853a8b88afc12bcb1eb8737887d5c807321fd68e0955,
ImageByteVerificationExit=1. Il vecchio scope verifica è CONSUMATO, con8controlli
cumulativi e35GET. Non rilanciare cattura, verificatore o vecchi launcher.

## Difetto e limite della diagnosi

Il codice originale rifiuta un blob assente a meno che il descrittore sia EMPTY
con data=e30=. La [specifica OCI1.1.1](https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md#guidance-for-an-empty-descriptor)
rende data facoltativo; i byte canonici sono sempre {}, size2, digest44136f….
Il test esegue il verificatore effettivamente consegnato nella capsula70ab863a
sulla variante e riproduce esattamente il reason dello STOP. Questo dimostra il
difetto del verificatore, NON che il blob privato mancante sul VPS sia quello.
La riconciliazione target verifica tale distinzione e blocca ogni altro caso.

La correzione è ammessa esclusivamente per la configurazione di una attestazione
BuildKit marcata nonruntime, tipo application/vnd.oci.empty.v1+json, digest SHA256
canonico di {}, dimensione esattamente2; data assente oppure e30= esatto. Se il
blob esiste i byte si leggono e verificano. Se assente si verifica la preimmagine
canonica e si contabilizza separatamente la ricostruzione, senza rete o fetch.
Gli altri manifesti/configurazioni/layer assenti o alterati restano bloccanti.
Soggetto dell'attestazione, layer, digest e rootfs restano tutti verificati;
nessuna attestazione incorporata diventa fiducia nel publisher o authority.

## Riconciliazione finita

Il sorgente legge lo scope precedente esatto root0700/file0600, senza link,
claim originale e suo profilo, più il risultato con hashd1e98ad3. Un risultato,
profilo, path o metadato diverso blocca prima di ogni lettura degli archivi.
Riconferma metadata stabili prima/dopo; nessuna scrittura nel vecchio scope.
Rilegge i tredici archivi originali della catturafa95a719/receipt9733fa7c,
con identici limiti600s/2GiBperarchivio/8GiBinput/8GiBespansiimmagine/32GiBset.
ZeroEngine, credenziali, file dei mount, SQL/OAuth, import, estrazione o lifecycle.

Nuovo scope fisso /etc/ouf/deploy-snapshots/m2-image-byte-reconciliation-fa95a719-20261101-v1,
create-only/root0700/file0600/fsync, massimo1controllo. Conserva tutti gli otto
scope precedenti; totale9controlli/35GET, senza riarmo o reset del precedente.
È manutenzione con codice corretto e precedente esatto, non retry automatico o
nuovo budget runtime. STOP/interruzione conserva tutto e non si rilancia.

## Riuso Teatri e riferimenti consultati

Riletti [handoffM1](OUF_M1_COMPLETED_20261026.md),
[dossier owner](../../evidence/csv-m1-f5-f6-owner-verification-20261026.json) e
[audit M2](../OUF_M2_CODE_EVIDENCE_GAP_AUDIT_20261026.md), in particolare metodo,
confini delle generazioni e tabella riuso concreto. Le13identità,26join,
20proprietà e8Cinema preservati guidano il riuso di provenance/owner/recovery e
MATCH/NEW/REVIEW; nessuna terza acquisizione o nuovo motore. Questa verifica OCI
è un prerequisito installativo; non sostituisce i contratti del caso applicativo.
Baseline riletta: miniPETM2v1.3 WP2/WP6/§10 e audit; policy resilienza v3 regole3–9/14–18;
GatewayPET1.5 T11/T11.3 e AuthorizationPET1.5 principi di separazione attori e
human-only. Gli originali pertinenti sono presenti nel repository con le versioni
indicate; nessuna conformità completa è dedotta dalla sola integrità degli archivi.

M1rimane tecnico8/8 e funzionale6/6; Farmacie SUCCEEDED61righe/10colonne10OPEN,
ministerialeSTRING. Niente upload/profiling/acquisizione/attivazione nuovi.
M2/G5/G6/G7,dueclient,ripetibilità/fault e provaUDP con ogni riga restano OPEN.
Restano distinti publisher/source membership, scan, Gatewayproposal privata,
owner/policy/custody/bearer, coorte completa, review e authority correnti.

## Qualifica del sorgente e consegna

[Source630f8a22](../../evidence/m2-image-byte-reconciliation-source-qualified-20261101.json):
17sorgenti chiusi, capsula241.905byte/SHA20e2107c. Push41330190298 e
PR41330196953, ciascuno46test/7suite, zero failure/error/skip/ResourceWarning;
tutti sei log finali letti. La prova HTTPS in questa prima qualifica riguarda
ancora il vecchio launcher; NON qualifica il nuovo comando.
I13export Docker29.8.1 originali e13varianti esplicite senza data sono verificati;
config/layer runtime identici. Il verificatore originale70ab riproduce il motivo
su ogni variante. L'identità del blob VPS resta da stabilire sul target.

ZIP13093040843 scaricato:92.283byte/SHAa7f06e8a, tutti cinque membri letti,
capsula uguale byte per byte al builder locale. Verifica crittografica effettiva
gh2.97 sul runner; bundle/statement/certificato/subject/source/repo/ref/workflow/
runner letti e confrontati. Nessuna verifica crittografica locale aggiuntiva.
Capsula pubblicata in58c1f120ba8c1912ce4f9e3f14d59259bb0a9a5c.
Il vecchio sorgente consegnato70ab e tutti235sorgenti congelati sono invariati.

Nuovo launcher cfd24741ec350e5df09b5683042446e77a7e5132,
SHA2561ac2191de860a7608af20200a5e748f6eba2949edf00008548da040a91f1ee15.
[Comando preparato](../../releases/OUF_M2_IMAGE_BYTE_RECONCILIATION_COMMAND_20261101.sh)
QUALIFICATO su push41330448686 e PR41330454602: ciascuno46test/7suite,
zero failure/error/skip/ResourceWarning, tutti sei log finali letti. Include
7test del NUOVO launcher e1consegna HTTPS NUOVA esatta,17test byte,4intake,
8reader/controllo,5capsula e4Docker29.8.1 con13originali+13varianti esplicite.
[Qualifica finale](../../evidence/m2-image-byte-reconciliation-delivery-qualified-20261101.json).

## Unica azione operatore corrente

Come oufadmin in SSH interattivo sul VPS eseguire UNA SOLA VOLTA il
[nuovo comando esatto](../../releases/OUF_M2_IMAGE_BYTE_RECONCILIATION_COMMAND_20261101.sh).
Il plugin OUF non espone la lettura di questi archivi amministrativi e l'agente
non ha un canale SSH. Questa è manutenzione; il percorso ordinario CSV resta MCP.
Il comando non ricattura immagini, non richiede altri9GiB e non modifica container.
Eventuale password sudo solo nel terminale locale; niente login IAM o token in chat.

Atteso PRIVATE_IMAGE_BYTES_VERIFIED_SOURCE_AND_RUNTIME_NOT_ADMITTED e
ImageByteReconciliationExit=0, conteggi9controlli/35GET. Il witness riporta quante
config empty sono ricostruite e quante senza data: l'assenza di questo caso non
conferma la causa privata e ogni blob nonempty mancante rimane STOP.
Restituire soltanto JSON pubblico e footer. STOP/interruzione conserva ogni file,
nessun rilancio, reset o nuova directory per aggirare il consumo.

Dopo il risultato: legare le prove private alla coorte effettiva e ai publisher
qualificati; preservare repairOS separati/non selezionati, poi completare
Gatewayproposal/policy-owner/custody/bearer e pacchetto/review/authority attuali
prima del flusso Farmacie61righe attraverso owner fino a UDP e relativi esiti.
