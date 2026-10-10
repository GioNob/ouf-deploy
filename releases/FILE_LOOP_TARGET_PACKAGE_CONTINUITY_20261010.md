# Pacchetti target e stato R9 — 10 ottobre 2026, seguito operativo

L'output operatore registra staging riuscito in /home/oufadmin/ouf-file-loop-offline-stage.LMawhAuO: checksum ZIP e interni validi per tutti e tre i moduli. Le immagini di questi archivi sono Semantic e826bd…, Ingestion 98af9d… e UDP 7a9797…; sono distinte dalle immagini delle precedenti CI di componente. Nessuna importazione, nuova firma d'installazione, modifica applicativa o R9.

I tre container Semantic/adapter/southbound sono running e le generazioni osservate sono stabili. Le cinque directory storiche esistono, root-owned, mode 0700. Questi metadati non provano i byte dei file privati, OCI host completo, reciproco peer, lease o salute applicativa.

R9 risulta failed/exit-code, MainPID=0, NRestarts=0, Restart=no, InvocationID ba95ba7239664789ac68430107ac6dc8. La stessa invocation precedentemente attiva è ora fallita. Non dedurre una causa DNS dal solo stato systemd, non riavviare, non resettare claim né rifare il launcher apply consumato. Serve lettura delle evidenze conservate con il reader sigillato già qualificato; non viene inventata nuova autorità.

## Provenienza dei pacchetti conservati

Workflow [38071155443](https://github.com/GioNob/ouf-deploy/actions/runs/38071155443), producer cc39a2d9a20a3edeacb1594d34e0a1780e897113: tutti e tre i job PASS. Scarica i ZIP originali immutabili, controlla tutti i checksum interni, immagine/source/scan precisi, SQL byte-per-byte fra tar sorgente e JAR, presenza SDK runtime ed esclusione dell'adapter di identità fixture. Firma i ZIP originali e le ricevute di continuità con chiavi effimere OIDC in CI; verifica identità workflow/ref, issuer GitHub, repository e commit esatti con Cosign 3.1.3.

Il primo tentativo GitHub Attestation API 38070844195 è fallito perché l'archivio attestazioni non è disponibile per repository privati personali. Il fallimento resta evidenza; il repository non viene reso pubblico. L'alternativa usa bundle Sigstore Fulcio/Rekor, non il servizio GitHub non disponibile. Nessun skip della verifica, nessuna chiave privata d'installazione. I fallimenti intermedi di preparazione dei bundle dovuti alla directory evidence già esistente sono corretti isolando publisher-evidence; non sono reinterpretati come prove crittografiche riuscite.

Il target possiede ancora ZIP immutati e record originali UNSIGNED. Le firme sono sidecar: la nuova verifica target dei bundle deve precedere l'affermazione publisherCryptoVerified. La provenienza del produttore non concede fiducia o autorità d'installazione e non sostituisce la nuova decisione HUMAN, inventario esteso OCI, readiness di migrazione o trust Java della nuova immagine.

## Lavoro restante immediato

Verifica crittografica target riusando i ZIP già scaricati; acquisizione dei nuovi public cacerts legati alla nuova immagine senza riutilizzare il vecchio truststore; diagnosi R9 read-only in una singola consegna. Nessuna nuova ingestion Cinema: il PASS storico 8/8 e la ricerca corrente su tre pagine restano conservati. Nuovi gate di rilascio non riaprono i gate già superati.

[Ricevuta strutturata](../evidence/file-loop-target-package-continuity-20261010.json). Le operazioni sul VPS richiedono ancora l'operatore per sudo; la preparazione e qualifica GitHub proseguono autonomamente.

## Chiusura della preparazione della prossima lettura

Public roots workflow 38071443267 PASS: sei test di estrazione (tamper, link privati, whiteout di file/antenato, root opaque, tar gzip/plain) e lettura dell'archivio reale. Firma e verifica del nuovo candidate-cacerts e della ricevuta: publisher 1cb25d6ad95e58d0405d01ea4a245ca85704ad11, artifact 11677280041. Il nuovo publicStoreHash è 98d34a90fca2688ef5674862d2a484e09e5ca25d2f07c5d654aa28f1581f3419, uguale al baselineHash della preparazione trust storica. Non dedurre nuova autorità da questo confronto: è possibile riutilizzare i byte del merge già provato solo se la nuova lettura root conferma manifest, public CA, baseline, receipt e P12, con ruolo 10001/mode0400 e riletture stabili. Il nuovo helper non rigenera, non monta, non firma e non apre chiavi private; quattro test negano baseline/CA/store cambiati, scope/ruolo/count errati e coercizioni bool.

La prossima consegna releases/file-loop-provenance-trust-r9-read-20261010.sh riusa i tre ZIP già scaricati. Scarica soltanto sidecar di provenienza/cacerts e il client Cosign 3.1.3 verificato con checksum; non cambia la visibilità del repository. Il client target verifica ZIP originali e ricevute con issuer, identità workflow/ref, repository e commit precisi; il materiale pubblico è verificato contro il suo producer separato. Poi un'unica fase sudo carica tre reader da byte verificati in memoria: confronto del trust esistente e diagnosi R9 sigillata già qualificata. Tutte le letture restano osservazioni, senza lock o nuova autorità. Anche in caso di trust negato viene tentata la diagnosi read-only R9; il codice d'uscita segnala qualsiasi blocco e conserva entrambe le ricevute.

La richiesta all'operatore è necessaria soltanto per la lettura sudo dei record protetti; i pacchetti applicativi non devono essere scaricati di nuovo, le immagini non vengono importate, i claim non vengono riscritti. Il nuovo installer/cutover non è ancora dichiarato applicabile.
