# Revisione immagini provider v2 — proposta, decisione umana pendente

Questa proposta riusa immagini, inventari, scansioni e verifiche già completati.
Non autorizza emissione di mandati, aggiornamento del runtime o avvio. Le prove
del VPS qui descritte sono ricevute riportate dall'operatore; i due ZIP sidecar
sono stati scaricati in cloud dal connettore e i loro SHA256 sono stati confrontati.
Le firme non sono state nuovamente verificate crittograficamente da questo lettore.

## Identità e collegamento delle prove

| Ruolo | CID | Manifest OCI | Config |
|---|---|---|---|
| adapter | f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67 | sha256:277dcefd4744c244f4f6f23f8969f3d0acd64369e2ff1bd67594955c4ca7fbbc | sha256:62e066bd021f386291f5de21ce0e1f9e67904a74b4146326070c7784493ad320 |
| southbound | 1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916 | sha256:c15541037a08276e36715a3c3798c2d07fe6faabf5547d3885a66cd10575e366 | sha256:d4c47bbeca75d94e2231e17ca14552885b7b339a5f33dbace411e275c79ded04 |

Le attestazioni originali firmano gli archivi compressi, non direttamente i digest
del manifest OCI. Subject adapter 8301649b854a01d0306fabb14a5f93dd08eb4b1df98c2af356c0c84773821207,
subject southbound 1588c2391f9da45f300d16dd191cfe483dff83f81ed9424baec40201e64d7641.
Le ricevute del pacchetto associano quei subject ai due config digest attuali.
Il collegamento config/manifest/CID viene dalla creazione fermata e dalla
qualificazione degli archivi già conservate; questa lettura non le ripete.

Il produttore originale è GioNob/ouf-semantic-registry, workflow
semantic-image-remediation.yml, ref refs/pull/26/merge, merge
0a1b4460c52c74cefe806286f043f71cbf5a5647. ZIP originale
2cdd7a73c1fc2a710f1e6604eb6cab2988492e4c45b5252defffa9832b91d9d0.
La firma del builder identifica il produttore dei byte; non approva i publisher
upstream e non conferisce authority OUF. Le ricevute dichiarano acceptanceGranted=false.

## Supplemento aggiornato già completato

La fonte è la branch codex/r4a-smoke-semantic-inventory, head
ae099d218d0b453af4f5aa4f9a15aebfb7ca705b, PR #26. L'audit precedente non aveva
letto queste ricevute: l'assenza di prove in quei documenti non era prova di
assenza nella branch. Riutilizzare i seguenti risultati, senza nuove scansioni,
trasferimenti o verifiche VPS finché la validità corrente resta sufficiente.

- Producer 37613612404, merge 00ba8b2ca6caf01902943b6d8d3dba60c00df6a9.
- Artifact 11478662099, SHA256 a23ee77e6f2e21fc9a7ca1beb144d11f22228cc801693cac5fad47ee30e863ea.
- Readback indipendente 37614224542, 38 test e cinque firme PASS.
- Ricevuta operatore 7 ottobre ore 13:55:40: cinque firme PASS, report
  /home/oufadmin/ouf-extended-fresh-v2.Bs2U5B/reports. È prova riportata, non SSH indipendente.
- Database v6.1.10 costruito 2026-10-07T06:31:48Z, archivio SHA256
  008449eb30e10988569b3bd54eb46158f33187211ba723f41ed9326ccfa1e174.
- Validità termina 2026-10-09T06:31:48Z, **9 ottobre alle 08:31:48 Europe/Rome**.

| Ruolo | Critical | High | Unknown | Medium | Low | Negligible |
|---|---:|---:|---:|---:|---:|---:|
| adapter | 0 | 0 | 0 | 5 | 0 | 0 |
| southbound | 0 | 0 | 0 | 142 | 18 | 4 |

Le soglie configurate sono rispettate. Non significa assenza universale di
vulnerabilità. Il conteggio southbound aggiornato 142 Medium sostituisce, per
questa scansione, il precedente 141. I vecchi report restano conservati.

## Decisioni specifiche ancora da assumere

La revisione custom esistente descrive prove e limiti: OpenResty 1.31.6.1 è uno
snapshot di sviluppo; zlib 1.3.2.1-motley è uno snapshot con chiave APK generata
in build; OpenSSL 3.4.8 ha una patch OpenResty portata. Proprietà del mantenimento
e fiducia dei publisher custom richiedono decisione esplicita. PCRE/Brotli
ereditati hanno byte/versioni misurati, ma la sola misura non dimostra tutta la
provenienza dei sorgenti. LuaRocks conserva 75 versioni; le associazioni MD5
sono inventario, non autenticazione upstream. WASM è deliberatamente omesso:
non è provata la compatibilità di casi d'uso che lo richiedano.

Sono disponibili 111 ELF adapter e 810 ELF southbound associati all'inventario,
16 identità di moduli statici, 188 file Lua distinti e il file generato LuaJIT
ricostruito da 246 sorgenti esatti. Queste prove non rendono completa la
copertura degli advisory. Non inventare acceptance per colmare tali limiti.

La decisione da preparare deve specificare per ruolo l'ambito d'uso, i publisher
e componenti custom accettati, i limiti di copertura riconosciuti, i requisiti
funzionali e il responsabile del mantenimento. Non usare una domanda generica
di autorizzazione o dedurre questa decisione dal verde CI.

## Raccordo con la transazione

Due documenti compatti candidati dependencyEvidence sono in
evidence/provider-v2-input-candidates-20261008/. Derivano dai report del nuovo
artifact e mantengono hash di inventario/report, config per ruolo, pin DB,
conteggi e assenza di ignoredMatches/package alerts. Non contengono firme OUF,
non sono atti di acceptance e non diventano autorità perché presenti in GitHub.
L'issuer deve verificare le prove originali prima di approvarne i byte.

Il nuovo validatore richiede il contratto ouf.semantic-provider-dependency-evidence.v1
e applica i 48h del database anche alla fine dell'intera finestra del mandato.
Rifiuta DB futuro/scaduto, schema/build discordanti, Critical/High/Unknown,
package alerts e ignored matches. Il controllo precede le chiavi nell'issuer
e viene ripetuto dopo la verifica del review firmato nei checkpoint. Non è
un verificatore Sigstore né un sostituto del giudizio publisher/custom.

Restano input OCI/context/launch e chiusura dei profili completa, accettazione
specifica image/rootfs per entrambi i CID, mandati delle autorità separate,
prova completa della coppia Docker, configurazione target e confezionamento
della transazione concreta. Nessun nuovo comando target di avvio è pronto.


## Explicit human lab image acceptance, 8 October 23:38:09 Europe/Rome

The user answered "accetto" to the concrete image review proposal. Receipt: evidence/provider-v2-lab-image-human-acceptance-20261008.json, approvalRef OUF_PROVIDER_V2_LAB_IMAGE_REVIEW_20261008_233809. It accepts the two exact v2 images for OUF-LAB, custom-component maintenance by OUF/GioNob, omitted WASM and documented provenance/advisory-coverage limits, with current 5/142 Medium counts. Do not ask this same acceptance again. This is the human message record, not a cryptographic issuer signature or target authorization token. It does not grant complete OCI/rootfs acceptance, role signing, runtime publication, leases, startup or release acceptance. Database freshness remains mandatory. Proceed autonomously with complete target input/profile closure and actual Docker cohort integration; no target start command is ready.
