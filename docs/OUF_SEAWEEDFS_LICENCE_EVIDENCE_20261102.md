## Coorte 4.52 verificata su runner ospitato — 3 novembre 2026

La [CI 41627470213](https://github.com/GioNob/ouf-deploy/actions/runs/41627470213) ha verificato l'esatta coorte tecnica e attestato la ricevuta bounded. La ricevuta hosted, ora trattenuta in `evidence/seaweedfs-452-cohort-readback-hosted-20261103.json`, è di 1.393 byte e ha SHA256 `da3482b4710e50c40634a89e37d7d17d78bdff8073d00e048ba00990de16f092`. L'artifact `13226228195` ha ZIP SHA256 `eff348904adb4ad63f6bf7304914b3972e11db468ea8c5d136c35972c5f1c6d4`.

Il readback conferma 262 moduli di terze parti, 353 testi legali e il contesto byte-bound dei tre risultati UNKNOWN del classificatore. Questo è un risultato tecnico, non un'accettazione legale: `licenceReview=OPEN`, `redistributionAccepted=false`, `durableImageCustody=OPEN`, `releaseAdmitted=false`, zero autorità runtime e zero operazioni target.

## Readback della coorte 4.52 — 3 novembre 2026

Il verificatore della [coorte candidata](OUF_SEAWEEDFS_452_COHORT_READBACK_20261103.md) collega l'archivio OCI completo, il readback indipendente, questo corpus storico e il delta della patch 15. La rilettura locale integrale ha riprodotto OCI e assessment, verificato firma e sorgenti e prodotto la ricevuta canonica SHA256 `390121e8d48793f0f10fa3351e8aa87fe5603fd7617f680ebc7dd978272b0a11`.

I tre risultati UNKNOWN sono vincolati a modulo, versione, percorso, hash e co-rilevazioni. Questo è contesto tecnico: `licenceReview=OPEN` e `redistributionAccepted=false` restano obbligatori. L'immagine completa resta in artifact CI temporaneo fino al 1 febbraio 2027; la custodia durevole è OPEN. Nessuna release, ammissione, operazione target o autorità runtime.

# SeaweedFS — licenze e attribuzioni della generazione esatta

## Review tecnica G1 — 3 novembre 2026

**Stima MiniPET circa 33%** (15,3/46, incertezza di circa 10 punti). I risultati qui sotto chiariscono due rilievi aperti e mantengono aperti G1, tutti gli 8 gate, tutti i 21 AT e M2. L'inventario privato ha 120 oggetti, con 0 copie reali.

### AWS SDK Go v1 nel percorso S3

Nel grafo di compilazione del candidato 4.51, legato dal suo SHA256 `67534a54978a5a157673a6a21ea26c147b0dbcb60c60d30497ce39e6ee3c435b` al record del binario `bb9f768e5afca39c7fdc2113e5caafd9f911d4537917dd25c520ee4dbdab1f74`, figurano **55 pacchetti di AWS SDK Go v1 su 1.738 pacchetti totali**. La versione è `v1.55.8`, fuori supporto AWS dal 31 luglio 2025. Il ramo principale upstream osservato al commit `c2ca83c0bf2f0c13b8cb3398728a1d4fd3f669ce` dichiara ancora la stessa versione. [Grafo e record conservati](../evidence/artifacts/storage-runtime-image-readback-41527990598.zip) · [go.mod upstream osservato](https://github.com/seaweedfs/seaweedfs/blob/c2ca83c0bf2f0c13b8cb3398728a1d4fd3f669ce/go.mod) · [Ciclo di vita AWS](https://aws.amazon.com/blogs/developer/announcing-end-of-support-for-aws-sdk-for-go-v1-on-july-31-2025/).

Nel tag esatto, una ricerca degli import v1 trova 34 file Go fuori dai test, 15 sotto `weed/s3api` e le sue sottodirectory. I blob esaminati coincidono con l'inventario upstream congelato. Multipart usa tipi v1 per avvio, completamento, abort e listing delle parti. Il codice di listing usa costanti e helper v1. Gli handler del bucket chiamano il decoder XML interno v1 per ownership e versioning, e il percorso ACL usa tipi v1. AWS KMS, SQS, remote storage S3 e backend S3 sono ulteriori punti d'uso. Disabilitare i servizi opzionali lascia il modulo nella build e lascia gli usi osservati nei gestori S3. L'analisi statica dimostra la dipendenza nel server candidato. La configurazione e il traffico del target richiedono una verifica distinta. [Tag e handler multipart](https://github.com/seaweedfs/seaweedfs/blob/153ab668c99731a6d29492bf6c61d0b4fa701101/weed/s3api/s3api_object_handlers_multipart.go) · [Handler bucket](https://github.com/seaweedfs/seaweedfs/blob/153ab668c99731a6d29492bf6c61d0b4fa701101/weed/s3api/s3api_bucket_handlers.go) · [Inventario dei blob](../releases/seaweedfs-upstream-source-tree-20261102.json).

Direzione tecnica per la prossima generazione: partire da un commit upstream verificato che rimuova SDK v1, oppure qualificare una patch circoscritta e mantenibile con copertura dei percorsi interessati. Il criterio tecnico proposto è assenza di v1 nel grafo compilato e nella SBOM del nuovo binario, con regressioni S3 su listing/paginazione, multipart, ACL e versioning e riconciliazione della copia con i client OUF. I nuovi byte richiedono scansione completa, nuova valutazione dell'applicabilità, provenienza e custodia. Il candidato corrente resta una base per le prove isolate e la raccolta di evidenze. Questa è una constatazione di ciclo di vita, senza un nuovo rilievo CVE.

### Rilettura dei tre UNKNOWN di licenza

Per tutte e tre le righe raw, la vista del classificatore coincide byte per byte con il testo originale e lo SHA256 coincide con quello della mappatura. Tutte e tre coesistono con una rilevazione Apache-2.0 nello stesso documento, insieme a BSD-3-Clause per Arrow e Thrift.

| Componente e percorso | Rilievo raw | Esito tecnico della rilettura |
|---|---|---|
| parquet-go v0.32.0 · `LICENSE` | `Copyright` | Il documento contiene Apache-2.0 e una menzione di copyright. Conservare testo e attribuzione. |
| Arrow Go v18.8.0 · `LICENSE.txt` | `Copyright` | Il documento aggrega Apache-2.0, attribuzioni e termini BSD-3-Clause. Conservare il documento completo e i notice. |
| Thrift v0.24.0 · `LICENSE` | `GNU-All-permissive-Copying-License` | Il documento aggrega più termini. Mantenere il rilievo associato al testo e verificare la pertinenza del componente coperto rispetto ai sorgenti compilati e alla distribuzione. |

Il rapporto grezzo mantiene 3 UNKNOWN. La SBOM mantiene NOASSERTION. La review di applicabilità, co-consegna e obblighi di redistribuzione resta aperta. [Corpus e risultati originali](../evidence/artifacts/storage-licences-native-41541625141.zip).

Verifica eseguita sui due archivi pubblici trattenuti: SHA256 degli archivi, checksum dei membri presenti, binding del grafo al record del candidato, corrispondenza dei blob selezionati del tag 4.51 all'inventario congelato e verifica byte/SHA delle tre viste. La rilettura è documentale e statica. Custodia durevole dell'immagine e coorte restano aperte. Per questa review sono stati consultati il MiniPET storage v1.1, il PET UDP v1.3 originale conservato nel pacchetto baseline v1.7 (§46, §81, §109.4–109.5) e la policy di resilienza v3.

---

Sessione avviata il 2 novembre 2026, Europe/Rome. Continuazione SW-WP1/G1; immagine e binario restano quelli qualificati in [OUF_SEAWEEDFS_RUNTIME_IMAGE_20261102.md](OUF_SEAWEEDFS_RUNTIME_IMAGE_20261102.md). Questo dossier raccoglie prove tecniche, senza dichiarare accettata la distribuzione.

## Raccolta e verifiche

Il corpus riguarda tutti i **245 componenti** identificati nell'esatta immagine: SeaweedFS, Go1.27.3 e243 moduli di terze parti. Il raccoglitore usa il go.mod/go.sum originali autenticati, versioni esatte, proxy Go senza fallback VCS, checksum database abilitato e timeout finiti. Non esegue codice dei moduli. Per ogni modulo confronta i checksum restituiti da Go e ricalcola indipendentemente h1 sui byte dell'intero ZIP e del go.mod; vengono conservati digest, versione e provenienza. Non basta verificare il solo testo della licenza.

La toolchain è collegata all'archivio sorgente Go1.27.3 verificato con SHA256 dal catalogo ufficiale HTTPS. Non si afferma una firma del publisher Go. Il sorgente SeaweedFS viene dall'archivio OUF originale278756504byte, con4390Gitblob/mode e firma del workflow OUF già riletti. Sorgente e dipendenze del binario non vengono ricompilati o aggiornati durante questo lavoro.

La raccolta corretta conserva **374 testi**. È un corpus prudenziale dei documenti legali presenti nei moduli, che può includere materiale di sottodirectory non collegato al programma: non equivale alla determinazione file per file degli obblighi applicabili. L'input del classificatore contiene copie byte-identiche dei candidati alla licenza sotto il nome LICENSE; ogni copia è legata al percorso e allo SHA256 originali. Serve a classificare anche COPYING senza cambiare i documenti originari o abbassare la confidenza0,9.

Tutti 245 componenti hanno almeno un testo principale classificato. Il report raw distingue296 file classificati e316 osservazioni:296 LOW,17 MEDIUM,3 UNKNOWN,0 HIGH/CRITICAL. Le17 osservazioni MEDIUM sono MPL-2.0; i3 UNKNOWN restano visibili e da esaminare. Sono classificazioni di licenza, distinte dagli UNKNOWN di vulnerabilità e dalla decisione binaria GO-2026-5932. Nessuna nuova eccezione di sicurezza, ignore o OpenVEX è introdotta.

## Collegamenti non dedotti dai nomi

- GeoArrow: conservate entrambe le licenze LICENSE_APACHE e LICENSE_MIT dalla stessa versione del modulo. Nessuna scelta automatica fra alternative.
- FlatBuffers Go: la licenza nella directory superiore è collegata al commit3b8644d32c50e86872584829af4b8caf180235ab. Tutti10file del modulo ZIP corrispondono ai Gitblob di go/ nello stesso commit; LICENSE.txt corrisponde al blobd645695673349e3947e8e5ae42332d0ac3164cd7. Nessun riuso della licenza di main o del tag corrente.
- Liner e GoHBase: testi COPYING originali conservati; la classificazione usa copie identiche con il solo nome della vista cambiato. Il testo non è riscritto per ottenere un match.

La SBOM originale rimane immutata: le sue247voci conservano NOASSERTION. Le osservazioni supplementari non vengono trasformate automaticamente in espressioni SPDX approvate o licenze accettate.

## Sorgenti MPL e confezionamento

Sono preparati i sorgenti completi dei **17 moduli MPL-2.0**, con ZIP originali, SHA256, h1 del build originale, licenze e notice. Il verificatore indipendente ricalcola h1 di ogni ZIP offerto. MPL-SOURCE-NOTICE.txt indica dove si trovano i sorgenti nel pacchetto; non afferma che il solo avviso esaurisca i requisiti. Non sono state modificate le fonti di questi moduli. Il corpus e l'offerta vanno associati alla consegna dell'eseguibile e alla review della coorte, prima di un'accettazione di distribuzione.

Riferimento primario consultato: [MPL2.0 e FAQ Mozilla](https://www.mozilla.org/en-US/MPL/2.0/FAQ/), in particolare disponibilità e comunicazione della forma sorgente nelle distribuzioni eseguibili. Restano da verificare gli obblighi effettivamente applicabili, i tre rilievi UNKNOWN e la co-consegna nel profilo finale. Nessuna approvazione legale o HUMAN/THS è simulata.

## Qualifiche e cronologia conservata

Dieci test mirati PASS: checksum completi, sorgente non selezionata alterata, go.mod errato, namespace/link/traversal, versioni floating, licenza vuota, mappature del classificatore, nomi con underscore e nessuna falsa accettazione.

Prima raccolta CI41539914970/source2f19765f:245 componenti/363testi/241classificazioni principali; il matcher non selezionava LICENSE_APACHE/MIT e i nomi COPYING non erano classificati. Non si deduce assenza di licenza da questa limitazione. CI41540742440/source1384e626 si è fermata su403 rate limit nel GET pubblico GitHub;84componenti già raccolti, pacchetto incompleto conservato. Corretto il GET autenticato con token CI solo nel lettore; il token non viene passato ai sottoprocessi Go.

CI41541085942/source69c71dcd ha completato raccolta/classificazione/offerta sorgenti. La rilettura indipendente ha però rifiutato lo ZIP:4file pubblici selezionati dal corpus, in sottodirectory di metadati, erano stati esclusi dall'upload mentre il manifest li includeva. Il successo del job non è una qualifica della consegna completa. L'upload corretto include tutti i membri del manifest; non è stato indebolito il controllo di chiusura. Ricevute, hash e limiti dei tentativi sono nel lock e nel dossier.

[Qualifica CI41541625141](https://github.com/GioNob/ouf-deploy/actions/runs/41541625141) **PASS**, sorgente `81a0e32784a2c96f685773edfb65f0cc7849e7eb`:10 test,374 testi,245 componenti con almeno una classificazione principale e17 offerte di sorgenti MPL complete. [Verifica indipendente CI41542075842](https://github.com/GioNob/ouf-deploy/actions/runs/41542075842) **PASS**, sorgente `4d1183ee2855999419e1b60a8b4f85b74889d5c3`:709 checksum dell'archivio nativo,243 binding go.sum,17 h1 ricalcolati nuovamente sugli ZIP offerti, assessment riprodotto, firma del workflow/source/ref/runner hosted autenticata. Nessun codice dei moduli eseguito.

L'[archivio nativo completo](../evidence/artifacts/storage-licences-native-41541625141.zip) conserva tutti i testi, le viste e i17 ZIP sorgenti:2702322byte/SHA256`851d65dc1ac3788178978b9effc04c257475492ad6d3e5dcc04346d033288c67`. L'[archivio metadata della verifica](../evidence/artifacts/storage-licences-readback-41542075842-metadata.zip) conserva report, manifesti e firme:484968byte/SHA256`b22605210d48b7b26ae929c94e8f94851a27ba259a418866f3a12248fb74701e`. I690membri esclusi dal secondo archivio sono nominati e restano disponibili byte per byte nell'archivio nativo completo; nessun corpo o sorgente è dichiarato custodito soltanto dal suo hash. Il download indipendente originale4938554byte è stato riletto localmente con717checksum metadata/byte e ricevuta della firma. [Dossier](../evidence/seaweedfs-licence-evidence-qualified-20261102.json). Questa conservazione del corpus non chiude la custodia dell'immagine eseguibile, ancora distinta.

## Manutenzione e residuo G1

La distinta reale contiene anche github.com/aws/aws-sdk-go v1.55.8. AWS ne dichiara la fine supporto dal31 luglio 2025: [annuncio ufficiale](https://aws.amazon.com/blogs/developer/announcing-end-of-support-for-aws-sdk-for-go-v1-on-july-31-2025/). Questo è un rilievo di ciclo di vita della dipendenza compilata, non una nuova CVE, una prova di sfruttabilità o la dimostrazione che il relativo percorso sia attivo nella topologia prevista. La valutazione di raggiungibilità, supporto upstream e possibile rimozione/migrazione resta da eseguire prima di dichiarare completo il candidato. Non si trasferisce una classificazione accettata per un hash a un nuovo rebuild.

G1 rimane OPEN per review delle licenze, custodia durevole dell'immagine, coorte completa e valutazione del ciclo di vita. Tutti8gate/21AT/M2 rimangono OPEN. MinIO è ancora in esercizio;0/120oggetti reali copiati e nessun nuovo effetto target dopo il controllo17/52EngineGET. Teatri/M1 tecnico8/8 e funzionale6/6, stessaFarmacie61righe/10OPEN/STRING, mappe congelate e28sorgenti precedenti preservati. Nessuna nuova acquisizione/profilazione, merge, grant, reset, replay o release acceptance.

La stima tecnica aggiorna soltanto il credito G1 da 65 a 75%:15,3/46 ≈ 33% sui pesi originali, con incertezza di circa10 punti. È una stima di pianificazione; non è accettazione, tempo consuntivato o percentuale di dati migrati.

Autorità consultata: MiniPET storagev1.1 §4–5/8–11; PET UDPv1.3 nel repository §46,§81,§109.4–109.5 e policy resilienzav3 già consultati. Gli originali allegati non sono disponibili in questa conversazione; nessuna conformità completa agli allegati è attestata.
