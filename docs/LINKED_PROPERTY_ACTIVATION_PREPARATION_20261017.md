# Preparazione del profilo di riconciliazione

**Tecniche 8/8; funzionali 2/6. Profilo proposto, non pubblicato.** Il codice installato e la migrazione V35 restano distinti dalla pubblicazione di regole native e dal collaudo funzionale sul VPS.

## Autorità normativa

La [specifica approvata al commit 83e2e85](https://github.com/GioNob/ouf-deploy/blob/83e2e85a0ae4107ba52486de7bdcbfe4502761cc/docs/LINKED_OBJECT_PROPERTY_RECONCILIATION_V1.md) e la relativa [policy verificabile](../policies/linked-object-property-reconciliation-v1.json) restano il riferimento per la riconciliazione. Sono state confrontate con i documenti allegati in `OUF_Reality_Baseline_Package_v1_7.zip`; gli 11 documenti DOCX coincidono con SHA256SUMS del pacchetto. L'evidenza dei digest è in [linked-property-pet-baseline-20261017.json](../evidence/linked-property-pet-baseline-20261017.json).

| Riferimento PET | Vincolo applicato |
| --- | --- |
| Blueprint0.3 §1, Matrix1.7 §1 e §6 | UDP materializza; Onboarding pubblica configurazioni; Ingestion esegue con versioni fissate; THS conserva l'autorità HUMAN. Il runtime non inventa parametri scheduler. |
| Onboarding1.6 §§7.5–7.6 | Nessuna validità derivata o priorità delle fonti inventata; authority per proprietà. |
| Onboarding1.6 §90, ONB-HIST-01…05 | Bundle storici immutabili; nessuna reinterpretazione retroattiva; nuova DRAFT per una configurazione diversa. |
| Onboarding1.6 §37 | Modifiche a source/scheduler tramite workflow governato; nessun consenso implicito alla disabilitazione. |
| UDP1.3 §§14–19 | Provenienza per proprietà, contributi e conflitti conservati; identità distinta dalla scelta del valore. |
| Ingestion1.3 §106 | Ogni run conserva il proprio bundle; niente sostituzione del profilo durante l'esecuzione. |

I dati Teatri restano una fixture dell'installazione. Il preparatore e le correzioni applicative non contengono diramazioni per CSV, nomi di fonti o proprietà Teatri. Le geometrie mantengono il percorso spaziale dedicato.

## Incompatibilità individuata e correzione

Il readback operatore mostra 20 proprietà con datatype `http://www.w3.org/2001/XMLSchema#string` e `reconciliation=null`. I validatori installati Onboarding e UDP ammettono solo i nomi brevi `string/number/integer/boolean/object` quando si abilita la nuova regola. Il decoder UDP usa direttamente il datatype pubblicato. Aggiungere soltanto le regole fallirebbe quindi la validazione.

La correzione accetta l'IRI esatto XSD string per il confronto e conserva l'IRI nel profilo serializzato: [UDP PR44](https://github.com/GioNob/ouf-udp-object-resolution/pull/44), commit `e66e6df0833a872f15170eb46a43f85e50dd859b`; [Onboarding PR45](https://github.com/GioNob/ouf-source-onboarding/pull/45), commit `b8b2eb23e36ea3166012edf84fb8c1fc3441dfca`. Non sono introdotte conversioni implicite di valori o alias generici per suffisso.

Qualifica: UDP [77 test mirati](https://github.com/GioNob/ouf-udp-object-resolution/actions/runs/39068244324), [CI completa](https://github.com/GioNob/ouf-udp-object-resolution/actions/runs/39068244334), [CRS/grid](https://github.com/GioNob/ouf-udp-object-resolution/actions/runs/39068244339); Onboarding [CI completa](https://github.com/GioNob/ouf-source-onboarding/actions/runs/39068142487), [browser](https://github.com/GioNob/ouf-source-onboarding/actions/runs/39068142455). Esiti PASS. Il primo test nuovo UDP aveva omesso il binding di identità della fixture prima della materializzazione: corretto il test, mantenuto il controllo applicativo. Nessuna migrazione aggiuntiva.

## Profilo concreto proposto

[linked-property-profile-proposal-20261017.json](../releases/linked-property-profile-proposal-20261017.json) contiene tutte le 20 proprietà con la rispettiva configurazione precedente attesa. Il profilo è vincolato a source `teatri-csv-6609b245`, versione `9860853e-e8f3-4b93-b9d2-03521a039962` e hash owner `sha256:ae7f46b4214d09c55a9885530920026258f0dcd588462c353b06d82185e12c9b`.

- `cardinality=SINGLE`: applicazione proposta del default conservativo della policy approvata, non attestazione di una cardinalità ontologica. Un vincolo semantico o sorgente incompatibile impone revisione prima dell'approvazione.
- `normalizerRef=EXACT_TYPED`, versione1: nessuna equivalenza di nomi/indirizzi o normalizzazione aggiuntiva inventata.
- `validity=SOURCE_INTERVAL`: rispetta soltanto gli intervalli già prodotti dal contratto temporale corrente. Non deriva validFrom/validTo da observedAt, date nel testo o ordine di acquisizione. Il temporalMapping completo deve essere confrontato prima dell'approvazione.
- `revisionField` e `deletionField` assenti: nessun contratto di revisione/cancellazione introdotto. Null, assenza e vuoto non cancellano.
- `authorityOrder`, datatype, accessLabel, mapping e policyRef esterno della materializzazione restano quelli esistenti.

La lettura owner del riferimento semantico esatto è stata tentata attraverso `semantic.get` e ha restituito HTTP403 `SEM_READ_RECEIPT_OR_POLICY_DENIED`. Non è prova di un vincolo mancante né motivo per adottare vecchie proposte semantiche come pubblicazioni correnti. Nessun login/grant/refresh è stato avviato per aggirarla. Il confronto con i vincoli semantici pubblicati resta aperto.

## Effetto dello scheduler

Verifica del sorgente Ingestion `f869d8b86b892a0c03c147dac9bb40cd5f873ff2`, fissato nel rilascio readiness: `PublishedActivation.decode` deriva `once` da `acquisitionMode=MANAGED`. Il campo top-level `triggerOnce=null` del readback non disabilita l'acquisizione unica.

`ActivationRepository.reconcile` sostituisce publicationId/sequence/checksum della schedule, rende immediatamente dovuta una nuova pubblicazione e disabilita la one-shot consumata solo quando `consumed_publication_id` è uguale al nuovo publicationId. Una nuova pubblicazione può quindi riarmare la sorgente. Può anche terminare preflight della vecchia pubblicazione come superseded. Le run avviate conservano il proprio bundle; questo non elimina il rischio di una nuova acquisizione.

Non esiste, nel percorso analizzato, un parametro nativo `publishProfileOnly` che garantisca zero acquisizioni. Non si scrive manualmente `consumed_publication_id`, non si falsifica un checkpoint e non si presume sufficiente una pausa locale o una lettura istantanea senza lease. Disabilitare la source cambierebbe lo stato operativo e richiede un percorso HUMAN esplicito; la successiva riabilitazione potrebbe avviare l'acquisizione. Nessuna di queste operazioni è stata eseguita.

## Preparazione e percorso nativo

Il preparatore offline [prepare.mjs](../tools/linked_property_profile/prepare.mjs) riceve uno snapshot completo e fresco della configurazione owner, i tre identificatori source/version/hash e la proposta. Confronta integralmente ogni proprietà attesa; aggiunge soltanto `reconciliation`; prova la conservazione del resto del documento. Scrive un nuovo file privato senza sovrascrivere file esistenti e senza rete, token, SQL o publisher. I digest locali non sostituiscono il configurationHash calcolato dall'owner. Il risultato mantiene sempre `readyForActivation=false`.

1. Qualificare e installare entrambe le correzioni XSD senza ripetere V35 o la vecchia autorità consumata. La sola CI non prova l'installazione.
2. Leggere, in una verifica coerente, la configurazione completa della versione attiva, le dipendenze semantiche e temporali e la schedule Ingestion con lease, pubblicazione consumata e run pendenti. Il readback precedente espone metadati delle proprietà, non tutta questa evidence.
3. Preparare la nuova configurazione con il delta limitato alle regole. Validare nativamente senza pubblicare.
4. Dal percorso HUMAN→Gateway→Onboarding: `POST /api/onboarding/v1/sources/{sourceId}/onboarding-versions/{versionId}/clone`; aggiornare solo la nuova DRAFT con `PUT` e `If-Match`; `validate`; `submit` con ETag; nuova approval challenge e revisione THS. Non riusare challenge o decisioni precedenti. La clone nativa non è dimostrata idempotente: un esito ambiguo richiede lettura/audit, non retry automatico.
5. Ottenere la vera attestation Ingestion sul nuovo hash e il controllo di identità nativo. Prima di `activate`, approvare esplicitamente gli effetti di acquisizione oppure implementare e qualificare un hold nativo per la source. Senza questa condizione la pubblicazione si ferma.
6. Solo dopo la decisione HUMAN: pubblicazione owner, readback di versione/checksum e 20 regole, verifica del comportamento scheduler concordato. Nessun replay delle 11 decisioni CREATE_NEW, nessuna ripresa del caso lasciato in quarantena.
7. Collaudo funzionale distinto, con input nuovi controllati: complementari; null/vuoti; uguaglianza e provenienza; conflitti tra record della stessa fonte; priorità esplicita; multivalore solo su fixture dichiarata; idempotenza; evidenze obsolete; isolamento accessi/tenant. La configurazione conservativa della fixture non prova da sola tutti i rami generici.

Il workflow [linked-property-profile-preparation.yml](../.github/workflows/linked-property-profile-preparation.yml) esegue i test offline e usa il runner VPS `ouf-vps-test` per leggere esclusivamente i metadati delle due immagini installate attese. Non entra nei container, non usa sudo, non legge database o credenziali e non pubblica profili. Questa osservazione non sostituisce la verifica di schedule e configurazione completa.

## Stato separato

| Livello | Stato |
| --- | --- |
| Implementazione generica originale e V35 | Installate, come da readback operatore conservato |
| Correzione XSD | Qualificata in CI; non installata |
| Profilo nativo | Proposta concreta pronta; non pubblicata |
| Scheduler e vincoli completi correnti | Verifica operativa residua; nessuna acquisizione autorizzata implicitamente |
| Collaudo funzionale VPS | Non avanzato; tecniche8/8, funzionali2/6 |

## Correzione della prima verifica immagini

Il run [39068802755](https://github.com/GioNob/ouf-deploy/actions/runs/39068802755) ha passato i 16 test offline e fermato la lettura VPS con `ONE_RUNNING_EXPECTED_APPLICATION_REQUIRED`. Il lettore aveva usato il digest della configurazione Docker come identità nativa del manifest containerd: il fallimento non prova drift del target. La verifica corretta deriva il digest nativo dagli stessi byte del pacchetto qualificato (ZIP fissato per ID, dimensione e SHA256; archivio, configurazione, sorgente e layer verificati con il modulo di custody già usato dal rollout). La derivazione avviene su runner GitHub, senza import di immagini; al VPS arrivano solo le identità pubbliche attese. Il confronto resta esatto, senza fallback su nomi o label.
