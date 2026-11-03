# SeaweedFS 4.52 — modulo di test IAM interamente su SDK v2

Data: 3 novembre 2026. Ambito: sviluppo e qualifica repository, zero operazioni target.

## Risultato

La patch27 `4.52-iam-module-sdk-v2.patch` migra i nove importatori SDK v1 residui
nel modulo `test/s3/iam`, incluso il framework condiviso. S3 e IAM usano i client
mantenuti SDK v2, rispettivamente `v1.114.1` e `v1.64.6`; core `v1.47.5` e Smithy
`v1.28.7` sono invariati. `go mod tidy` elimina SDK v1 e JMESPath dal modulo e dai
checksum. README e `install-deps` scaricano i pin dichiarati, senza reinserire v1
né effettuare aggiornamenti floating.

Sulla sequenza cumulativa27 patch, gli importatori diretti Go di AWS SDK v1
sono zero nell'intero sorgente. Questo non equivale alla rimozione delle
dipendenze indirette da tutte le integrazioni opzionali del modulo root.

## Compatibilità e limiti di esecuzione

- La regione del framework rimane `us-west-2`; il client statico dei test group
  conserva `us-east-1`. Endpoint, path style, form Query e nomi delle azioni restano
  quelli dei test originali.
- Modalità distinte: credenziali statiche/sessione firmate SigV4 e token Bearer
  con credenziali SDK anonime. Le credenziali parziali sono negate prima del trasporto.
- Calcolo e validazione checksum `WhenSupported`, un tentativo SDK per chiamata,
  timeout HTTP30s. Il timeout Keycloak specifico60s in CI resta conservato.
- SDK e richiesta raw autenticata ricevono contesti di test; cleanup registrati
  hanno contesto indipendente30s. Le attese del probe del framework rispondono
  alla cancellazione, conservando il limite preesistente30 tentativi.
- I benchmark usano `testing.B` tramite `testing.TB`, senza costruire una falsa
  `testing.T`. Enumerazioni, booleani e liste IAM/S3 seguono le forme SDK v2;
  gli errori API vengono estratti dalla catena Smithy.

## Evidenze locali

La sequenza completa27 patch si applica al commit upstream
`984eac6a790be89e2a11de175a7413e1e3e32dd3`; i15 file modificati da questo lotto
sono confrontati byte-per-byte con l'implementazione provata.

Compilazione del modulo completo con `-mod=readonly`: PASS, **senza modfile o
sostituzioni**. I pin storici JWT `v5.3.0` e testify `v1.8.4` sono stati scaricati
normalmente e restano invariati. Il grafo dei test contiene **303 pacchetti**;
il grafo del modulo ha **20 voci** incluso il modulo principale, zero SDK v1 e
zero S3 manager deprecato.

Sono PASS **14 test top-level e4 sotto-casi**, senza rete: sei nuovi test del
framework, sei test precedenti del client service account e due signer.
Le nuove prove coprono Query IAM firmata e risposta tipizzata, token di sessione,
regione/path/body/checksum S3, Bearer anonimo, errori annidati e503 senza retry
aggiuntivo, cancellazione/credenziali parziali, e firma raw dell'estensione
`UpdateGroup` con `Disabled=true`.

Il workflow dedicato ripete applicazione cumulativa, compile/test esatti,
assenza importatori v1, grafi e idempotenza `go mod tidy`, poi attesta il manifest.
Lo stato hosted resta PENDING fino alla ricevuta della CI.

## Cosa resta aperto

Non sono eseguiti roundtrip SeaweedFS/Keycloak live né accettazione delle policy.
Tolleranze/skip e comportamenti di cleanup/probe storici non sono trasformati in
prove di conformità runtime. Nessun codice server è modificato da questo lotto;
la coorte OCI esatta a15 patch non cambia e nessuna release è ammessa.

Matrix1.7, PET UDP §109.4/109.5 e policy resilienza v3 restano vincolanti.
Gate0/8, AT0/21 e oggetti reali0/120; MinIO resta attivo. Scope17/52 Engine GET,
Teatri/M1 e Farmacie preservati, senza replay/reset/grant, merge o deploy.
