# M2 — Semantic originale identificato; due origini residue e gate sicurezza aperti

1 novembre 2026, Europe/Rome. Proseguimento della ricevuta target `ca16c7e3`:
lo scope 12 è consumato, restano **12 controlli / 35 GET Engine**. Nessun nuovo
comando VPS è richiesto da questo checkpoint. Non rilanciare le vecchie consegne.

## Risultato verificato

Il Semantic conservato non è il vecchio candidato `622614b0`. L'artifact originale
del pacchetto completo, `11907557440`, run `38584614991`, contiene il modulo
`eccef11a97367f20e278db40b9ed6f45dd980c37`. La configurazione `29e32c14…` e
l'envelope nativo `b61bc39c…` coincidono con la ricevuta target. Il job
`41345531053 / 124964417117` ha verificato ZIP completo, configurazione, tutti i
layer e diff ID espansi, poi la firma Cosign del soggetto originale
`COHORT_SHA256SUMS`, vincolata al publisher `8bff54a5` e al workflow originale.

L'agente ha scaricato l'artifact di evidenza `13099216732`, verificato SHA/312.517
byte, tutti i sette membri del payload firmato e **198 blob Git con i rispettivi
mode**, confrontati con l'albero GitHub del commit esatto, ottenuto separatamente.
Ha confrontato certificato, workflow/ref/issuer/source e riverificato la firma
ECDSA del payload. La catena Sigstore e la trasparenza sono verificate nel job
Cosign nominato; non sono dichiarate riverificate localmente.

L'intero ZIP di evidenza è ora conservato nel repository. Il
[riconciliatore offline](../../scripts/reconcile-m2-retained-origin-evidence-20261101.py)
produce il [profilo corrente](../../releases/m2-retained-runtime-origin-reconciliation-20261101.json)
senza importare/eseguire il contenuto del profilo precedente. Mantiene distinte
ricevuta operatore, identità config/envelope, sorgenti, publisher e ammissione.
Le mappe congelate da235/19/17/21/23sorgenti sono immutate.

[Readback indipendente](../../evidence/m2-retained-semantic-provenance-readback-20261101.json).
La prima qualifica del riconciliatore, source `aae34e77`, run `41349863951`,
job `124977507535`, passa sei test senza failure/error/skip; log finale letto.
La qualifica finale source `ec4e118b`, run `41350639594`, job `124979828237`,
passa **otto test**, zero failure/error/skip; log finale letto. I due test aggiunti
conservano il diniego della scansione e proteggono path/hash del report. Tutti i
19 file pubblicati confrontati con i Git blob locali, zero differenze.
[Registro finale](../../evidence/m2-runtime-provenance-reconciliation-qualified-20261101.json).

## Scansione dell'immagine realmente conservata

Run `41349863937`, job `124977507436`, source `aae34e77`: scanner Trivy0.70.0
completato sullo stesso archivio originale, senza build/import. Il report
image-bound copre tutte le severità e gli unfixed: **3 HIGH,56 MEDIUM,38 LOW**,
nessun CRITICAL/UNKNOWN riportato. Il gate HIGH/CRITICAL/UNKNOWN esistente ha
correttamente fatto fallire il job. Questo è un diniego di sicurezza reale,
non un problema da eliminare allentando il controllo.

| Pacchetto | Rilievo HIGH | Versione conservata | Correzione indicata dal report |
|---|---|---|---|
| curl | CVE-2026-92392 | 8.18.0-1ubuntu2.7 | 8.18.0-1ubuntu2.8 |
| libcurl4t64 | CVE-2026-92392 | 8.18.0-1ubuntu2.7 | 8.18.0-1ubuntu2.8 |
| libbrotli1 | CVE-2026-111497 | 1.2.0-3build1 | 1.2.0-3ubuntu0.1 |

Il [readback](../../evidence/m2-retained-semantic-scan-readback-20261101.json)
conserva hash ZIP/report, dati image-bound e rilievi; il report integrale compresso
è nel repo. Il riconciliatore ne controlla hash/config/conteggi e impedisce che
HELD diventi PASS. Il candidato sostitutivo `c2dae77b`, config `a6f00cda`/nativo
`d06aeb52`, resta separato e non selezionato; le sue qualifiche precedenti non
sanano l'immagine installata né costituiscono una nuova selezione o installazione.

## Residuo effettivo

| Elemento | Stato verificato | Passaggio necessario |
|---|---|---|
| Semantic conservato | Sorgenti/config/envelope e publisher originale collegati; scansione attuale HELD | Usare la sostituzione qualificata solo nella coorte/review governata; nuova ammissione corrente prima degli effetti |
| Gateway-owner | Config `f983b5a8`, nativo `979de5eb`, sorgente dichiarato `81fdf7a5`; artifact originale contiene solo JUnit | Cercare la prova eseguibile originale; in sua assenza, un eventuale nuovo pacchetto va dichiarato candidato distinto, con impatto sulla coorte. Mai ricostruire e dichiarare uguaglianza |
| MinIO | Config `69b2ec20`, manifesto selezionato `a1a8bd4a`; lookup esatto non riuscito | Conservare il gap publisher/origine e verificare gli input originali disponibili; niente tag o mirror sostitutivo implicito |
| Altra coorte | Quattro core, due repliche READ e quattro riferimenti vendor già qualificati, ora collegati alla ricevuta | Completa membership/publisher/scan e custodia privata restano gate distinti; il numero11 non significa11publisher autenticati |

Il [readback MinIO](../../evidence/m2-retained-minio-selected-descriptor-readback-20261101.json)
registra anche una verifica HTTP pubblica distinta: challenge401, token anonimo
del registry ottenuto, GET root/manifesto esatti ancora401. Nessun token è
conservato o esposto, nessuna credenziale utente è usata. Il job CI precedente
SUCCESS significava soltanto risultato diagnostico conservato, non origine
provata. Nessuna ripetizione automatica o fallback.

Il profilo pubblico è preparazione di evidence, non un input già autenticato dal
controller privato congelato. Restano: integrazione delle nuove origini nella
coorte completa, membership e custodia effettive, policy/owner/bearer correnti,
proposal Gateway, pacchetto esecutivo e review concreti, HUMAN e autorità dual-role.
La chat/plugin non dispone di shell root o degli archivi privati del VPS. Prima
di richiedere un'altra azione operatore si deve qualificare una consegna concreta
che copra il residuo necessario, senza accumulare microdiagnostiche.

## Continuità di prodotto

Riletti mini-PET M2, roadmap, audit e handoff compatibilità Teatri. Riferimenti
normativi pertinenti: Matrix1.7§§1/4, Blueprint0.3§§4/7/9, Semantic1.3§160.14.
Sono sezioni consultate, non una nuova accettazione integrale dei sette PET.

Teatri/M1 resta tecnico8/8,funzionale6/6,26join/13identità/20proprietà/8Cinema.
Stessa Farmacie61righe/10OPEN/ministerialeSTRING: nessun upload/profiling o nuova
acquisizione. M2/G5/G6/G7,61esiti UDP,ripetibilità/fault e due client reali restano
OPEN. Dopo il ciclo file: grafo/search, poi verticali/API con scheduler/delta.
Nessun nuovo grant/reset/authority, deploy, merge o release acceptance.
