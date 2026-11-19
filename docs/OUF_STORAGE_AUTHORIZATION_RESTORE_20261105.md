# Onboarding — ripristino di decisioni Authorization e autorità corrente

## Due passi completati nel codice

1. Il common-cut fisico usa ora decisioni, proiezioni e audit V40 popolati dal servizio Authorization reale, insieme al bundle e al puntatore policy.
2. Il servizio richiede un controllo corrente indipendente dal backup; il ripristino di una policy vecchia non consente preparazione, riconsegna o uso dell'autorità.

Il driver conserva due decisioni: la prima consegnata dal processo di drain, la seconda da una JVM nuova per riconciliazione e freeze. La seconda revoca definitivamente la prima; il cut contiene proiezione versione 2, una decisione DELIVERED, una REVOKED, cinque eventi di preparazione/consegna/sostituzione e quattro eventi owner. Sono incluse le valutazioni reali del registry Authorization.

Dopo il taglio il driver revoca la seconda decisione, libera la proiezione a versione 3, attiva una policy versione 2 senza grant e avanza a generazione 2/revocata l'autorità sintetica esterna. Il restore dai soli export riporta intenzionalmente policy versione 1 e decisione DELIVERED: l'autorità esterna resta alla revoca corrente. Falliscono direttamente prepare/deliver e i tentativi owner. Anche l'assenza dell'autorità esterna blocca prepare/deliver. Tabelle owner, decisioni, proiezione, policy e audit devono coincidere esattamente con il cut dopo i tentativi respinti e la verifica S3.

## Vincolo implementato

La porta `StorageRecoveryAuthorityFence` è obbligatoria; il costruttore privo di adattatore nega. Lega installazione, tenant, policy, generazione indipendente e finestra positiva al massimo di 15 minuti. La preparazione non supera quella scadenza. V41 registra la generazione nella decisione immutabile e nel fingerprint idempotente; le vecchie righe V40 ricevono zero e restano inutilizzabili. Ogni uso verifica nuovamente generazione e autorità corrente; il gate ripete il controllo dopo l'audit prima del commit.

La produzione dovrà fornire un verificatore che mantenga l'esclusione della revoca fino al commit, senza chiamate remote sotto lock. Non è installata alcuna implementazione produttiva. Le prove componentistiche usano evidenze sintetiche; la prova fisica usa un file locale limitato a 4096 byte, esterno alle directory di backup/restore, e revoca sequenziale. Non si dichiara serializzazione distribuita né protezione già qualificata contro rollback logico a postmaster invariato.

Restano i lock reali PostgreSQL, l'audit atomico owner, GET fuori transazione, budget 128 letture/24 ore, transazione 12 secondi, lock 2 secondi, statement 5 secondi. Nessuna nuova decisione rinnova il budget dell'intento o la custodia.

## Qualifica della sorgente finale

Sorgente `087fcf21e7402cd5057972093dc0565f03e35427`, [PR Onboarding 54](https://github.com/GioNob/ouf-source-onboarding/pull/54).

- [Nativi 42018524212](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42018524212), job 127215042365: **63 scenari owner + 8 API/storage PASS**, zero fallimenti/errori/skip. Sei casi aggiunti: fence mancante, revoca/assenza durante prepare/deliver, binding/finestra non validi, nuova generazione con stessa policy, revoca durante GET e controllo dopo audit.
- [Ripristino e readback 42018524202](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42018524202): producer 127215043102 e readback 127215996971 **SUCCESS**. **39 membri ZIP, 38 checksum, 272 binding sorgente, tutti i 1.695 file di backup** verificati. Quindici copie semanticamente alterate sono respinte dopo ricalcolo del manifest esterno.
- System ID `7704646733391904808`, target fisico `ouf_onboarding_upload_frozen_v39`, PostgreSQL 17.11 e medesima OCI33. Due oggetti sintetici/36 byte, sei PUT AccessDenied, dodici stop storage e due PostgreSQL puliti. Restano valide le prove WAL mancante prima di S3 e JVM mantenuta viva attraverso la distruzione/ripristino del database.
- Il secondo runner esegue readback degli archivi e delle ricevute, non un secondo restore nativo. Il pacchetto finale non è stato nuovamente scaricato localmente. Diff, sintassi Python e regressione dei placeholder WAL passano in locale; Java/PostgreSQL/S3 sono eseguiti su Linux CI.

[Ricevuta strutturata](../evidence/storage-authorization-restore-qualified-20261105.json). Custodia degli artifact fino al 3 febbraio 2027:

| Artifact | Byte | SHA256 |
| --- | ---: | --- |
| 13411121370 — onboarding-common-cut-readback-42018524202 | 7165954 | `sha256:76540f526be9712a4dbb0861008a7e3e988268a7c11aaae9067c5fd03c14cc96` |
| 13410711639 — onboarding-common-cut-42018524202 | 7173225 | `sha256:862239b9531405ea56bda7945816397b3c05ccae3495aea0aa56888ab8f2c4ea` |
| 13409979051 — onboarding-upload-native-42018524212 | 103291 | `sha256:27523c52e18361aab645e7bcd247d7c7c47fbb99f378129f167c710c5283ca54` |

Deploy antecedente `254228b5f96130cc072a80e17079a2bbd2747513`: **50/50 workflow SUCCESS**. I controlli del nuovo checkpoint documentale sono distinti dalla qualifica nativa.

- **CI sorgente 8/8 SUCCESS**, incluse PR42018532139/push42018524519, scansione immagine bloccante e avvio container. Suite generale: 428 riportati meno 63 nativi saltati = 365 eseguiti PASS; i 63 nativi sono tutti eseguiti nel job dedicato.

## Prima esecuzione e correzione del verificatore

La prima sorgente `788046bf76a2ce152b1d4880a7855327f3aff50f` ha superato 63 scenari nativi + 8 API/storage e il ripristino fisico. Il [run 42017913750](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42017913750), producer 127212985997, è riuscito; il job di readback 127213887742 è fallito su `REVOCATION_AFTER_NAMED_CUT`.

Il confronto costruiva le righe attese cambiando DELIVERED in REVOKED senza ricalcolare l'ordine. PostgreSQL ordina gli snapshot per l'intero JSON: il cambio di stato può invertire le due righe. L'originale artifact 13409298911 è stato scaricato per la diagnosi locale: 7.172.284 byte e SHA256 `8d3a95a4d071547e1afd752c4d4e4044d396ee9f0f91f89c00b594c22dd17a80`, identici ai metadata GitHub. Il confronto integrale delle righe dopo ordinamento per decision_id è riuscito; alterare la generazione resta respinto.

La correzione `087fcf21e7402cd5057972093dc0565f03e35427` cambia soltanto il readback, conserva ogni campo nel confronto e aggiunge un negativo sulla generazione alterata. Codice applicativo, SQL e driver fisico sono identici alla prima esecuzione. Nessun checksum dell'archivio originale è stato modificato; non si dichiara un readback locale completo del pacchetto. Log, archivio originale e copia del readback fallito 13410790717 sono conservati, insieme all'artifact nativo 13409733221.

## Limiti e continuazione

Autenticazione Gateway/THS, sessione fidata, registrazione approvata della capability, verificatore corrente produttivo, custodia completa dei writer, audit durevole dei dinieghi e revoca distribuita restano aperti. Sono aperti anche rollback logico, UDP/Ingestion, rollout misto, riapertura governata e RPO/RTO rappresentativi.

Prossima coppia proposta: definire il binding del verificatore indipendente agli owner piattaforma/Authorization esistenti; qualificare il rollback logico a postmaster invariato con generazioni correnti, senza installare grant target.

MinIO/source-lock e MiniPET 18,3/46 = 39,78%, 0/8 gate, 0/21 AT, 0/120 oggetti reali invariati. Nessun merge, deployment, operazione target, ammissione, reset o grant runtime. Tutte le prove precedenti sono preservate.
