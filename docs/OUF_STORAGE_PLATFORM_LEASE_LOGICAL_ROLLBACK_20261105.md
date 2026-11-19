# Onboarding — binding piattaforma e rollback logico Authorization

## Due passi

1. Implementato `PlatformStorageRecoveryAuthorityFence`: un adattatore interno che collega l'ammissione fidata del worker alla generazione corrente della piattaforma e conserva la protezione dalla revoca fino al commit.
2. Qualificato il replay logico di policy, decisioni, audit Authorization e proiezione di consegna/azioni mantenendo invariati JVM, runtime e postmaster PostgreSQL.

Sorgente `a0f6a91488f28ec5213d334764eb11c72585abb6`, [PR Onboarding54](https://github.com/GioNob/ouf-source-onboarding/pull/54). [Contratto nel codice](https://github.com/GioNob/ouf-source-onboarding/blob/a0f6a91488f28ec5213d334764eb11c72585abb6/docs/STORAGE_RECOVERY_PLATFORM_LEASE.md).

## Binding agli owner esistenti

La configurazione d'installazione continua a fornire identità, tenant e proiezioni validate; Gateway/ServletAuthorization e THS/TrustedWriteProof conservano autenticazione e comando HUMAN; il registry Authorization esistente valuta policy, capability e decisioni. L'adattatore non introduce un nuovo issuer, endpoint, bean o grant.

La revisione di configurazione può tornare a una versione precedente e le tabelle possono essere ripristinate. La generazione indipendente è quindi fornita dall'ammissione protetta della piattaforma, fuori dal set owner/Authorization ripristinato, e non viene letta dal vecchio puntatore ACTIVE. Il binding contiene installazione, tenant e generazione; il confronto con la prova corrente è obbligatorio.

La porta fidata `CurrentAuthority.tryAcquire` deve acquisire senza attesa una lease locale che impedisca revoca/cambio generazione fino al rilascio. Il provider deve effettuare verifiche remote prima dell'ammissione; una semplice cache ALLOW non soddisfa il contratto. L'adattatore richiede una transazione effettiva, riusa una lease per transazione, la mantiene durante il commit e la rilascia dopo completamento o rollback. La lease viene separata/ripristinata durante sospensione/REQUIRES_NEW. Prova non valida o acquisizione assente/contesa negano senza attesa, rinnovo o reset di budget.

La policy, la freschezza HUMAN e la scadenza restano verificate dal servizio Authorization ad ogni uso. Una generazione esterna nuova invalida il worker già ammesso, anche per nuova preparazione o riconsegna. Il processo non si riammette automaticamente.

## Rollback qualificato e limiti precisi

Le prove salvano righe realmente popolate, revocano la decisione consegnata e avanzano lo stato esterno. Il primo caso cambia policy e revoca; il secondo cambia soltanto la generazione esterna lasciando la policy consentita. Un helper privilegiato solo di test esegue TRUNCATE e reinserimento delle righe salvate: trigger di INSERT e immutabilità restano attivi, nessun percorso di restore produttivo è introdotto.

Tornano la vecchia policy e la decisione DELIVERED. Sullo stesso worker vengono respinti cinque tentativi: prepare, deliver, drain, reconcile e freeze. Postmaster e sessione non cambiano; snapshot ripristinati intatti dopo i dinieghi; budget già esaurito rimane128, zero GET e zero asset pubblicati.

Il perimetro è **Authorization e proiezione owner di consegna/azioni**, non il restore logico dell'intero database. Gli intenti di upload e i budget non vengono riavvolti dalla fixture. Non si dichiara ricostruzione dei budget o degli audit dopo rollback di tutti i dati owner. Il provider di test usa un read/write lock in memoria separata dal database: prova ciclo di vita e concorrenza locale, non persistenza o esclusione distribuita fra processi.

La piattaforma deve avanzare/fissare la generazione corrente prima del rollback governato. Un rollback non coordinato che lasci invariata anche la generazione esterna non è rilevato da questo contratto. Nuova ammissione non concede riapertura o nuovo budget.

## Qualifica

- [Nativi42020505033](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42020505033), job127221774836: **71 scenari owner + 8 test API/storage PASS**, zero failure/error/skip. Otto scenari nuovi: sei sul ciclo della lease e due sul rollback logico.
- I due riepiloghi nativi riportano postmaster/runtime invariati, cinque dinieghi ciascuno, snapshot intatti, budget128 e zero GET. Uno revoca l'autorità esterna, l'altro ne cambia soltanto la generazione.
- [Regressione fisica42020505198](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42020505198): producer127221775165/readback127222715863 SUCCESS. **39 membri/38 checksum/274 sorgenti/1695 file backup**, 15 negativi semantici; due oggetti/36byte, 6 AccessDenied, 12 stop storage+2PG puliti. SystemID7704650532553719848. Rimane la fixture fisica a file esterno sequenziale del checkpoint precedente, non una qualifica distribuita del nuovo provider.
- **CI sorgente8/8 SUCCESS**, comprese [PR42020514344](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42020514344) e [push42020505077](https://github.com/GioNob/ouf-source-onboarding/actions/runs/42020505077), scansione bloccante e boot container. Suite generale436riportati -71native saltati =365eseguiti PASS; i71nativi sono tutti eseguiti nel job dedicato.
- **Readback locale dell'artifact nativo PASS:**99file,98checksum,271blob sorgente Git; suite XML71/0errori/0failure/0skip; due ricevute logiche con sette tabelle identiche e runtime coincidente con la decisione ripristinata. Metadata digest/byte verificati prima del controllo. Nessuna riesecuzione locale Java/PG/S3; il pacchetto fisico non è stato scaricato localmente.
- Qualifica riuscita alla prima esecuzione della sorgente a0f6a914. Diff e sintassi Python verificati localmente; gli archivi e i fallimenti precedenti sono preservati.
- Deploy antecedente aa17823c: **48/50 SUCCESS, due workflow ancora in corso** al checkpoint: [Chatbot cohort42019232596](https://github.com/GioNob/ouf-deploy/actions/runs/42019232596) e [Discovery42019233075](https://github.com/GioNob/ouf-deploy/actions/runs/42019233075). Non sono dichiarati50/50PASS; controlli del nuovo checkpoint documentale separati.

[Ricevuta completa](../evidence/storage-platform-lease-logical-rollback-qualified-20261105.json), [verificatore locale riproducibile](../scripts/readback-platform-logical-native-20261105.py). Lo script si esegue dalla checkout Onboarding esatta, con l'originale artifact13410549610 in `target/platform-logical-native.zip`.

| Artifact | Byte | SHA256 |
| --- | ---: | --- |
| 13410549610 — onboarding-upload-native-42020505033 | 132306 | `sha256:420541c2374b84930507034aa05b7bcd66ae32298048a438b4ce17062c6d19ed` |
| 13412060555 — onboarding-common-cut-readback-42020505198 | 7170979 | `sha256:325989b37e594534ece2b6a01bfe2e2ed10b9d4d2f68cd7afcf36db42ffe10df` |
| 13410808964 — onboarding-common-cut-42020505198 | 7178192 | `sha256:e61695efa40a85a42d1e560b40d4f26e10367d03011bd3a46b291683fe40327d` |

Custodia Actions fino2027-02-03T11:37:45Z.

## Riferimenti verificati

- Baseline v1.7, invarianti Authorization AUTH-X01/X08/X09/X13/X15: identità fidata, enforcement owner, snapshot immutabile, fail-closed e guardie di dominio dopo ALLOW.
- Invarianti Gateway GW-X02/X14/X18: controllo backend cumulativo, propagazione identità/capability e distinzione tra configurazione Git e stato ACTIVE.
- Policy di resilienza OUF v3: autorità/generazioni fresche, nessun lock durante attese, revoca non ritentata automaticamente e budget conservato.
- Implementazioni esistenti: InstallationConfigurationService, InstallationRuntimeProjectionService, InstallationBootstrapApi, TrustedActorResolver e AuthorizationPolicyRegistry.

## Confini e prossima coppia

Provider corrente durevole e indipendente, ammissione Gateway/THS operativa, revoca fra processi, custodia completa, audit durevole dei dinieghi, rollback completo owner/budget, UDP/Ingestion, rollout misto, riapertura e RPO/RTO restano aperti.

Prossima coppia proposta: collegare una sorgente durevole di generazione/revoca esterna al set di restore, poi qualificare riavvio del provider e concorrenza fra processi. Non assegnare grant target o riusare revisioni di configurazione come generazioni di recupero.

MinIO/source-lock e MiniPET18,3/46=39,78%, 0/8gate, 0/21AT, 0/120oggetti reali invariati. Nessun merge, deploy, operazione target, admission runtime o grant. Prove precedenti preservate.
