# M2 — contratti installati, firme e handoff operativo

31 ottobre 2026, Europe/Rome. Continuazione su PR54; PR50 conserva il raccordo
del progetto. M1/Teatri resta acquisito (8/8 tecnico, 6/6 funzionale). M2/G5–G7,
24 AT, 8 UX, 8 criteri di stabilità e due client restano aperti.

Farmacie conserva lo stesso asset/job/profilo SUCCEEDED: 61 righe, 10 colonne,
codice ministeriale STRING e i 10 campi OPEN già confermati. Non ripetere
upload, profiling o acquisizioni Teatri/Farmacie. Il caricamento termina in UDP
con gli esiti di tutte le righe; le capability di ricerca sugli oggetti caricati
sono un passaggio successivo, come richiesto dall'owner.

## Risultati nuovi e verificabili

| Intervento | Sorgente | Evidenza e limite |
| --- | --- | --- |
| Contratto reale del certificato publisher | `54aece8a1955fd5015621f8556d643ba15dd9a54` | CI [41235043033](https://github.com/GioNob/ouf-deploy/actions/runs/41235043033), job124636905839: 3 test crittografici reali PASS, log finale letto. Verifica offline in namespace senza rete, con `gh`2.97.0 fissato per checksum, bundle e trust root espliciti. Pacchetto/bundle alterati e repository ID errato respinti. Il test riguarda un artefatto CI, non l'ammissione dei pacchetti VPS. |
| Lettura di READY12 con handoff corrente | `57b0dc8355a2bda49bcbbc87e73871c07c8cd126` | CI [41235431451](https://github.com/GioNob/ouf-deploy/actions/runs/41235431451): 98 test di protocollo/13 suite + DB2/TLS7/IAM2 =109/16 suite, quattro log finali letti, zero errori/failure/skip/ResourceWarning. Anche push41235426258 PASS; letto il protocollo98. |
| Client e server installati uniti tramite TCP | `d50bb7f069b2e729a81b029b39ece84cc9564270` | Push [41235673020](https://github.com/GioNob/ouf-deploy/actions/runs/41235673020)/job124638824285 e PR [41235678562](https://github.com/GioNob/ouf-deploy/actions/runs/41235678562)/job124638839814: 3 casi PASS per evento, zero errori/failure/skip, entrambi i log finali letti. Client Ingestion non modificato, server Onboarding reale, catena Spring Security/bridge/policy/audit e PostgreSQL reali. Solo il decoder crittografico JWT è una fixture. Non prova APISIX, IAM reale o VPS. |
| GET IAM senza rinnovo implicito | `916da45af3df78080de1bc12592fd3e62b7d8e6e` | CI [41236491041](https://github.com/GioNob/ouf-deploy/actions/runs/41236491041):105 protocollo/14 suite + DB2/TLS7/IAM4 =118/17 suite, quattro log finali letti, zero errori/failure/skip/ResourceWarning. Native IAM push41236486162/job124641243906:4 PASS, letto anche quel log finale. Nuovo profilo input v2 e trasporto namespace di sola lettura. |
| Nuova review parent con tutti gli input correnti | `eb0eea3d313e169dd610670a3578f357501b6d24`, fix CI `4861d85d007faccc0129b26742770c738fe4f09e` | PR [41238086572](https://github.com/GioNob/ouf-deploy/actions/runs/41238086572)/job124645988302 e push [41238083267](https://github.com/GioNob/ouf-deploy/actions/runs/41238083267)/job124645978368:36 PASS per evento (pubblicazione8, parent12, nuova review16), zero errori/failure/skip/ResourceWarning, entrambi i log finali letti e artefatti pubblicati. Compilatore isolato235 sorgenti; tutte le136 associazioni congelate conservate. Non autentica input o autorità target. |
| Handoff durante VERIFY_APPLICATION | `ad924d830c12aaa9b4c00bd679c15e85ce09b8f6` | CI [41238636808](https://github.com/GioNob/ouf-deploy/actions/runs/41238636808):111 protocollo/15 suite + DB2/TLS7/IAM4 =124/18 suite, quattro log finali letti. Sei nuovi casi: materiale/firme/lock reali, generazioni e lease native simulate. Nessun rientro paused/initial provider, signing, start o prova readiness implicita. |
| Fence corrente dei producer e tre predecessori ritirati | `09666364dc016a9ed1ce93fe829cf486d421bba8` | CI [41239011363](https://github.com/GioNob/ouf-deploy/actions/runs/41239011363):116 protocollo/16 suite + DB2/fence Docker2/TLS7/IAM4 =131/20 suite, quattro log finali letti, zero failure/error/skip/ResourceWarning. Cinque nuovi casi di protocollo e due Docker29.8.1 reali: generazioni ferme osservate; restart+stop negato senza riparazione. Authority/altre lineage restano simulate nella fixture Docker. |
| Provenienza del compilatore esportato | `60711ad94ea785e99169a486ef18c491d1436b43` | PR [41239432016](https://github.com/GioNob/ouf-deploy/actions/runs/41239432016)/job124650015051 e push [41239426222](https://github.com/GioNob/ouf-deploy/actions/runs/41239426222)/job124649997503:39 PASS ciascuno (8+12+16+3 crittografici), zero failure/error/skip/ResourceWarning. Entrambi i log finali letti; compilatore, bundle e trust root esplicito pubblicati. Byte reali del compilatore235 sorgenti attestati/verificati offline, con repo/owner/workflow/source/signer esatti. Non è ammissione target o firma runtime. |

La verifica Onboarding/Ingestion già presente in `291f34f1` è stata recuperata,
non riscritta: CI41231189545/job124625573989 prova36 test client/consumer più10
SDK; job124625574150 prova25 Java owner,10 SDK e14 Discovery. I log finali sono
stati letti. La nuova prova TCP colma il precedente limite del client contro
un server HTTP simulato; non sostituisce le ammissioni del deployment.

## Correzioni causali

Il publisher respingeva anche un certificato valido dopo il successo della
crittografia. Il parser assumeva `subjectAlternativeName` come oggetto
`{type,value}`. Il binario fissato `gh`2.97.0 usa sigstore-go1.2.2, dove
`certificate.Summary` espone una stringa. Il controllo ora confronta l'esatta
stringa SAN e conserva issuer, repository/owner ID, source ref/commit,
signer commit, hosted runner, timestamp e digest del subject. Non normalizza
forme diverse. Il fallimento precedente41231189160 è conservato.

Fonti primarie consultate: [go.mod di gh2.97.0](https://github.com/cli/cli/blob/v2.97.0/go.mod),
[Summary di sigstore-go1.2.2](https://github.com/sigstore/sigstore-go/blob/v1.2.2/pkg/fulcio/certificate/summarize.go)
e [contratto CLI](https://cli.github.com/manual/gh_attestation_verify).

`DiscoverySelectedRuntime.observe_held()` è una lettura sotto l'invocation fence
esistente della transizione. Usa il vero adapter di readiness del Registry e
`CurrentOperationalWorker`, verifica le immagini senza importarle e conserva
la storia READY12. Non chiama il provider barrier iniziale, il Registry pausato,
start/signing, Gateway/MCP apply, pubblicazione o producer release. Il test
integrato conserva firme/materiali/journal e due lock reali dopo la scadenza
della finestra iniziale; Registry e selezione immagini restano foglie simulate
in quella prova. Il risultato dichiara `fullCohortProven=false`.

## IAM: lettura esplicita, nessun login o refresh

Il precedente `kcadm get` non garantiva assenza di effetti autenticativi:
[AuthUtil di Keycloak26.7.4](https://github.com/keycloak/keycloak/blob/26.7.4/integration/client-cli/admin-cli/src/main/java/org/keycloak/client/cli/util/AuthUtil.java)
rinnova il token quando restano meno di cinque secondi, anche per un GET.
Il nuovo reader non invoca kcadm. Legge solo il file di sessione privato
esplicitamente recensito, tramite il proc-root del processo Keycloak fissato,
senza seguire symlink nei percorsi interni. Verifica byte/metadata/generazione,
seleziona in memoria il solo bearer corrente e usa un figlio Python fissato
per un GET nel namespace corretto. Token su stdin, niente token in argv/env,
niente refresh token o client secret nel protocollo figlio, niente redirect,
POST, endpoint OAuth, fallback o riparazione della cache.

`ouf.discovery-current-iam-workload-inputs.v2` aggiunge `readOnlyAdmin`:
programma Python, riferimento esatto al file di sessione nel container, server
di sessione, realm amministrativo e porta loopback approvati. Il nuovo input
hash deve appartenere alla nuova review parent; v1 non viene promossa a v2
implicitamente. La configurazione del workload e il suo esempio di token
restano evidenze di configurazione, non un bearer workload emesso/verificato.

Il test reale usa lo stesso digest Keycloak26.7.4 già catturato per il target.
Verifica il segreto montato contro l'owner, respinge un segreto cambiato,
una sessione scaduta prima di HTTP e un bearer invalido senza refresh/cache
repair. Login/import realm esistono soltanto nella preparazione della fixture.
Le sette prove proc/FD non possono eseguire qui: il sandbox non espone
`/proc/<pid>/stat`. La qualifica hosted le ha eseguite tutte, senza skip, nel
job124641258797. Non sono stati indeboliti i guard per il sandbox. Gli otto
casi di protocollo IAM passano anche localmente dopo la modifica.

## Continuazione richiesta

I nuovi predicati `VerifyingOperationalWorker` e `CurrentProducerFence` sono
qualificati separatamente dal compilatore235 sorgenti, il cui contenuto resta
invariato. Il primo opera soltanto ai quattro punti in-flight espliciti della
verifica applicativa dopo l'unpause; il secondo legge due volte, tramite il
vero ProducerAdapter, lo stesso inventario di quiescenza, confronta l'evidenza
durabile e impone che Registry/MCP/Gateway precedenti restino ritirati.
L'inventario completo di tutti i possibili writer DB non è dimostrato qui.
Nessuno dei due predicati è ancora una composizione completa del controller.

Il workflow parent ora attesta gli esatti byte del compilatore ed esegue i tre
casi crittografici in un namespace senza rete e senza credenziali GitHub:
artefatto/bundle alterati e repository ID errato respinti. La fixture richiede
il percorso workflow esplicito; anche il publisher originario passa3 casi
in CI41239431999/job124650014570, log finale letto. Gli artefatti nuovi includono
bundle e trust root da recensire esplicitamente; non concedono fiducia automatica.
ZIP push/artifact13055694875 hash
`03077f58020736902dfc20e8c0e5549f120446a4a50006ad109030875f559e81`;
ZIP PR/artifact13055789782 hash
`58e73e0ca3a2b3c2f51fae8c24b46da95d20019c53a08f9282ceb84b51f55574`.

`current_review.py` e il compilatore separato `current_review_capsule.py`
completano l'assemblatura dichiarativa dei sei componenti parent con tutti e
cinque gli input correnti: database, provenienza, TLS, IAM v2, retirement/backup.
Verificano generazioni, profilo, truststore, client Engine, issuer/realm/scopi/
audience, predecessori MCP/Gateway e intento backup del child firmato. Nessuna
sostituzione di hash preesistenti. Cambia solo il componente coorte: il child e
gli altri cinque componenti rimangono identici; serve una nuova decisione HUMAN
e nuove firme parent sull'esatta nuova review.

Il compilatore esportato ha solo `prepare`/`inspect`, richiede isolamento
`-I -B -S`, input/hash e directory privata espliciti; crea una sola volta,
preserva output parziali e non ripara né ripete. Receipt solo con hash e limiti.
La prima CI41237953849 aveva36 test PASS ma upload negato per proprietà root
del file0600. Il fix cambia il proprietario del solo artefatto pubblico CI al
runner; non modifica la custodia degli input privati. La CI successiva prova
anche l'upload. ZIP push/artifact13055982968 hash
`e9508042669fb4d50f0b5058dbbf7f299079fd74f5b0b06c225e33f2a070a4a1`;
ZIP PR/artifact13055623370 hash
`242bf84521726378fb80f6c14c0f227a2d509a30cbca87a89c741e711c716d9c`.
Sono artefatti CI distinti, non un pacchetto di esecuzione target approvato.

Completare il checkpoint/controller nativo sigillato con i reader correnti,
inclusi coorte, custody/provenance e appartenenza degli artefatti, backup e fence,
TLS/IAM e reale ammissione del workload. Comporre il nuovo pacchetto di esecuzione
e l'esatta review privata parent/child/provider/gate/worker/publication. Il nuovo
profilo IAM v2 richiede i suoi riferimenti privati espliciti. La sola lettura
READY12 non è un checkpoint completo di pubblicazione né un comando di installazione.

Non è pronto un nuovo comando target. Restano da provare installazione composta,
discovery OntoPiA governata dopo ricerca locale, rotazione/boot/recovery nel
perimetro richiesto, Farmacie→UDP con tutti gli esiti e due client reali.
Nessun nuovo upload/profile/acquisizione, target apply, grant, login, reset,
replay, merge o accettazione è stato eseguito da questo incremento.

Baseline consultata: Blueprint0.3 §§3–4/9–10, Matrix1.7 §7, Registry1.3 §159.2,
Mini-PET M2v1.3 e policy di resilienza v3. Gli originali del pacchetto1.7 sono
conservati con i checksum nel dossier strutturato; le copie testuali sono ausili
di lettura, non una nuova autorità normativa.
