# Continuazione Semantic/MCP dopo R8 — 9 ottobre 2026

Stato aggiornato10 ottobre: lettura privata riuscita; lease QUIESCED, autorizzazione revocata e set vuoti. L'attivazione/rinnovo del9 ottobre resta evidenza storica. Causa dell'arresto non ancora provata; applicazioni discovery non aggiornate. Questa continuazione riprende il lavoro già autorizzato e non apre un nuovo sprint né modifica la baseline normativa.

## Evidenze e contesto ricostruito

La [ricevuta R8](../evidence/provider-r8-active-renewed-lease-target-20261009.json) coincide esattamente con l'ultimo output fornito in questa conversazione. L'autorizzazione è consumata: nessun replay di apply, avvio, cleanup o recovery, nessun reset delle claim. applicationHealthProven=false e notReleaseAcceptance=true restano espliciti.

La lettura indipendente del runner VPS, [run37995216597/job114039400538](https://github.com/GioNob/ouf-deploy/actions/runs/37995216597), alle23:44:17 Europe/Rome, conferma i due CID/PID R8 immutati e zero riavvii. [Proiezione conservata](../evidence/discovery-rollout-topology-after-r8-20261009.json). Nessuna chiave, env, log applicativo, exec, chiamata provider o azione lifecycle. Questa lettura verifica Docker/sysfs; non verifica la membership della lease root-private o la salute applicativa.

Semantic corrente conserva CID7ae83be8c1fe9fe25774b7d748e35153652b29b2501886f89daeabb83bd1a147, immaginef6525f2512c72a600ebcbc7060d55355d86e0627487b655e7c5c6288a0be7fc6, host vethca2111d/ifindex1377, bridgebr-113b5f0a3c53, IP172.18.0.6 e MACb2:96:a1:e2:c1:8d. I due mount privati esistenti sono read-only. MCP conserva la precedente immagine99a158f780243b3fa05199bed9db01197be8ae60ae1e75ad5432964509422872 e i due mount read-only. Sono metadati osservati, non applicazioni già aggiornate.

Sono stati esaminati gli alberi correnti dei sette repository OUF e i documenti/codice pertinenti al passaggio corrente. Snapshot main: Onboarding21de5f21e903e6e99f4ef4d6617a446d60a54792; Ingestiona8ba969a5a0e20e9c53977d2875094ce82802f9d; UDP6285b733c49b89cb6d3382abe8dc469f8a0e8b1b; Gatewaydbdc24b5481dc9473b21b360ab1142c9aef0194b; MCP5615fdcad8cbcad9ff41ec3d0ad2ccbf9423c042; Semanticd188e5e727eca7a22f414f43f164f85c31411bcf; Deployeb7f9234b45287a50da3888b26ee5bf06707686a prima della nuova lettura.

Il successivo allegato è il pacchetto completo OUF Reality Baseline Package v1.7, generato il16 settembre2026 e dichiarato CURRENT_NORMATIVE_BASELINE dal manifest. SHA256 dell'archivio: e63df67e8817eec38a9d4b3eb736b020f693b932f3360dc02f4555330f2201ce. Tutte le323 voci SHA256SUMS sono PASS. Questo sostituisce la precedente limitazione della conversazione alla sola roadmap.

Letti manifest/README, Matrix L0v1.7 e le prescrizioni pertinenti al passaggio; estratto il testo dei sette PET per la consultazione. Non si dichiara un collaudo completo del sistema o una verifica riga per riga di tutti i PET. Precedenza: Matrixv1.7, PET applicabile, Terminology Noticev1.1 e Blueprintv0.3 per i requisiti non superati.

| Modulo | PET corrente |
| --- | --- |
| MCP | v1.4 |
| Gateway | v1.5 |
| Ingestion | v1.3 |
| Source Onboarding | v1.6 |
| Authorization | v1.5 |
| UDP | v1.3 |
| Semantic | v1.3 |

Vincoli applicati: capability umane indipendenti dal canale e mediate dal Gateway; owner API private MCP senza ricorsione Gateway-/mcp; nessun HEALTHY ricavato da fatti parziali; proposte discovery separate da approvazione/pubblicazione umana. Semantic§§159–160 richiede migrazione/recovery compatibile e riferimenti agli snapshot pubblicati; Gateway§§T11/T33 conserva default-deny e binding upstream indipendenti. La baseline normativa non è stata modificata.

## Scansione degli stessi artefatti

La PRdraft [Semantic33](https://github.com/GioNob/ouf-semantic-registry/pull/33) aggiunge un produttore di evidenze, senza build/import o operazioni VPS. Parte dalle immagini già firmate: Semantice9730d879f171530d56843670d7d5139dd7ef2f4ee59c812a1361224392a73b3, MCPa0bfc5a3c4eb8710d64b7621224a373d3cfe6db03bc79fc6adbf071c3a220e47; archivi già conservati in /home/oufadmin/ouf-discovery-signed-stage-pn8_x4vj.

Il codice verifica ZIP, hash dell'archivio conservato, quattro soggetti firmati per ruolo, workflow/commit/ref del produttore e binding SBOM/config/source. Conserva gli SBOM byte-identici, congela un solo nuovo DBv6/checksum, verifica il binario Grype0.120.0 e scansiona senza rete. Firma e verifica le nuove evidenze nel repository pubblico del produttore. Anche esiti sfavorevoli rimangono firmati e conservati; Critical/High/Unknown o package alerts bloccano il gate successivo.

Run [37995215112](https://github.com/GioNob/ouf-semantic-registry/actions/runs/37995215112) sul commit38d19c527fbec82849d6a3cf2628173411f5e2d8: scansione e attestazione completate, job finale FAILURE per copia del bundle in directory root-owned non scrivibile dal runner. Le sei firme reali sono poi recuperate e verificate nel [readback37995713266](https://github.com/GioNob/ouf-deploy/actions/runs/37995713266), senza ripetere scansioni. La futura consegna cambia ownership soltanto degli output pubblici dopo la scansione; le modifiche di consegna non attivano automaticamente una nuova scansione. Tre test locali sull'artefatto MCP reale e sui confini di hash/percorso/duplicati/source, DB/ignored matches/severity sono PASS. Nessuna nuova firma operatore o accettazione è implicata.

## Passaggio applicativo da completare

1. COMPLETATO: nuove immagini corrette, scansioni firmate con soglia PASS e verifica di dieci soggetti sul target. Gli archivi precedenti sono conservati come evidenza storica e restano bloccati dalla scansione fresca.
2. Comporre un applicatore specifico e migration-aware. Il vecchio launcher MCP usa wget dentro l'immagine; il candidato statico non lo include. Il vecchio Semantic launcher è vincolato a migrazioni byte-identiche; qui è previsto V10 additivo. Nessuno dei due è applicabile senza correzione.
3. Risolvere concretamente il peer Semantic prima del cutover. La porta host1377 è parte del binding osservato. Una ricreazione ordinaria può cambiarla anche mantenendo IP/MAC: serve un raccordo governato alla nuova generazione e alla configurazione/source closure del guard, preservando la lease corrente e i suoi limiti. Non aggiornare soltanto un booleano né disabilitare regole.
4. Riutilizzare credenziale e trust preparati; collegare chiave discovery distinta e mount necessari. Aggiornare backup privato al cutover; conservare il container precedente e gestire esplicitamente compatibilità V10/recovery. Nessun restore automatico che cancelli scritture successive.
5. Installare le sole route discovery additive, conservando la correzione Cinemaouf-udp:8080 e tutte le route autenticate. Installare descriptor/policy/grant owner con conferma umana prevista dal prodotto; attivare descriptor MCP dopo readiness reale.
6. Provare CLASS/teatro/it,en con idempotenza, job e candidati owner reali. Nessuna pubblicazione/adozione automatica e nessun fallback locale.

## Risultato umano ancora richiesto

Il file Teatri già caricato, asset6609b245-86ed-4315-8ce0-73f2a8555bf3 e profile7984c39c-7396-4248-ab0a-f2efc390b49c, va riutilizzato. Cinema8/8 e la classehttps://api.ouf-lab.it/semantic/cinema#Cinema restano preservati. Seguono mapping dei20campi, pin semantici pubblicati, DRAFT/review/THS/compatibilità/ACTIVE, un run Ingestion e lettura UDP autorizzata via chatbot. Nessun nuovo upload/profile o job nazionale è stato eseguito in questa continuazione.

Le vecchie sezioni storiche dei piani non autorizzano replay. L'autorizzazione corrente a leggere/scrivere GioNob copre codice e documentazione; non è trattata come pubblicazione semantica, grant applicativo o firma di un nuovo mandato privilegiato. Non si richiede una conferma generica per questi lavori già autorizzati.

## Nuovo blocco osservato e correzioni in verifica

Il DBv6.1.10 costruito2026-10-09T06:32:32Z, checksum10771a4ded5ec61df357f3bdc3d92807aedf23a717bcd2395c9decfdee20524f, scade11ottobre08:32:32 Europe/Rome. La soglia fallisce per13Unknown in entrambi i ruoli. Semantic:0Critical/0High/169Medium/17Low/13Unknown; MCP:0Critical/0High/0Medium/1Low/13Unknown. Nessun ignored match/package alert. [Evidenza e diagnosi](../evidence/discovery-fresh-dependency-block-and-remediation-20261009.json).

Gli Unknown sono advisory GovulnDB della stdlib Go: Semanticgo1.26.7 nel binario ereditato /usr/bin/pebble; MCPgo1.25.13 nel binario applicativo. La fonte ufficiale [Go1.26.9](https://go.dev/doc/devel/release#go1.26.9) conferma fix di sicurezza dell'8ottobre; il report [GO-2026-6617](https://pkg.go.dev/vuln/GO-2026-6617) indica la versione corretta1.26.9. Non viene inferita la raggiungibilità di tutti i finding; la soglia non viene abbassata o reinterpretata.

[Semantic34](https://github.com/GioNob/ouf-semantic-registry/pull/34) elimina il solo service manager ereditato dal filesystem finale Java; Java21, JAR e migrazioni restano nella stessa linea di sorgenti. La CI verifica assenza di Pebble ed esecuzione Java reale. [MCP50](https://github.com/GioNob/ouf-mcp-server/pull/50) pinnaGo1.26.9 per build/modulo/verify/CI, mantenendo versioni delle dipendenze e comportamento dei tool. Nessun cambiamento al VPS. Le nuove build firmate [37995955667](https://github.com/GioNob/ouf-semantic-registry/actions/runs/37995955667) (Semantic) e [37995954188](https://github.com/GioNob/ouf-mcp-server/actions/runs/37995954188) (MCP) hanno conclusione SUCCESS. Il dettaglio finale è riportato nel checkpoint seguente.

La scansione modifica il prossimo passo: gli archivi precedenti restano conservati ma non sono oggi applicabili alla release sotto la soglia corrente. Se le nuove build passano, conservare/verificare i nuovi archivi firmati in una nuova directory e aggiornare i soli binding del candidato; non sostituire silenziosamente vecchi digest/source pin. Il cutover/peer binding/migrazione/grant e il risultato Teatri rimangono da completare.

## Checkpoint verificato: nuove immagini conservate sul target

[Evidenza finale](../evidence/discovery-remediated-application-qualification-20261009.json). Soglia invariata: zero Critical, High e Unknown, nessuna deroga. Semantic conserva 169 Medium e 17 Low; MCP conserva 1 Low. Questo PASS non significa assenza di ogni vulnerabilità.

| Ruolo | Sorgente firmato | Produttore | Immagine | Archivio SHA256 |
| --- | --- | --- | --- | --- |
| Semantic | 403531a9df1cbc877078f8126fd1fc4ff18acea9 | 47d70fac4d69f23a24c552cd5cac4ebaf797c529 | sha256:b1a7956a673f88b5ee65d174c2eda7b9e448153e101348c06fdd53c0640e700b | e1a62b7f53497ed471e6539d90ab02efbb4ee68c9f90f3904bcce42618ceaff6 |
| MCP | 3ba1d4abcf62af1572997a217a333fa8d231c29f | db45385648c7956e045d2d8f0b3f8e3f24270dac | sha256:33eb5195d926bbc15397a82ccd2b1a6c0ae0461f3ff86dd1bb7bbcc7fbc8e7c7 | be646ac6499f9cb6c781b899f6a7dbdb6057fde4b6a2b71407229a5a6e8cc853 |

La [CI Semantic 37996454179](https://github.com/GioNob/ouf-semantic-registry/actions/runs/37996454179) ha superato tutti e tre i job: Java21/PostgreSQL17, recovery e build container non-root. Il primo tentativo si era fermato sul checksum Dockerfile non aggiornato alla rimozione dichiarata di Pebble; è stato corretto il solo record Dockerfile in evidence/source-checksums.txt. Il sorgente firmato resta 403531a9; i successivi cambi sono il workflow produttore e il record checksum, senza nuovi input di produzione. Non è stata ripetuta la scansione.

La [CI MCP 37995954220](https://github.com/GioNob/ouf-mcp-server/actions/runs/37995954220) è PASS: test con race detector, pairwise, build, migrate, maintenance-worker, staticcheck e govulncheck. Il successivo ripristino del bit eseguibile di scripts/verify.sh conserva il contenuto e non modifica il binario firmato.

Il [run target 37996500108](https://github.com/GioNob/ouf-deploy/actions/runs/37996500108) ha verificato dieci firme reali, cinque per ruolo, con workflow/commit/ref esatti e byte dell'archivio/config/layer/SBOM. Nuova directory privata: /home/oufadmin/ouf-discovery-remediation-stage-6j7rh3xz. Nessuna importazione Docker, configurazione applicativa o operazione lifecycle; la vecchia directory resta conservata.

Il [piano migrazioni sul VPS 37996574805](https://github.com/GioNob/ouf-deploy/actions/runs/37996574805) confronta il JAR corrente con il nuovo sorgente esatto. V1–V9 sono identiche; unica aggiunta V10__discovery_request_idempotency.sql, SHA256 85708e1d37184177471f225806ca21c4088915f766197020f8fefe109407e911. Provider/workload-auth/gateway discovery non risultano abilitati nel Semantic corrente.

Il prossimo lavoro è l'applicatore con migrazione e recovery, coordinato al nuovo binding ingress Semantic. Occorre preservare la lease R8 finché il passaggio completo è concretamente pronto; qualunque modifica al suo profilo sealed richiede una nuova transizione con autorità distinta, senza riciclare l'approvazione consumata. L'estensore esistente è limitato ad append di un flusso in stato QUIESCED e non implementa un cambio del peer: non va riutilizzato come generico patcher. Restano da implementare e verificare raccordo del guard, credenziali/mount discovery, route additive, policy/grant/descriptor e prova owner reale.


## Checkpoint 10 ottobre Europe/Rome: peer planner verificato, lettura privata pronta

L'ingresso Semantic non è una modifica alla tabella DNS/lease ouf_sem_provider: è un predicato peer BRIDGE_PORT del profilo shared-face southbound, attualmente ifindex1377. Anche quel profilo è vincolato a driver, journal e autorità sealed. Cambiarlo senza una nuova chiusura autenticata romperebbe le verifiche di avvio; nessun hash/booleano verrà aggiornato da solo.

Il compilatore puro tools/semantic_peer_replacement/peer_rebind.py prepara soltanto una replace rule e la sua inversa, dopo verifica di struttura/footprint e due peer completi con OCI e generazione autenticate dal futuro chiamante. Non esegue né autorizza il cambio. [CI37998070148/job114049073781](https://github.com/GioNob/ouf-deploy/actions/runs/37998070148): PASS con nft e namespace Linux reali, otto prove TCP, sei casi negativi, una sola regola ingress cambiata, lease e tabella estranea invariate, recovery condizionale verificata. I CID/hash/generazioni della prova sono fixture, non attestazioni del VPS. [Evidenza](../evidence/semantic-peer-replacement-native-qualification-20261010.json).

Il lettore tools/semantic_target_review/read_cutover_inputs.py è fissato al commit 550c5e733fdafe33ac6b5f0117231d53c603b510, SHA256 b9ea8aa1a8cf31d28dfa1df0960dcf6930880d11244fe1f84e710bfe0b9ec4cf. Verifica in memoria driver, profili, journal, source closure, hash OCI completi dei due container R8 e native shared-face table pair; osserva generazione/NIC/peer reciproco del Semantic corrente e la lease. Non importa codice operativo installato, non legge ENV/chiavi, non esegue richieste DNS/provider, non modifica firewall/configurazioni o lifecycle.

Importante per questo worker specifico: il lettore non acquisisce il common lock. Il worker usa flock non bloccante e la contesa potrebbe far fallire il rinnovo. Si verificano invece riletture stabili, hash e inode; cambiamenti durante la lettura producono READ_BLOCKED. La proiezione è osservativa e non costituisce uno snapshot atomico autorizzante. Il precedente lettore post-start che trattiene il lock non è il comando proposto per questa continuazione.

[CI37998809709/job114051546329](https://github.com/GioNob/ouf-deploy/actions/runs/37998809709) PASS: quattro test di perimetro, quattro di consegna e bash -n. Download a commit esatto; hash verificato prima di sudo e nuovamente sui byte catturati in memoria prima di compile/exec Python -I -B. Alterazioni bloccate prima dell'esecuzione; exit del reader preservato attraverso tee.

[Preparazione e comando esatto](../evidence/discovery-cutover-input-read-preparation-20261010.json). La lettura è ora completata: output operatore ricevuto10 ottobre06:54:27 Europe/Rome, exit0, result.txt in /home/oufadmin/ouf-discovery-cutover-read.swMLhjl8. [Ricevuta completa](../evidence/discovery-cutover-input-target-20261010.json). Il timestamp di esecuzione non compare nell'output e non viene inventato. Il comando seguente è storico, già eseguito:

```bash
(
  set -euo pipefail
  umask 077
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  [ -x "$OUF_GH" ] || OUF_GH="$(command -v gh)"
  OUF_READ_BOOT="$(mktemp -d "$HOME/ouf-discovery-read-launch.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' \
    'repos/GioNob/ouf-deploy/contents/releases/discovery-cutover-input-read-20261010.sh?ref=6df2a6846aa96094a35b0f705e683bc9e1c9ef7b' \
    > "$OUF_READ_BOOT/run.sh"
  printf '%s  %s\n' '565251c27c28314d8bf6247921c44dec4407a91194f723b4281cc3fce534ed0e' "$OUF_READ_BOOT/run.sh" | sha256sum -c -
  bash "$OUF_READ_BOOT/run.sh"
)
```

Attesi OUF_DISCOVERY_CUTOVER_INPUT_READ e OUF_DISCOVERY_CUTOVER_READ_EXIT, con result.txt nella directory temporanea dell'utente. sudo serve a leggere i binding root-private; nessun nuovo mandato viene firmato/consumato. READ_BLOCKED non autorizza apply/recovery. Non ripetere apply/start/cleanup/lease R8. Prima di applicare restano necessari nuovo peer OCI completo e reciproco, autorità distinta/closure signed, applicatore migration-aware/readiness, route/policy/grant/descriptor e prova owner reale.


## Osservazione corrente: revoca della lease, causa da leggere

La ricevuta CUTOVER_INPUT_BINDINGS_CAPTURED conferma il Semantic corrente CID7ae83be8…/PID3789123, namespaceInode4026532695, startTicks128311383 e peer reciproco1377 su br-113b5f0a3c53, IP172.18.0.6/MACb2:96:a1:e2:c1:8d. I due driver shared-face, journal, OCI completi e source closure R8 risultano verificati. Il CID R8 adapter/southbound e le tabelle ingress sono gli stessi; questo non è un cutover o una prova di salute applicativa.

La lease attuale è QUIESCED, leaseAuthorized=false, startAuthorized=false, providerSetsEmpty=true. Tutti i conteggi approvati/inet/bridge dei due flussi sono zero. Il journal è coerente e ha hash a58f0cb6e011879fc22723356d19926adf8945c38dcdbf2d21ab3fa34dd6f7f1; struttura verificata, owner hash invariato656c23f…. Il traffico esterno dei due flussi non è ora permesso dalla lease. Il successo iniziale TWO_FLOW_LEASE_ACTIVE_AND_RENEWED non viene riscritto, ma non descrive più lo stato corrente.

Questo output non prova il motivo della revoca o lo stato attuale del servizio systemd. Il sorgente del worker verifica la finestra executionExpiresAt all'ammissione; la sua authorityLifetime è CURRENT_R8_PROCESS_GENERATIONS_UNTIL_STOP_FAILURE_OR_REBOOT. Non attribuire l'arresto alla semplice scadenza della finestra senza evidenza. Il nuovo lettore preparato tools/semantic_target_review/read_r8_worker_quiescence.py legge soltanto claim/authorization/program hashes/record diagnostici del preciso snapshot semantic-r8-lease-8wfsv1aa e proprietà delle due unit lease/Docker; nessun codice operativo installato viene importato/eseguito, nessun lock, start/stop/reset o journal generale.

La prossima lettura diagnostica serve a distinguere failure registrata, stop e stato della dipendenza Docker. Una nuova attivazione resta da comporre e autorizzare distintamente soltanto dopo causa e recovery concrete; nessuna claim viene resettata o riutilizzata. Le correzioni applicative firmate e il planner peer isolato restano validi come preparazione, non autorizzano ancora il target.


## Comando successivo: sola diagnosi del worker consumato

[Preparazione verificata](../evidence/provider-r8-worker-quiescence-read-preparation-20261010.json): lettore a13d50881e0eeab5fc66e9432b43fa4658e046b8, SHA256 b7197def3b3f3bf1d108428f61ccc5652dbb916c22f22caf8a5414e761507e3f; launcher 174c8d02c0199a5eb3e87e23ffbfe44a4a44d4c4, SHA256 40862a23cca3fb0b2da255edef464cdf8ebfe8a1272cae536677732c25cad128. [CI38026120077/job114137210582](https://github.com/GioNob/ouf-deploy/actions/runs/38026120077) PASS: quattro test di perimetro/diagnostica oscurata, quattro di consegna, bash -n. Nessuna esecuzione VPS di questo comando è ancora avvenuta.

```bash
(
  set -euo pipefail
  umask 077
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  [ -x "$OUF_GH" ] || OUF_GH="$(command -v gh)"
  OUF_WORKER_BOOT="$(mktemp -d "$HOME/ouf-r8-worker-read-launch.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' \
    'repos/GioNob/ouf-deploy/contents/releases/provider-r8-worker-read-20261010.sh?ref=174c8d02c0199a5eb3e87e23ffbfe44a4a44d4c4' \
    > "$OUF_WORKER_BOOT/run.sh"
  printf '%s  %s\n' '40862a23cca3fb0b2da255edef464cdf8ebfe8a1272cae536677732c25cad128' "$OUF_WORKER_BOOT/run.sh" | sha256sum -c -
  bash "$OUF_WORKER_BOOT/run.sh"
)
```

Incollare OUF_R8_WORKER_QUIESCENCE_READ e OUF_R8_WORKER_QUIESCENCE_READ_EXIT. Il comando legge i record conservati e i soli metadati systemd specificati; non riattiva la lease, non legge log generali/ENV/chiavi, non acquisisce il lock e non avvia/ferma/resetta alcun servizio. L'esito READ_BLOCKED resta un arresto della sola lettura, senza cleanup/apply automatico.
