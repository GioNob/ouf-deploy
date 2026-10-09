# Continuazione Semantic/MCP dopo R8 — 9 ottobre 2026

Stato: provider avviato, lease attivata e rinnovata secondo la ricevuta operatore; applicazioni discovery non ancora aggiornate. Questa continuazione riprende il lavoro già autorizzato e non apre un nuovo sprint né modifica la baseline normativa.

## Evidenze e contesto ricostruito

La [ricevuta R8](../evidence/provider-r8-active-renewed-lease-target-20261009.json) coincide esattamente con l'ultimo output fornito in questa conversazione. L'autorizzazione è consumata: nessun replay di apply, avvio, cleanup o recovery, nessun reset delle claim. applicationHealthProven=false e notReleaseAcceptance=true restano espliciti.

La lettura indipendente del runner VPS, [run37995216597/job114039400538](https://github.com/GioNob/ouf-deploy/actions/runs/37995216597), alle23:44:17 Europe/Rome, conferma i due CID/PID R8 immutati e zero riavvii. [Proiezione conservata](../evidence/discovery-rollout-topology-after-r8-20261009.json). Nessuna chiave, env, log applicativo, exec, chiamata provider o azione lifecycle. Questa lettura verifica Docker/sysfs; non verifica la membership della lease root-private o la salute applicativa.

Semantic corrente conserva CID7ae83be8c1fe9fe25774b7d748e35153652b29b2501886f89daeabb83bd1a147, immaginef6525f2512c72a600ebcbc7060d55355d86e0627487b655e7c5c6288a0be7fc6, host vethca2111d/ifindex1377, bridgebr-113b5f0a3c53, IP172.18.0.6 e MACb2:96:a1:e2:c1:8d. I due mount privati esistenti sono read-only. MCP conserva la precedente immagine99a158f780243b3fa05199bed9db01197be8ae60ae1e75ad5432964509422872 e i due mount read-only. Sono metadati osservati, non applicazioni già aggiornate.

Sono stati esaminati gli alberi correnti dei sette repository OUF e i documenti/codice pertinenti al passaggio corrente. Snapshot main: Onboarding21de5f21e903e6e99f4ef4d6617a446d60a54792; Ingestiona8ba969a5a0e20e9c53977d2875094ce82802f9d; UDP6285b733c49b89cb6d3382abe8dc469f8a0e8b1b; Gatewaydbdc24b5481dc9473b21b360ab1142c9aef0194b; MCP5615fdcad8cbcad9ff41ec3d0ad2ccbf9423c042; Semanticd188e5e727eca7a22f414f43f164f85c31411bcf; Deployeb7f9234b45287a50da3888b26ee5bf06707686a prima della nuova lettura.

L'allegato corrente è la roadmap del16 settembre, non il pacchetto integrale dei sette PET. Letti la roadmap allegata, gli aggiornamenti nei repository, le regole operative OUF, il piano nazionale e i manifest/riferimenti normativi esistenti. Non viene dichiarata una nuova lettura integrale dei PET assenti né una verifica riga per riga. L0/Matrixv1.7 e le versioni PET restano quelle della roadmap.

## Scansione degli stessi artefatti

La PRdraft [Semantic33](https://github.com/GioNob/ouf-semantic-registry/pull/33) aggiunge un produttore di evidenze, senza build/import o operazioni VPS. Parte dalle immagini già firmate: Semantice9730d879f171530d56843670d7d5139dd7ef2f4ee59c812a1361224392a73b3, MCPa0bfc5a3c4eb8710d64b7621224a373d3cfe6db03bc79fc6adbf071c3a220e47; archivi già conservati in /home/oufadmin/ouf-discovery-signed-stage-pn8_x4vj.

Il codice verifica ZIP, hash dell'archivio conservato, quattro soggetti firmati per ruolo, workflow/commit/ref del produttore e binding SBOM/config/source. Conserva gli SBOM byte-identici, congela un solo nuovo DBv6/checksum, verifica il binario Grype0.120.0 e scansiona senza rete. Firma e verifica le nuove evidenze nel repository pubblico del produttore. Anche esiti sfavorevoli rimangono firmati e conservati; Critical/High/Unknown o package alerts bloccano il gate successivo.

Run [37995215112](https://github.com/GioNob/ouf-semantic-registry/actions/runs/37995215112) sul commit38d19c527fbec82849d6a3cf2628173411f5e2d8: scansione e attestazione completate, job finale FAILURE per copia del bundle in directory root-owned non scrivibile dal runner. Le sei firme reali sono poi recuperate e verificate nel [readback37995713266](https://github.com/GioNob/ouf-deploy/actions/runs/37995713266), senza ripetere scansioni. La futura consegna cambia ownership soltanto degli output pubblici dopo la scansione; le modifiche di consegna non attivano automaticamente una nuova scansione. Tre test locali sull'artefatto MCP reale e sui confini di hash/percorso/duplicati/source, DB/ignored matches/severity sono PASS. Nessuna nuova firma operatore o accettazione è implicata.

## Passaggio applicativo da completare

1. Acquisire l'esito reale e le firme della nuova scansione. Se la soglia fallisce, correggere le dipendenze coinvolte con un nuovo candidato nominato; mantenere le immagini correnti e tutta l'evidenza storica.
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

[Semantic34](https://github.com/GioNob/ouf-semantic-registry/pull/34) elimina il solo service manager ereditato dal filesystem finale Java; Java21, JAR e migrazioni restano nella stessa linea di sorgenti. La CI verifica assenza di Pebble ed esecuzione Java reale. [MCP50](https://github.com/GioNob/ouf-mcp-server/pull/50) pinnaGo1.26.9 per build/modulo/verify/CI, mantenendo versioni delle dipendenze e comportamento dei tool. Nessun cambiamento al VPS. Le nuove build firmate sono37995955667(Semantic) e37995954188(MCP), ancora in verifica al presente checkpoint.

La scansione modifica il prossimo passo: gli archivi precedenti restano conservati ma non sono oggi applicabili alla release sotto la soglia corrente. Se le nuove build passano, conservare/verificare i nuovi archivi firmati in una nuova directory e aggiornare i soli binding del candidato; non sostituire silenziosamente vecchi digest/source pin. Il cutover/peer binding/migrazione/grant e il risultato Teatri rimangono da completare.
