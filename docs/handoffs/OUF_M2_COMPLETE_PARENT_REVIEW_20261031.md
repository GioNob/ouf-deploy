# OUF — Review parent completa nella forma, preparazione isolata qualificata

31 ottobre 2026, Europe/Rome. Sorgente `bcbc4aa86a6fc687929edac7649b9fb0af336364`, [PR54](https://github.com/GioNob/ouf-deploy/pull/54) in bozza, non unita. [Evidenza](../../evidence/m2-complete-parent-review-20261031.json).

Il compilatore precedente produceva frammenti separati. `parent_review.py` ora ricompila e collega tutte le sei sezioni esatte del contratto parent: Registry child, provider, finestra gate, worker, coorte e pubblicazione governata delle capability. Il risultato passa il parser della review completa; rimane una proposta privata non autenticata, senza firma, concessione, applicazione o accettazione del target.

`publication_primitives.py` verifica prima dell'esecuzione i sette file Gateway di `60788cf965334441be0a33c345f5c0bcd66cbdde`, i due helper Onboarding di `be388e1462778438a208c2e00e166370fee32189` e il catalogo Discovery locale. Il materializzatore originale e la factory Lua leggono una fotografia in memoria già verificata; nessuna rilettura successiva dei file sorgente può alterare il piano. Il packaging verifica i corpi senza eseguirli.

`publication_review.py` riusa i due compilatori qualificati. Produce soltanto le tre route request/status/candidates, le tre capability Discovery e uno scope OAuth condiviso `ouf.semantic.discovery`. Conserva tutte le route, assegnazioni, concessioni e associazioni OAuth estranee. Identity issuer/audience/workload, costanti del template Lua esistente, chiave Discovery del nuovo Gateway e alias Registry devono coincidere. Chiave di delega distinta, route ID e selettori senza collisioni, upstream Registry esatto, root dei journal separate. Nessuna adozione storica, estensione di scope, conferma automatica HUMAN o token nuovo.

Il child resta un contratto separato di tredici fasi, con corpo originale, hash dei byte originali, binding HUMAN dichiarato, finestra finita e sezioni Gateway/MCP esatte. Nessuna proiezione o rifirma. Il compilatore non verifica il contenuto del file HUMAN né le firme: lo fanno i verificatori nativi attuali prima degli effetti. I test dimostrano che gli effettivi verificatori Ed25519 parent/child accettano gli scope preparati e che la review non rende attuale un'autorità scaduta. Baseline, immagini, IAM e osservazioni applicative dei test rimangono fixture esplicite.

La preparazione privata root richiede input hash-bound e directory vuota 0700. Crea prima un claim esclusivo e fsynced, poi l'assembly 0600 e infine una ricevuta con soli hash e flag. `inspect` verifica i file senza riscriverli; un'esecuzione parziale non viene completata, adottata o ripetuta. Il compilatore sigillato espone esclusivamente `prepare` e `inspect`, richiede Python `-I -B -S` e non rivela percorsi/dati privati in caso d'errore. Nessuna modalità apply o firma.

## Qualifica acquisita

- Locale: 8 test pubblicazione PASS in 0.232s e 12 test parent PASS in 11.043s, zero errori/saltati. Regressione dei 15 test del compilatore infrastrutturale precedente PASS in 9.141s.
- [CI41202906043](https://github.com/GioNob/ouf-deploy/actions/runs/41202906043), job124542099651: 8 test PASS in0.612s e 12 PASS in11.669s, zero errori/saltati; log finale letto direttamente.
- Artifact13042814391 scaricato: ZIP688234byte SHA `e523964ba09276245b1c09c8ad63fc4c286d2917ab5bad1cda35592cfe179349`; esattamente due membri. Capsule2295652byte SHA `d9c5b020e041ad83de7d19a24257d2d333e08d27b89bc8b6b57ca93f9b8ac5c7`.
- Tutti i136moduli, i10file helper, baseline, loader e metadati confrontati; ricostruzione locale byte-identica. Source-map anchor `eaacfca7912e094b77f11528473bdcfe493bcf31f7eb50dee26d6d73bea7e36a`; loader `242cce9f329499d68941732dca2e08c4f4c5fc76e751b589367b4c7e360ea8bc`; payload `132444cd98b2746624399eb756a9a111c04ec671112e48b5f41e406707a9d644`.
- Claim `d7659f7046df772b6a846301dee404cef8c7155d` corrisponde al checkout merge della CI; è provenienza, non fiducia autenticata nell'editore.

Le closure precedenti da37moduli worker,108moduli del primo compilatore e128moduli infrastrutturali restano invariate. La correzione QUIESCED qualificata a35eba/77eb rimane acquisita nel suo ambito causale; non prova retroattivamente il proprietario del vecchio flock nell'incidente41f935.

## Prossimo passaggio e limiti reali

`completeParentReviewShape=true` significa che esistono tutte le sezioni compilate. `inputsAuthenticated`, `currentNativeAdmissionProven`, `publicationExecutorIntegrated`, `runtimeAuthorityIssued`, `targetApplyAuthorized`, `capabilitiesPublished`, `applicationE2EProven` e `releaseAcceptance` restano **false**. L'owner esecutivo della pubblicazione coordinata e l'ammissione corrente completa rimangono da integrare e qualificare. I requisiti di ammissione nel parent non sono ricevute native e non sbloccano il release barrier.

Per compilare la concreta review di installazione servono input privati correnti sul VPS e i binding scelti per child/HUMAN, senza riutilizzare scope consumati. La sessione attuale espone GitHub e MCP OUF; questi non consentono accesso root ai file e ai servizi dell'host. Il sistema MCP ha restituito HEALTHY/actionRequired=false, ma questo non prova la coorte M2 né la corretta installazione sul VPS. Serve un canale operatore al server per la verifica reale. Non richiedere né riportare chiavi, credenziali o token in chat. Non è ancora pronto un nuovo comando target da far eseguire.

M2/G5–G7,24AT,8UX,8stabilità, boot/rotazione e due client reali rimangono aperti. Teatri M1/G4 tecnico8/8 e funzionale6/6 acquisiti. Farmacie resta la stessa acquisizione SUCCEEDED61righe/10colonne, ministeriale STRING/tutte10aperte; nessun upload, profiling o acquisizione da ripetere. Nessuna applicazione target, grant, reset, replay, merge o accettazione del rilascio.
