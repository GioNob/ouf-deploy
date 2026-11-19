# OUF — Onboarding V38 installato; prossimo passo THS dello stesso job

28 ottobre 2026, Europe/Rome. **MANAGED_FILE_OWNER_V38_INSTALLED_E2E_NOT_ACCEPTED**, complete/readiness=true, **Exit=0/DeliveryExit=0**. [Ricevuta completa](../../evidence/managed-file-owner-v38-update-target-20261028.json), [JSON finale e footer riportati](../../evidence/managed-file-owner-v38-update-target-20261028.log). Fonte: output finale incollato dall'utente, letto integralmente; nessuna lettura indipendente del log VPS o verifica crittografica indipendente della sua attestazione in questa sessione. I timestamp nanosecondo sono conservati come interi esatti.

## Esecuzione acquisita e consumata

Scope `/etc/ouf/deploy-snapshots/managed-file-owner-v38-update-b03d681a-20261028-v1`, comando, review e authority sono **CONSUMATI**. NON riconsegnare/rilanciare il controller, la preparazione o i reader; non riapprovare vecchie review. Tutti i predecessori restano consumati. Nessun rollback o restore eseguito.

- Review: `3eb5712707a63aef0cf0c09d2ad71c84575671c96d9d4fa1cba42598f8ac8f83`.
- Authority: `8f8d2c438e4200e2dfc1cdd33018ac173dc87a34b33486d3b7caffcd943e1d5e`.
- Frozen plan: `6d256f8874e721bcd2d349e7efdd0ee2d881cd0cd4edca14ffc5b4ec330139ee`.
- Execution inputs: `b03d681a8070b31ab29ab9515846421e98ff55a197e963f447d645b1c824a120`.
- Conditional native plan: `05e1398deae80106cbd9be45c04f9d9ffbe94303af882f06accb1f6d1a75b191`.
- Risultato canonico SHA256: `0601fdfadd157eedbdd35144e7913e152d3d1f1a67e4927317e2de6a566a61ca`.
- Native binding: `c6f72349b8b3a9f7d11f7b9c63fe0f67a159e3be3ea56f9b2a349a9e8f48a2d7`.
- Runtime binding: `05f8dab7097dd4a42d010b609d88b9be634d26b302222c67169a68377dd853d1`.

Installato SOLO Onboarding source `9d19fad3dd750dd5b9e77253d3e7e82029c1aca7`, immagine `sha256:7b9d3e918beea500929cb9e3e88165b6c574cedac6067e56206fb2ffa1d65b51`, schema **38**. Generazione PID3556687/startTicks91092970, mnt[4,4026532358], net[4,4026532422]. Un vecchio owner trattenuto fermo; **12 peer invariati**, MCP invariato, Registry worker intatto. PR53 non è stata unita da questa registrazione.

## Backup, conservazione ed effetti riportati

Backup quiescente di **735424 byte**, parsing del payload riuscito, nessun restore. Percorso `/etc/ouf/deploy-snapshots/managed-file-owner-v38-update-b03d681a-20261028-v1/onboarding.dump`; SHA256 `fcc9bff58d3e13e6b763913b15cdf2ec67dec97368949409a8787b61ec29feff`.

**Due migrazioni37/38 applicate dal normale startup dell'owner**, zero SQLwrite del controller. Storia migrazioni esatta, tutti i12fingerprint operativi invariati, tenant legacy non backfillato, nuovi guard abilitati e tabella ownership receipt vuota. Stesso Farmacie asset/job, FAILED/tentativi5/version0/generation0 conservato; nessun lavoro profile/readiness pendente e zero budget/eventi. operationalStateHash `742ea4f30b2dae85fd06dcbad9bc3c6ad427938615371a5631b94a88f7e94f6a`. Questa prova è limitata alle12tabelle qualificate, non all'intero database o a tutti i contenuti mount.

Contatori:300EngineGET/8Enginewrite/1imageLoad/3readinessGET/7metadata owner/1contenuto overlay/7SQL READ ONLY/2processi backup; zero adminGET/PUT,quarantine stop,letture file credenziali SERVICE. Tre firme installazione con lettura delle chiavi secondo review. Controller OAuth/IAM/Gateway0; bootstrap OAuth normale dell'owner possibile, conteggio non osservato.

Zero ownership receipt, grant, budget, resume, nuovi job/upload, acquisizioni o attivazioni. mountSourceContentIdentityProven=false, effectiveBrowserTokenScopesProven=false, applicationE2EProven=false, releaseAcceptance=false.

Directory `/home/oufadmin/ouf-managed-file-owner-v38-update-delivery.PoZBFYQo`; Log/DeliveryLog `bootstrap.log` nella stessa directory. RuntimeLog `/usr/local/lib/ouf-managed-file-owner-v38-update-f00094e876add2eb/operator.log`. Non richiedere nuovamente questi log; non pubblicare dump, metadata, review privata, Env, token o chiavi.

## Prossimo passo: scheda THS SOLO UTENTE

Inviare questo link all'utente; **NON aprirlo come agente**:

https://api.ouf-lab.it/trusted-human/managed-files/recovery/?asset=9c502da5-b5d8-405e-b3f5-60eb31ecb513&job=677480c8-3d10-44fd-9dad-f72ddeed20a4

Aprire il collegamento completo con l'account OUF **ouf-admin**. Usare inizialmente soltanto **Aggiorna stato**. Verificare l'identità/tenant effettivi mostrati e riportare stato, tentativi cumulativi, ultimo blocco, eventuale sessione e richiesta di riconciliazione ownership. Principal atteso `b93d8cf6-cd14-4ee6-91d7-84cd76c4f500`, tenant atteso `ouf-lab`; sono riferimenti attesi, non una prova della sessione browser. SSH e connettore non provano la sessione THS.

V38 offre la riconciliazione HUMAN della sola prova tenant legacy mancante. La scheda deve mostrare original uploader, contesto sessione, hash/dimensione, review/versione/generazione freschi. La decisione richiede conferma esplicita e motivo e crea soltanto una ricevuta append-only. Nessuna ownership è stata concessa dall'installazione.

Tre decisioni HUMAN distinte, con stato e ricevute freschi:
1. Riconciliazione **ownership legacy** dello stesso asset/job, soltanto dopo verifica del contesto mostrato.
2. Nuovo budget **3tentativi/900s** sullo stesso job; cumulativi6–8, mai reset.
3. **Resume** dello stesso job e della stessa sessione, separato dal budget.

Non anticipare budget/resume prima della ricevuta ownership e dello stato corrente. Risposta ambigua: riconciliare lo stesso comando/sessione; nessun secondo budget o nuovo commandKey. Un401/403 richiede solo messaggio visibile/codice/correlationId, senza login ripetuti alla cieca o nuovi grant.

## Lavoro applicativo ancora aperto

Farmacie asset `9c502da5-b5d8-405e-b3f5-60eb31ecb513`, job `677480c8-3d10-44fd-9dad-f72ddeed20a4`. Originale13903byte, SHA256 `f670059bb524832aa9cd78fbe5e907be053244248ff1ef4d7962b14fcd72c311`, UTF8BOM/semicolon,61righe/10colonne: originale/hash/parser/preview e61righe→UDP/provenance ancora da provare, poi D5–D7/dueclient reali/E2E. Riutilizzare Teatri/M1/typed/ASSETS/LATEST; M1/G4 acquisiti, M2/G5/G6/G7/E2E aperti, Supervisor dopo E2E completo.

Policy56 SERVICE e Policy58 exact-job acquisite; nessun nuovo ruolo, descriptor, IAM o grant. Prima di future capabilities governate verificare l'account effettivo ouf-admin; nessuna scrittura di recupero via agente. No reset/replay/nuovo job/upload/terza acquisizione/attivazione implicita/Registry restart o reinstall/merge/release acceptance/subagenti/automazioni.

[Qualifica storica del controller](../../evidence/managed-file-owner-v38-update-qualified-20261028.json), [handoff di consegna consumato](OUF_MANAGED_FILE_OWNER_V38_NATIVE_UPDATE_20261028.md), [pianoM2](../../releases/csv-m2-plan-20261026.json), [roadmap](../OUF_M2_ROADMAP_20261026.md).
