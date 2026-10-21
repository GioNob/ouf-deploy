# Provider v2: recupero dopo R4 con revisione broker/runtime — R5

Stato: proposta concreta, non autorità; nessuna operazione R5 sul VPS. L'esecutore resta disabilitato fino a nuova accettazione esplicita, perché R4 è stato consumato e cambiano due sorgenti sigillate.

## Stato reale disponibile

Ricevute dell'operatore, non acquisizioni indipendenti: R4 ha richiesto due avvii, entrambi negati dal broker. Adapter rimane STAGED in tutti i journal; southbound è DELETING nel journal adapter e CREATED nei journal broker/deployment. Entrambi sono Docker created, Running false, PID zero, mai avviati secondo StartedAt. Nessuna firma/artifact della fase di ammissione è presente. Wrapper corrente SHA256 `2c752d0c65383d59862ef3f8a84ec94fa07ebf2d40117329b73d8338d48b4815`.

Lettura runc riportata il 9 ottobre 2026 alle 12:52:00 Europe/Rome: list exit 0, nessuno dei due CID presente nel root conservato da southbound; root SHA256 `c64c266a92b2d9ff052a8f2b817ee730406b2ddde47d550a52effb822b181342`. L'assenza riguarda quel root, non root sconosciuti. Nessuna cancellazione preliminare è proposta. Il recupero ricontrolla l'assenza prima delle chiavi e nega se trova un residuo. I contatori storici R4 di chiavi/ciclo di vita restano incerti; lo zero della lettura non li sostituisce.

CID adapter `f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67`; southbound `1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916`.

## Revisione esatta da accettare

| Sorgente | SHA256 originale | SHA256 proposto |
|---|---|---|
| scripts/semantic_provider_deployment_broker.py | 943ebeaee7d714ea5b00e59a1bac680803bff097b7f9e7cb2f218a26c61bf140 | 3069c3dbbb959d8e8d423f5fc0c22db65aa4a50e2ba1874ad26ccd3a928af0cf |
| scripts/semantic_provider_docker_runtime.py | acf9c5140b700fbb4448d4b8eccd3d3ae3f7e6af5e173aa0474965ad170e6141 | 7894d0e942642d1daa5ae2e29c85cd7f0584b7cd285c539cab3ae624bab0bba9 |

Nuova chiusura completa runtime+observer: `702403e9cd99ddc4ddeed7166f3f408c55657fc690e475e0b35bb5d2c2242bb3`; originale `dc87593c5c3b2e4859545de25b92702d93666e8d5c988f03e35fcf2df24c1ae4`. La trasformazione pura `tools/semantic_transaction_profiles/repair_broker_sources.py` è pinned al SHA256 `c1479f6cb24bb376b83a6d61f61a80760dc7cf3ae9bc8c5ae9a7e7af6e5b3c8f` e nega sorgenti originali diverse. Il pacchetto originale ff13uh3n resta intatto: le due revisioni si applicano ai byte in memoria per una nuova pubblicazione; non si sovrascrive l'installazione R4.

Il broker attende esclusivamente l'acquisizione del lock comune, entro il budget di autenticazione esistente di 18 secondi, mantenendo l'inode. Nessun retry del corpo dell'operazione, nessuna estensione delle finestre firmate. Conserva una prima diagnosi privata per fase, con codice motivo, classe, punti dell'eccezione e indicazione di salvataggio; nessuna sovrascrittura di diagnosi precedente. Il runtime espone quale fase broker è stata negata. Non cambiano OCI/rootfs/NIC/peer/generazione/guard o i relativi controlli.

Il lock nonblocking originale è stato riprodotto con flock reali: un contendente viene negato subito. Il difetto è compatibile con R4, ma non ne prova la causa storica: l'eccezione originale era stata scartata. R5 corregge quel difetto osservabile e la perdita della diagnosi; eventuali altri controlli target restano obbligatori e possono negare l'ammissione.

## Singolo recupero proposto

Esiste `tools/semantic_target_review/execute_broker_source_recovery.py`, commit `600415529f5761f4c8c9bcf9c9396e39f0ae7896`, SHA256 `6d1cda07b3e4e6e37e62411d86ede8a794f8c10447b6e40b6a247ac80c7b5197`. PENDING approvalRef e APPROVED_AT None negano prima delle letture. Dopo l'accettazione, cambiano soltanto i due campi di autorizzazione con riferimento/timestamp effettivi della risposta umana.

Riusa tutti i sedici input accettati di R4, incluse le due context cfc1bfc… / ce46668… e le evidenze dipendenze e5b31a… / 17ae547…. Nessun nuovo file context, asset, image, rootfs, SBOM, scan, guard bootstrap o preparazione. Riusa i bridge già presenti sul VPS R2 qGpE9is0 ed R3 3ssUuaKX verificandone gli hash; scarica solo nuovo esecutore e trasformazione pura.

Prima delle chiavi verifica claim R4, wrapper corrente, entrambe le osservazioni/R4 denial e otto record di ruolo. Controlla la pubblicazione originale di 81 file; soltanto i tre journal southbound avanzati usano gli hash del readback R4, mentre tutti gli altri byte mantengono il pin originale. Non modifica quei file. Verifica i sedici hash e ricompila le due policy OCI complete; deve ottenere la stessa framePolicy. Verifica la vecchia chiusura sorgenti, applica la trasformazione pinned e pretende la nuova chiusura completa esatta.

Sotto il lock esistente osserva i due candidati Docker ancora created/mai avviati e gli stessi hash di stato del readback R4, il guard nativo con set provider vuoti e l'assenza dei due CID nell'inventario runc del root southbound conservato. Se un controllo deriva, nega prima delle chiavi; non avvia una cleanup alternativa.

Riserva una sola claim `broker-source-recovery-claim.json` e crea un nuovo contesto con due mandati legati alla nuova chiusura. Emette otto nuovi record di ruolo firmati usando le chiavi esistenti. Le successive emissioni native previste dal broker/node/installer restano soggette ai relativi mandati e controlli. Finestra 240 secondi dal clock root, interamente coperta dalla validità delle dipendenze fino al 10 ottobre 2026 alle 08:33:47 Europe/Rome.

Pubblica nuovi profili e journal STAGED in una nuova directory, preservando tutti i contesti R2/R3/R4, le firme, le claim e i journal avanzati. Le due riparazioni orchestrator R3 già accettate restano caricate in memoria, senza alterare i loro file. Il bridge modifica esclusivamente i due confronti del predecessore wrapper, da empty storico a preciso hash R4 corrente. CAS sotto i controlli firmati/nativi e conservazione del predecessore; poi una sola coppia di richieste Docker tramite il runtime nominato. Nessun Docker start diretto, riavvio daemon, sudo generale, esportazione/generazione chiavi, reset journal, cancellazione preliminare, rollback o retry automatico. Nessun lease/provider grant, chiamata provider autorizzata dall'orchestratore, Teatri discovery o accettazione di rilascio.

Esito/diagnosi di entrambi conservati. I contatori dopo una claim irreversibile restano incerti se non misurati. La nuova diagnosi broker deve consentire il motivo concreto in un eventuale fallimento, senza ripetere l'errore di R4.

## Verifica

Cinque test reali filesystem/lock e native CI `37907402224` (quattro job SUCCESS) verificano la trasformazione proposta e l'ammissione di due container Docker 29.8.1 sotto contesa forzata con due marker applicativi. Nessuna autorità target viene dai fixture/chiavi CI.

Quattro test R5 locali e CI `37920751753`, job `113787810922`, SUCCESS: rifiuto prima dell'approvazione, esatto stato parziale R4, override limitato ai soli tre hash di journal osservati, otto firme reali con chiavi CI isolate e pubblicazione coerente della nuova chiusura senza alterare input/sorgenti originali. Queste prove non eseguono il main root R5 sul VPS né attestano l'avvio dei due CID reali.

L0 Matrice v1.7 e PET Authorization v1.5 AUTH-05/06/07/08/09/12 consultati. Il vincolo già accettato nel [review sign/start](PROVIDER_V2_SIGN_START_REVIEW_20261009.md) richiede «un intervento umano esplicitamente limitato al risultato osservato» dopo un fallimento. L'accettazione richiesta copre insieme le due revisioni/nuova chiusura e questo unico recupero R5. Non si richiede di ripetere le accettazioni dei sedici input, immagini o rootfs già valide.
