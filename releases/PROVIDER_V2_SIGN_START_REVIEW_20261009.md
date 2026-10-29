# Provider v2 — proposta di mandati e avvio controllato
Review: `OUF_PROVIDER_V2_SIGN_START_REVIEW_20261009_R1`. Stato: **PROPOSTA, nessuna autorità concessa**.

## Perimetro richiesto alla persona
L'approvazione richiesta qui è distinta dalle accettazioni già registrate delle immagini OUF-LAB e dei sedici input/frame/rootfs. Quelle accettazioni restano valide nel proprio perimetro e non vengono richieste di nuovo.

Si propone di autorizzare l'operatore root a materializzare due mandati limitati ai CID e ai byte sotto indicati, usare le due autorità Ed25519 già installate per la transazione e chiedere l'avvio coordinato dei due candidati attraverso il runtime autenticato. Non è autorizzazione generale a usare le chiavi o ad avviare altri container. Il documento e i JSON di proposta non sono mandati ACTIVE, non sono firme e non possono essere consumati come autorità target.

| Ruolo | CID esatto | Transazione |
| --- | --- | --- |
| Adapter | `f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67` | `a1c2768460dc488c73a9d5aabc71fa106373512eb8fe58510654326ce3743b07` |
| Southbound | `1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916` | `a2cb1cd204239fba17e43f71530345ee6e50dde60967a2c40a605d9f70cd6266` |

Le due proposte JSON in `evidence/provider-v2-execution-review-20261009/` vincolano, per ruolo, gli otto hash degli input, il documento OCI completo, il transport hash, manifest/config distinti, il sigillo v1 originale e la chiusura runtime/observer. Il JSON completo `controlled-execution-review.json` conserva anche le autorità, i percorsi, le operazioni ammesse e le esclusioni.

## Evidenza disponibile e custodia
L'operatore ha riportato alle07:19:55 Europe/Rome del9Ottobre `SEALED_SOURCE_AND_ACCEPTED_PAIR_PREFLIGHT_PASS`, bootstrapPASS ed exit0. Il messaggio è conservato come ricevuta dell'operatore, non acquisizione indipendente del VPS. Nuovo package:
`/etc/ouf/deploy-snapshots/semantic-provider-v2-transaction-source-ff13uh3n`.

Sono41 file verificati, manifestSHA256 `2699c82124b6bfcbd61991f09a96ebb5c6a2d336aaf3384dcae9288101b29de4`, entry intakeSHA256 `edc3c97d54a9d241c93ea9791f4dffce9984565763c2236ad1644e8b90c4c4b5`, sourceClosureHash `dc87593c5c3b2e4859545de25b92702d93666e8d5c988f03e35fcf2df24c1ae4`.
I16 input originali in `/etc/ouf/deploy-snapshots/semantic-provider-v2-transaction-draft-g1yrsazc` sono stati riutilizzati senza modifiche. Zero mandati, firme, letture di chiavi, scritture di configurazioni esistenti, operazioni container o chiamate provider. Non ripetere questa preparazione.

La CI37886341835 al commit53ee1edb7703cc42026e267ac08dc1bb40cc186c passa i quattro job. Il nuovo job prova due start Docker29.8.1 reali su Engine/containerd propri, le29 sorgenti originali sigillate, documenti OCI fissati prima dei task, filesystem atteso separato image/initlayer, sigillo completo senza esclusioni, node-v4/broker/installer/peer-v6 e due marker applicativi. Immagini, chiavi e autorità di questa fixture sono CI-only. Non prova stato live target, approvazione target, reboot o accettazione del rilascio.

## Autorità e finestra proposte
Installer `ouf-lab-infrastructure-installer`: TARGET_REVIEW, DEPLOYMENT_INTENT e FINAL_DEPLOYMENT_APPROVAL.
Attestatore `ouf-lab-node-attestor`: LIVE_NODE_ACCEPTANCE per il frame/seal esatto, con generazione osservata CREATED; il percorso node-v4 verifica il mandato e produce l'attestazione della generazione reale. Si usano soltanto le keyRef già installate `ouf-lab-installer-ed25519-1` e `ouf-lab-attestor-ed25519-1`, sotto il profilo/trust policy fissati. Le chiavi restano sul VPS; nessuna nuova chiave, export o trasferimento.

Il CreationIntent resta **creation-only**: applicationStartAuthorized=false. È il mandato finale distinto, firmato dall'installer e verificato dal runtime, a poter autorizzare l'avvio applicativo dei CID esatti.

Entrambi i mandati avranno T0 preso dall'orologio root all'invocazione e scadenza T0+240secondi. Tutte le firme e verifiche devono rientrare nella finestra e nella validità della dependency evidence: **9Ottobre08:31:48 Europe/Rome (06:31:48Z)**. Non sono emessi ora. Se l'evidenza non copre l'intera finestra, la firma viene negata; non si estende la validità vecchia. Un eventuale aggiornamento delle evidenze deve conservare la diagnosi e rendere espliciti i nuovi hash, senza ripetere preparazioni o accettazioni non cambiate.

## Modifiche operative proposte
1. Verificare i due mandati e gli input completi prima di leggere una chiave.
2. Emettere le firme con le autorità esistenti e verificarle realmente.
3. Pubblicare una nuova chiusura privata di profili/journals STAGED, con allowlist limitata ai due CID.
4. Verificare guard vuoto, custodia, candidati mai avviati e firme sotto il lock comune; sostituire per compare-and-swap soltanto `/usr/local/sbin/ouf-semantic-admitted-v2`, il cui wrapper vuoto originale è4956b05ec41fd54a27c00f2b6606d17be97dd84b3c09cff8b252d0fc886331bd. Ripetere i controlli ai checkpoint attorno alla sostituzione.
5. Rilasciare il lock comune prima delle due richieste Docker concorrenti, perché il runtime deve acquisire i propri lock. Non è consentito uno start Docker ad hoc che bypassi questo orchestratore.
6. Consentire soltanto l'ammissione prevista dal runtime: controlli reali OCI/rootfs/NIC/peer/generazione/guard e protezioni native scoped prima del rilascio dell'applicazione; conservare entrambi i readback e la ricevuta/diagnosi.

Owner di rete fissato:656c23f18e3f3eb4c1ce630f5056be87f7883eab7b048065092dafbd018284a8. Nessun cambio dei resolver approvati. Nessun riavvio daemon, nuovo sudo generale, grant lease provider dall'orchestratore o chiamata API provider dall'orchestratore. Nessun job Teatri, nuovo asset, rollout Semantic/MCP o accettazione del rilascio da questa approvazione.

## Esito parziale e confini della prova
La transazione può aver firmato o sostituito il wrapper prima che un controllo successivo neghi l'avvio; può anche aver avviato un solo candidato. Le claim, lo stato del wrapper, i risultati Docker e le osservazioni dei due candidati devono restare conservati. Nessun replay, retry o rollback automatico. Il recupero, se necessario, richiede un intervento umano esplicitamente limitato al risultato osservato. I contatori incerti non vengono riscritti a zero.

Il PASS di questa futura transazione significherebbe ammissione/avvio dei due runtime; non prova reboot, stabilità generale, autorizzazione lease provider o release acceptance.

## Decisione ancora necessaria
L'approvazione umana di **questa specifica proposta di firma, pubblicazione runtime e avvio controllato** è PENDING. Non esiste ancora un comando target da eseguire. Dopo la risposta umana si deve registrare la decisione e completare la materializzazione root dei mandati e la procedura operator-only, fissata ai byte e ai limiti qui riportati.

Riferimenti: PET Authorizationv1.5 AUTH-05/06/07/09/12; regole operative `releases/OUF_WORKING_RULES.md`. I documenti di progetto non costituiscono da soli una nuova richiesta o approvazione umana.
