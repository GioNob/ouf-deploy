# Revisione concreta R7 — ammissione provider dopo audit

**Stato: PREPARATO, NON AUTORIZZATO.** ReviewRef `OUF_PROVIDER_AUDITED_RECOVERY_REVIEW_20261009_R7`. Executor e launcher contengono ancora `PENDING_AUDITED_PROVIDER_RECOVERY_APPROVAL`; nessun comando target va eseguito in questo stato. [Audit delle cause](PROVIDER_EXPERIMENT_AUDIT_20261009.md), [scope esatto](../evidence/provider-audited-recovery-scope-20261009.json).

L'ultima approvazione umana copriva il cleanup R6, concluso con successo e consumato. Questa revisione propone una nuova versione delle sorgenti, nuovi atti firmati e un nuovo avvio coordinato. Richiede quindi approvazione specifica, senza chiedere di ripetere le accettazioni image/frame/rootfs già valide.

## Oggetti e codice verificato

| Oggetto | Identità |
| --- | --- |
| Adapter CID | `f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67` |
| Southbound CID | `1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916` |
| Ultimo output consumato | `/etc/ouf/deploy-snapshots/semantic-provider-v2-transaction-aj1j95xl` |
| Cleanup concluso | `/etc/ouf/deploy-snapshots/semantic-r6-terminal-cleanup-f87o7724` |
| Ricevuta cleanup SHA256 | `8ed508977b44da7b18de04fb89255a571eccbc77dc1ab66ec5d5621c97eae948` |
| Wrapper corrente atteso | `cc4645eefedb2301afb6c7ac898716950f866cc5a19086e8c8ec854d26493d8b` |
| Commit executor/delta preparati | `4c1b74c96d54e02f2d18f1248c0e1ea7a02ed46b` |
| Executor SHA256 | `d8701f210d46cc882a785d05ab4959f23d62f857338804cda1b2bdeff78d443f` |
| Launcher inerte SHA256 | `d51c18891c70d7ffbb4e347a8566572d0521b22941c3fc6ad00355b48c5e4fb5` |
| Nuovo manifest intake | `72594fc88836cd82c382f10e8ed42adc2e04458a00df6738b05cd258916a65a6` |
| Nuovo entry intake | `a4e9c02915cc32ab839456de57f88e57d42aa607922ba6db8a320fd27bfdc240` |
| Nuova chiusura runtime/observer | `4b9fbd3149b417a2a696302784aa54d0569b5e87ddc66ac439c153c9ab16bc02` |

Executor: [execute_audited_provider_recovery.py](../tools/semantic_target_review/execute_audited_provider_recovery.py). Launcher: [provider-audited-recovery-20261009.sh](provider-audited-recovery-20261009.sh). Il contenuto executor è stato riletto dal commit remoto e confrontato byte per byte con quello testato. Il launcher scarica soltanto executor e otto file delta; ogni elemento è vincolato a commit e SHA256. Nessun nuovo trasferimento dei pacchetti originali già sul VPS.

## Modifica proposta

Il builder puro riusa il pacchetto originale `semantic-provider-v2-transaction-source-ff13uh3n`, verificandone manifest e ogni file. Mantiene le due correzioni runtime R5 già installate. Aggiunge cinque correzioni runtime: rispetto del budget residuo del produttore e diagnosi durevole nelle quattro CLI node/approval/preparer/driver. Sostituisce tre utility con le versioni verificate: publisher con directory risultati, guarded switch e authenticated switch. Aggiorna entry e manifest coerentemente, incluso il binding esatto al wrapper R6.

Viene creato un solo nuovo pacchetto privato coerente, senza modificare quello originale o gli output consumati. Le directory sono root:root 0700 indipendentemente dall'umask. La pubblicazione crea e verifica **quattro directory risultati vuote** prima dello switch. Gli hash completi dei file modificati e l'elenco dei delta sono nello scope e nella [proposta del pacchetto](../evidence/provider-audited-source-package-proposal-20261009.json).

Restano invariati i 16 input accettati, le immagini manifest/config, gli argomenti e l'ambiente OCI, gli utenti, i mount, i profili, il bundle parent corretto e i sigilli rootfs reali v1. Adapter: 3.390 voci / 46.079.786 byte, sigillo `8744724088d02145b86b433058a4336fcb9c873a4a92e7009753209c284d3d73`. Southbound: 7.458 voci / 255.900.260 byte, sigillo `52e06f47e1da5a107525e2260b9d375329997181dd13de7023654278aeaf3f39`. Lo scope conserva tutti gli hash degli input per confronto automatico; non deriva autorità da CI o da vecchie firme.

## Operazione monouso proposta

1. Verificare approvazione reale e intervallo temporale; rileggere esattamente ricevuta cleanup, claim consumato, sorgenti, input e prove conservate. Verificare le evidenze dipendenze e la compatibilità della coppia prima di leggere chiavi o emettere firme.
2. Sotto il lock comune esistente, osservare guard vuoto, wrapper R6, hash di stato Docker e metadati container attesi. Verificare assenza dei due task containerd e delle due voci runc usando endpoint/root già osservati. Un residuo o una differenza blocca prima delle chiavi; nessun cleanup implicito.
3. Riservare un **nuovo claim esclusivo**, `/etc/ouf/deploy-snapshots/semantic-provider-audited-recovery-20261009-claim.json`, un contesto nuovo e un output nuovo. Conservare gli hash delle evidenze precedenti. Nessun claim o journal passato viene cancellato o azzerato.
4. Creare due mandati root circoscritti agli stessi CID/input e alla nuova chiusura sorgenti, con finestra operativa di **240 secondi**. Usare le autorità locali già predisposte per gli otto record iniziali e per le successive attestazioni/approvazioni di ammissione. Nessuna nuova chiave e nessuna delega generale sudo.
5. Invocare una volta il normale orchestratore: autenticazione, pubblicazione, switch del wrapper con confronto esatto della versione precedente, due richieste Docker tramite attivazione coordinata controllata, verifica della coppia ammessa/running. Le policy e i vincoli di ammissione restano obbligatori. Non viene fornito un `docker start` diretto.
6. Conservare ricevuta o diagnosi della stessa esecuzione, inclusi i record per fase dei produttori e il cohort readback; verificare la conservazione delle vecchie evidenze. Nessun retry, pulizia automatica, riavvio daemon, lease provider o accettazione release. Un fallimento dopo switch non implica rollback o task assenti: leggere il risultato conservato.

L'approvazione proposta consente di iniziare questa operazione **una sola volta entro due ore dalla nuova approvazione umana**. La finestra temporale sarà registrata soltanto quando arriva il messaggio umano effettivo; oggi i timestamp sono `None`. Il mandato di 240 secondi deve inoltre terminare entro **2026-10-10T06:33:47Z (08:33:47 CEST)**, scadenza reale delle evidenze dipendenze. Nessun codice estende quella validità. Se scade prima della consegna/esecuzione, va aggiornata l'evidenza necessaria e riesaminata la differenza.

## Verifica completata e significato del risultato

Il percorso nativo nuovo arriva a due processi applicativi reali dopo emissione degli atti tramite il firmatario di produzione, autenticazione, publisher, broker e produttori reali. Usa una coppia sintetica indipendente con profili differenti e rootfs almeno della dimensione southbound osservata. [Evidenza e limiti](../evidence/provider-audited-native-validation-20261009.json). Quattro job riusciti sia su `20ddf260` sia su `4c1b74c9`; dettaglio e link nell'audit.

Le regressioni reali del trasporto provano il difetto dei 5 secondi e mantengono scadenza, bound output e comportamento fail-closed. Le prove del recupero coprono l'assemblaggio dai byte originali, il riuso degli input, la conservazione delle evidenze, le directory private e l'handoff pre-key. Le prove di consegna coprono download completo, primo/ultimo 404, hash errato, approvazione pendente ed exit nonzero da sudo. I sostituti usati nelle prove di consegna/preflight non sono osservazioni del VPS.

Il successo CI autorizza una valutazione del codice, non il server. Questa sessione non ha avviato o modificato container VPS. L'approvazione è richiesta per il cambiamento concreto appena descritto; il suo esito operativo sarà dimostrato soltanto dalla ricevuta target. Il risultato applicativo Teatri richiederà ancora rollout Semantic/MCP, grant discovery e il flusso prodotto governato.

## Consegna dopo approvazione

Registrare il messaggio umano e la sua data effettiva, sostituire soltanto riferimento e timestamp dell'approvazione nell'executor; aggiornare i corrispondenti pin del launcher e ripetere le prove mirate di binding/consegna. La chiusura sorgenti runtime proposta resta identica. Pubblicare il commit esatto e fornire un solo comando operatore verificato. Non consegnare il launcher PENDING come comando eseguibile e non chiedere di ripetere il cleanup concluso.

## Verifica finale della consegna

Commit `91f866a2a2a79740a1729d5f4feeb3a8ba5f593d`, [run 37960736584](https://github.com/GioNob/ouf-deploy/actions/runs/37960736584): tutti e quattro i job SUCCESS. Verificati nei log i due marker di pubblicazione/avvio e le 13 prove del recupero/consegna. Riletti dal commit GitHub e confrontati byte per byte executor, otto delta e launcher. [Ricevuta della verifica](../evidence/provider-r7-delivery-validation-20261009.json) con hash dei log. Nessuna modifica di autorità o operazione VPS; approvazione sempre PENDING.
