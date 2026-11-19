# R3 v12 sul kernel del lease di generazione 2 — D-050, R-027

## Contratto della consegna

Task-66 compone la closure v12, lega l'emissione alla migrazione del task-65,
ammette nell'upgrade 11 → 12 soltanto l'owner g2 pubblicato da quella migrazione
e aggiunge la precondizione di start. Non esegue migrazioni, emissioni o
installazioni sul VPS. I runbook `ops/vps/r3-*` restano fuori consegna: la loro
rigenerazione con `LATEST = 12` è affidata a Claude.

Il contratto di ripristino è quello di
[task-65](OUF_SEMANTIC_LEASE_KERNEL_MIGRATION.md). **Il punto di non ritorno
per tornare alla v11 è l'emissione v12**, prima dell'upgrade. Il finalize è
invece il punto di non ritorno per le tabelle della generazione 1; già il suo
intento durevole impedisce restore. Non esiste rollback automatico.

## Input e tre impronte

L'indice conserva lo schema `ouf.semantic-provider-r3-inputs.v1`, con gli
stessi campi `schema`, `files`, `sources` e binding `{path, sha256}`. Soltanto
dalla v12 il set chiuso di `files` aggiunge:

| Nome logico | File del task-65 |
| --- | --- |
| `migrationPlan` | `MIGRATION_CLAIM/plan.json` |
| `migrationReceipt` | `MIGRATION_CLAIM/receipt.json`; dopo finalize può essere `MIGRATION_CLAIM/finalize-receipt.json` |
| `generationReceipt` | `GENERATION_DIRECTORY/generation-receipt.json` |
| `bootPointer` | `/etc/ouf/coordinated-boot-installation.json` corrente |

`MIGRATION_CLAIM` e `GENERATION_DIRECTORY` vengono dal plan trattenuto, non
sono nuovi parametri o directory da creare con questa consegna. L'indice v12
va preparato dopo la migrazione con percorsi e hash acquisiti dai file reali.
Non si modificano le ricevute del task-65 per farle assomigliare agli esempi.
`coordinator`, `coordinationJournal` e `settings.coordinatorBinding` devono
indicare l'owner g2 e il suo journal pubblicati. Tutti gli altri input della
consegna e i due nomi delle tabelle dei candidati restano quelli governati.

Il compositore riconcilia il digest interno del plan, la ricevuta, il kernel
derivato 1 → 2, il sigillo nativo, la closure dell'owner e il puntatore. Sono
ammessi soltanto `LEASE_KERNEL_MIGRATED` o `LEASE_KERNEL_FINALIZED`.
L'emissione e l'upgrade rileggono gli stessi file ai percorsi derivati,
verificando hash e uguaglianza dei byte con gli input; negano una ricevuta di
restore oppure un finalize iniziato senza ricevuta finale. Il journal live
deve coincidere con l'input, essere QUIESCED e avere lease/start false.
Per la prima emissione v12 il plan deve legare esattamente la testa v11
autenticata. L'upgrade verifica anche owner e coordinatore precedenti.

Le tre impronte mantengono significati distinti:

1. `leaseGuard.configurationHash` delle NIC, anche nelle dichiarazioni dei
   peer, è SHA256 del JSON canonico dell'intero kernel g2. Include
   `generation: 2`, `providerFlowMatch: ORIGINAL_TUPLE` e `tableName` con
   suffisso `_g2`. Anche il nome tabella nel leaseGuard viene aggiornato.
2. `lease.ownerConfigurationSha256` autentica i byte dell'owner g2 pubblicato;
   `leaseStructureHash` è il suo sigillo nativo, riconciliato con la ricevuta.
   La struttura conserva metainfo, espressioni e tutti gli handle. Non adotta
   gli handle di un template o di una ricostruzione al boot.
3. L'impronta boot appartiene alla migrazione e alla ricevuta della
   generazione. La v12 non ricrea né risigilla il boot.

## Closure e compatibilità

`SOURCE_MAP_V12` e `REPLACEMENTS_V12` selezionano compilatore e refresh v2
soltanto da `version >= 12`. `sources` deve essere esattamente
`SOURCE_INPUTS_V12`, compreso il compilatore g1 trattenuto come input.

Per conservare i contratti chiusi dei loader broker/driver, il nome storico
`tools.materialize_southbound_kernel` contiene un alias autosufficiente:
esegue i byte trattenuti del validatore g1 in un modulo privato e li passa
al compilatore v2, conservando anche gli helper `fields`, `ip`, `name` e
`port` richiesti dal loader shared-faces. Non importa ricorsivamente se stesso. Il refresh v2
importa questo alias; lo stesso refresh è consegnato come
`readback_margin_compiler` al supervisore.

Il loader dell'owner consegnato nella sola closure v12 autentica i dodici
sorgenti della generazione migrata: gli otto dell'owner storico, i due del
boot storico e i due moduli v2. Il task-65 unisce le closure owner/boot nel
nuovo `sourceHashes`; i due sorgenti boot sono verificati senza eseguirli.
Carica prima g1, poi g2 e seleziona esplicitamente gli alias g2 prima dei
consumatori owner/backend. I pin del supervisore sono ricalcolati soltanto
per il loader e il refresh cambiati; gli altri pin restano invariati.
Queste derivazioni controllano la presenza esatta dei frammenti sostituiti:
un drift nega con `R3_V12_SOURCE_CONTRACT_DRIFT`.

Nessun file sorgente storico o modulo della migrazione è riscritto. I
golden acquisiti sul HEAD `83babf6cdfa937927e233bf6cd2d09924ca44777`, prima
delle modifiche, legano ogni input e ogni documento/autorizzazione emesso
dalle composizioni v1–v11. Restano anche i replay storici con sorgenti
trattenuti delle versioni precedenti.

## Sequenza completa sul VPS

I passi seguenti sono una procedura per l'operatore, non comandi eseguiti in
questa worktree. Si usano Python `-I -B`, custodia e binding degli eseguibili
già richiesti dalle CLI esistenti. Ogni plan/apply usa il proprio digest e
un claim nuovo; si conservano tutti i journal e i parziali.

1. **Stop R3 v11.** Usare `scripts/operate-semantic-provider-r3.py` con
   `--action stop`, prima `--plan`, poi `--apply --plan-sha256` del plan.
   Verificare entrambi i CID fermi, epoche terminali, restart policy `no`,
   supervisore WAITING sulla sequenza v11 e lease QUIESCED.
2. **Migrazione 1 → 2.** Usare
   `scripts/migrate-semantic-lease-kernel.py --plan --to-generation 2`, poi
   `--apply --to-generation 2 --plan-sha256` dello stesso plan, con gli
   argomenti comuni del documento task-65. Custodire il claim: N è intatta,
   N+1 è presente, vuota e sigillata; nuovo owner, boot e puntatore sono
   pubblicati. Il provider resta fermo. La v11 non è valida per start in
   questo stato.
3. **Finestra di restore.** Se occorre interrompere il passaggio, usare
   `--restore --migration-directory MIGRATION_CLAIM --plan-sha256` del
   plan di migrazione, **prima di emettere la v12**. Restore riconcilia
   puntatore/unità, elimina soltanto N+1 e conserva il sigillo N: dopo il
   readback la v11 torna avviabile. Non riusare apply già consumati.
4. **Emissione v12.** Preparare il nuovo indice con gli input sopra, quindi
   `scripts/issue-semantic-provider-operation-authorization.py --supersede`,
   prima `--plan`, poi `--apply --plan-sha256`, usando l'autorità esistente.
   Custodire payload, firma e ricevuta. Da questa emissione il ritorno alla
   v11 è vietato: task-65 nega restore con
   `LEASE_KERNEL_R3_HEAD_CHANGED_RESTORE_DENIED`.
5. **Upgrade v11 → v12.** Usare `scripts/upgrade-semantic-provider-r3.py`,
   prima `--plan`, poi `--apply --plan-sha256`. Il solo cambio autorizzato
   di coordinatore è quello dal predecessore del plan all'owner g2
   pubblicato, con journal QUIESCED. Stato condiviso del supervisore e
   journal storici sono conservati. Ogni altro cambio resta
   `R3_UPGRADE_SHARED_STATE_DRIFT`. Nessun container è avviato dall'upgrade.
6. **Finalize.** Con provider ancora fermo, usare la CLI task-65:
   `--plan --operation finalize --migration-directory MIGRATION_CLAIM
   --migration-plan-sha256 MIGRATION_PLAN_HASH`, poi `--finalize` con
   gli stessi binding e `--plan-sha256 FINALIZE_PLAN_HASH`.
   `--output-directory` indica un claim finalize nuovo; il binding del
   wrapper deve essere quello pubblicato dall'upgrade. Il finalize elimina
   solo N, conserva N+1 e produce `finalize-receipt.json`. Già
   `finalize-intent.json` chiude il restore delle tabelle N.
7. **Start v12.** Usare la CLI operate con `--action start`, plan/apply
   governati e binding del wrapper v12. Devono essere assenti **entrambe**
   le tabelle N; devono essere presenti entrambe le tabelle N+1 con il
   sigillo owner esatto; il journal non deve essere BLOCKED. Restano tutte
   le altre precondizioni storiche, compreso QUIESCED al primo start e il
   ripristino volatile previsto. Il gate è ripetuto prima delle richieste
   Docker, dopo il ripristino volatile; copre anche `restart-one` v12.

La lettura usata dal finalize non è uno start: può osservare N e N+1
coesistenti e non viene bloccata dalla nuova precondizione. Le versioni fino
alla v11 conservano il comportamento di operate precedente.

## Errori e ripresa

Prima dell'emissione v12 vale restore della migrazione, nei limiti esatti del
task-65. **Dall'emissione in poi si procede solo in avanti sul kernel g2**:
si conserva il claim fallito, si corregge il problema e si riemette una
versione successiva con le autorità e le procedure governate. Il provider
resta fermo per tutta la finestra. La v12 non aggiunge una procedura per
saltare un upgrade parziale né estende le politiche di migrazione.

Un finalize interrotto si riconcilia sullo stesso plan secondo il task-65;
non si ripete una cancellazione già avvenuta. La presenza anche di una sola
tabella predecessore nega start con `R3_LEASE_KERNEL_NOT_FINALIZED`.
Famiglie g2 mancanti, espressioni o handle diversi negano con
`R3_LEASE_KERNEL_STRUCTURE_DRIFT`; un journal BLOCKED nega con
`R3_LEASE_KERNEL_JOURNAL_BLOCKED`. Nessuno di questi casi autorizza start,
riscrittura del journal, adozione di un nuovo sigillo o bypass TLS/IAM.

## Verifica locale e CI

`tests/test_semantic_provider_r3_v12.py` esercita golden v1–v11, composizione
g2, NIC/peer, entrambi i loader broker/supervisore, ricevute e puntatore,
emissione legata alla testa v11, osservazione completa dell'upgrade, owner
estranei, gate sul sigillo e dinieghi prima di qualunque start.

I workflow R3 di emissione, installazione e integrazione includono la nuova
suite. Solo il workflow di integrazione, che già dispone di nft e gate root,
abilita anche la prova v12 con `OUF_LEASE_KERNEL_V2_NATIVE=1`: un `unshare
--net` privato installa N/N+1 reali, verifica il diniego durante coesistenza,
elimina N, verifica il gate positivo e poi i dinieghi BLOCKED/drift.
Non usa Docker né servizi host. Dipendenze o namespace non disponibili con
il gate abilitato sono errori, non skip.

Su Windows le prove nft native restano saltate: i risultati portabili non
attestano nft, systemd, esecuzione CI o readiness del VPS. Per i comandi e
gli esiti della sessione locale vale il report della consegna.

La regressione complessiva include anche tre test dell'installer autostart
che confrontano i pin offline in `ops/vps/r3-autostart-install.sh`. Quei pin
sono ancora precedenti alla v12 e la suite segnala il drift dei file
modificati. È necessaria la rigenerazione dei runbook da parte di Claude,
già riservata fuori dal perimetro del task; i test e i pin non sono aggirati.
