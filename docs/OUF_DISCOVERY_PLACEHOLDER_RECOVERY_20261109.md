# Discovery: rimozione verificata del segnaposto southbound

9 novembre 2026. **Esecuzione conclusa sul VPS alle 09:06 CET. Non ripetere.** [Ricevuta operatore](../evidence/discovery-placeholder-removed-operator-20261109.json): segnaposto rimosso, nessun umount, frame e journal invariati; coordinatore ancora BLOCKED.

## Evidenza corrente

La [ricevuta delle 08:46 CET](../evidence/discovery-lifecycle-operator-20261109.json) prova, nei limiti della lettura sequenziale:

- adapter: nessun processo registrato, task, shim, directory runc, tabella propria o handle; journal DELETED/CLEANED/ROLLED_BACK;
- southbound: gli stessi oggetti nativi risultano assenti, mentre i metadata containerd sono presenti. Resta il percorso netns, inode 4040196, diverso dall'inode del namespace registrato. Journal DELETING/PROTECTED;
- coordinatore BLOCKED, leaseAuthorized=false, due set per famiglia e zero elementi.

L'inode diverso non prova da solo un file cancellabile. Il preparatore crea un file root 0600 contenente esattamente `{}` prima di montarvi il namespace. La possibilità che sia rimasto quel segnaposto è un'ipotesi, verificata nel comando prima di agire.

## Effetto del comando

[Consegna](../scripts/deliver-discovery-placeholder-20261109.sh), sorgente [633aecc9ca6585ef3684f560125f64652d115c87](https://github.com/GioNob/ouf-deploy/commit/633aecc9ca6585ef3684f560125f64652d115c87). Verifica quattro script con SHA256, poi esegue Python isolato tramite sudo.

1. Verifica la ricevuta retained esatta e i binding correnti; prende i lock già esistenti dei due runtime, della coorte e delle lease. Non crea lock sostitutivi.
2. Ricontrolla il lifecycle sotto quei lock: processi/task/regole propri assenti, journal attesi, lease BLOCKED/vuote. Queste verifiche sono precondizioni della modifica.
3. Verifica il solo netns southbound: inode 4040196, file regolare root:root 0600, un link, due byte `{}`; filesystem diverso da nsfs, stesso mount del parent e assenza da mountinfo. Mantiene aperti gli inode e ripete il controllo dopo la registrazione dell'intento.
4. Conserva copia e metadata, quindi rimuove soltanto quel file. Verifica l'unlink dell'inode trattenuto e i journal/frame invariati.

Un namespace ancora montato, anche diverso da quello registrato, viene conservato. Sono conservati anche bind mount ordinari, altri byte, inode, permessi o link. Nessun umount, cancellazione containerd, avvio/stop, modifica nft, transizione del coordinatore o riscrittura dei journal. Non vengono richiesti token né chiamati provider, database o S3.

L'intento distinto è in `/var/lib/ouf-storage-migration/discovery-southbound-placeholder-20261109`; evidenze private in una nuova directory `discovery-placeholder-*`. Non rilanciare dopo un intento o un effetto parziale: il comando stesso rifiuta il riuso. Durata massima 180 secondi.

## Esito e passo successivo

Esito ricevuto: `SOUTHBOUND_UNMOUNTED_PLACEHOLDER_REMOVED`. Significa rimozione dell'ultimo residuo filesystem osservato. Il coordinatore resta BLOCKED e i journal storici restano conservati: **providerReady=false e newGenerationAdmitted=false**.

La [quiescenza del coordinatore](OUF_DISCOVERY_COORDINATOR_QUIESCENCE_20261109.md) è ora qualificata e da eseguire; resta da qualificare l'ammissione di una nuova generazione provider, poi credenziale/TLS Semantic, backlog/grant e installazione MCP PR84 già compilata. Non usare il successo di questa rimozione come autorizzazione tecnica a riavviare i vecchi CID.

## Qualificazione

[CI 42582681407](https://github.com/GioNob/ouf-deploy/actions/runs/42582681407), job 129044958878: 9 test unitari e 2 prove Linux native, zero skip, log letti. Le prove native montano realmente nsfs e un bind mount ordinario in namespace usa e getta; entrambi sono preservati. Dopo umount della fixture viene rimosso soltanto il segnaposto originale. Coperte inoltre sostituzione inode dopo intento, contenuto/permessi/link differenti, intento fallito e precondizioni con processi o lease presenti.

La prova nativa copre il confine filesystem; l'esecuzione del controller sul VPS è documentata nella ricevuta operatore sopra. [Evidenza](../evidence/discovery-placeholder-reconciliation-qualification-20261109.json). Questo passo non cambia F1–F6 e non prova E2E.
