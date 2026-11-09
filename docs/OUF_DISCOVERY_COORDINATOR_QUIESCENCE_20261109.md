# Discovery: quiescenza del coordinatore

9 novembre 2026. **Eseguito sul VPS alle 09:31 CET: HELD per NFT_INSTALLATION_STRUCTURE_DRIFT, prima di intento o scritture. Non rilanciare.** [Ricevuta](../evidence/discovery-coordinator-quiescence-held-operator-20261109.json). Il prossimo passo è il [confronto in sola lettura](OUF_DISCOVERY_NFT_DRIFT_READ_20261109.md). La [rimozione del segnaposto](../evidence/discovery-placeholder-removed-operator-20261109.json) è conclusa; non va ripetuta.

## Risultato cercato

Portare il coordinatore osservato da BLOCKED a QUIESCED usando la sua operazione esistente, conservando lease e avvio disabilitati. Il provider resta fermo. L'ammissione di una nuova generazione resta un passo successivo da qualificare.

## Comando consegnato

[Wrapper](../scripts/deliver-discovery-coordinator-quiesce-20261109.sh), SHA-256 `c8c468c78b253e6d33125a4c3d924f11badc13f2c72b267f945bc6fddeb2083c`.

Sorgenti fissati al commit [3c961d3e897d3573e6c7af2abe49cac8f53c9f45](https://github.com/GioNob/ouf-deploy/commit/3c961d3e897d3573e6c7af2abe49cac8f53c9f45). Il wrapper scarica cinque script e sei moduli del coordinatore, ne verifica tutti gli hash e lancia Python isolato tramite sudo. Non richiede GitHub CLI.

1. Verifica la ricevuta completata in `discovery-placeholder-cksr_p4w` e i binding correnti. Acquisisce i lock già esistenti dei due runtime, della coorte e delle lease.
2. Ricontrolla sotto lock l'assenza di processi/task/regole propri e namespace dei vecchi provider, i loro journal attesi, i frame dei container e la proprietà della struttura nft. Richiede coordinatore BLOCKED, lease/start false e tutti i set vuoti.
3. Conserva preflight e stato precedente; registra un nuovo intento, distinto da quello della rimozione.
4. Invoca `Coordinator.quiesce()` con sei moduli originali del repository verificati per hash. La funzione pubblica QUIESCING, esegue un solo batch di quattro `flush set`, verifica i set vuoti e pubblica QUIESCED. Il trasporto rifiuta qualsiasi altro comando di scrittura.
5. Rilegge coordinatore e struttura, controlla lease/start false, journal dei vecchi provider e frame invariati, namespace ancora assenti. Salva la ricevuta.

I sei moduli sono quelli fissati nel repository. Questo non attesta l'identità dell'intero pacchetto runtime installato. Il comando non esegue gli esecutori storici di ammissione e non riusa la loro autorità.

## Effetti e risultato

Effetti previsti: due transizioni del solo journal del coordinatore e un batch nft che svuota quattro set già osservati vuoti. Struttura delle tabelle, journal di ammissione/runtime, metadata containerd e container vengono conservati. Nessun avvio/stop, nuova lease, DNS, token, chiamata provider, DB o S3.

Esito atteso: `DISCOVERY_COORDINATOR_QUIESCED`, con `coordinationState=QUIESCED`, `leaseAuthorized=false`, `startAuthorized=false`, `providerReady=false` e `newGenerationAdmitted=false`.

L'intento è `/var/lib/ouf-storage-migration/discovery-coordinator-quiesce-20261109`; le evidenze private sono in una nuova directory `discovery-coordinator-quiesce-*`. Il comando rifiuta un intento già presente. In caso di HELD restituire il JSON senza rilanciare: dopo una scrittura parziale non è previsto rollback o replay automatico. Limite del controller: 180 secondi.

## Prove e limite della qualifica

[CI 42585264317](https://github.com/GioNob/ouf-deploy/actions/runs/42585264317), job 129053446029: **7 test unitari e 2 prove native, zero skip**, log letti.

Le prove native usano nftables reale e journal privato in namespace Linux usa e getta. Verificano BLOCKED → QUIESCED, struttura conservata e lease/start false; una modifica estranea alla struttura viene preservata e causa arresto prima di qualsiasi scrittura. Le prove unitarie coprono anche set non vuoti, fallimento del flush, assenza di intento, hash errato e rifiuto di comandi o batch diversi.

La successiva esecuzione VPS si è fermata al controllo di proprietà: i test qui descritti non coprivano la corrispondenza tra l'impronta storica e quella attuale. La causa della differenza resta aperta. [Evidenza della qualifica](../evidence/discovery-coordinator-quiescence-qualification-20261109.json). F2–F6 restano aperti; seguono nuova generazione provider, credenziale/TLS Semantic, controllo backlog/grant e pubblicazione MCP già candidata.
