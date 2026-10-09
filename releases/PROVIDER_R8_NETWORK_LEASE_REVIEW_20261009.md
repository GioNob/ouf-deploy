# Current checkpoint — lease denied before claim; corrected approved delivery ready

Operator result at22:27:35 Europe/Rome: NATIVE_SERVICE_COMMAND_FAILED, systemctl exit1, stderr empty, at exact-name-filtered inventory line210. No claim/snapshot/service start reached; lifecycle0, doNotRerunApply=false. [Receipt](../evidence/provider-r8-lease-preclaim-denial-20261009.json). The retained diagnostic did not name the subcommand; do not invent which of the two inventories failed. The correction enumerates both service inventories without a name pattern and checks exact membership. Genuine inventory failures remain fatal; diagnosis now includes subcommand and stdout/stderr hashes/counts.

Existing human approval22:21:21 remains valid and unconsumed; first invocation deadline10Oct00:21:21 Europe/Rome unchanged. No new approval or scope extension. Core/compiler and runtime bindings unchanged. Corrected source `c662f886ec01785b98d3a79ee09df622ec183da7`, entrypoint SHA2567d12b9809a7db6d9b0963ef89957c7d224b5f59b733662f4878a89dd6208565a. Native CI37987266796/job114012260043 SUCCESS: actual systemctl absence and loaded-service detection, then actual lease opening, renewal, DNS-error revocation and replay denial. [Validation](../evidence/provider-r8-lease-systemctl-correction-validation-20261009.json).

Use only corrected launcher `releases/provider-r8-network-lease-systemctl-fix-20261009.sh`, SHA256a7b79d292184ec7403f15c5d977fe962aaaf45b3e118cc8a21b9728b7eecdead. Reuses `/home/oufadmin/ouf-r8-lease.8XKYoqHc/activation_core.py` and compiler, downloads only the corrected entrypoint under a new name, preserves old result.txt and writes result-systemctl-fix.txt. Explicit gh path and existing reader remain unchanged. Never use the old launcher again. No target mutation performed here; verify claim absence again inside the corrected action, execute once, then preserve output. The lease action still checks exact current R8 process generations and the original QUIESCED owner. Teatri/Semantic/MCP roadmap remains open.

Earlier checkpoints below are historical and superseded.

# Approvazione ricevuta — esecuzione operatore in attesa

Messaggio umano “Approvo” del 9 ottobre 2026 alle22:21:21 Europe/Rome. La prima invocazione è autorizzata fino al **10 ottobre00:21:21 Europe/Rome**; la lease resta poi vincolata alla vita degli attuali due processi. [Ricevuta](../evidence/provider-r8-lease-human-approval-20261009.json). L’approvazione include la copia corretta del compilatore e il perimetro sottostante. Non chiederla nuovamente.

Entrypoint approvato commit `6aa13656205f5dc3f355954874d3324c354ed1da`, SHA256 `6038e18a83a085eaab48ce10f94214ff6f8bf15a649e4af85e4640aae9ff0557`; soltanto riferimento e due tempi cambiano dalla versione sottoposta a revisione. Launcher `provider-r8-network-lease-20261009.sh` SHA256 `a304dae0cfd02b15e28c610d2fb48b9757e53a682a4e54a03b44b24b3c2ef386`. Consegna verificata con il percorso esplicito gh, tre hash e bootstrap in memoria; un riferimento errato viene rifiutato prima delle operazioni target. Nessuna azione VPS eseguita qui. Eseguire una volta e conservare output; nessun replay.

La proposta sottostante è la revisione storica approvata; i riferimenti PENDING descrivono il suo stato prima della decisione.

# Proposta concreta: attivare la lease dei due flussi R8 già previsti

Stato: **preparata, non approvata, non eseguibile sul target**. Il codice mantiene APPROVAL_REF PENDING e tempi zero. La ricevuta operatore delle 21:37:45 Europe/Rome del 9 ottobre, [registrata integralmente](../evidence/provider-r8-post-start-target-20261009.json), conferma entrambi i processi R8 ancora running, stessi PID, zero riavvii e journal STARTED invariati. Stato rete: QUIESCED, autorizzazione lease false, quattro set inet/bridge vuoti, struttura verificata. Nessuna unità lease/coordinated rilevata. L'avvio R8 è concluso e non viene ripetuto.

## Ambito da approvare

| Flusso | Processo esistente | Destinazione già configurata | Limite |
|---|---|---|---|
| Adapter | CID f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67, PID1826443, avvio 19:10:21.87693854Z | https://schema.gov.it:443/sparql | TCP443, lease massima30s |
| Southbound | CID 1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916, PID1826422, avvio 19:10:21.846292298Z | https://auth.ouf-lab.it/realms/ouf | TCP443, lease massima30s |

Gli hash degli URL corrispondono esattamente a quelli appena letti; le forme degli URL provengono dagli input conservati della migrazione. Nessuna nuova destinazione, IP fissato, porta o eccezione privata viene introdotta. Owner hash `656c23f18e3f3eb4c1ce630f5056be87f7883eab7b048065092dafbd018284a8`, kernel hash `0a646e6109d2dc32aabdbbe26436784de8a83bdeb023a36c5b2712315666f5b5`; journal iniziale `a58f0cb6e011879fc22723356d19926adf8945c38dcdbf2d21ab3fa34dd6f7f1`. Resolver esistenti 46.38.225.230 e 46.38.252.230, timeout2s, budget apply1s, rinnovo15s. Restano applicati i limiti più corti delle risposte DNS effettive.

L'azione operator-only proposta:

1. Rilegge nello stesso flusso i due processi e la generazione QUIESCED, i file/sorgenti già sigillati, i comandi boot caricati e l'assenza della nuova unità.
2. Conserva ricevuta precedente e autorizzazione specifica in un nuovo snapshot `semantic-r8-lease-*`. Crea una claim esclusiva `/etc/ouf/provider-r8-network-lease.claim`; nessun reset o replay.
3. Avvia soltanto l'unità temporanea `ouf-semantic-provider-lease-r8.service`, non abilitata al boot, Restart=no, legata alla vita di docker.service. Nessun daemon-reload o riavvio Docker è richiesto.
4. Il worker verifica l'approvazione, mantiene la versione precedente del journal e pubblica una sola autorizzazione LEASE_READY sotto il lock originale. Verifica gli otto file originali del coordinatore e ne mantiene la custodia. Esegue i moduli esistenti con il solo compilatore lease corretto, separatamente vincolato nella nuova autorizzazione; revoca iniziale, DNS fresco, aggiornamento atomico e readback restano quelli del coordinatore. Nessuna riscrittura delle regole, dei profili, dei container o dei loro journal R8.
5. Restituisce successo soltanto dopo due cicli distinti DNS/apply/readback, servizio attivo con PID coerente e membership corrente di entrambi i flussi. Conserva la causa interna degli errori e tenta l'arresto della sola unità appena creata se la verifica iniziale fallisce.

Durata dell'autorizzazione proposta: vita degli attuali due processi, fino ad arresto, errore del worker o reboot. Ogni ciclo controlla CID, immagine, runtime, PID, StartedAt, zero riavvii e sorgenti di rete. Stop/errore usa la revoca del coordinatore esistente; se la revoca non è dimostrabile, i timeout kernel restano finiti e il risultato lo dichiara. Nessun riavvio automatico o riarmo autonomo. Una nuova generazione richiede una nuova decisione. La finestra per la prima invocazione sarà vincolata al messaggio di approvazione, massimo due ore; non è ancora impostata.

Il worker non effettua chiamate HTTP ai provider. Dopo l'apertura, i workload approvati possono invece raggiungere gli endpoint previsti: non confondere zero richieste emesse dall'orchestratore con assenza di traffico globale. L'azione non concede capability discovery, non pubblica semantica e non esegue il job Teatri. Non è accettazione di release o prova di salute applicativa.

## Implementazione e verifiche

Entrypoint `tools/semantic_lease_activation/activate_r8_lease.py`, nucleo `activation_core.py`. Il lettore già presente `/home/oufadmin/ouf-r8-post-read.Tl08rnjI/read.py` viene riutilizzato con SHA256 ab61835ef55396ddacf4513acc0f21adbaab1b50ac32ad2fdc4c80a23d1835c8; non occorre rifare il suo download o la lettura manuale. Le sorgenti owner esistenti corrispondono ad a10df126d229dfefd9e0a4d716a07f1f535b6cd6; non vengono aggiornate.

I test locali verificano mancata autorità della proposta PENDING, finestra esplicita, drift rispetto all'effettiva ricevuta operatore, claim non sovrascrivibili, conservazione della causa interna e assenza di riavvio/boot automatici. La workflow dedicata verifica gli otto hash e prova il core con systemd, DNS UDP e nft reali in un namespace di rete CI isolato: apertura, rinnovo, errore DNS, revoca e rifiuto del replay. Esito remoto corretto: SUCCESS sul commit `908b69e5b46350e042bec35ad0ef243698d538ec`, [run37983913602](https://github.com/GioNob/ouf-deploy/actions/runs/37983913602), job114001007971. I log dimostrano due cicli, risposta al guasto DNS con revoca e rifiuto del replay. [Ricevuta CI](../evidence/provider-r8-lease-native-validation-20261009.json). Fixture e test non diventano autorità target.

PET consultati: Matrice v1.7, Gateway v1.5 T11.3/GW-NET-01–05, Authorization v1.5 AUTH-05–12. L'unità supervisiona il coordinatore esistente, non introduce un nuovo prodotto. L'approvazione R8 precedente riguardava i container e non conferisce questa separata autorità di rete.

Dopo l'attivazione riuscita: aggiornare l'evidenza dipendenze degli artefatti Semantic/MCP già conservati, procedere con rollout e grant discovery, poi il percorso Teatri già concordato. Nessun ricaricamento asset né fallback locale.

## Difetto trovato nella prova nativa prima del target

La prima prova remota, run37983256268/job113998780301 sul commit17644c1be6a5d47522b05d4e77718efa600d778a, ha rifiutato l’apertura con FRESH_RESOLUTION_UNUSABLE. Il compilatore originale inseriva la risposta del primo flusso nella configurazione completa mentre il secondo era ancora vuoto: la validazione globale rifiutava quindi ogni prima attivazione della coppia. Il test riproduce il problema con il sorgente originale, non con un mock.

La correzione valida ogni flusso risolto separatamente durante il ciclo; restituisce la stessa transazione atomica solo dopo la validazione di entrambi. Un solo flusso invalido mantiene la revoca di tutti e quattro i set. Nessun limite DNS, TTL, destinazione, sorgente, porta o controllo di indirizzo viene allentato.

Il vecchio compilatore SHA256 `1c0d7f1243752fe216ef62eefbc2e3253b8f2503b518fafe11277e4d7721a084` rimane sul VPS immutato. La nuova copia SHA256 `c3160940cf79678cb8e44c036cb0d947016f885ab09acfe6cce571833db5b079` vive soltanto nel nuovo snapshot privato e deve essere esplicitamente inclusa nell’approvazione di questa azione. La chiusura originale non autorizza i byte modificati. Il worker conserva sia il vincolo vecchio sia quello nuovo nella capsula. Non è stata eseguita alcuna azione sul VPS durante queste prove.

## Consegna predisposta, ancora inerte

`releases/provider-r8-network-lease-20261009.sh` controlla PENDING prima di ogni download o sudo. Usa il GitHub CLI già presente in `$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh`, scarica soltanto i tre nuovi file e verifica ogni SHA256. Riusa il lettore locale esistente. La parte sudo ricontrolla l’entrypoint e ne esegue esattamente i byte verificati in memoria, senza rileggerli dopo la verifica.

Entrypoint preparato SHA256 `01a7c766111313aae941f5ecda97a0efc4b8842822bbf0e8a09d188fc8c9648b`; core `51259c988eae4b506f2696ad3f5bf6e954eca9c4396cb36da75e0845ff49e50b`. Dopo l’approvazione umana effettiva, vincolare soltanto riferimento e finestra temporale dell’entrypoint, aggiornando i relativi pin nella consegna. Nessuna modifica al core, al compilatore o al perimetro approvato. Nessun comando target è ancora autorizzato.

Prova di consegna locale superata: percorso esplicito gh, tre hash, esecuzione dei byte verificati e rifiuto PENDING prima delle operazioni target. Il test sostituisce solo il trasporto GitHub e sudo nel proprio ambiente temporaneo; non conferisce alcuna autorità né osserva il VPS.
