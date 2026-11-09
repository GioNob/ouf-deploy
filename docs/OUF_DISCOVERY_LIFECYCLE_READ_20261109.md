# Discovery: riconciliazione del lifecycle corrente

9 novembre 2026. Stato: **lettore pronto, esecuzione VPS pendente**. La ricevuta delle 06:51 UTC riporta adapter DELETED e southbound DELETING; non contiene lo stato nativo necessario a scegliere il recupero.

## Cosa verifica il prossimo comando

[Consegna](../scripts/deliver-discovery-lifecycle-20261109.sh), sorgente [789a2e131abda301424f7d011b545e4607a5703b](https://github.com/GioNob/ouf-deploy/commit/789a2e131abda301424f7d011b545e4607a5703b). Il wrapper scarica tre file dal commit immutabile, verifica tutti gli SHA256 ed esegue il lettore in Python isolato con sudo. Nessun parametro richiesto.

- Conserva gli esatti CID/frame API1.44 di provider v2 e southbound v2; verifica wrapper e configurazione già osservati. Nessuna normalizzazione MAC.
- Legge i journal adapter/broker/admission/preexec e il coordinatore lease; il codice runtime storico viene letto come dati, mai eseguito.
- Legge runc dalla radice registrata e dal binario con hash atteso; containerd dal socket dichiarato dal dockerd corrente, namespace moby. Un errore non è convertito in assenza.
- Confronta generazioni dei PID, shim dei due CID, handle netns, tabelle nft del profilo e set lease. Acquisisce inventari nativi prima/dopo e ricontrolla file/frame.
- Salva le evidenze selezionate in una nuova directory privata sotto /var/lib/ouf-storage-migration; stampa soltanto il riepilogo. Non legge file di credenziali o configurazioni TLS.

Sono ammessi soltanto Docker GET e comandi nativi list/info; nessun start, stop, delete, kill, rollback, umount, modifica nft o journal, OAuth, provider, S3 o SQL. I vecchi writer MinIO, il provider legacy e Teatri non sono coinvolti. Fino a24 letture native da5secondi ciascuna,6 Docker GET,40 letture file runtime, deadline complessiva120secondi. Sono limiti del diagnostico, separati dal budget di analisi dei dati.

## Come usare il risultato

| Classificazione | Conseguenza |
| --- | --- |
| NATIVE_RUNTIME_OR_PROCESS_PRESENT | Individuare la generazione corrente prima di qualsiasi pulizia. |
| NATIVE_RUNTIME_DIRECTORY_REMAINS | Riconciliare lo stato runc rimasto nella radice registrata. |
| CONTAINERD_TASK_REMAINS / SHIM_REMAINS | Qualificare la rimozione dei soli residui provati; lo stato Docker exited non basta. |
| GUARD_OR_NAMESPACE_HANDLE_REMAINS | Verificare proprietà e contenuto delle regole/namespace prima della pulizia mirata. |
| NO_NATIVE_RESIDUE_OBSERVED | Nessuno dei residui controllati è osservato; i journal consumati restano conservati e la nuova generazione va comunque ammessa. |
| READ_INCOMPLETE | Il report identifica una lettura o una coerenza non dimostrata; non significa risorsa assente. |

Le osservazioni sono sequenziali, senza lock globale. Il successo del lettore non qualifica automaticamente cleanup o avvio: `cleanupQualified:false`, `startQualified:false`. Non riutilizzare gli esecutori terminali con approvazioni dell'ottobre scorso né riscrivere DELETING in DELETED.

## Prove e limiti

[CI 42580864748](https://github.com/GioNob/ouf-deploy/actions/runs/42580864748), job129038979362, log letti:16 test del nuovo lettore e10 regressioni dell'helper, zero skip. Casi coperti: null runc, output errato/nonzero, duplicati, PID presente con namespace illeggibile, task residuo, metadata containerd assenti, cambio concorrente e binding journal per candidato. Nessun test esegue il recupero sul VPS; non si dichiara qualifica nativa completa. Tre file pubblicati riletti byte per byte e sintassi Bash verificata.

[Dettagli](../evidence/discovery-lifecycle-reader-qualification-20261109.json). F1 resta acquisito; F2–F6 e il percorso funzionale1024 restano aperti. Dopo questo risultato: pulizia residua e nuova generazione provider, poi collegamento credenziale/TLS Semantic, backlog/grant e attivazione MCP già compilata.
