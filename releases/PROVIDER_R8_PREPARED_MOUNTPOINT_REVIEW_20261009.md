# R8 — proposta concreta di accettazione del rootfs preparato e recupero

**Stato: proposta, approvazione umana ancora assente. Executor e launcher sono inerti. Nessun nuovo avvio o cleanup eseguito sul VPS. R7 è consumato.**

## Evidenza e causa

La lettura riportata dall'operatore il 9 ottobre alle 20:09:27 Europe/Rome è completa, exit 0: snapshot `/etc/ouf/deploy-snapshots/semantic-r7-rootfs-read-cxgamg_7`, SHA256 canonico della diagnosi `8ed76674a2d31377457d5942892c98310a4625ee96296492e9d07a41c1a22b72`. [Ricevuta integrale](../evidence/provider-r7-rootfs-target-20261009.json). È evidenza fornita dall'operatore, non acquisita indipendentemente dal cloud.

Il confronto con l'immagine offline identifica soltanto sei nuove voci adapter e tre southbound nella semantica dell'immagine. Nessuna differenza di contenuto, permessi, proprietari, xattr o link dei file già presenti. Tutte le nuove voci corrispondono ai bind OCI dichiarati o al loro unico nuovo genitore. I byte totali restano invariati. I contatori link delle directory e il modo della radice offline sono trattati esattamente come nella comparazione di immagine già documentata; il sigillo v1 integrale a runtime non viene normalizzato né indebolito.

L'errore di progettazione era accettare il sigillo del container fermo prima della creazione dei punti di mount, per poi confrontarlo con il rootfs preparato dal runtime. La lettura corrente prova le nove voci aggiunte; il test nativo riproduce il meccanismo con destinazioni inizialmente assenti. Il vecchio sigillo osservato nell'eccezione R7 non era stato conservato: questa lettura non pretende di ricostruirlo. L'errore adapter durante la lettura del peer resta compatibile con la rimozione di southbound, senza prova dell'ordine storico.

## Esatto ampliamento dell'accettazione proposto

| Ruolo | CID | Nuove voci vuote ammesse |
|---|---|---|
| adapter | `f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67` | directory `/run/ouf-semantic-provider`; file `adapter.json`, `provider-receipt.key`, `server.crt`, `server.key`, `trust-bundle.pem` in quella directory |
| southbound | `1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916` | directory `/run/ouf-semantic-provider`; file `/run/ouf-semantic-provider/trust-bundle.pem` e `/usr/local/apisix/conf/apisix.yaml` |

Directory root:root 0755; file root:root 0644, zero byte, un link, nessun xattr. Sono i placeholder sottostanti ai bind, non i contenuti privati montati. Ogni file deve corrispondere esattamente a un bind `ro` dell'OCI già accettato. Nessun percorso aggiuntivo, file riempito, nuovo link o altro cambiamento è ammesso dalla verifica della proposta.

| Ruolo | Vecchio sigillo v1 conservato | Nuovo sigillo v1 proposto | Voci e byte del nuovo sigillo |
|---|---|---|---|
| adapter | `8744724088d02145b86b433058a4336fcb9c873a4a92e7009753209c284d3d73` | `92c26698ef0899e909a503f5db856f55a1cc0cf44c8f6648ba4d498a6c2533c4` | 3396; 46079786 |
| southbound | `52e06f47e1da5a107525e2260b9d375329997181dd13de7023654278aeaf3f39` | `4236ebc8a571b5f177f2365ccfed78ba3b0bd43fce2ea75c1e34c0b90f7a844d` | 7461; 255900260 |

I nuovi valori non concedono autorità da soli. Il verificatore ricostruisce i sigilli dalle mappe private complete, verifica l'immagine offline originale, deriva esclusivamente le nove voci dall'OCI accettato e confronta tutto il resto. La nuova approvazione umana viene poi vincolata a mandati root e firme di ruolo distinti. Le precedenti accettazioni restano immutabili. PET Authorization v1.5 AUTH-05–12 e Matrice v1.7 consultati; nessuna fixture o chiave CI è autorizzazione target.

Le immagini manifest/config, i sedici input, i due CID, i profili OCI, gli utenti 10006/636, i limiti, i mount reali e le reti restano quelli già accettati. La chiusura runtime resta `4b9fbd3149b417a2a696302784aa54d0569b5e87ddc66ac439c153c9ab16bc02`: nessun file del runtime cambia. Il nuovo pacchetto modifica soltanto i due sigilli letterali dell'utility di autenticazione e i riferimenti di manifest/wrapper nell'entrypoint.

## Transazione proposta, una volta sola

1. Leggere nuovamente lo stato corrente e confrontarlo con i fatti R7 già ricevuti; verificare le mappe complete e i nove placeholder. Riutilizzare il lettore locale esistente, senza reinstallarlo. Questa verifica prima della mutazione non ripete la preparazione di immagini o input.
2. Riservare un nuovo contesto R8; prevalidare entrambi i nuovi mandati con le autorità esistenti, senza firme né lettura delle chiavi, prima della manutenzione. Su un diniego conservare la diagnosi e fermarsi.
3. Eliminare soltanto i due task containerd `STOPPED`, con PID applicativi assenti e nessuna voce runc, mediante il gate temporaneo alias-aware già riuscito in R6. Niente force, kill, cancellazione dei container o restart dei daemon. Ripristinare esattamente il wrapper R7 e verificare il guard vuoto.
4. Emettere nuovi mandati di 240 secondi per i due sigilli proposti, riusando le chiavi di ruolo esistenti; pubblicare il pacchetto coerente in un nuovo snapshot, effettuare lo switch sotto guard e invocare una sola ammissione coordinata dei due CID tramite il percorso esistente. Nessun Docker start diretto o retry automatico.
5. Conservare diagnosi e risultati, inclusi fase, motivo e tracce redatte. Non trasformare l'eventuale avvio in accettazione di release, lease provider, reboot, salute applicativa o successo della filiera Teatri.

| CID/ruolo | Task STOPPED, PID assente | Shim PID / startTicks | Hash metadati containerd da preservare |
|---|---|---|---|
| adapter | 1806098 | 1806045 / 190930717 | `cbdba850b09632b8e14948d19771e2d82ef9c64801176342dcec5ac147881f34` |
| southbound | 1806118 | 1806057 / 190930718 | `ffdcbe53176a3a0200da521e2f7e0731c27986c0dcd2a6e6e1edb4db0dfe7659` |

Wrapper R7 `050cb98116da36efd315d93f4e95471dfe0543c8447fd135b7b1261c7bf587e2`; owner guard `656c23f18e3f3eb4c1ce630f5056be87f7883eab7b048065092dafbd018284a8`; root runtime `c64c266a92b2d9ff052a8f2b817ee730406b2ddde47d550a52effb822b181342`. Scope completo, incluse generazioni shim, hash argv, immagini e input: [JSON](../evidence/provider-r8-mountpoint-recovery-scope-20261009.json), SHA256 `24f6c5a25893e1757bb903b74b90155e39d19864d377ed3a31a94e80bfce1a86`.

## Verifica e consegna

[CI nativa 37972142027](https://github.com/GioNob/ouf-deploy/actions/runs/37972142027): tutti e quattro i job riusciti. La nuova prova usa un'immagine sintetica di 7525 voci e 264328608 byte, utenti distinti e root readonly/non-readonly, cinque e due bind su destinazioni mancanti. I sigilli attesi vengono derivati prima di creare i candidati, su overlay indipendenti. I due programmi arrivano al marker applicativo attraverso pubblicazione e broker/node/approval/preparer/driver reali; il sigillo precedente risulta diverso, il controllo v1 resta integrale. [Ricevuta della verifica](../evidence/provider-r8-prepared-rootfs-native-validation-20261009.json). È una verifica del meccanismo e dell'implementazione, non un'osservazione dell'avvio sul VPS.

Le prove mirate coprono rifiuto di dati/permessi/link/xattr diversi, integrità del pacchetto, approvazioni vecchie/scadute, cambiamento PID/sigillo/wrapper, rimozione dei soli due task, ripristino del wrapper anche al fallimento della seconda rimozione e consegna con gh fuori dal PATH. Nessun comando mutatore è stato eseguito sul VPS durante questa preparazione.

Executor e scope: commit `7d377692e8714f439cea819b6d1aabf0dad0db7b`; executor SHA256 `7a4d68895c33c01562298948cfdb2c65c18c1b3525eeb34e8bc36891a998ba3e`. Launcher `releases/provider-prepared-mountpoint-recovery-20261009.sh`, ancora `PENDING_PREPARED_MOUNTPOINT_RECOVERY_APPROVAL`. Non viene fornito un comando di esecuzione finché questa proposta non è approvata.

Alla ricezione dell'approvazione umana registrare riferimento e orario reali, impostare soltanto le tre costanti di approvazione e aggiornare i pin di consegna, verificare i byte remoti e il percorso del launcher, quindi consegnare il singolo blocco operatore con gh esplicito: `$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh`. Non chiedere nuovamente l'approvazione già appena concessa. Non cambiare scope, accettazioni o codice a sua insaputa.

Gli helper locali R6 e R7 già eseguiti vengono riutilizzati per hash; si trasferiscono soltanto il nuovo executor, il verificatore della proposta e lo scope. La dependency evidence corrente scade il **10 ottobre 2026 alle 06:33:47Z (08:33:47 Europe/Rome)**; la manutenzione e la nuova finestra dei mandati devono rientrare nella validità, senza estensioni implicite. Qualsiasi nuova incertezza conserva il claim e impedisce il replay.

La filiera prodotto resta aperta: asset Teatri `6609b245-86ed-4315-8ce0-73f2a8555bf3`, profilo `7984c39c-7396-4248-ab0a-f2efc390b49c` già presenti; nessun job nazionale, ricaricamento o fallback locale. Dopo provider: Semantic/MCP, grant discovery e filiera chatbot → approvazione umana → onboarding → ingestion/duplicati/merge → UDP/MCP.
