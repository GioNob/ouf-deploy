# Registro della configurazione dell'host

## Cattura e ricostruzione D-065

Il registro macchina aggiunge le voci `capture.*` alle otto voci storiche.
Il profilo privato associa istanze e percorsi agli ID, conserva la distinta
di custodia dei segreti e indica le tabelle di cui ripristinare il solo schema.
Il guard di boot Docker comprende unità, drop-in, puntatore e dispatcher.
La catena R3 conserva le ricevute e riemette l'autorità sull'host di prova.
[Registro](../tools/privileged_executor/host-register.json) ·
[Guard di boot](OUF_SEMANTIC_LEASE_KERNEL_MIGRATION.md)

La CI confronta unità, installer e schemi con i selettori del registro.
Ogni plan verifica indipendentemente le istanze osservate sull'host.
Il verbale del secondo host documenta la recuperabilità e l'RTO di ogni livello.
[Cattura, verifica e ricostruzione](OUF_CAPTURE_AND_REBUILD.md)

## Rilascio della configurazione APISIX

`deploy.gateway-release@2` registra il profilo privato, la chiave Admin di APISIX, lo stato per run e il puntatore all'ultimo rilascio. Il custode configura `gateway.source` con i soli campi `repository` e `workflow`. Per aggiornare un profilo precedente, rimuovere `gateway.source.tokenFile` dal JSON prima del bootstrap. Il plan e l’apply leggono i metadati e scaricano lo ZIP del repository pubblico con il token temporaneo che il workflow passa su stdin. Il bearer viene inviato solo ad `api.github.com`. Il profilo contiene anche socket Docker, container, IP di loopback e porta nel namespace APISIX, percorso della chiave Admin e dizionario `values` per i segnaposto. Il file della chiave resta privato, di proprietà di root e con antenati in custodia root. [Profilo di esempio](privileged-executor.example.json) · [Registro host](../tools/privileged_executor/host-register.json)

Nel dispatch `release`, indicare run CI, artifact ID, PR e SHA della testa revisionata. Il plan scarica lo ZIP originale, verifica i tre file v1 e pubblica i conteggi per azione con l'impronta da approvare. L'apply ripete la verifica e confronta lo stato vivo prima delle scritture. Il journal privato conserva il piano, lo snapshot, le review, gli intenti e il risultato. La ricevuta APPLIED fornisce `releaseRun` e `receipt` per un dispatch `return` con una nuova review. Il ritorno controlla il rilascio corrente, la generazione e i corpi prima di ripristinare lo snapshot. [Workflow di rilascio](../.github/workflows/gateway-release.yml)

Prima di approvare, aprire **Annotations** in cima alla pagina del run e leggere **Da approvare: apply** oppure **Da approvare: return**. Confrontare il digest con il nome del job. Se l’annotazione è troncata, la sezione **Cosa approvi** in testa al riepilogo del job precedente contiene l’elenco completo. Dopo i conteggi, la tabella elenca tutte le risorse nell’ordine del bundle. Questo esempio usa rotte illustrative.

| Risorsa | Azione | Campi che cambiano |
|---|---|---|
| `routes/a` | nuova | — |
| `routes/b` | modificata | `upstream.nodes[0].port`, `uri` |
| `routes/c` | invariata | — |

Per ogni risorsa modificata il riepilogo pubblica solo i percorsi dei campi, fino a 64. La voce finale `… N altri` indica quanti percorsi ulteriori sono stati omessi. Con un esecutore precedente che restituisce solo i conteggi, il riepilogo passa dai conteggi direttamente al job da approvare.

Per il recupero, acquisire sotto lock profilo, journal per run e `gateway-head` come insieme coerente e cifrato. Ripristinarli dopo il bootstrap dello stesso commit. Una testa `PENDING` conserva l'esclusione dopo un'interruzione o una compensazione non verificabile. Il custode riconcilia gli intenti e le risorse coinvolte prima di riaprire il rilascio. La prova nativa copre ritorno, rifiuto di una rotta e ripristino su APISIX temporaneo. [Prova nativa](../tests/test_gateway_release_native.py)

## Rilascio dei moduli applicativi

Le voci D-065 descrivono i tipi di archivio di competenza deploy. La distinta privata associa ogni istanza al modulo, alla revisione dell'esecutore, al commit del modulo e ai digest approvati. [Guida di rilascio](OUF_MODULE_RELEASE.md)

| Identificativo e versione | Responsabile, archivio e contenuto | Classe e segreti | Cattura | Ripristino, dipendenze e ordine | Prova di ripristino |
|---|---|---|---|---|---|
| `deploy.module-release.profile@2` | Custode dell'esecutore. Sezione `modules.onboarding` del profilo privato con nomi, reti, IP, alias, image ID, pin CI, migrazione, gate, readiness e percorsi. Comprende il riferimento all'inbox configurata nell'environment del trasporto. | Configurazione. Segreti esclusi dal profilo. | Acquisire copia privata, SHA-256 canonico, proprietario, permessi e versione del modulo esecutore. Registrare il collegamento tra inbox e variabile di environment. | Ripristinare percorsi, proprietari e profilo dopo l'esecutore fissato e prima dei pacchetti. Ricostituire environment e revisori secondo D-072. | Validare il profilo, confrontarne il digest e verificare che l'inbox contenga lo ZIP atteso. |
| `deploy.module-release.artifact@1` | Custode del trasporto. ZIP originale della CI, manifest, immagine e ricevuta di provenienza. | Configurazione. Immagine pubblicabile, senza credenziali di esercizio. | Conservare i byte dello ZIP e la ricevuta con repository, run, tentativo, artifact ID, commit, alberi e digest. | Dopo il profilo, ripristinare lo ZIP con nome per digest nell'inbox. Conservarlo anche oltre la scadenza dell'artefatto CI. | Ricalcolare SHA-256 esterno e interno e verificare tag, label e identità Docker/OCI con il lettore di pacchetto. |
| `deploy.module-release.journal@2` | Custode dell'esecutore. Lock, digest consumato, inspect precedente, CID, generazione al cancello, piano e consumo della migrazione, intenti, ricevute terminali e relative firme `receipt.ed25519` e `return-receipt.ed25519` quando presenti. | Configurazione privata. Trattare come segreta la baseline che può includere ENV sensibili. Custode e consumatore sono l'esecutore e l'owner del recupero. Le credenziali presenti seguono la rotazione del rispettivo produttore. | Cattura privata cifrata e coerente di journal e lock durante la quiescenza. Preservare tutti i tentativi, permessi e ricevute. | Dopo profilo e archivio, ripristinare la custodia prima di abilitare apply. Riconciliare CID, reti, intento di segnale e digest consumati con i container presenti sull'host. | Verificare rifiuto del replay e ritorno simulato con stessa identità e readiness. Su un host ricostruito qualificare le identità effettive prima di riaprire il mandato. |

Il profilo `modules.mcp` aggiunge eseguibile, argv, readiness 204, pin del trasporto, CID PostgreSQL, socket locale, variabile di binding del servizio, versione iniziale, lista e impronta delle migrazioni e schema finale per la modalità dedicata. L'environment protetto custodisce il riferimento `MCP_RELEASE_TRANSPORT_PROFILE`. Conservare la ricevuta con lo ZIP e i due journal con la fotografia SQL iniziale. In prova di recupero verificare il rifiuto del ritorno a storia o schema difforme prima dello stop del candidato. [Voce D-065 deploy.module-release.mcp@1](../tools/privileged_executor/host-register.json)

## Esecutore privilegiato condiviso

La voce `deploy.a2.successor-image@1` copre lo ZIP Semantic selezionato, entrambi gli image ID, gli inventari Flyway e la review sul CID al cancello. La restituzione del CID originario presuppone la compatibilità dello schema applicato con l’immagine conservata, qualificata nel task-24c. [Custodia e prova di ripristino](../tools/privileged_executor/host-register.json)

Le voci `deploy.a2.executor@2`, `deploy.a2.profile@2` e `deploy.a2.journal@2` registrano sorgenti, custode, cattura, ordine di ripristino e prova. Ripristinare insieme il journal del run e quello del modulo per riconciliare la terza approvazione con il CID al cancello. La configurazione dell’inventario contiene container, socket locale, ruolo, database e mappa IAM. La ricevuta della prova chatbot segue la ricevuta del cutover. [Registro host](../tools/privileged_executor/host-register.json)
