# Discovery: controllo dei binding di avvio v2

9 novembre 2026. La [lettura delle 07:24 CET](../evidence/discovery-activation-bindings-operator-20261109.json) è completata: Semantic e MCP sono running, provider v2 e southbound v2 sono exited. Il provider legacy resta created e senza reti. Le reti condivise sono presenti; connettività, configurazione effettiva e validità della credenziale non sono state provate.

**Eseguito e concluso alle 07:51 CET:** [ricevuta operatore](../evidence/discovery-startup-inputs-operator-20261109.json). Credenziale e truststore preparati risultano coerenti con i riferimenti conservati, ma non installati. Certificati validi per data e nome; catena TLS, handshake e credenziale presso l'issuer non ancora provati. Adapter DELETED e southbound DELETING nei journal del runtime personalizzato.

## Perché non basta ordinare docker start

Questi due CID v2 corrispondono alla creazione e all'avvio storici con runtime Docker personalizzato. Il suo codice tiene un registro di creazione/avvio e rifiuta replay di stati consumati. La ricevuta delle 07:51 CET conferma il runtime v4 e i due journal: adapter DELETED, southbound DELETING. Il codice create accetta solo STAGED e start solo CREATED; questi stati non consentono un normale restart. DELETING non prova da solo un task nativo residuo né la causa della pulizia incompleta.

Il reader verifica il runtime attualmente registrato e l'eventuale entry dei due CID. Legge il wrapper e il sorgente solo come dati, ne confronta gli hash e legge il broker/journal associato. Non esegue codice dal VPS, non invoca broker, non modifica il registro o il runtime, non riusa autorizzazioni storiche e non avvia alcun container. Un journal DELETED o un candidato assente resta un risultato da affrontare, non viene resettato.

## Contenuto della verifica

- Tre container esatti, vincolati alle impronte API1.44 della ricevuta: Semantic, provider v2 e southbound v2. MCP e provider legacy non vengono toccati.
- Configurazione adapter e due file APISIX dai soli mount bind read-only dichiarati. Essendo i container fermi, questa è una lettura dei sorgenti host, non della vista applicativa montata.
- Corrispondenza dei path search/fetch, workload/scope/audience dichiarati, riferimento della credenziale OIDC, dichiarazioni TLS e certificati.
- Validità temporale e nome host dei certificati con OpenSSL locale. Nessun handshake, richiesta provider o prova della catena di fiducia.
- Un solo file credenziale già preparato, seguito da un record metadata con hash noto: confronto dei byte, dei permessi e delle dichiarazioni d'identità, senza mostrare valore o hash della credenziale. Nessuna autenticazione presso Keycloak.
- Truststore preparato: confronto con hash e metadata conservati, senza installazione.
- Frame dei container e registrazione dei runtime confrontati prima/dopo. Nessuna normalizzazione del campo MAC.

La lettura può aprire materiale sensibile già incluso nella configurazione APISIX (chiave TLS incorporata) e la credenziale preparata selezionata. Il riepilogo non li emette. I file di chiave TLS separati dell'adapter non vengono aperti. Nessuna scrittura a configurazioni, credenziali, DB o servizi; soltanto nuove prove private nella directory operativa.

Massimo 8 GET Docker, 40 letture file limitate a 16 MiB complessivi, deadline del reader 90 secondi. I componenti di lettura indipendenti conservano un motivo READ_INCOMPLETE senza stampare messaggi arbitrari. Il risultato non è un'autorizzazione tecnica del runtime né una prova E2E.

## Lettura completata

Non ripetere il comando. Nessun servizio avviato, DB, token o richiesta provider. `startAdmitted:false` è un valore dichiarato dal reader: non è il risultato di un'ammissione o avvio tentati. Il report osserva file host dei mount fermati, non la configurazione Spring effettiva.

I sorgenti e la delivery rimangono nei commit indicati sotto per riproducibilità storica. Le prove private restano in `/var/lib/ouf-storage-migration/discovery-startup-inputs-te5d6tiq`.

## Prove e riferimenti

Source `066168fafad38c0f722541e710fb46ce2ac370de`, reader SHA256 `0df0567b786f6d5317951c838062e166a4d5037a07d95a3c145b578949372a89`. Delivery `8d44de9007487e312514d42dbfc5a0a0beadeccf`, wrapper SHA256 `c67471fd1ea84842adac361c597582df79f8d19af4c2a55241a581c757bd1309`. Due sorgenti e wrapper riletti, sintassi Bash verificata.

Dieci test locali, zero errori/skip: frame prima di letture sensibili, scope dei percorsi/mount, runtime standard senza ammissione implicita, candidato assente e journal DELETED, esclusione di valori sensibili dal riepilogo, metadata preparati cambiati prima di accesso alla credenziale. Test reale OpenSSL con certificato temporaneo: validità/nome corretto accettati, nome diverso non coincidente, chiave privata rifiutata come input certificato. [Evidenza](../evidence/discovery-startup-reader-qualification-20261109.json). Non è una prova Docker nativa o VPS del nuovo reader.

Fonti del formato: [adapter e TLS](https://github.com/GioNob/ouf-api-gateway/tree/ace683b1019f79adaace86796b67e463b93ec12e/tools), [runtime personalizzato](../tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_docker_runtime.py), [preparazione materiale per ruolo](../tools/m2_discovery_installation_profile/material_role_preparation.py). Sono fonti per interpretare i binding, non programmi storici da rieseguire.

## Passo successivo

Occorre riconciliare il lifecycle nativo del southbound e preparare una nuova generazione ammessa per il percorso provider, conservando i journal precedenti. Non modificare DELETED/DELETING in STAGED e non sostituire il runtime con runc per eludere l'ammissione. Le prove native storiche del provider/worker sono componenti riusabili, non un installer corrente già pronto. Stato dei task/handle residui e avviatore per questa installazione restano da qualificare.

Poi collegare la credenziale/truststore preparati a Semantic, verificare trasporto/issuer e backlog, abilitare il worker. La [PR MCP84](https://github.com/GioNob/ouf-mcp-server/pull/84) ha qualificato manifesto ACTIVE e immagine con test/CI; non installa nulla sul VPS. Asset/profilo Teatri e budget persistente restano conservati.
