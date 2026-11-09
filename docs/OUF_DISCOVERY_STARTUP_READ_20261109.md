# Discovery: controllo dei binding di avvio v2

9 novembre 2026. La [lettura delle 07:24 CET](../evidence/discovery-activation-bindings-operator-20261109.json) è completata: Semantic e MCP sono running, provider v2 e southbound v2 sono exited. Il provider legacy resta created e senza reti. Le reti condivise sono presenti; connettività, configurazione effettiva e validità della credenziale non sono state provate.

Il file credenziale dichiarato da Semantic non ha mount. I sorgenti indicano materiale già preparato il 29 ottobre: un file credenziale e un truststore. La loro presenza e coerenza corrente sono ancora da verificare.

## Perché non basta ordinare docker start

Questi due CID v2 corrispondono alla creazione e all'avvio storici con runtime Docker personalizzato. Il suo codice tiene un registro di creazione/avvio e rifiuta replay di stati consumati. La ricevuta corrente non espone HostConfig.Runtime né quel registro. Non è ancora provato che un nuovo start possa usare gli stessi container.

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

## Comando corrente sul VPS

Come oufadmin, con la normale eventuale password sudo locale:

```bash
(
  set -euo pipefail
  ouf_startup_read=$(mktemp /tmp/ouf-startup-read.XXXXXX)
  trap 'rm -f -- "$ouf_startup_read"' EXIT
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 30 \
    'https://raw.githubusercontent.com/GioNob/ouf-deploy/8d44de9007487e312514d42dbfc5a0a0beadeccf/scripts/deliver-discovery-startup-20261109.sh' \
    -o "$ouf_startup_read"
  printf '%s  %s\n' 'c67471fd1ea84842adac361c597582df79f8d19af4c2a55241a581c757bd1309' "$ouf_startup_read" | sha256sum -c -
  bash "$ouf_startup_read"
)
```

Restituire soltanto il JSON finale. Esito generale atteso: DISCOVERY_STARTUP_INPUTS_READ; controllare anche gli esiti dei singoli blocchi runtime/configuration/preparedMaterial. Le prove private e il materiale esistente vanno conservati.

## Prove e riferimenti

Source `066168fafad38c0f722541e710fb46ce2ac370de`, reader SHA256 `0df0567b786f6d5317951c838062e166a4d5037a07d95a3c145b578949372a89`. Delivery `8d44de9007487e312514d42dbfc5a0a0beadeccf`, wrapper SHA256 `c67471fd1ea84842adac361c597582df79f8d19af4c2a55241a581c757bd1309`. Due sorgenti e wrapper riletti, sintassi Bash verificata.

Dieci test locali, zero errori/skip: frame prima di letture sensibili, scope dei percorsi/mount, runtime standard senza ammissione implicita, candidato assente e journal DELETED, esclusione di valori sensibili dal riepilogo, metadata preparati cambiati prima di accesso alla credenziale. Test reale OpenSSL con certificato temporaneo: validità/nome corretto accettati, nome diverso non coincidente, chiave privata rifiutata come input certificato. [Evidenza](../evidence/discovery-startup-reader-qualification-20261109.json). Non è una prova Docker nativa o VPS del nuovo reader.

Fonti del formato: [adapter e TLS](https://github.com/GioNob/ouf-api-gateway/tree/ace683b1019f79adaace86796b67e463b93ec12e/tools), [runtime personalizzato](../tools/semantic_cohort_admission/cohort-draft/scripts/semantic_provider_docker_runtime.py), [preparazione materiale per ruolo](../tools/m2_discovery_installation_profile/material_role_preparation.py). Sono fonti per interpretare i binding, non programmi storici da rieseguire.

## Passo successivo

Usare l'esito per preparare il ripristino del percorso provider/southbound e il mount credenziale/truststore Semantic con il minimo cambiamento necessario. Prima di abilitare il worker verificare il backlog. La build MCP con sei strumenti ACTIVE e i relativi grant rimangono da completare. Asset/profilo Teatri e budget persistente restano conservati.
