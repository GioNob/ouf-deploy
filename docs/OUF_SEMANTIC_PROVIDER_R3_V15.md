# R3 v15 — route D-052 e flussi dichiarati

Sprint 01, task 70 · D-052.2 · R-028

## Problema

Il nome Docker dell’adapter compare su due reti. Risolverlo come nodo
upstream può far scegliere ad APISIX l’IP egress, mentre il flusso
`GATEWAY_ADAPTER` ammette l’IP interno. D-052 pubblica il nodo numerico
nella sorgente già montata e conserva `upstream_host` per TLS. D-052.2
verifica la corrispondenza al momento dell’emissione dell’autorizzazione
R3. [Pubblicazione D-052 e contratti B1 v3/g6](OUF_SEMANTIC_PROVIDER_ROUTES_D052.md)

## Controlli

| Verifica v15 | Diniego |
| --- | --- |
| Percorso e SHA-256 della proiezione coincidono con la sorgente del mount `/run/ouf-semantic-provider/historical-apisix.yaml` nelle ricette launch e policy del southbound. | `R3_EGRESS_CONFIG_UNPROVEN` |
| Esiste un solo `GATEWAY_ADAPTER` TCP nel candidato southbound. La stessa tupla `(purpose, source, destination, protocol, port)` compare una volta in `coordinator.kernel.staticFlows`. | `R3_EGRESS_FLOW_MISSING`, `R3_EGRESS_FLOW_AMBIGUOUS` |
| Tutte le route hanno un solo nodo con IP interno dell’adapter e porta del flusso. Le NIC interne dei due ruoli condividono il bridge. Un nome come nodo, la NIC egress dell’adapter o una porta diversa fanno fallire il confronto. | `R3_UPSTREAM_FLOW_MISMATCH` |
| L’upstream usa `https` e `pass_host: rewrite`. Tutte le route usano lo stesso `upstream_host`, presente testualmente nei SAN DNS del certificato. Il digest del certificato nella proiezione coincide con la voce di `server.crt` in `adapter/launch.sources` e `adapter/policy.sources`. | `R3_UPSTREAM_TLS_IDENTITY_MISMATCH` |
| Host e porta di `discovery` e dell’eventuale `issuer` coincidono con quelli ricavati da `identity_provider_v13.issuer_endpoint`. Il transport composto contiene l’unico flusso `IDENTITY` TCP verso quella porta con il peer legato da v13. | `R3_EGRESS_NETWORK_MISMATCH` |
| Un nodo su un peer IP estraneo all’adapter o un campo di uscita ulteriore nella proiezione eccede i flussi verificati. Il parser D-052 chiude il profilo di configurazione anche prima della proiezione. | `R3_EGRESS_FLOW_MISSING` |

Il controllo riguarda le destinazioni dichiarate nel file e nel kernel,
incluso l’endpoint OIDC. La prova TLS, lo scambio OIDC/JWKS e la chiamata
applicativa richiedono verifiche dopo l’avvio.

## Lettore e input da legare

Invocare `read_routes_v15.py` dalla consegna fissata per commit durante il
plan di emissione, con UID e GID effettivi root su Linux. Gli argomenti
sono tutti obbligatori.

```bash
sudo /usr/bin/python3.13 -I -B "$delivery/tools/semantic_provider_r3/read_routes_v15.py" \
  --routes "$routes_source" --routes-sha256 "$routes_sha256" \
  --southbound-launch "$southbound_launch" --southbound-launch-sha256 "$southbound_launch_sha256" \
  --southbound-policy "$southbound_policy" --southbound-policy-sha256 "$southbound_policy_sha256" \
  --adapter-launch "$adapter_launch" --adapter-launch-sha256 "$adapter_launch_sha256" \
  --openssl "$openssl_path" --openssl-sha256 "$openssl_sha256"
```

- `--routes` indica il **percorso host** nella voce della ricetta, ossia
  `apisix.yaml` nella consegna D-052. Legare `--routes-sha256` al digest
  post-pubblicazione confermato dalla ricevuta D-052 e dal risultato B1 v3.
- I tre binding di ricetta provengono dal risultato B1 v3. Usare il
  `path` e lo `sha256` del `opensslBinding` di `ops/vps/r3-settings.json`.
  Il binding di `server.crt` proviene dall’unica sorgente con quel nome
  in `adapter/launch.sources`. Il lettore applica UID, GID, modo, limite
  di dimensione e SHA-256 delle voci ai file montati e rilegge gli input
  per hash prima di pubblicare la proiezione.
- Il certificato è un singolo PEM pubblico. Il lettore respinge il
  marcatore `PRIVATE KEY`, verifica il binario OpenSSL prima e dopo
  l’esecuzione e gli passa i byte verificati su stdin in un ambiente
  esplicito. Da `x509 -outform DER` estrae la sola estensione SAN DNS
  strutturata. Il confronto usa i nomi esatti, senza espansione wildcard.
- Lo stdout contiene un solo JSON canonico con LF. Ai campi di
  `routes.project` si aggiunge `adapterTlsIdentity` con
  `certificateSha256` e `dnsNames` ordinati e unici. Le policy, i byte del
  certificato, `ssls`, le chiavi e `client_secret` sono esclusi dalla
  proiezione. Un diniego restituisce exit 1 e un solo codice pubblico su
  stderr, per esempio `R3_ADAPTER_CERTIFICATE_PRIVATE_KEY`,
  `R3_ADAPTER_CERTIFICATE_READ_DENIED`,
  `R3_ADAPTER_CERTIFICATE_SAN_UNPROVEN` o `R3_ROUTES_OPENSSL_UNPROVEN`.

`DATA_INPUTS_V15 = DATA_INPUTS_V13 | {'southbound/routesProjection'}`.
Pubblicare lo stdout riuscito in un nuovo file `routes-projection.json`
root:root `0600` nella consegna. Nell’indice `ouf.semantic-provider-r3-inputs.v1`
aggiungere `files['southbound/routesProjection'] = {path, sha256}`, con
l’hash dei byte esatti, LF incluso. Emissione e upgrade usano lo stesso
file e lo stesso pin. Il file APISIX originale e il certificato rimangono
sorgenti della ricetta, in custodia. La proiezione è tracciata negli hash
degli input del piano. L’autorizzazione lega il digest della policy di
frame, che contiene il digest della sorgente APISIX.

`SOURCE_INPUTS_V15` conserva i pin v13/v14, incluso il compilatore g1, e
aggiunge quattro binding `{path, sha256}` nella sezione `sources`,
tutti dai byte della stessa consegna revisionata.

- `tools/semantic_provider_r3/egress_v15.py`
- `tools/semantic_provider_r3/read_routes_v15.py`
- `tools/semantic_provider_routes/routes.py`
- `tools/semantic_provider_routes/custody.py`

I controlli si applicano da `version >= 15`. I moduli aggiunti non entrano
nelle closure di esecuzione del broker e del supervisore. I golden
verificano byte degli input, documenti e autorizzazioni v1–v14.

## Sequenza sul VPS per Claude

1. Con entrambi i CID fermi, verificare g2 `QUIESCED`, lease e start
   disabilitati, e testa `OPERATE` v14. Acquisire la ricevuta D-052 di
   pubblicazione, quella B1 v3 e il manifest firmato di acceptance g6.
   Usare il digest del manifest confermato da g6 come pin di `acceptance`.
2. Rigenerare emissione e upgrade con la stessa consegna revisionata.
   Puntare i blocchi `adapter/*` e `southbound/*` delle ricette al
   risultato B1 v3 e verificare i relativi pin. Cambiano soltanto i byte
   di `southbound/launch` e `southbound/policy`. Conservare i binding
   `historicalTemplate`, A2, D-042, `identityProviderPeer` e l’intera
   catena di migrazione g2 secondo la procedura R3 corrente.
3. Al plan di emissione, acquisire `identityProviderPeer` con il lettore
   v13 e la proiezione con il lettore v15. Registrare gli hash dei due
   file nell’indice. Verificare `DATA_INPUTS_V15` e `SOURCE_INPUTS_V15` e
   fissare il digest di `inputs.json` per plan/apply e upgrade. Pubblicare
   la proiezione soltanto dopo l’exit 0 del lettore. Conservare il file
   originale del plan per la ricomposizione.
4. Eseguire il normale plan/apply dell’emissione v15 con supersessione
   di v14, quindi il normale plan/apply di upgrade. Verificare i CID,
   i transport, i sigilli D-042 e il kernel del lease già legati. Il
   percorso `upgrade.py` ricompone con la sequenza della testa, confronta
   il payload v15 firmato e richiede candidati e coordinatore condivisi.
   La prova locale confronta v14/B1 precedente/g5 con v15/B1 v3/g6 e
   passa dai controlli di payload e stato condiviso dell’upgrade.
5. Usare il percorso esistente di `operate.py` per il controllo a coppia
   ferma e lo start governato. Gli epoch terminali conservano la loro
   autorizzazione storica. `volatile_restore.py` continua a confrontare
   i CID, l’OCI atteso e i sigilli D-042. Il cambio dei soli digest nelle
   sorgenti di frame preserva questi valori, inclusa la sorgente del
   mount. Entrambi i moduli usano i binding della versione selezionata.
   Dopo lo start, verificare TLS/OIDC e il percorso applicativo con le
   prove operative esistenti.

La sequenza VPS è da eseguire dopo la review. Le prove di questa consegna
usano fixture sintetiche e mantengono separato l’esito operativo.
La rigenerazione delle consegne `ops/vps` comprende anche i manifest
software che fissano il vecchio digest di `compose.py`. Il test di
consegna di `r3-autostart-install.sh` segnala tale differenza finché quel
pin conserva i byte di v14.
