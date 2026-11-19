# R3 v13 — southbound verso identity provider sulla rete condivisa

D-051, R-027; sprint-01/task-67. Questa consegna prepara codice e prove;
non attesta installazione, start, TLS o discovery/JWKS sul VPS.

## Problema e flusso

APISIX usa discovery/JWKS dell'issuer HTTPS. Sul VPS il nome dell'issuer è
un alias Docker di Caddy sulla rete backend condivisa. La risoluzione porta
quindi all'endpoint privato, mentre la v12 ammette su quella faccia soltanto
Semantic → southbound:10443. Il successo attraverso l'IP pubblico e il lease
egress non prova il percorso scelto da APISIX.

La v13 aggiunge **un solo flusso logico**, `purpose: IDENTITY`, al transport
firmato del southbound. IP, MAC, rete, nome, alias e porta sono dati:

- andata: IP southbound → IP identity provider, TCP dport dell'issuer,
  `ct state { new, established }`;
- risposta: tupla inversa, TCP sport dell'issuer, `ct state established`;
- famiglia bridge: `ether daddr` del peer in andata, `ether saddr` del peer
  in risposta. Nessun ifindex del peer identity provider;
- famiglia inet: la stessa tupla e gli stessi stati; le risposte entrano
  dal bridge dichiarato;
- ARP sulla faccia backend: richiesta verso l'IP dichiarato con destinazione
  Ethernet broadcast o MAC del peer; risposte unicast. In ingresso si
  verificano MAC Ethernet, sender ARP e coppia di IP. Restano le coppie ARP
  necessarie per il peer Semantic già dichiarato. Le altre facce conservano
  le regole precedenti.

Una nuova connessione inversa non è una risposta established. Nessuna regola
generica verso la subnet, nessuna delega del backend al lease, nessun bypass
di TLS/IAM. Il binding BRIDGE_PORT del flusso Semantic preesistente resta
invariato: questa consegna non risolve R-002 su quel flusso.

## Origine indipendente dell'issuer

Le ricette southbound legano i file APISIX in `launch.sources` per percorso
e hash; non contengono il testo di discovery. Non è corretto estrarre un
hostname da un digest o aggiungere un valore issuer libero nel nuovo input.

L'alternativa già pubblica e legata è il kernel del coordinatore derivato
dal profilo P: in
`tools/semantic_transaction_network/build_target_network_policy.py`,
`assemble()` costruisce `providerFlows` aggiungendo `oidcIssuerEndpoint`
con la sorgente egress del southbound; il provider usa la sorgente adapter.
La migrazione e la v12 conservano tali endpoint nel kernel g2.

La v13 seleziona **l'unico** `providerFlows` la cui `source` appartiene alle
NIC firmate del southbound. Da `endpoint` ricava host HTTPS e porta (443
è il default del protocollo). Non seleziona per alias proposto, posizione
nell'array, hostname o IP costanti. Zero o più corrispondenze negano con
`R3_OIDC_ISSUER_AMBIGUOUS`; URL non HTTPS o con credenziali negano con
`R3_OIDC_ISSUER_REQUIRED`. Non si modifica il kernel per risolvere un diniego.
Questo evita di leggere o copiare file APISIX potenzialmente contenenti chiavi.

## Nuovo input e composizione

`DATA_INPUTS_V13 = DATA_INPUTS_V12 | {'identityProviderPeer'}`. Lo schema
dell'indice resta `ouf.semantic-provider-r3-inputs.v1`, con binding
`{path, sha256}`. Il nuovo documento canonico, eventualmente seguito da LF,
ha schema `ouf.semantic-identity-provider-peer.v1` e questi campi:

| Campo | Contenuto |
| --- | --- |
| `peer` | CID e nome container; nome/ID rete e bridge; IPv4 e MAC endpoint; alias issuer e lista completa ordinata degli alias; porta; `dockerBinding` `{path,sha256}` e `dockerSocket` come path locale assoluto |
| `southbound` | CID corrente, IPv4, nome/ID rete e bridge della sua faccia condivisa |
| `observationHashes` | SHA256 dei tre output formattati Docker: identityProvider, southbound, network |

La composizione confronta alias/porta con l'endpoint indipendente sopra,
richiede nome/ID rete e bridge coincidenti nelle due dichiarazioni e una NIC
southbound sul medesimo bridge e IPv4, senza `leaseGuard`.
Il lettore verifica anche il medesimo NetworkID in entrambi gli inspect e
la corrispondenza del bridge nelle opzioni della rete Docker.
Gli hash di osservazione sono lineage della lettura, non firme autonome.
Il nuovo file va legato per hash nell'indice e nel payload emesso.

`SOURCE_MAP_V13` conserva la closure v12 e aggiunge
`tools/semantic_provider_r3/identity_provider_v13.py`;
`SOURCE_INPUTS_V13` conserva anche il compilatore g1 trattenuto. Soltanto per
`version >= 13`, `sources_v13()` estende i moduli di peer, materializzazione,
template e admission nei documenti emessi. Gli ancoraggi sono verificati
esattamente una volta: drift dei sorgenti nega, non applica una sostituzione
parziale. L'helper viene incorporato nei byte sigillati della libreria peer;
il loader broker/driver mantiene il proprio set chiuso di nomi storici.

Le v1–v12 conservano ogni byte di input e output nelle fixture storiche.
`tests/fixtures/r3-v1-v12-pre-v13-hashes.json` conserva v1–v11 e aggiunge
la composizione v12 acquisita su HEAD
`a1828c66938cb2102c446ad4592ced6e2b002900`, prima delle modifiche.
Kernel g2, refresh, input e ricevute della migrazione restano quelli v12.

## Verifica live prima del processo

L'identità dichiarata è inclusa nel transport southbound firmato con
`peerIngress.kind: IDENTITY_PROVIDER_MAC`. Il preparer la rilegge prima
di costruire il profilo e installare le tabelle. Il driver la rilegge ad
ogni autorizzazione sincrona del preexec, anche prima di rilasciare il processo.
La policy risolta deve ancora coincidere esattamente con il transport firmato.

Ogni osservazione esegue due coppie di `docker inspect --format` e
`docker network inspect --format`. Verifica CID, nome, running, rete/NetworkID,
IP, MAC, tutti gli alias e bridge. Le due coppie devono essere identiche.
L'eseguibile Docker è controllato per hash/custodia prima e dopo ogni comando;
API **1.44**, ambiente fisso, stdin chiuso, timeout e output limitati. Non
si osservano `Config`, legacy `Config.MacAddress`, Env, mount o credenziali;
la MAC confrontata è esclusivamente quella dell'endpoint della rete scelta.
Non si acquisisce alcun ifindex del peer identity provider.

Drift nega con `R3_IDENTITY_PROVIDER_LIVE_DRIFT`. Restano i dinieghi del
trasporto source-bound per comando fallito, hash o custodia non validi.
`R3_IDENTITY_PROVIDER_ISSUER_DRIFT` e
`R3_IDENTITY_PROVIDER_NETWORK_NOT_SHARED` distinguono errori di composizione.
Non è un monitor continuo: dopo lo start le regole restano vincolate a IP/MAC,
mentre la verifica degli alias si ripete al successivo admission/start.

## Sequenza sul VPS per Claude

Procedura da generare con i percorsi e hash reali; non è stata eseguita da
questa worktree. Non rigenerare né applicare la migrazione g2. Non riusare
claim consumati. I wrapper `ops/vps/r3-*` restano da rigenerare con v13.

1. **Fermare il provider v12** con l'operatore R3 esistente: plan, review del
   plan, apply sul suo digest. Conservare epoche e ricevute; verificare CID
   fermi, epoche terminali, lease QUIESCED e g2 finalizzata. Caddy deve restare
   running perché è una dipendenza osservata, non un candidato da riavviare.
2. **Leggere l'identity provider.** Consegnare e verificare per hash i nuovi
   sorgenti. Da root Linux, con umask 077 e file nuovo, eseguire:

   ```sh
   set -euC
   umask 077
   /usr/bin/python3 -I -B tools/semantic_provider_r3/read_identity_provider_v13.py \
     --docker "$DOCKER" --docker-sha256 "$DOCKER_SHA256" \
     --docker-socket "$DOCKER_SOCKET_PATH" \
     --container "$IDP_CONTAINER_NAME" --network "$SHARED_NETWORK_NAME" \
     --southbound-id "$SOUTHBOUND_CID" \
     --coordinator "$G2_OWNER" --coordinator-sha256 "$G2_OWNER_SHA256" \
     --historical-template "$SOUTHBOUND_TEMPLATE" \
     --historical-template-sha256 "$SOUTHBOUND_TEMPLATE_SHA256" \
     > "$NEW_IDENTITY_INPUT"
   sha256sum "$NEW_IDENTITY_INPUT"
   ```

   `DOCKER_SOCKET_PATH` è un path assoluto, senza prefisso `unix://` (il
   lettore lo aggiunge). `SOUTHBOUND_TEMPLATE` è l'input historicalTemplate
   già usato dalla composizione. Il lettore non pubblica file: il redirect deve
   essere esclusivo (`set -C`, file assente) e non va riusato dopo un diniego.
   Verificare exit zero prima di usare il file. Conservare anche i tre hash
   di osservazione. Nessun comando di lifecycle, DNS, HTTP o TLS nel lettore.
3. **Preparare l'indice v13:** stessi input dati v12 e binding g2 correnti,
   più `files.identityProviderPeer` con path/hash appena acquisiti; `sources`
   esattamente `SOURCE_INPUTS_V13`. Non cambiare CID, ricette, accettazione,
   coordinatore, kernel, tabelle o storia per superare un diniego.
4. **Emettere v13:** `scripts/issue-semantic-provider-operation-authorization.py
   --supersede`, prima `--plan`, poi `--apply --plan-sha256` sul plan prodotto,
   con i consueti argomenti di input/autorizzazione. La testa deve essere v12
   OPERATE: la nuova sequenza è 13. Custodire payload, firma e ricevuta.
5. **Upgrade v12 → v13:** `scripts/upgrade-semantic-provider-r3.py`, plan e
   apply sul relativo digest, come nel [runbook upgrade](OUF_SEMANTIC_PROVIDER_R3_UPGRADE.md).
   È un upgrade normale: stesso owner/coordinatore g2, journal e lock;
   nessun nuovo caso speciale in `shared_state()`, nessuna migrazione.
6. **Start v13:** `scripts/operate-semantic-provider-r3.py --action start`,
   plan e apply sul relativo digest, con gli argomenti esistenti. Restano
   i controlli v12 (g2 finalizzata, sigillo nativo, predecessore assente,
   journal non BLOCKED e precondizioni di esercizio) più la verifica live
   del peer nel preparer/preexec. In caso di diniego conservare parziali e
   journal: non rilanciare start, emettere una seconda lettura o cambiare
   binding per simulare il successo.
7. **Prova applicativa separata:** dopo start, verificare discovery/JWKS e
   percorso APISIX con le autorizzazioni operative pertinenti. Il PASS del
   test TCP sintetico non prova issuer, certificati, JWT o E2E reali.

## Prove

Portabili: composizione deterministica, chiusura dei loader reali, golden
v1–v12, regole inet/bridge e ARP, mirror senza ifindex IdP, upgrade sullo
stesso coordinatore, dinieghi issuer/rete e cambiamenti IP/MAC/alias/NetworkID,
rilettura nel driver e lettore limitato a inspect formattati.

Il workflow R3 esistente `semantic-provider-r3-integration.yml`,
`ubuntu-24.04`, esegue la prova nativa con `OUF_R3_V13_NATIVE=1` e
`unshare --mount --net --fork`. Usa un bridge backend con southbound, IdP,
terzo host e Semantic in netns separate; carica le tabelle di ruolo emesse
dalla composizione v13. Prima prova tutti i listener senza filtro; poi prova
IdP:443 PASS, IdP:444 DROP, terzo:443 DROP e Semantic:10443 PASS. I positivi
devono fare ARP reale; i negativi TCP hanno neighbour espliciti per non
scambiare un mancato ARP per un diniego TCP. Si prova anche il verso inverso
NEW, che deve essere scartato. Il ciclo si ripete con br_netfilter disabilitato
e abilitato, controllando contatori bridge e inet. Opt-in non eseguibile
fallisce, senza skip. Fuori CI/root Linux la prova nativa è uno skip esplicito.

La rete, /run, i namespace, i listener e le regole del test sono sintetici e
isolati. Nessun container Docker o servizio esterno necessario.

## v14: verifica live solo nel preparer (18/11)

**Cosa è successo.** Lo start v13 sul VPS (epoca 15) è fallito nella fase
`start` del driver del southbound (`ADMISSION_OR_DRIVER_FAILED`). Le fasi
`prepare` e `hook` invece erano passate. L'adapter ha prodotto
`NODE_OBSERVATION_UNPROVEN` solo di conseguenza: ha preso il turno quando il
southbound era già caduto.

**Perché.** In modalità `start` il driver chiama `authorize()` tre volte, sotto
il lock comune e dentro un unico budget di verifica di 5 secondi
(`budgetSeconds`). La v13 aggiungeva a ogni chiamata quattro `docker inspect`,
eseguiti mentre dockerd avvia anche l'altro container. Già la fase `hook`
della v13 è durata circa 2 secondi in più dell'intero start della v12.

**Cosa cambia nella v14.** La v14 è identica alla v13, con gli stessi input e le
stesse regole, tranne un punto: il driver **non** rilegge più l'identity
provider dal vivo. La lettura live, doppia e confrontata, resta nel preparer.
Il preparer è l'admission di ogni start: gira una volta, prima che le tabelle
di ruolo vengano installate e verificate (`PROTECTED`).

**Perché resta sicuro.** Le regole bridge restano legate a IP e MAC dichiarati
di Caddy. Se l'identity provider cambiasse identità tra preparer e start, il
flusso non passerebbe e si fermerebbe in modo chiuso.

**Test.** La composizione v14 coincide con la v13 in ogni documento, tranne:
- il sorgente `driver_v7.py`, privo delle sole due righe della rilettura;
- i documenti che ne portano l'hash o la radice di versione.

Il preparer è byte per byte quello della v13.

**Sequenza sul VPS.** Emissione v14 (plan con lettura dell'identity provider,
poi apply), upgrade 13 → 14, start, sonda C.
