# Passo C — sonda JWT/TLS governata (D-049)

La sonda verifica il percorso applicativo del Semantic senza riavviarlo né
modificarlo (R-002). Il codice e le prove locali non attestano un risultato sul
VPS. L'esecuzione operativa resta un'invocazione umana di plan e apply.

## Input e custodia

`scripts/probe-semantic-provider-c.py` richiede Linux, root:root e Python con
`-I -B` e `os.setns` (Python 3.12 o successivo). Importa gli strumenti R3 in sola
lettura. Non emette firme, rinnova lease, modifica nft o invoca lifecycle Docker.

Gli argomenti comuni sono:

| Argomenti | Binding |
| --- | --- |
| `--install-root`, `--wrapper`, `--wrapper-sha256` | Installazione R3 e wrapper attivo |
| `--docker`, `--docker-sha256`, `--docker-socket` | CLI Docker verificata prima e dopo inspect |
| `--systemctl`, `--systemctl-sha256`, `--nft`, `--nft-sha256` | Lettori R3 già esistenti |
| `--issuance-home` | Home dell’operatore che ha emesso l’autorizzazione R3, ricavata dal runbook |
| `--inputs`, `--inputs-sha256` | Override esplicito del manifest degli input R3 e della sua impronta |
| `--installation-profile`, `--installation-profile-sha256` | Profilo `ouf.semantic-provider-installation.v1` |
| `--southbound-ca`, `--southbound-ca-sha256` | Bundle PEM pubblico verificato con custodia root |
| `--output-directory` | Directory nuova `/etc/ouf/deploy-snapshots/semantic-provider-c-probe-YYYYMMDDTHHMMSSZ` |

Il runbook usa la sequenza autenticata dai due ruoli per leggere lo stato scritto
da `r3-issue` per quella versione. Verifica l’istante di emissione firmato, la
custodia root dell’indice indicato e il digest firmato dell’accettazione. La
proposta lega il percorso e il digest dell’indice per il successivo apply.
Il puntatore della sonda è `/root/.ouf-c-probe-state`, configurabile con
`C_PROBE_STATE`. Per la cattura D-065 il responsabile della sonda conserva
il puntatore (solo percorso, privo di segreti) insieme alla consegna e alle
evidenze. Al ripristino verifica percorso, proprietà root e impronte della
consegna con il piano conservato. Un apply consumato resta storico.

Il peer `semanticPeer` è riconciliato con `preparationA` del manifest di
accettazione, il cui hash deve coincidere con l'autorizzazione R3 corrente.
Il manifest A2 deve contenere lo stesso peer. Il runtime installato, i suoi
loader e il preparer da cui proviene il binding del comando `ip` sono verificati
come in `operate.observe`. Si riusa `verify_peer` del preparatore del profilo P:
PID, startTicks, device/inode del netns, boot ID, endpoint Docker e collegamento
veth reciproco al bridge devono coincidere. CID, immagine e StartedAt vengono
ricontrollati. Drift: `HELD`, `C_SEMANTIC_IDENTITY_DRIFT`.

Le sole variabili copiate da inspect sono le sette `OUF_SCHEMA_GOV_`:
`GATEWAY_BASE_URL`, `SEARCH_PATH`, `FETCH_PATH`, `TOKEN_ENDPOINT`, `CLIENT_ID`,
`WORKLOAD_SCOPE`, `CLIENT_SECRET_FILE`. Il valore del segreto non appartiene al
piano né al suo hash. Gli altri valori dell'ambiente non sono riportati.

IP, porte e nomi provengono dal profilo P. L'alias southbound del Semantic deve
coincidere con quello del profilo; ingresso e relay devono coincidere con il
transport R3 installato. Il codice non contiene CID, IP, porte o alias del VPS.

## Plan e apply

`--plan` ricontrolla l'identità e chiama l'osservatore R3 in sola lettura.
Richiede entrambi i ruoli STARTED/live/running, supervisore ACTIVE con epoche e
autorizzazione coerenti, lease LEASE_READY autorizzata e entrambe le tabelle
inet/bridge per ruolo presenti. In caso contrario: HELD e zero richieste di
rete della sonda. Il plan legge soltanto il resolver del container, mai il
segreto; non avvia il figlio e non esegue richieste DNS, TLS o HTTP.

`--apply --plan-sha256 <hash>` ripete le osservazioni e confronta il digest
prima di creare esclusivamente directory e `probe-claim.json`, tramite le
primitive R3 `digest_plan`, `mkdir_once`, `write_once`. Un output esistente
impedisce il replay. Il piano comprende input pubblici, configurazione,
identità, osservazione R3, destinazione e limiti.

Solo un processo figlio esegue `os.setns` sul descriptor del netns verificato.
Il padre resta nel namespace originale. Nel figlio i core dump sono disabilitati.
Le risoluzioni A sono interrogazioni UDP dirette al primo nameserver di
`/proc/<pid>/root/etc/resolv.conf`, senza resolver dell'host, search domain o
fallback. Risposte troncate/malformate falliscono senza retry. La risoluzione
dell'alias southbound deve dare esattamente l'IP legato.

Prima di leggere il segreto, un handshake senza HTTP verifica la catena
southbound con SNI uguale all'alias e il solo bundle legato. Catena/SNI non
convalidati: HELD, `C_SOUTHBOUND_TLS_UNPROVEN`, zero letture del segreto. La CA
fornita da Claude nel runbook è:

```text
/etc/ouf/deploy-snapshots/semantic-provider-v2-trust-vf7B4SM5/trust-bundle.pem
2e3f4bd8bdcefa651718233d2e7e0fb80cadecf69a3ad9deed00e55e85bf8401
```

Se quel file manca o non supera custodia/hash, fermarsi e riconciliare l'input
con l'owner; non sostituire il trust bundle o disattivare verifiche.

Il figlio apre il segreto solo via `/proc/<pid>/root/<file>`, con lettura
limitata e rifiuto dei symlink nei componenti interni del percorso. Usa il
contenuto in memoria (rimuove soltanto eventuali CR/LF finali); registra
`secretsRead: 1`. Ricontrolla la generazione prima delle richieste e intorno alla
lettura del segreto. Il figlio comunica al padre esclusivamente risultati redatti.

Il token endpoint HTTPS usa `ssl.create_default_context()` e il trust store
di sistema dell'host; il nome TLS è l'host configurato. HTTP è ammesso soltanto
quando tutti gli indirizzi risolti appartengono alle subnet del backend del
peer R3, ricavate dal profilo P (nell'installazione corrente, `ouf-backend`).
L'evidenza `tokenTransport` registra tale scelta. Nessun redirect o proxy.

## Casi e limiti

| Caso | Richiesta e atteso |
| --- | --- |
| P1 | POST form `client_credentials`, client/segreto/scope del Semantic; 200, Bearer e scope concesso nel risultato OAuth o nel JWT |
| P2 | POST searchPath, `Content-Type: application/sparql-query`; 200, almeno una riga |
| P3 | GET fetchPath con `uri` della prima riga P2 codificata nella query string; 200 |
| N1 | Ricerca senza Authorization; 401 |
| N2 | Ricerca con un carattere della firma JWT cambiato; 401 |
| N3 | Ricerca con JWT troncato a metà; 401 |
| N4 | Stesso token P1 dopo `exp + 5 s`; 401. SKIPPED solo se `expires_in > 600` |
| N5 | GET searchPath; 400 o 404 |
| N6 | POST diretto all'IP/porta adapter senza Authorization; timeout, rete irraggiungibile, rifiuto TCP oppure 403 |
| N7 | TLS southbound con SNI `c-probe-invalid.invalid`, senza credenziali; handshake fallito oppure 4xx |

Query SPARQL fissa:

```sparql
SELECT DISTINCT ?uri WHERE { ?uri a ?type . FILTER(isIRI(?uri)) } LIMIT 5
```

P2 legge il formato SPARQL Results JSON `results.bindings`, variabile `uri` di
tipo `uri`, da una a cinque righe. La URI resta in memoria, non nell'evidenza.
P1 interpreta `exp` soltanto per pianificare l'attesa; l'accettazione del token
viene verificata dal percorso southbound. Non viene richiesta una seconda credenziale.

N7 mantiene la verifica della CA e del nome. Un errore locale di verifica del
certificato per lo SNI errato è classificato TLS_FAILED: il caso prova il
fallimento della connessione TLS verificata, non necessariamente un rifiuto
server del solo valore SNI. N6 usa l'alias adapter del profilo e lo stesso
bundle; un errore TLS verso l'adapter è un fallimento, non una prova di blocco rete.
Un timeout HTTP dopo una connessione TLS completata non soddisfa N6; il fatto
`connectionEstablished` distingue questo caso dal timeout di connessione.

N4 viene eseguito dopo gli altri negativi, mantenendo il token P1. La sonda
prevede 8 tentativi HTTP verso southbound, oppure 7 quando N4 è skipped; il
contatore comprende anche un tentativo N7 che fallisce nell'handshake. P1 e N6
sono contati separatamente dal limite southbound. Un guard impedisce il 13°
tentativo; nessun retry. L'handshake preliminare non invia HTTP.

Fra i tentativi HTTP passa almeno un secondo dal termine del precedente.
Timeout massimo di 10 secondi per richiesta, corpo limitato a 2 MiB; interruzione
assoluta anche per risposte lente. Budget complessivo 15 minuti dall'inizio
dell'osservazione del comando, inclusa l'attesa N4. Apply riserva gli ultimi
60 secondi al readback. La consegna del codice precede questo budget.

Ogni caso registra codice HTTP/esito TLS o rete, durata, SHA-256 e lunghezza del
corpo; P2 anche numero righe. Corpi, token, segreto e Authorization non vengono
stampati né salvati. Anche in caso di errore si tenta il readback finale R3.
`C_PROBE_PASSED` richiede tutti i casi conformi (con l'unico skip ammesso N4) e
osservazione finale identica, compresi identità e input. Altrimenti
`C_PROBE_FAILED`, con `failedCases` e/o `r3Unchanged: false`; i gate prima dei
casi possono produrre HELD. `result.json` è esclusivo; exit 0 solo per
PLAN_READY o C_PROBE_PASSED. Conservare i parziali, senza rilanciare un apply
consumato. In caso di perdita/kill del processo, la claim resta e impedisce il
riuso della stessa directory anche se manca il risultato.

## Consegna operatore

`ops/vps/c-probe.sh` conserva il pin commit a zero per Claude. Prima dell'uso
Claude deve fissarlo al commit revisionato (D-001); il launcher rifiuta il pin
zero. Il launcher scarica soltanto quel commit e verifica ogni file contro
gli hash SHA-256 espliciti, con custodia root. Gli hash riguardano i byte Git
LF consegnati, anche se la worktree Windows usa CRLF. La closure include i
loader R3 esistenti; vengono invocati solo i lettori.

Per il plan l'operatore deve fornire i binding pubblici correnti e indipendenti;
non ricalcolarli per adattare un drift:

```bash
sudo env \
  C_R3_INPUTS="${R3_INPUTS:?}" C_R3_INPUTS_SHA256="${R3_INPUTS_SHA256:?}" \
  C_INSTALLATION_PROFILE="${PROFILE_P:?}" C_INSTALLATION_PROFILE_SHA256="${PROFILE_P_SHA256:?}" \
  C_WRAPPER_SHA256="${WRAPPER_SHA256:?}" C_SYSTEMCTL_SHA256="${SYSTEMCTL_SHA256:?}" \
  bash c-probe.sh plan > "$HOME/c-probe-plan.json"

sudo bash c-probe.sh apply <planSha256> > "$HOME/c-probe-apply.json"
```

Il launcher salva consegna e argomenti pubblici del plan sotto custodia root;
apply riusa entrambi e ne verifica nuovamente la consegna. Il puntatore è
`$HOME/.ouf-c-probe-state` dell'utente root che esegue il launcher. Non viene
sovrascritto: per una nuova invocazione governata scegliere esplicitamente un
nuovo `C_PROBE_STATE` assoluto sotto custodia root, uguale per plan e apply.
L'eventuale `C_INSTALL_ROOT` può indicare un'installazione R3 differente,
restando vincolato nel piano. I redirect sono valutati dalla shell dell'operatore.

## Qualificazione locale e CI

```bash
python -I -B -m unittest discover -s tests -p test_semantic_provider_c.py -v
bash -n ops/vps/c-probe.sh
```

Le prove portabili generano una CA e un certificato sintetici con OpenSSL e
usano esclusivamente loopback: OAuth e southbound finti, adapter non in ascolto,
negativi, scadenza, limiti, redazione stdout/evidenze, plan senza segreto,
precondizioni R3 fallite senza richieste, binding del profilo, DNS diretto,
deriva del piano/readback e creazione esclusiva delle evidenze. Le attese sono
virtuali nei test; non dimostrano limit-count reale.

Il workflow `semantic-provider-c-probe.yml` usa soltanto `ubuntu-24.04`, eventi
pull_request e workflow_dispatch, permessi contents:read. Un passo distinto
root verifica il vero fork/setns in un netns locale vuoto e il namespace del
padre invariato. Non usa Docker, VPS, IAM o schema.gov.it. Tale prova viene
saltata nella suite portabile ordinaria. Il passaggio reale nel netns del
Semantic, la catena installata e l'esito applicativo restano da osservare sul
VPS con mandato operativo; non sono dedotti dal verde locale o CI.
