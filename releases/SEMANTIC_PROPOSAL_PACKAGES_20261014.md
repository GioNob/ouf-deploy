# Pacchetti del canale semantic proposal — 14 ottobre 2026

I tre nuovi pacchetti unsigned sono qualificati e verificati. Il canale non è installato sul VPS e Teatri non è registrato né eseguito. Il checkpoint completa la produzione dei pacchetti prevista dal [handoff del canale](SEMANTIC_PROPOSAL_CHANNEL_20261013.md); non sostituisce l'autorità o l'accettazione dell'installazione.

[Build/scansioni/export38508140057](https://github.com/GioNob/ouf-deploy/actions/runs/38508140057): tre job SUCCESS. [Manifest completo con hash, CI e limiti](semantic-proposal-candidate-qualified-20261014.json).

| Modulo | Sorgente esatta del pacchetto | Main dopo merge | Artifact |
| --- | --- | --- | --- |
| Registry | bdfe0f75a5fc4790a5c5ff36e201c3d99713ecc0 | 0b150851487640bf3841433f48264aa8914c1d6c | 11868169115 |
| MCP | d43f5604976b07c66d58c5180d871c5656c44d4d | 760e685d0259a2319d72ad268b38fff1bd061bee | 11868243649 |
| Gateway | 23b02bd2195d36499b6618750d52dd49d65c9a60 | 3a31a30ae67b606bf225710e580b53e98e93bdc8 | 11868323361 |

I pacchetti fissano i commit candidati, integrati dalle PR37/66/73. Non si cambiano i manifest per dichiararli costruiti da un diverso merge commit.

Registry: tutte le CI sorgente passano;65 test Java/PostgreSQL, zero errori/fallimenti/skip, e smoke dell'immagine di produzione. Dipendenze Java aggiornate e compatibilità Jackson2 mantenuta; prima risposta e replay usano lo stesso JSON persistito. SDK canonico e SQL esistenti restano invariati. MCP:24 esecuzioni dello stesso commit, dodici tipi di workflow, tutte SUCCESS; x/sys aggiornato a0.44.0. Gateway: tutte le CI passano;66 test mirati con Lua effettivo, incluso il nuovo confine Python.

Il gate respinge HIGH/CRITICAL/UNKNOWN, incluse le vulnerabilità senza fix. Le prime scansioni hanno bloccato i pacchetti e sono conservate. La scansione MCP ora usa rootfs per analizzare il vero gobinary; quella Gateway analizza una copia byte-esatta di requirements-dev.txt chiamata requirements.txt e la lega al sorgente all'export. Un report senza copertura non passa.

Per Lupa,2.8 non è presentato come una correzione upstream provata: le note di rilascio non la dimostrano. Il motore dei test conserva Lua5.4, disabilita python.builtins e python.eval e nega l'accesso agli attributi Python; la regressione verifica il confine. Non è una sandbox generale né il runtime APISIX. La scansione Gateway copre le dipendenze dichiarate, non l'intera closure Python transitiva installata.

Gli ZIP scaricati sono verificati contro i digest Actions e tutti i checksum interni. Registry image ID: sha256:1e2dac4a6619f511056abc91dd153ce7687efc25aec25aa77a6f66c9f2f67cfd. Il verificatore non estrae né esegue gli artefatti.

## Consegna sul VPS completata — non ripetere

Ricevuta fornita dall'operatore il14 ottobre2026 alle06:05 CEST: [evidenza target](../evidence/semantic-proposal-candidate-stage-target-20261014.json). I tre ZIP sono conservati in `/home/oufadmin/ouf-semantic-candidates-20261014.fADvCV9u`; digest e manifest coincidono con la qualifica. È un risultato riferito dall'operatore, non una rilettura indipendente. Nessun effetto runtime. Il comando seguente è storico e non va ripetuto.

La continuazione IAM del13 ottobre è ora integrata tramite PR5: [radici già custodite](POLICY_TOKEN_ROOT_DELIVERY_20261013.md), claim consumata; [migrazione e riuso del ledger completato](POLICY_TOKEN_MIGRATION_ASSEMBLY_20261013.md). Queste evidenze non erano in main durante la confezione dei pacchetti; il nuovo staging non le sostituisce e non autorizza la ricreazione delle radici.

## Consegna storica

Serve questo passaggio operatore perché la sessione non dispone di SSH o di una superficie di esecuzione sul VPS. Non serve sudo. Il launcher scarica circa207MB in una nuova directory privata della home e richiede1GiB libero; conserva ricevute, fase e motivo di eventuale blocco. Ogni download ha un timeout, un solo tentativo e nessun retry automatico. Non modifica container, unità, database, chiavi o R12.

Il client portable esistente viene preferito, come richiesto da [AGENTS](../AGENTS.md). Non installare un altro client e non fornire token in chat. Eseguire sull'host oufadmin:

```bash
(
  set -euo pipefail
  umask 077
  GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$GH" ]; then GH="$(command -v gh)"; fi
  [ -x "$GH" ]
  DELIVERY_DIR="$(mktemp -d "$HOME/ouf-semantic-delivery-20261014.XXXXXXXX")"
  timeout 60s "$GH" api 'repos/GioNob/ouf-deploy/contents/releases/semantic-candidate-stage-20261014.sh?ref=e089cc4d2619809e5894941da71b8b61debf59ee' --jq .content |
    base64 --decode > "$DELIVERY_DIR/stage.sh"
  printf '%s  %s\n' 1df0e75c0ceddc7b1d4af64bac3fc9fe71b254437b3ecdb8c4ed7d677d870bc2 "$DELIVERY_DIR/stage.sh" |
    sha256sum -c -
  bash "$DELIVERY_DIR/stage.sh"
)
```

Restituire solo la riga OUF_SEMANTIC_CANDIDATE_STAGE finale, che contiene hash e stato senza credenziali. Il risultato atteso è UNSIGNED_PACKAGES_VERIFIED_NOT_APPLY_READY. I pacchetti Actions scadono il13 novembre2026; un'eventuale futura conservazione va verificata sugli stessi hash, senza rigenerarli o sostituirli silenziosamente.

## Migrazione e passaggio all'installazione

[Confronto dell'effettivo JAR candidato](semantic-proposal-migration-review-20261014.json): tutti i nove SQL V1–V9 corrispondono byte per byte alla qualificazione storica conservata. L'unica aggiunta è V10__proposal_command_receipts.sql, SHA2567ee3a19ad02cdc4ea5ccd58d8ab96268046bd114962c7d6cd5c8717c8c3b0820. V10 crea il ledger delle ricevute e i suoi vincoli/trigger. Questo confronto non legge il database corrente e non ammette una migrazione. Avviare l'applicazione prima dell'ammissione governata sarebbe prematuro.

Restano necessari custodia/trust firmati per la nuova immagine, binding OCI/peer e schema attuali, backup/restore/fence, chiave dedicata per le ricevute Gateway→Registry con ancestry protetta, integrazione reale DomainOwner/source/transport, installer sigillato con entry/reporter, mandato HUMAN finito e attestor indipendente. Le precedenti accettazioni V11, le chiavi di test e le claim consumate non autorizzano questi nuovi byte. Il native proposal path non chiude automaticamente token-owner, sei mount o budget/sessioni.

Solo dopo installazione e verifica dei grant effettivi si potranno registrare le21 DRAFT, validare e ottenere vere card THS, quindi pubblicare e approvare/attivare il profilo. Il ciclo CSV richiederà ancora run reale, ACK durevoli, lineage e ricerca autorizzata completa delle13 righe. Non ripetere il precedente denial permanente prima di una nuova via deployata e autorizzata.

Nessun apply, migrazione, firma, grant, reset di budget, operazione R12, registrazione Teatri o nuovo risultato CSV è stato eseguito. Le ricevute CI attestano la qualificazione descritta, non l'installazione o la salute applicativa target.
