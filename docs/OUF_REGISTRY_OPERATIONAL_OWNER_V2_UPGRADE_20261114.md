# Aggiornamento governato del worker del registry da v1 a v2 (sprint-01, task-30b)

Riferimenti: D-029, D-031; `docs/OUF_REGISTRY_OPERATIONAL_OWNER_V2_20261114.md` (v2, task-30a).

## Cosa sostituisce
Sul VPS gira la v1 `ouf-registry-token-7cb59501000058b5dc5030ad.service` (configurazione `0b72275f…`), che rinnova la credenziale IAM del registry. Due fence le danno l'esclusiva:
- il **fence v1** (`<v1>/fence/fence.json`, `active: true`);
- il **fence globale** lasciato dal predecessore *postboot*, che dopo il CAS della v1 contiene il valore del fence v1.

La v1 tiene il **lock comune** dell'owner logico per tutta la vita del processo. Il suo ledger porta il contatore cumulativo dei tentativi: 321 storici più quelli fatti dalla v1.

## Azioni (`tools/semantic_registry_operational_owner_v2/upgrade.py`, capsula v2)
| Azione | Effetti |
|---|---|
| `upgrade-prepare <v1Sha> <attempt>` | sola lettura sulla v1; scrive la review privata (`semantic-registry-operational-upgrade-review-…/review.json`) |
| `upgrade-issue <review> <sha>` | approvazione da TTY dell'hash esatto; firme `DEPLOYMENT_INTENT` e `FINAL_DEPLOYMENT_APPROVAL` dell'installer; finestra HUMAN di 900 s |
| `upgrade-install <review> <sha>` | una volta per tentativo (claim): root v2, **stop v1**, contatore letto sotto i lock, ledger v2, ricevuta v2 firmata dall'attestor, CAS dei fence |
| `upgrade-start <review> <sha>` | `disable --now` v1, `daemon-reload`, `enable --now` v2; attesa della prima pubblicazione |
| `upgrade-rollback <review> <sha> [planSha]` | plan, poi apply: ripristino della v1 finché la v2 non ha pubblicato |

### Binding della v1 (prepare, e di nuovo a issue e install)
Tutti questi elementi sono verificati per hash e devono essere identici in ogni fase. Qualsiasi deriva produce STOP prima di qualsiasi effetto.
- configurazione v1 (`0b72275f…`), nella propria installation root;
- ricevuta v1 completa, verificata con la semantica v1: finestra corrente dell'attestor, valida fino al 2027-01-02;
- unità che fissa quella configurazione;
- fence v1 attivo;
- fence globale uguale al valore v1;
- identità del lock comune.

### Configurazione v2
Restano gli stessi `ownerInputs` (credenziale, IAM, output), `policy`, CA IAM, lock comune e eseguibili. Cambiano:
- root `…-v2-<attempt>-<logical>` (installazione e ledger);
- capsula v2;
- fence v2;
- `verification.mandateLedgerRoot`;
- unità `ouf-registry-token-v2-<attempt>-<logical24>.service`.

Gli altri valori:
- `predecessorInputsHash` = hash della configurazione v1;
- `proposalHash` = digest della proposta di aggiornamento (configurazione v1, manifest v2, destinazioni, tentativo);
- `priorControlledAttempts` resta 321 come base storica.

### Install, in ordine
1. Claim `operational-upgrade-<logical>-<attempt>.claim.json`: nessun replay dello stesso tentativo.
2. Root v2: sandbox, capsula, CA, configurazione, fence v2 inattivo, unità non abilitata.
3. `systemctl stop` della v1 e attesa dello stato inactive. Serve perché la v1 tiene il lock comune.
4. Sotto il lock comune e il lock del ledger v1:
   - lettura e validazione del ledger v1: se c'è un tentativo in corso (`RESERVED`/`DISPATCHING`/`PUBLISHING`), STOP;
   - ledger v2 con `prior` = contatore cumulativo finale della v1;
   - `attestedAt` dentro la finestra HUMAN e ricevuta v2 firmata dall'attestor (`priorControlledAttempts` = contatore v1);
   - CAS del fence globale (valore v1 → valore v2), CAS del fence v1 (`active: false`), attivazione del fence v2.

Il ledger v1 non viene mai scritto.

### Contatore
La configurazione v2 conserva la base 321. Il contatore vivo sta nella **ricevuta firmata**: il guard v2 lo legge da lì, deve essere ≥ 321 e stabile tra i cicli, e il worker lo confronta con il ledger v2.

## Rollback
Ammesso solo finché il ledger v2 ha `publications = 0`. Il plan indica quali fence ripristinare: ciascuno deve essere nello stato originale o in quello post-aggiornamento, altrimenti serve una riconciliazione manuale.

L'apply:
1. `disable --now` della v2;
2. CAS inverso dei fence;
3. `daemon-reload` ed `enable --now` della v1.

La v1 riparte con il suo ledger intatto. Un nuovo tentativo usa `attempt` + 1, con root e unità nuove.

## Interruzione
Il rinnovo si ferma dallo stop della v1 fino alla prima pubblicazione della v2, cioè per la durata di install più start. Il token già pubblicato resta valido fino alla sua scadenza.

## Runbook `ops/vps/registry-owner-upgrade.sh`
1. Verifica `python3.13`.
2. Scarica, a un commit fissato, il builder v2, il cui hash è fissato. Scarica anche la release di dipendenza, che il builder verifica per hash, e gli 11 sorgenti.
3. Costruisce la capsula in modo deterministico e la accetta solo se il suo sha256 è `K`.
4. Esegue l'azione richiesta.

Gli argomenti vengono ripuliti dai CR e validati prima di qualsiasi effetto.

Sequenza della cerimonia, entro metà dicembre 2026:
```
prepare 1 → issue <review> <sha> → install <review> <sha> → start <review> <sha>
```

## Test
`test_native_upgrade.py` usa un'installazione v1 sintetica ma reale (firme Ed25519, guard v1 e v2, ledger e fence reali) e simula solo `systemctl`. Copre:
- aggiornamento completo, con contatore conservato, v1 fermata dal suo fence e guard v2 attivo;
- replay rifiutato;
- deriva tra prepare e install senza effetti;
- tentativo v1 in corso, con rollback che riavvia la v1;
- rollback dopo l'installazione e rifiuto dopo la pubblicazione;
- secondo tentativo su root nuove;
- scope legato alla review esatta.
