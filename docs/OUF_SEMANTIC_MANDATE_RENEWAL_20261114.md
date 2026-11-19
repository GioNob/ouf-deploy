# Rinnovo automatico dei mandati (sprint-01, task-28)

Riferimenti: D-018, D-023, D-028, D-029, D-030; `docs/OUF_SEMANTIC_AUTHORITY_MANDATES_20261114.md` (registro, task-27); `ouf-api-gateway` `docs/OUF_GATEWAY_AUTHORITY_MANDATE_INCIDENTS.md` (incidenti, task-31).

## In breve
`tools/semantic_mandate_renewal/renewal.py run` gira una volta al giorno come root, tramite un timer systemd. A ogni esecuzione:
1. verifica la coerenza tra ancore, profilo d'autorità e `keyRefs`, e le precondizioni D-018;
2. se un mandato configurato scade entro 30 giorni, scrive una generazione nuova con una finestra di 90 giorni nel registro B1/B2 e poi in quello della base;
3. deriva la **base versionata** per il broker v4 di B2;
4. pubblica uno stato a schema chiuso, che il collector del gateway trasforma in incidenti.

In caso di anomalia **non rinnova** e apre un incidente locale. Non legge chiavi private, non firma, non accede alla rete (`PrivateNetwork=true`).

## Configurazione `ouf.semantic-mandate-renewal.v1`
La configurazione è il file `/etc/ouf/authority-mandate-renewal/configuration.json`, root 0600. La unit la fissa per hash con `--configuration-sha256`.

Campi esatti:
- `renewalSource` e `mandatesModule`: i due sorgenti installati, controllati per hash a ogni run. `mandates.py` viene compilato dai byte verificati;
- `installationRef`, `entityRef` e `issuerRef` (`ouf-authority-mandate-renewal-job`);
- `authorityProfile`;
- `b1b2` {`anchor`, `ledgerRoot`, `keyRefs`};
- `base` {`anchor`, `ledgerRoot`, `versionedRoot`, `keyRefs`};
- `stateRoot`;
- `windowSeconds` (7776000) e `renewBeforeSeconds` (2592000): valori fissi.

L'installer deriva i `keyRefs`:
- base: `keyRefs.installer` e `keyRefs.attestor` del profilo;
- B1/B2: le chiavi dell'ancora B1/B2 con la stessa chiave pubblica dell'installer.

## Coerenza e precondizioni
Tutto viene valutato **prima** di qualsiasi scrittura.

| Controllo | Codice se fallisce |
|---|---|
| L'ancora B1/B2 punta a profilo e base configurati; il profilo punta alla base; i `keyRefs` corrispondono; le chiavi pubbliche B1/B2 coincidono con quella dell'installer | `AUTHORITY_COHERENCE_UNPROVEN` |
| `custodyIntact`: profilo e ricevuta di custodia con l'hash fissato, root, non scrivibili da gruppo e altri. `keyBindings` è controllato solo nella sintassi | `PRECONDITION_CUSTODY_INTACT_UNMET` |
| `keyNotRevoked`: nessuna chiave configurata è revocata, né nell'ancora né nel registro | `PRECONDITION_KEY_NOT_REVOKED_UNMET` |
| `noOpenSecurityIncident`: nessun incidente aperto | il `reasonCode` del primo incidente |
| Registro valido (custodia, catena, invarianti; nessun `.tmp-*`) | codice di `mandates.py`, per esempio `MANDATE_TEMPORARY_ENTRY_PRESENT` |
| Nessun mandato già scaduto | `MANDATE_EXPIRED_WITHOUT_RENEWAL` |
| Base versionata coerente con il registro, senza temporanei né file estranei | `VERSIONED_BASE_DRIFT`, `VERSIONED_BASE_TEMPORARY_ENTRY_PRESENT`, `UNKNOWN_VERSIONED_BASE_ENTRY` |

Un mandato già scaduto **non** si rinnova automaticamente: significa che il job non ha funzionato per 30 giorni, e decide l'umano.

## Rinnovo (T-30, 90 giorni)
Per ciascun registro, in modo indipendente:
- se per tutte le chiavi configurate `expiresAt − now > 30 giorni`, il registro resta com'è;
- altrimenti si scrive **una** generazione con tutte le chiavi configurate: `notBefore = max(now, notBefore corrente)` ed `expiresAt = notBefore + 90 giorni`. Le precondizioni sono tutte vere, e `evidenceSha256` punta a `stateRoot/evidence/<sha>.json` (hash di ancore, profilo, ricevuta e snapshot dei registri).

Ordine: B1/B2, poi base, poi base versionata. Un errore interrompe il run: i passi successivi non avvengono.

## Base versionata
`versionedRoot/<N>.json` per ogni generazione N del registro base:
- è l'ancora base con `notBefore`, `expiresAt` e `state` delle chiavi configurate presi dal mandato effettivo alla generazione N. Le altre chiavi sono invariate;
- JSON canonico, validato con `base_anchor`;
- scritto con temporaneo `O_EXCL` + `os.link` esclusivo + rilettura.

Se un file manca (per esempio dopo un crash tra registro e base versionata), il run successivo lo ricrea in modo deterministico. Se esiste con byte diversi: `VERSIONED_BASE_DRIFT`.

Le configurazioni di ammissione di B2 fisseranno `<N>.json` per path e hash.

## Stato e incidenti
- **Stato:** `stateRoot/status.json`, root 0600, riscritto in modo atomico a ogni run. Schema `ouf.semantic-mandate-renewal-status.v1`: `checkedAt`, `outcome` (`NOOP`/`RENEWED`/`BLOCKED`), `reasonCode`, `ledgers` {b1b2, base} → {generation, headSha256, earliestExpiresAt}, `versionedBase`, `openIncident`. Contiene solo codici e hash, nessun path. Se un registro non è leggibile, i suoi valori sono `0`/`null`, e il collector segnala anche la scadenza vicina.
- **Incidente:** un BLOCKED crea `stateRoot/incidents/open.json` con `O_EXCL`. Contiene {reasonCode, firstSeenAt, evidenceSha256}. Finché esiste, ogni run è BLOCKED e lo stato riporta il **primo** `reasonCode`, così la causa originale resta visibile in operational awareness.
- **Concorrenza:** due run sovrapposti sono esclusi da un flock sulla directory di stato (`RENEWAL_ALREADY_RUNNING`).
- **Exit code:** 0 per NOOP o RENEWED, 2 per BLOCKED. Su stderr compare solo `MANDATE_RENEWAL=<OUTCOME> REASON=<CODE>`.
- **`--dry-run`:** valuta tutto e pubblica lo stato. Non scrive generazioni, base versionata né incidenti. Stampa `WOULD_RENEW` se un rinnovo sarebbe dovuto.

## Installazione (`ops/vps/mandate-renewal-install.sh`)
Prerequisito (D-030): il collector del gateway (task-31) è già rilasciato.

`plan` è in sola lettura e stampa `PLAN_READY` con l'hash del piano. `apply <planSha256>`:
1. verifica `python3.13` e scarica `renewal.py` e `mandates.py`, fissati per commit e hash;
2. crea `/etc/ouf/authority-mandate-renewal` (codice + configurazione) e le directory `/var/lib/ouf-authority-mandates/{b1b2,base,base-versioned}` e `/var/lib/ouf-authority-mandate-renewal`, tutte 0700;
3. installa le unità `ouf-authority-mandate-renewal.{service,timer}` (copie revisionate in `ops/systemd/`, con l'hash della configurazione al posto del segnaposto);
4. esegue `daemon-reload` e un run `--dry-run`, poi abilita il timer.

Rifiuta di procedere se una qualsiasi destinazione esiste già: nessuna reinstallazione implicita.

## Chiusura dell'incidente (`ops/vps/mandate-renewal-incident-close.sh`)
Il runbook usa il codice installato e l'hash della configurazione letto dalla unit.
- `plan` mostra l'incidente e i temporanei `.tmp-*` presenti nei registri e nella base versionata (path, dimensione, hash).
- `apply <planSha256>`:
  1. rimuove solo quei temporanei, dopo averne riverificato l'hash;
  2. archivia `open.json` in `incidents/closed/`;
  3. avvia una volta il servizio.

  Non tocca mai `N.json`. Prima dell'apply l'umano verifica la causa dell'incidente.

## Rapporto con gli altri task
- **task-29:** il runtime v5.1 si installa con `mandateRoot` = `/var/lib/ouf-authority-mandates/b1b2`.
- **task-30:** il worker del registry legge il registro della base (`at()`, `ever_revoked()`).
- **task-31:** il collector del gateway legge `status.json`.
- **B2:** le configurazioni di ammissione fissano un file della base versionata.

## CI
`.github/workflows/semantic-mandate-renewal.yml`:
- test nativi come root (`OUF_MANDATE_RENEWAL_NATIVE=1`);
- non regressione del registro;
- `bash -n` e ShellCheck sui due runbook.

Le unità sono verificate con un test che le confronta byte per byte con l'output dell'installer.
