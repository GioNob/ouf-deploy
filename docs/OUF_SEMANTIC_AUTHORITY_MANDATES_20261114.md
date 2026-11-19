# Registro dei mandati e runtime v5.1 (sprint-01, task-27)

Riferimenti: D-018, D-028, D-029; `docs/OUF_SEMANTIC_RUNTIME_V5_ARMING_20261112.md`.

## Perché
Il mandato delle chiavi installer e attestor è scritto nelle trust policy, che i consumatori fissano per hash. Per estendere `expiresAt` bisognerebbe cambiare l'hash, e questo invaliderebbe la configurazione v5 e ogni armatura già emessa. D-028 separa le due cose:

- **ancora**: la policy già pubblicata, immutabile. Contiene chiavi pubbliche, issuer, ruoli e stato;
- **registro**: generazioni append-only che portano solo finestre temporali e revoche.

Ancore attuali:

| Tipo | Schema | sha256 |
|---|---|---|
| B1/B2 | `ouf.semantic-provider-b1b2-trust-policy.v1` | `6ef247ee…4f95` |
| base | `ouf.semantic-deployment-trust-policy.v1` | `21122630…bd42` |

## Moduli
- `tools/semantic_authority_mandates/mandates.py`: autocontenuto, solo libreria standard. Non importa `semantic_b1b2_authority`, ma ne riscrive le regole sintattiche (`policy()` e `base_policy()`) e l'envelope di firma.
- `tools/semantic_runtime_v51/`: runtime e verificatore dell'armatura v5.1.

I moduli B1 (`tools/semantic_b1b2_authority/`, `tools/semantic_runtime_v5/`) restano invariati byte per byte, perché la closure B1 li fissa.

## Formato del registro `ouf.semantic-authority-mandate.v1`

### Custodia
- Directory root:root `0700`, senza symlink, con antenati di root non scrivibili da gruppo e altri.
- Ammette solo file `N.json` (N decimale da 1, senza zeri iniziali): root:root `0600`, un solo link, al massimo 64 KiB.
- Le generazioni sono contigue da 1 a M, con M ≤ 512.
- Ogni altra voce è rifiutata:
  - file o directory estranei: `UNKNOWN_MANDATE_ENTRY`;
  - buchi: `MANDATE_GENERATION_GAP`;
  - temporanei di scrittura `.tmp-<N>-<32 hex>`: `MANDATE_TEMPORARY_ENTRY_PRESENT`.

### Generazione
JSON canonico: chiavi ordinate, separatori `,` e `:`, solo ASCII, senza newline finale. Vale `bytes == canonical(decode(bytes))` e le chiavi duplicate sono rifiutate.

```json
{"anchor":{"path":"…","sha256":"…"},"entityRef":"…","generation":N,"installationRef":"…",
 "issuedAt":<epoch>,"issuerRef":"<job>","mandates":[{"expiresAt":…,"keyRef":"…","notBefore":…,"state":"ACTIVE|REVOKED"}],
 "preconditions":{"custodyIntact":true,"evidenceSha256":"…","keyNotRevoked":true,"noOpenSecurityIncident":true},
 "previousSha256":null|"<sha256 di N-1.json>","schema":"ouf.semantic-authority-mandate.v1"}
```

### Invarianti, verificati a ogni lettura e prima di ogni scrittura
1. `anchor` coincide con il binding passato dal chiamante, in tutte le generazioni. `installationRef` ed `entityRef` coincidono con quelli dell'ancora.
2. `previousSha256` forma una catena di hash: `null` solo per N = 1.
3. Ogni `keyRef` esiste nell'ancora ed è unico nella generazione. Le liste contengono da 1 a 32 voci.
4. `0 ≤ notBefore < expiresAt` e `expiresAt − notBefore ≤ 7776000` (90 giorni).
5. Una voce `ACTIVE` richiede che tutte e tre le precondizioni siano `true`. Una generazione di sola revoca può avere precondizioni false.
6. `issuedAt` non decresce tra le generazioni ed è ≤ `now`. Per ogni chiave, `notBefore` non decresce, a partire dalla generazione 0.
7. **Revoca monotona.** Una chiave `REVOKED` nell'ancora o in una generazione resta `REVOKED` in tutte le generazioni successive (`MANDATE_REVOCATION_REVERSED`). Omettere la chiave in una generazione successiva non la riattiva.
8. Il registro non porta ruoli, chiavi pubbliche né issuer: questi vengono solo dall'ancora.

### Generazione 0 e mandato effettivo
- La generazione 0 è l'ancora: per ogni chiave valgono `notBefore`, `expiresAt` e `state` della policy pubblicata.
- Il mandato effettivo di una chiave è quello della generazione più alta che la nomina, oppure la generazione 0.
- Se l'ancora dice `REVOKED`, lo stato effettivo è sempre `REVOKED`.

## API (`mandates.py`)
Tutti gli errori sono `MandateDenied(<CODICE>)`, con codici `[A-Z0-9_]` e mai contenuti degli input.

- `MandateLedger(anchor_binding, ledger_root, installation, entity, clock=time.time, budget=None)`
  - `refresh(now=None)`: legge e valida ancora e registro, poi conserva la vista. Le query seguenti usano la vista conservata (la prima query fa `refresh` da sola).
  - `current(key_ref, role, now=None)`: restituisce il mandato effettivo (`keyRef`, `issuerRef`, `roles`, `publicKey`, `notBefore`, `expiresAt`, `state`, `generation`). Le condizioni sono: l'ancora concede `role`, lo stato è `ACTIVE` sia nell'ancora sia nel registro, e `notBefore ≤ now < expiresAt`. Altrimenti `ACTIVE_MANDATE_REQUIRED`.
  - `at(key_ref, t)`: il mandato della generazione più alta con `issuedAt ≤ t` che nomina la chiave, oppure la generazione 0. Lo userà il task-30 per le ricevute durevoli (D-029).
  - `ever_revoked(key_ref)`: `True` se la chiave è revocata nell'ancora o in una qualsiasi generazione.
  - `snapshot()`: `{anchorSha256, generations, headSha256}`. Grazie alla catena di hash, `headSha256` copre tutto il registro.
- `MandateAuthenticator(anchor_binding, ledger_root, openssl_binding, clock, budget)`
  - `verify_b1b2_detached(raw, signature_raw, role, issuer, installation, entity)`:
    - envelope `ouf.semantic-provider-b1b2-detached-signature.v1`, dominio `OUF-SEMANTIC-PROVIDER-B1B2-EVIDENCE\0V1\0` e frame identici a `authority.py`;
    - OpenSSL vincolato per path, hash e versione;
    - richiede un'ancora B1/B2;
    - controlla `current()` all'inizio e alla fine, con clock non regressivo (`MANDATE_CLOCK_REGRESSED`);
    - alla fine rilegge ancora e registro; se lo snapshot è diverso: `MANDATE_LEDGER_CHANGED_DURING_VERIFICATION`.
- `write_generation(ledger_root, anchor_binding, installation, entity, mandates, preconditions, issuer_ref, evidence_sha256, clock)`. È la primitiva del task-28:
  1. rilegge e valida tutto;
  2. costruisce M+1 (`issuedAt = int(clock())`) e la valida con gli stessi invarianti;
  3. scrive `.tmp-<M+1>-<hex>` con `O_EXCL`, `0600`, e fa fsync;
  4. pubblica con `os.link` esclusivo su `M+1.json`; se il file esiste già: `MANDATE_GENERATION_EXISTS`, senza sovrascrivere;
  5. rimuove il temporaneo, fa fsync della directory, rilegge e confronta;
  6. restituisce `{generation, sha256}`.

  Non legge chiavi private. Un temporaneo rimasto per un crash blocca lettori e scrittori (fail closed): va rimosso con un intervento governato.

## Runtime v5.1: differenze rispetto a v5
| v5 | v5.1 |
|---|---|
| schema `ouf.semantic-docker-runtime-adapter.v5` | `ouf.semantic-docker-runtime-adapter.v5.1` |
| `b1b2TrustPolicy` {path, sha256} | `b1b2Anchor` {path, sha256} + `mandateRoot` (path assoluto) |
| `b1b2AuthorityModule` = `authority.py` | `b1b2AuthorityModule` = `mandates.py`, compilato dai byte verificati e mai importato da path |
| `B1B2Authenticator` | `MandateAuthenticator` per `RUNTIME_ARMING` |
| `verify_files`: hash della policy | hash dell'ancora + validazione strutturale del registro a ogni operazione (`V51_MANDATE_LEDGER_INVALID`) |
| codici `*_V5_*`, `binding_v5` | `*_V51_*`, `binding_v51` |

Tutto il resto è identico:
- fase INACTIVE, due CID candidati;
- generazioni di armatura (`ouf.semantic-docker-runtime-arming.v1`) e marker `.consumed`;
- `runtimeConfigurationSha256`, `acceptanceSha256`, intent del broker, delega a v4;
- journal `ouf.semantic-docker-runtime-journal.v1`.

Nel runtime la validazione del registro è solo strutturale. Un mandato scaduto non blocca `state` né `delete`; un registro malformato blocca invece ogni operazione su un CID, come oggi una policy alterata. Il controllo temporale vive nel verificatore isolato.

Semantica dell'armatura (requisito 11):
- un'armatura emessa durante un mandato valido non è più verificabile dopo la scadenza, come in v5;
- una generazione di rinnovo che copre `now` la rende di nuovo verificabile, senza cambiare configurazione né armatura;
- una revoca nel registro la rende inverificabile per sempre.

## Fuori perimetro
- **task-28**: job di rinnovo automatico (timer systemd root, finestra di 90 giorni, rinnovo a T-30, precondizioni D-018, incidente se non soddisfatte), pubblicazione del registro sul VPS e runbook. Per la base resta aperta la nota di D-028.
- **task-29**: reinstallazione governata del runtime v5.1 prima di B2 (nuova configurazione e nuova armatura).
- **task-30**: worker del registry con ricevuta durevole, basata su `at()` + `ever_revoked()`, da completare entro il 2027-01-02.

## CI
`.github/workflows/semantic-authority-mandates.yml` esegue in modo nativo, come root su `ubuntu-24.04`:
- `test_semantic_authority_mandates.py`;
- `test_runtime_v51_arming.py`;
- per non regressione: `test_runtime_v5_arming.py`, `test_semantic_b1b2_authority.py` e `test_semantic_provider_b1_install.py`.

Con la variabile nativa impostata, un ambiente senza root Linux fallisce invece di saltare i test.
