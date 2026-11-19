# Runtime v5.1 al posto del v5 di B1 (sprint-01 task-29b)

## Scopo
Sostituire, dietro il wrapper `/usr/local/sbin/ouf-semantic-admitted-v2`, il runtime v5 installato da B1 (task-25) con il v5.1 (task-27). Il v5.1 verifica `RUNTIME_ARMING` con l'ancora B1/B2 e il registro dei mandati (D-028), quindi B2 non dipende più dalla finestra della policy che scade il 2027-01-02. Tutto resta INACTIVE: nessun container avviato e nessuna armatura.

## Strumenti (nuovi, versionati)
- `scripts/install-semantic-runtime-v51.py`: plan/apply.
- `scripts/restore-semantic-runtime-v51-wrapper.py`: annullamento v5.1 → v5.
- `tools/semantic_runtime_v51_install/common.py`: osservazione condivisa in sola lettura.
- Runbook `ops/vps/runtime-v51-install.sh` e `ops/vps/runtime-v51-restore.sh`. Fanno anche da launcher: scaricano la consegna al commit fissato e la verificano file per file. L'apply riusa la consegna del plan e la ricontrolla.

Restano invariati: strumenti e closure B1, `tools/semantic_runtime_v5*`, `tools/semantic_runtime_v51/`, `mandates.py` e la primitiva `switch_existing_wrapper`. Il ripristino a v4 del task-26 resta il secondo livello.

## Stato di partenza (verificato a ogni osservazione)
- **Wrapper:** hash `764c26d5…`, forma canonica, punta a sorgente e configurazione della root B1.
- **Ricevuta B1** `result.json`: `SEMANTIC_PROVIDER_B1_INSTALLED_INACTIVE`, piano B1 `e8444689…`, `wrapperAfter` = wrapper, `configurationSha256` = byte della configurazione.
- **v5 installato** (`572912ec…`): compilato dai byte verificati. Girano i suoi `load_configuration`, `verify_files` e `arming_absence` reali, e l'esito deve essere due liste vuote.
- **Successor:** i candidati della configurazione v5 = `containerIds` di B1 = ruoli dell'accettazione. Sono `created` e mai avviati, con frame stabile.
- **Lock della guardia** vuoto, con identità stabile.
- **Accettazione gen 3:**
  - ricevuta 29a, manifest e firma legati per hash;
  - registro dei mandati valido;
  - firma `ARTIFACT_ACCEPTANCE` verificata con `MandateAuthenticator` (ancora = `b1b2TrustPolicy` del v5, issuer = `armingIssuerRef`);
  - closure = runtime v5.1 `8c7a166b…`, verificatore `142bb726…`, `mandates.py` `86e70b8c…` a `c25dca54`;
  - ogni altro campo uguale al manifest gen 2, tranne `generation`, `softwareClosure` e `issuedAt` (D-027). Se un campo differisce, il codice è `ACCEPTANCE_V51_CONTEXT_DRIFT` con `differingFields`.

## Configurazione v5.1
- **Copiati dal v5:** `runtime*`, `python*`, `driver*`, `admission*`, `registryRoot`, `runtimeStateRoot`, `opensslBinding`, `armingIssuerRef`, `candidates` (INACTIVE).
- **Nuovi:**
  - `acceptance` = gen 3;
  - `b1b2Anchor` = policy B1/B2 `6ef247ee…`;
  - `mandateRoot` = `/var/lib/ouf-authority-mandates/b1b2`;
  - `armingRoot` = `<root>/arming` (vuota, 0700);
  - verificatore e `b1b2AuthorityModule` (= `mandates.py`) puntano alle copie installate.

## Sequenza dell'apply
1. Digest uguale al plan. `mkdir` esclusivo della root `semantic-runtime-v51-install-20261114-v1` e pubblicazione con `publish_once` (file 0600, directory 0700).
2. Loader v5.1 reale compilato dai byte **installati**: `load_configuration`, `verify_files` (compresa la validazione del registro) e `arming_absence`.
3. Smoke `--version` in un processo isolato.
4. `switch_existing_wrapper` invariata. A `BEFORE_CLAIM`, `BEFORE_RENAME` e `AFTER_RENAME` si rifà l'osservazione completa più la verifica della pubblicazione.
5. Readback del wrapper, smoke tramite il wrapper, osservazione finale e `result.json` (`SEMANTIC_RUNTIME_V51_INSTALLED_INACTIVE`).

Nessun retry: dopo la creazione della root `doNotRerunApply` è true. Contatori: 0 operazioni sui container, 0 chiavi lette, 0 firme, nessun riavvio.

## Ripristino
Riporta i byte di `<root v5.1>/switch/prior-runtime-wrapper.sh` (= wrapper B1) in una root di claim nuova (`semantic-runtime-v51-restore-v1`). È ammesso solo se:
- il claim è coerente;
- i target B1 sono invariati;
- `arming/` v5.1 e v5 sono vuote;
- i successor non sono mai stati avviati;
- il lock è vuoto.

Non dipende dalla ricevuta dell'installazione, quindi funziona anche dopo un apply parziale. Se il wrapper è già quello v5, l'esito è `NOTHING_TO_RESTORE`.

## Sul VPS (umano)
```bash
cd $(mktemp -d)
C=<commit del runbook>
H=<sha256 del runbook>
curl -fsS -o r.sh https://raw.githubusercontent.com/GioNob/ouf-deploy/$C/ops/vps/runtime-v51-install.sh
echo $H r.sh | sed 's/ /  /' | sha256sum -c
bash r.sh plan            # poi, dopo la review di Claude: bash r.sh apply <planSha256>
```
