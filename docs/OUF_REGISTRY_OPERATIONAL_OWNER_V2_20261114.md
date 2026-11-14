# Worker del registry v2: ricevuta datata e verifica durevole (sprint-01, task-30a)

Riferimenti: D-029, D-031; `_handoff/sprint-01/analysis-task30-registry-receipt.md`; registro dei mandati in `docs/OUF_SEMANTIC_AUTHORITY_MANDATES_20261114.md`; job di rinnovo in `docs/OUF_SEMANTIC_MANDATE_RENEWAL_20261114.md`.

## Perché un pacchetto nuovo
`tools/semantic_registry_operational_owner/` (v1) è fissato per hash nelle closure dell'installazione M2 discovery: `tools/m2_discovery_installation_profile/*_sources.json` e `lease_capsule.py` fissano `core`, `store`, `guard`, `contract` e `installation`. Per questo la v2 è un pacchetto separato, `tools/semantic_registry_operational_owner_v2/`, con un builder dedicato, `scripts/build-registry-operational-owner-v2-capsule.py`. La v1 resta invariata byte per byte, e la CI della v2 lo verifica.

## Differenze v1 → v2
| | v1 | v2 |
|---|---|---|
| Ricevuta | `…installation-receipt.v1`, senza tempo | `…installation-receipt.v2` con `attestedAt` (epoch int) firmato, campi esatti |
| Configurazione | `verification` {trustPolicy, openssl, context} | più `mandateLedgerRoot`, per default `/var/lib/ouf-authority-mandates/base` (task-28) |
| Verifica a ogni ciclo | firma `CREATION_ATTESTATION` nella finestra **corrente** dell'attestor | firma verificata con la chiave dell'ancora base e mandato `at(attestedAt)` dal registro; chiave mai revocata |
| Sandbox systemd | — | il registro della base è montato in sola lettura; `key_isolation` lo esclude per le chiavi |
| Capsula | 8 sorgenti | 10 sorgenti: più `durable` e `tools.semantic_authority_mandates.mandates` (byte identici al file del registro) |

Restano identici:
- la firma (envelope `ouf.semantic-deployment-detached-signature.v1`, dominio `OUF-DEPLOYMENT-EVIDENCE\0V1\0`, OpenSSL vincolato);
- la configurazione fissata per hash nella unit;
- i sorgenti in esecuzione, il fence, la credenziale e l'output.

## Verifica durevole (`durable.verify_receipt`)
1. `attestedAt` è intero e ≤ `now + 300`. Codici: `DATED_INSTALLATION_RECEIPT_REQUIRED`, `RECEIPT_ATTESTED_IN_FUTURE`.
2. Il registro della base si legge in sola lettura con `mandates.MandateLedger`: custodia, catena, invarianti e niente temporanei. Le violazioni restituiscono il codice di `mandates.py`, per esempio `MANDATE_TEMPORARY_ENTRY_PRESENT` o `MANDATE_GENERATION_GAP`.
3. Envelope esatto: ruolo `CREATION_ATTESTATION`, issuer `attestorRef`, scope e `payloadHash`.
4. La chiave non è mai stata revocata, né nell'ancora né nel registro (`ATTESTOR_KEY_REVOKED`).
5. `at(keyRef, attestedAt)`: stato `ACTIVE`, ruolo e issuer concessi dall'ancora, `notBefore ≤ attestedAt < expiresAt` (`ATTESTOR_MANDATE_AT_ATTESTATION_REQUIRED`).
6. Verifica Ed25519 con la chiave pubblica dell'ancora (`DETACHED_SIGNATURE_INVALID`).
7. Alla fine si rileggono il registro e la firma: lo snapshot deve essere identico (`MANDATE_LEDGER_CHANGED_DURING_VERIFICATION`).

Effetto: la scadenza dei mandati non ferma il worker, perché conta solo il mandato in vigore ad `attestedAt`. Una revoca, o un registro corrotto, lo fermano sempre.

## Installazione
`install_files` scrive la ricevuta v2. Legge `attestedAt` **prima** della firma, dentro la finestra HUMAN dell'autorità d'installazione (`ATTESTATION_INSIDE_HUMAN_WINDOW_REQUIRED`), e quel valore fa parte dei byte firmati.

L'aggiornamento di un'installazione v1 in esercizio a v2 è il task-30b. La cerimonia sul VPS, con la firma dell'attestor, va fatta entro metà dicembre 2026 (D-031).

## CI
`.github/workflows/semantic-registry-operational-owner-v2.yml`:
- componenti, contratto e capsula v2;
- test nativi: TLS IAM, ricevuta datata con Ed25519 reale, installazione e sandbox;
- non regressione della capsula v1;
- verifica che ogni pin della v1 nelle closure M2 corrisponda ai byte di HEAD.
