# Accettazione generazione 3 per il runtime v5.1 (sprint-01, task-29a)

Riferimenti: D-024, D-027, D-028, D-029; `_handoff/sprint-01/task-29.md` §29a.

## Perché
L'accettazione B1 generazione 2 firma una `softwareClosure` con i tre file del runtime v5. Installare il v5.1 (task-29b) con quella accettazione dichiarerebbe file non installati (D-027). La generazione 3 firma la closure v5.1:
- `tools/semantic_runtime_v51/semantic_provider_docker_runtime_v51.py`;
- `tools/semantic_runtime_v51/arming_verifier_v51.py`;
- `tools/semantic_authority_mandates/mandates.py`.

## Strumento
`scripts/issue-semantic-provider-acceptance-v51.py` ha lo stesso contratto dell'emettitore del task-24: stessi input (profilo, A2, ricreazione, rootfs, ricette v2), stesso manifest `ouf.semantic-provider-b1-artifact-acceptance.v2`, stesse lacune dichiarate. Le differenze sono queste:
- la closure è quella v5.1 e la generazione deve essere ≥ 3;
- il mandato della chiave installer per `ARTIFACT_ACCEPTANCE` si legge da **ancora B1/B2 + registro dei mandati** (`--mandate-root`, D-028):
  - `at(issuedAt)`: mandato in vigore a `issuedAt`, `ACTIVE`, mai revocato;
  - `current()`: mandato al momento della firma, prima e dopo;
- firma e verifica (subito dopo la firma e alla rilettura) passano da `MandateAuthenticator`, con lo stesso envelope e lo stesso dominio B1/B2. Lo strumento funziona quindi anche dopo il 2027-01-02, se il registro è stato rinnovato;
- `mandates.py` si compila dai byte della closure verificati per hash, senza importarlo da path.

Gli strumenti B1 (emettitore, signer, verificatore) restano invariati. Il modulo nuovo `tools/semantic_acceptance_v51/` riusa solo le funzioni pure di `semantic_b1_acceptance` (build, decodifica, validazione).

## Plan e apply
- `plan`: non legge la chiave. Mostra i byte del manifest, il loro hash, il mandato in vigore (con la sua generazione) e lo snapshot del registro.
- `apply <planSha256>`: legge la chiave una volta (`privateKeysRead: 1`), firma, verifica, scrive manifest, firma e `result.json` e li rilegge.

Se il registro cambia tra plan e apply, l'hash del piano cambia e l'apply viene rifiutato.

## Runbook `ops/vps/acceptance-v51.sh`
Scarica, a un commit fissato, lo strumento e i suoi moduli, ciascuno con il suo hash. La consegna del plan viene salvata e riusata dall'apply. Output: `/etc/ouf/deploy-snapshots/semantic-provider-acceptance-v51-g3/`.
