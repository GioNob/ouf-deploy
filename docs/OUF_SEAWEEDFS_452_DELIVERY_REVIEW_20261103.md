# SeaweedFS 4.52 — dossier tecnico di co-consegna

Data: 2026-11-03  
Stato: `TECHNICAL_DELIVERY_DOSSIER_PREPARED_REVIEW_OPEN`

## Risultato

Il dossier ricostruisce e chiude tecnicamente il materiale di review per il
candidato SeaweedFS 4.52 qualificato a 15 patch. Il binding resta quello del
candidate lock attestato:

- upstream `984eac6a790be89e2a11de175a7413e1e3e32dd3`;
- binario SHA256 `85fa52c68a783f3cf4d54ae6064e7b46d022982c1bef4460616dd76cdc609033`;
- OCI manifest `sha256:1bb1ff9d7a42e98f5c6a90903644ed5e18e83a89d76bccbc4d16ce6b8027c6b4`;
- candidate lock SHA256 `81ce6f162cd1ca0e0ac60511ae4565e9e7315d56bccbeefd9882a729307939ea`.

Il generatore ricombina senza rete il corpus storico autenticato e il delta
patch 15, verificando i rispettivi SHA256 e ogni membro elencato nei manifest.
Il risultato contiene:

| Evidenza | Quantità verificata |
|---|---:|
| Moduli terzi correnti | 262 |
| Set riusati byte-identici | 224 |
| Versioni nuove/cambiate | 38 |
| Testi terzi | 353 |
| Archivi sorgente MPL integri | 17 |
| Osservazioni raw UNKNOWN | 3 |
| Viste senza classificazione | 3 |

Gli UNKNOWN sono conservati nel loro contesto Arrow, Thrift e parquet. Le tre
viste senza classificazione sono mantenute come categoria distinta. Nessuno dei
due insiemi viene convertito automaticamente in una decisione di licenza.

## Materiale prodotto

- `evidence/seaweedfs-452-component-obligation-matrix-20261103.json` e `.csv`:
  componente, versione, provenienza, testo originale, hash, osservazioni raw e
  quesiti di review. Ogni espressione resta `NOASSERTION`, ogni applicabilità
  `OPEN_HUMAN` e ogni accettazione obblighi `false`.
- `evidence/artifacts/seaweedfs-452-attribution-source-review-bundle.zip.part-000..002`:
  tre parti binarie uguali da 610.711 byte, concatenate in ordine dalla
  workflow per ricostruire il bundle ZIP esatto.
- `evidence/artifacts/seaweedfs-452-attribution-source-review-bundle.zip`
  (ricostruito): matrice, 353 testi terzi, testi root candidati, i 17 archivi
  sorgente MPL, output raw del classificatore, candidate lock e manifest chiuso
  `SHA256SUMS`.
- `releases/seaweedfs-452-delivery-evidence-lock-20261103.json`: lock derivato
  del dossier. Non modifica né sostituisce il candidate lock attestato.
- `releases/seaweedfs-452-durable-custody-plan-20261103.json`: requisiti di
  custodia, con destinazione, retention, copia, readback e recovery ancora
  esplicitamente non eseguiti.
- `scripts/build-seaweedfs-452-delivery-evidence.py` e
  `scripts/verify-seaweedfs-452-delivery-evidence.py`: generazione deterministica
  e verifica fail-closed.

Il bundle ricostruito è di 1.832.133 byte e ha SHA256
`d02665c32943bb362f3ace5a7c96093634807d468354b1aaaf5f77efe8bc0f19`.
Una seconda generazione indipendente dagli stessi input ha prodotto lo stesso
SHA256.

## Limiti e autorità

Questo lotto non è un parere legale e non chiude SW-G1. Restano `OPEN_HUMAN`:

1. espressione applicabile e obblighi per ciascun componente;
2. forma finale di attribuzioni, notice, indicazione modifiche e sorgenti;
3. sufficienza del bundle per la modalità di distribuzione scelta;
4. accettazione o rifiuto della redistribuzione;
5. destinazione e retention della custodia durevole;
6. copia dell'OCI completo, readback e prova di recovery;
7. ammissione finale della coorte.

Il dossier registra `redistributionAccepted=false`, `durableImageCustody=OPEN`,
`releaseAdmitted=false`, `runtimeAuthorityIssued=false` e `targetOperations=0`.
Non cambia MinIO attivo, gate/AT, oggetti reali, Scope17/52, Teatri/M1 o
Farmacie. L'artifact OCI temporaneo continua ad avere scadenza 2027-02-01.

## Riproduzione

```bash
python3 scripts/build-seaweedfs-452-delivery-evidence.py \
  --candidate-lock releases/seaweedfs-452-candidate-lock-20261103.json \
  --historical-licences g1-licences-baseline-41541625141.zip \
  --licence-delta seaweedfs-452-patch15-licence-delta.zip \
  --output-dir /tmp/seaweedfs-452-delivery

cat evidence/artifacts/seaweedfs-452-attribution-source-review-bundle.zip.part-{000,001,002} \
  > evidence/artifacts/seaweedfs-452-attribution-source-review-bundle.zip

python3 scripts/verify-seaweedfs-452-delivery-evidence.py \
  --delivery-lock releases/seaweedfs-452-delivery-evidence-lock-20261103.json \
  --matrix evidence/seaweedfs-452-component-obligation-matrix-20261103.json \
  --matrix-csv evidence/seaweedfs-452-component-obligation-matrix-20261103.csv \
  --bundle evidence/artifacts/seaweedfs-452-attribution-source-review-bundle.zip \
  --custody-plan releases/seaweedfs-452-durable-custody-plan-20261103.json
```

La workflow dedicata verifica bundle, manifest, hash dei 353 testi, 17 sorgenti,
confini di autorità e casi negativi; conserva e attesta una ricevuta bounded.
