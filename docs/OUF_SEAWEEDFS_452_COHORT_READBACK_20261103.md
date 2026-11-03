# SeaweedFS 4.52 — readback della coorte candidata

## Stato

La coorte tecnica del candidato è stata riletta localmente sui byte esatti ed è
`TECHNICAL_COHORT_VERIFIED_NOT_ADMITTED`. Questo stato non chiude SW-G1, non
accetta la redistribuzione e non concede autorità runtime.

La verifica lega questi quattro elementi:

- archivio completo dell'immagine prodotto dalla CI 41622752493, artifact
  13224053625, 194.296.104 byte, SHA256
  `bca4d0a493717812d464f9dc6c7478d918c5dd7f56cd7b5d21f0d4fbcccaeed9`;
- readback indipendente 13225461651, SHA256
  `8fade01821e5cd6f8c76fd6828ec7fd8c522072fbee5280823697475cb43582b`;
- delta licenze della patch 15, SHA256
  `7cf2b9dc596ded071c9c75f1bfeb87245f443e25984b9cddf8bf4f411791eda2`;
- corpus storico completo delle licenze, SHA256
  `851d65dc1ac3788178978b9effc04c257475492ad6d3e5dcc04346d033288c67`.

Il verificatore ricostruisce nuovamente il readback dell'archivio completo,
controlla i 16 checksum interni e i 21 file sorgente, riproduce assessment e OCI,
verifica il binding della firma GitHub al workflow, al commit produttore
`7a775d2a63ae5ede005056c325db85e2f335ed94` e al runner ospitato, quindi collega
il binario, il manifest OCI e i due corpus di licenza al lock del candidato.

Risultato locale riproducibile:

- binario SHA256 `85fa52c68a783f3cf4d54ae6064e7b46d022982c1bef4460616dd76cdc609033`;
- manifest OCI `sha256:1bb1ff9d7a42e98f5c6a90903644ed5e18e83a89d76bccbc4d16ce6b8027c6b4`;
- 262 moduli terzi e 353 testi legali legati ai checksum;
- contesto esatto dei tre risultati `UNKNOWN` del classificatore verificato;
- [ricevuta canonica ospitata](../evidence/seaweedfs-452-cohort-readback-hosted-20261103.json)
  SHA256 `da3482b4710e50c40634a89e37d7d17d78bdff8073d00e048ba00990de16f092`;
- 6 test unitari del verificatore PASS, oltre alla rilettura integrale.

Il [workflow dedicato 41627470213](https://github.com/GioNob/ouf-deploy/actions/runs/41627470213)
ha completato con successo tutti i sette step sul sorgente `fe6b392c1e5789513c6cea18fdf913b0acf1c559`.
Ha scaricato gli artifact originali con permesso Actions in sola lettura, ripetuto
la verifica su runner ospitato, attestato la ricevuta e conservato soltanto la
ricevuta bounded. L'artifact 13226228195 è un ZIP da 988 byte con un solo membro,
SHA256 `eff348904adb4ad63f6bf7304914b3972e11db468ea8c5d136c35972c5f1c6d4`,
scadenza 1 febbraio 2027. Il download indipendente locale ha confermato digest,
membro unico e byte della ricevuta. Il workflow non pubblica né distribuisce
l'immagine.

## Contesto dei tre risultati di licenza

La verifica conserva i risultati grezzi e non li converte in espressioni SPDX
approvate:

| Modulo e file | SHA256 | Rilevazioni nello stesso testo |
|---|---|---|
| Arrow Go v18.8.0 `LICENSE.txt` | `ff2fe52b8dfd2574c6ea7f0c407948c857f62672c2a3a9a17083ee10af8067ef` | Apache-2.0, BSD-3-Clause, `Copyright` UNKNOWN |
| Thrift v0.24.0 `LICENSE` | `89aa7b27868669299bd8a6c53b72ec4beadce42dad6c8336797cc26e1e8df98d` | Apache-2.0, BSD-3-Clause, `GNU-All-permissive-Copying-License` UNKNOWN |
| parquet-go v0.32.0 `LICENSE` | `6720c58d56926778b4656eb72c446ef65e8a416e2d2af498c8caaab24a02c8e9` | Apache-2.0, `Copyright` UNKNOWN |

Il contesto tecnico è verificato. Applicabilità, obblighi di co-consegna e
accettazione della redistribuzione restano `OPEN` per la review competente.

## Limiti e gate

L'archivio completo dell'immagine resta custodito soltanto come artifact CI con
scadenza 1 febbraio 2027: non è custodia durevole. Il corpus e il delta delle
licenze sono conservati nel repository, ma la review non è accettata. La coorte
dei contenuti è verificata; custodia durevole e ammissione della coorte restano
aperte.

Stato invariato: circa 35% ±10 di avanzamento ingegneristico, 0/8 gate chiusi,
0/21 AT accettati e 0/120 oggetti reali copiati. MinIO resta in esercizio.
Scope17/52 Engine GET, Teatri/M1 8/8 tecniche e 6/6 funzionali, e Farmacie
61 righe/10 OPEN/STRING sono preservati. Nessuna operazione target, replay,
reset, grant, merge, deploy o nuova autorità è stata eseguita.

Autorità applicate: PET UDP v1.3 §§109.4–109.5, Matrix v1.7 §§1/4/5 e policy di
resilienza v3. Il verificatore nega esplicitamente lock che dichiarino release,
autorità runtime, risultati vulnerabilità grezzi non nulli o operazioni target.
