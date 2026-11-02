# SeaweedFS — proposta di valutazione di applicabilità per SW-G1

2 novembre 2026. **Bozza da sottoporre all’owner: non approvata, non è una VEX ammessa e non cambia il gate corrente.** Nessun ignore, nessuna opzione --vex o soppressione aggiunta agli scanner. Il rapporto grezzo rimane HELD con1UNKNOWN.

## Decisione concreta proposta

Nel solo MiniPET MinIO→SeaweedFS, consentire una valutazione di non applicabilità per GO-2026-5932, limitata al binario server SHA256 `bb9f768e5afca39c7fdc2113e5caafd9f911d4537917dd25c520ee4dbdab1f74`, soltanto dopo review umana dell'evidenza di compilazione e della fonte ufficiale. La classificazione proposta è `not_affected` con motivazione `vulnerable_code_not_present`. Il modulo x/crypto è presente; la famiglia di pacchetti OpenPGP interessata non risulta importata nel grafo effettivo di compilazione.

Il criterio vigente di SW-G1, MiniPET v1.0 §5, è: «Zero CRITICAL/HIGH/UNKNOWN secondo gate vigente, provenienza verificabile; nessun ignore aggiunto per passare». Il gate implementato resta HELD sul rapporto grezzo. Per questo la proposta richiede una decisione esplicita dell'owner sul criterio di applicabilità; l'autorizzazione generale allo sviluppo non basta per modificarlo. Nessuna decisione viene inferita dalla qualifica del laboratorio, dal completamento dell'inventario o dal comando offline17.

| Evidenza | Stato |
|---|---|
| Sorgente SeaweedFS | `153ab668c99731a6d29492bf6c61d0b4fa701101`, release4.51 dichiarata |
| Build posseduta da OUF | Go1.27.3, CGO0, JOSE4.1.6 e x/net0.62.0; distinta dall'asset upstream |
| Binario oggetto della proposta | SHA256bb9f768e5afca39c7fdc2113e5caafd9f911d4537917dd25c520ee4dbdab1f74 |
| Grafo compilato |1738pacchetti; `golang.org/x/crypto/openpgp` e sotto-pacchetti assenti |
| Hash del grafo | `67534a54978a5a157673a6a21ea26c147b0dbcb60c60d30497ce39e6ee3c435b` |
| Risultato grezzo |0HIGH/CRITICAL,1UNKNOWN; nessuna soppressione |
| Gate produzione |HELD; nessuna review/applicabilità ammessa, nessuna installazione |

## Fonti e significato tecnico

L'[advisory ufficiale Go](https://vuln.go.dev/ID/GO-2026-5932.json), consultato il2novembre, è pubblicato e modificato al7luglio2026 e non dichiara una versione corretta. Identifica la famiglia `golang.org/x/crypto/openpgp`, incluso packet/armor/clearsign/errors/elgamal/s2k. Un aggiornamento nominale del modulo non costituisce correzione del vecchio pacchetto. Non deduciamo dalle PR upstream aperte che la banca dati sia già cambiata.

La [specifica OpenVEX](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md) distingue il componente assente dal componente presente con codice vulnerabile escluso dalla build. Quest'ultimo è il significato della motivazione proposta. È una valutazione tecnica da approvare, non una tolleranza generica verso vulnerabilità raggiungibili o future.

La provenienza verificata è quella della build OUF nel workflow/source/ref esatti su runner hosted; non è una firma del publisher upstream né prova di uguaglianza con il suo asset. I rapporti originali e i riferimenti immutabili restano in [dossier della qualifica del piano](../evidence/seaweedfs-offline-plan-qualified-20261102.json), [sicurezza server](../evidence/seaweedfs-patched-security-held-20261102.json) e nel [dossier delle prove di copia](../evidence/seaweedfs-copy-core-qualified-20261102.json), con readback indipendente CI41507064288 PASS e archivio dei rapporti grezzi/provenienza.

## Vincoli dell’eventuale decisione

- Riferimento al solo advisory GO-2026-5932 e al binario esatto sopra, senza accettare altri UNKNOWN o HIGH/CRITICAL.
- Rapporto raw conservato integralmente; nuova valutazione separata, motivata e collegata al reviewer/decisionRef secondo il processo del progetto. Nessun documento VEX standard utilizzabile automaticamente viene emesso da questa bozza.
- Qualsiasi variazione di binario, sorgente, patch dipendenze, toolchain, grafo compilato o perimetro dell’advisory invalida la valutazione fino a nuova review. L'import di uno dei pacchetti interessati rende la proposta inammissibile.
- La decisione di applicabilità non autorizza installazione, copia dei dati o cutover. G0,G2–G7,corpi/writer/DB,coorte,custody e autorità runtime continuano nei rispettivi gate. Nessuna accettazione M2 viene prodotta.

Se il criterio resta strettamente zero anche sul rapporto raw, questo candidato rimane HELD: si attende una correzione verificabile del rapporto/advisory o si riqualifica una build che superi quel criterio, senza rinominare dipendenze, falsificare versioni o sopprimere findings. Nessuna decisione dell'owner è stata ancora acquisita.
