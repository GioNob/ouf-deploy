# Proposta — allineamento controllato della baseline Go del MCP

Stato: **PROPOSTA, decisione owner non acquisita**. 30 ottobre2026, Europe/Rome.
Questa proposta riguarda il vincolo tecnologico del PET. Non autorizza deploy,
import, grant, budget, replay, attivazioni o accettazione M2.

## Decisione concreta proposta

Aggiornare il solo vincolo Go del MCP da minor1.25 a **Go1.26.10**, con pin
esatto iniziale di toolchain e checksum. Conservare Go SDK MCP1.7.0, protocollo
2026-07-28, singolo codebase/binario e process role server/maintenance-worker,
API, capability, ownership, Gateway, Authorization e THS. Le patch compatibili
1.26 restano soggette ai gate; una nuova minor richiede una decisione controllata.

Identificativo della decisione proposta:
`APPROVE_CONTROLLED_MCP_GO_BASELINE_1_26_10`.

I DOCX originali e i323 checksum della baseline restano intatti. Dopo una decisione
esplicita si registra un addendum/supersession controllato e si aggiornano le
proiezioni normative, conservando origine, motivazione e gate. Nessuna approvazione
è dedotta da questa bozza, dalla sola delega di sviluppo, da una CI verde o da un
precedente merge tecnico.

## Discrepanza osservata

| Fonte | Vincolo/fatto |
| --- | --- |
| Matrix1.7, baseline tecnologica MCP | Go1.25 e SDK ufficiale1.7.x; toolchain/checksum e gate di conformità/interoperabilità |
| PET MCP1.4, Parte II §65 | «Go toolchain 1.25 obbligatoria»; sono ammessi aggiornamenti patch compatibili sottoposti ai gate CI |
| PET MCP1.4, runtime baseline | Go1.25.0 o patch compatibile della stessa minor |
| MCP09d1f521, `go.mod` | `go 1.26.10`, SDK ufficiale1.7.0 |
| Stesso commit, Dockerfile/CI/verify | Build Go1.26.10 e controllo esatto di quella toolchain |
| Pacchetto MCP selezionato | Artifact12882394596, immaginea013bceb49696a72853948b14f802e479e268e02046a889f142500d3022f5580; build infoGo1.26.10 verificata nel readback |

Il testo normativo è stato riletto nei DOCX originali:
[Matrix1.7](../baseline/v1.7/package/docs/l0/OUF_Cross_Module_Alignment_Matrix_v1_7_Channel_Neutral_OA_Aligned.docx)
e [MCP1.4](../baseline/v1.7/package/docs/l1/OUF_MCP_Server_v1_4_Go_Channel_Neutral_Operational_Awareness.docx).
Non è una dichiarazione di conformità completa dei PET.

Sorgente candidato: [go.mod](https://github.com/GioNob/ouf-mcp-server/blob/09d1f521703f2e896398c751b41008f22c6dca0d/go.mod),
[Dockerfile](https://github.com/GioNob/ouf-mcp-server/blob/09d1f521703f2e896398c751b41008f22c6dca0d/Dockerfile),
[verify](https://github.com/GioNob/ouf-mcp-server/blob/09d1f521703f2e896398c751b41008f22c6dca0d/scripts/verify.sh).
[Readback pacchetto](../../evidence/m2-discovery-native-witness-and-packages-20261029.json).

## Motivazione e alternative

La [policy ufficiale Go](https://go.dev/doc/devel/release) supporta una release
fino all'arrivo di due major successive. Go1.26 è uscito il10febbraio2026 e
Go1.27 il19agosto2026: ne consegue che Go1.25 è fuori supporto alla data della
proposta. È una deduzione dalla policy/date ufficiali, non un'eccezione già
concessa al PET OUF.

Il [database ufficiale Go, GO-2026-6809](https://go.googlesource.com/vulndb/+/refs/heads/master/data/reports/GO-2026-6809.yaml)
indica il fix crypto/x509 in1.26.10 e1.27.3. Il registro progetto
[OUF_RESILIENCE_ADOPTION](../OUF_RESILIENCE_ADOPTION.md), sezione «Sicurezza emersa
durante la qualifica», documenta il precedente passaggio da1.25.13 a1.26.9 per
vulnerabilità raggiungibili. L'ulteriore patch1.26.10 è documentata nei checkpoint
acquisizione. Questi sono motivi e prove tecniche; nei riferimenti consultati non
è stata trovata una decisione esplicita che aggiorni il vincolo minor del PET.
Non si conclude che una decisione non possa esistere altrove.

| Opzione | Valutazione |
| --- | --- |
| Confermare1.26.10 con addendum controllato | Raccomandata: candidato già costruito e qualificato nel suo perimetro; fix di sicurezza e minor supportata, senza nuovo cambio di SDK/architettura |
| Tornare a1.25 | Non proposta: linea fuori supporto; richiederebbe ricostruzione e nuova verifica dei finding, senza presumere sicuro il downgrade |
| Passare a1.27 | Opzione futura distinta: nuova minor/build/pacchetto e nuova qualifica; non è implicita in questa proposta |

## Gate conservati e stato

Restano obbligatori pin/checksum/go.sum, SCA senza suppression, regressioni dei
contratti, conformità ufficiale MCP2026-07-28, interoperabilità con client
indipendenti, build/SBOM/scan/provenienza, OCI/rootfs e ammissione corrente del
target. L'approvazione dell'addendum non rende automaticamente PASS alcun gate.

I risultati storici M1/G4 restano conservati nel loro perimetro: questo
allineamento non li riscrive e non attribuisce autorità retroattiva.
La qualifica dei sorgenti e del pacchetto rimane tracciata nei record esistenti.
Non si attribuisce alla sola suite Go/SDK la conformità ufficiale completa o la
prova dei due client reali M2. Piena coorte corrente, TLS/IAM/DB/fencing/trust,
boot/rotation, pubblicazione coordinata e vero CSV→UDP con esiti per riga restano
OPEN. Le capabilities UDP sugli oggetti caricati rimangono qualificate
separatamente; search non è una fase del caricamento.

Fino alla decisione il pacchetto MCP resta una selezione tecnica con discrepanza
normativa aperta. Nessun comando di installazione target è consegnabile sulla
base di questa proposta. Gli input e i comandi consumati restano consumati.
