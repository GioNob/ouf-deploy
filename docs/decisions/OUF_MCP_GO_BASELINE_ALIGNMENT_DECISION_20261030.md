# Decisione owner — baseline Go corrente supportata per MCP

Stato: **APPROVATA dall’owner nella conversazione, 30 ottobre 2026, Europe/Rome**.
Identificativo: `APPROVE_CURRENT_STABLE_SUPPORTED_MCP_GO`.

L’owner ha risposto alla proposta di allineamento della baseline:

> Va benissimo usare l'ultima versione di go. Anzi, direi che è auspicabile.

La decisione supera il vincolo Go 1.25/patch della stessa linea di Matrix 1.7 e
PET MCP 1.4, Parte II §65. Il nuovo vincolo è la **release stabile corrente e
supportata di Go**, risolta e fissata esattamente per ogni candidato. Non si usa
un tag mobile `latest` e non si includono beta, release candidate o versioni devel.
Gli aggiornamenti della sola toolchain, anche di linea, sono compresi nella
preferenza espressa; restano subordinati a compatibilità e tutti i gate previsti.
Non occorre una nuova approvazione per il solo passaggio di versione Go.

## Versione iniziale risolta

Al 30 ottobre 2026 è **Go 1.27.3**. I tag stabili del repository ufficiale Go sono
stati consultati tramite GitHub; la release è fissata al commit
`2aae1000ea1d4b28923b96db28acf4e3b99d6aff`. Il relativo
[VERSION ufficiale](https://github.com/golang/go/blob/2aae1000ea1d4b28923b96db28acf4e3b99d6aff/VERSION)
riporta `go1.27.3` e `time 2026-10-19T22:20:36Z`.
La [policy di supporto e cronologia](https://go.dev/doc/devel/release)
rimangono riferimenti per le successive verifiche.

Il pacchetto MCP 12882394596/commit 09d1f521 con Go 1.26.10 conserva il suo
readback storico. Occorrono un **nuovo candidato 1.27.3, build, controlli e
pacchetto** prima di aggiornare la selezione installabile: la decisione non
trasforma il vecchio binario in una build della nuova toolchain.

## Contratti e prove conservati

Restano SDK MCP ufficiale 1.7.0, protocollo 2026-07-28, singolo codebase/binario
con process role server/maintenance-worker, API, capabilities, ownership, Gateway,
Authorization e THS. Restano obbligatori pin/checksum/toolchain/go.sum, SCA senza
suppression, regressioni, conformità MCP ufficiale, interoperabilità, SBOM/scan/
provenienza, verifica dell’immagine e ammissione corrente del target. Le prove
storiche M1/G4 rimangono valide esclusivamente nel loro perimetro; nessun gate
M2 diventa PASS per effetto di questa decisione.

I DOCX originali e i 323 checksum della baseline restano byte-exact. Questo è
un addendum controllato, non una modifica retroattiva dei testi originali:

| Originale | SHA-256 conservato |
| --- | --- |
| Matrix 1.7 | d48a3b36ea3dd23622da380ec498f753fcd37f49f534735fe7ef904def387b1b |
| MCP PET 1.4 | 83165c93197bc4d9fca9bfbbb346b48977931b0e0527849e57b894078cec1008 |

La [proposta 1.26.10](OUF_MCP_GO_BASELINE_ALIGNMENT_PROPOSAL_20261030.md) rimane
un documento storico immutato; questa decisione acquisisce l’orientamento più
ampio espresso dall’owner verso la release stabile corrente, non soltanto 1.26.10.

## Perimetro operativo

La decisione risolve la discrepanza normativa della toolchain. Non è un grant,
un reset di budget, un replay, un’ammissione nativa o un’accettazione M2.
Piena coorte corrente, TLS/IAM/DB/fencing/trust, boot/rotation, pubblicazione
coordinata e vero CSV→UDP con tutti gli esiti per riga rimangono da qualificare.
Le capabilities UDP si qualificano separatamente sugli oggetti caricati;
search non è una fase del caricamento. Gli scope consumati restano consumati.
