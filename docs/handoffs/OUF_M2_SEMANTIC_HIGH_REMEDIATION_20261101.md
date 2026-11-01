# M2 — Tre HIGH risolti nel candidato Semantic qualificato

1 novembre 2026, Europe/Rome. Priorità esplicita dell'owner: risolvere i HIGH.
La correzione è verificata nel candidato sostitutivo esatto già necessario per M2.
Il VPS conserva ancora l'immagine precedente: il suo diniego di sicurezza rimane.

| Pacchetto | Versione installata conservata | Versione nel candidato | Esito |
|---|---|---|---|
| curl | 8.18.0-1ubuntu2.7 | 8.18.0-1ubuntu2.8 | CVE-2026-92392 assente |
| libcurl4t64 | 8.18.0-1ubuntu2.7 | 8.18.0-1ubuntu2.8 | CVE-2026-92392 assente |
| libbrotli1 | 1.2.0-3build1 | 1.2.0-3ubuntu0.1 | CVE-2026-111497 assente |

Il candidato è sorgente `c2dae77b42f1811b704465f6ab813c91d808ade4`, configurazione
`a6f00cda`, envelope nativo `d06aeb52`, artifact originale `13066396654` nel
repository `GioNob/ouf-semantic-registry`. Sono riutilizzati gli stessi byte:
nessuna ricostruzione, rietichettatura o modifica applicativa. Le qualifiche
applicative precedenti restano quelle del
[dossier credenziali](../../evidence/m2-native-provider-credential-qualified-20261101.json):
133 test modulo, container smoke e 14 casi nativi con Java/Keycloak, più la
verifica indipendente Docker29.8.1. Questa consegna non li dichiara rieseguiti.

Il nuovo controllo rilegge l'archivio originale esatto, tutte le configurazioni,
i layer e i diff ID; Trivy0.70.0 scansiona OS e JAR a tutte le severità, unfixed
inclusi, con ignore file esplicitamente vuoto. Esito: **0 HIGH,0 CRITICAL,0 UNKNOWN,
53 MEDIUM,4 LOW**. Oltre al gate esistente, richiede i tre pacchetti presenti in
inventario nelle versioni vendor corrette usando l'ordinamento Debian nativo;
nega anche il CVE che rimanga presente a una severità più bassa. Una scansione
riutilizzata come corrente deve avere meno di 24 ore; l'ammissione target deve
ricontrollare la freschezza. Questa registrazione conserva una prova datata.

Qualifica sorgente `c893120b`, [run41351198866](https://github.com/GioNob/ouf-deploy/actions/runs/41351198866),
job124981513469:15 test, zero failure/error/skip e scansione reale PASS; log finale
letto. Evidenza originale13100779425,100.936 byte, SHA256 `4fed16f6…`, preservata.

Readback indipendente sorgente `835e52b6`,
[run41351447269](https://github.com/GioNob/ouf-deploy/actions/runs/41351447269),
job124982301308 PASS, log finale letto. Rilegge intero ZIP, sei membri e quattro
checksum, ricompone il risultato e verifica con gh2.97.0 la catena Sigstore,
trasparenza, workflow/ref/source esatti e runner hosted. Evidenza13101203812,
109.538 byte, SHA256 `4e4551c6…`, preservata e confrontata localmente con tutti
i membri originali. La catena è verificata nel job nominato; il lettore offline
controlla il relativo output esatto e non dichiara una nuova verifica locale.

Il [profilo di provenienza](../../releases/m2-retained-runtime-origin-reconciliation-20261101.json)
include ora `roles.semantic.remediationCandidate`. Mantiene sul ruolo installato
sorgenteeccef11a/config29e32c14/nativeb61bc39c e `HELD_HIGH_CRITICAL_UNKNOWN` con
i tre HIGH: non scambia il candidato con il target. I test aggiunti respingono
alterazioni di entrambi gli ZIP e verificano la separazione di immagini/authority.
[Dossier strutturato](../../evidence/m2-semantic-high-remediation-qualified-20261101.json).

Riferimenti consultati: Matrix1.7§1, Blueprint0.3§9, Semantic1.3§159.2, miniPET M2
v1.3 e handoff compatibilità Teatri del31ottobre. Nessuna nuova accettazione
integrale PET viene dedotta dalle sole scansioni o dai checksum.

Il prossimo lavoro è integrare il candidato nella coorte esecutiva e nella
review concreta. Restano origini Gateway-owner/MinIO, membership completa e
custodia privata, policy/owner/bearer correnti, proposta Gateway, pacchetto
sigillato, HUMAN/dual-role e sostituzione/readback target. La chat/plugin non ha
shell VPS; preparare e qualificare l'intera consegna necessaria prima di
coinvolgere l'owner. Non chiedere un'altra microdiagnostica o rilanciare vecchi
comandi. Nessuna nuova azione VPS richiesta in questo checkpoint.

Scope12 consumato:12controlli/35GET immutati, tutti235/19/17/21/23pin congelati
preservati. M1/Teatri8/8tecnico e6/6funzionale acquisiti; stessa Farmacie61righe,
10OPEN e codice ministeriale STRING preservata. M2/G5–G7 e due client OPEN;
restano61esiti UDP, ripetibilità e fault reali. Poi grafo/search e verticali/API
con scheduler/delta. Nessuna nuova selezione, installazione, authority, grant,
reset, merge o release acceptance.
