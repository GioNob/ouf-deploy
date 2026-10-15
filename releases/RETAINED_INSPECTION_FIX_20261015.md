# Correzione del preparatore — 15 ottobre 2026

La diagnosi target è archiviata al commit
`1a7927fbb7f399025bb0d787d3d5b24f72c149a6`, nel rapporto
`releases/VPS_INVENTORY_ASSESSMENT_20261015.md`. L'unica differenza del registro
fra frame storico/CLI corrente e API1.44 è Aliases della rete, con generazione
immutata e letture stabili. Cinque storie DB sono ora disponibili.

Questa tranche cambia solo la preparazione e le relative prove:

- Preflight e preparazione finale usano lo stesso lettore accoppiato: due CLI e
  due API1.44, socket locale esatto, CLI autenticata dal relativo hash e ambiente
  pulito. Lo storico completo deve coincidere con la CLI corrente prima di IAM.
- Le osservazioni API restano integre e forniscono i nuovi binding degli intenti,
  così i successivi adapter1.44 non confrontano hash provenienti dalla CLI.
- Il confronto fra i due canali mantiene identità, Config, HostConfig, Mounts e
  tutti i campi di rete. Solo Aliases può avere la forma osservata: CLI null,
  API lista limitata di nomi già presenti nei DNSNames o nell'identità del
  container. Alias estranei, altre differenze o letture instabili sono negati.
- Nessun binding o dizionario viene normalizzato, nessun hash storico riscritto.
  Il confronto accoppiato viene ripetuto alla fine della preparazione.
- Il marker semantic esatto SCHEMA `"ouf_sem"` viene conservato nella storia
  attesa, come già avviene negli altri moduli. Il riferimento readiness usa
  l'intera storia attesa, incluso quel marker. Marker diversi e checksum
  incompatibili continuano a essere negati.

Capsula nuova e distinta:
`releases/chatbot-file-preparation-capsule-20261015.json`, SHA256
`33d42e9aa04968035201a30a5d7d8a79c45ee4e42ebafabefe32deaa8722ae90`.
La capsula14 e i riferimenti immutabili precedenti restano conservati.
Il launcher Python seleziona la nuova capsula; nessun nuovo comando target viene
pubblicato da questo documento prima della qualificazione.

Prove locali: test di formato e di creazione completa della request a quattro
mount, dinieghi per Config/Host/Mount/IP/MAC/Endpoint/DNS/alias, instabilità dei
due canali, preflight storico prima di IAM, marker semantic e launcher/capsula.
Il test entry completo non è eseguibile localmente senza i sorgenti owner
qualificati, presenti nei checkout espliciti della CI.

Prova nativa aggiunta alla CI: container temporaneo su rete isolata per lettura
CLI/API tramite il lettore di produzione, quindi database e ruolo applicativo
temporanei con storia Flyway reale. Il test verifica marker e checksum, storia e
righe preservate, conteggio ruoli e assenza di promozione a superuser. Setup e
cleanup mutano esclusivamente fixture GitHub Actions, mai il VPS.

Non è una prova della preparazione completa di tutti gli owner, né di installazione
target o CSV end-to-end. IAM corrente, ledger e lettura MCP restano aperti; B03/B04
restano qualificazione completa della consegna e integrazione reale. I sei pin
applicativi, il pacchetto1,7GB e gli otto Cinema restano invariati. Nessun rollout,
approvazione HUMAN, reset di budget o autorità runtime in questa tranche.
