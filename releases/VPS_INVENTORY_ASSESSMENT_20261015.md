# Baseline VPS — 15 ottobre 2026

L'output v2 dell'operatore conferma sul target la causa del blocco
`RETAINED_REGISTRY_NATIVE_GENERATION_CHANGED`: confronto fra rappresentazioni CLI
e API1.44 differenti dello stesso container semantic. Entrambi i canali sono
stabili. Il frame storico e la CLI corrente coincidono in tutti gli otto campi;
l'API1.44 differisce soltanto in `networkSettingsHash`.

La differenza strutturale unica è
`NetworkSettings.Networks.ouf-backend.Aliases`: `null` nella CLI, lista nella
risposta1.44. Non sono cambiati ID, immagine, PID, avvio, Config, HostConfig,
Mounts o altri campi della rete osservati. Non è un problema dei sei microservizi.
Non modificare lo storico, ignorare l'hash della rete o normalizzare binding
firmati per far passare il controllo.

## Provenienza

- [Output selezionato v2 restituito](../evidence/vps-inventory-v2-20261015.json).
- Allegato: `Pasted text(20261015-011628).txt`,35032bytes.
- SHA256 dell'allegato:
  `cd7e107aa37590e7e65e29d588cd72bd73d4f8f7133638e0d2739121d30ccfcf`.
- Unico record JSON estratto e formattato senza cambiarne i valori. Le righe di
  terminale esterne sono escluse; nessun valore di credenziale presente.
- È il rapporto selezionato stampato dal launcher, non l'intero inventario dei
  98 container. Il rapporto integrale rimane sul VPS a
  `/home/oufadmin/ouf-vps-inventory-v2.sRYFvsMe/inventory-full.json` e non è stato
  letto da questa sessione. Non dichiararlo archiviato qui.
- Dati forniti dall'operatore, non telemetria VPS firmata o accesso SSH diretto.

## Chiusure diagnostiche

| Punto | Risultato |
| --- | --- |
| B02 — causa del confronto storico | Diagnosi chiusa: differenza di canale nella rappresentazione Aliases, osservata sul target. Correzione del preparatore ancora da qualificare. |
| Elenco container | Raccolta dichiara98 OUF, nessun container estraneo; owner approfonditi8. I binding di questi8 rimangono stabili. |
| DB semantic | 10 righe: marker SCHEMA e migrazioni1–9; server170011, nessuna prepared transaction. |
| DB onboarding/ingestion/UDP/MCP | Storie leggibili:32/15/35/9. Questo è inventario, non ancora verifica dei byte del pacchetto o prova di upgrade. |
| Ownership MCP | Bootstrap superuser osservato. Il workload non ha ownership o privilegio TRIGGER su security_incident; il piano di migrazione deve conservarne la gestione governata. |
| Asset Teatri | Ancora presente,13 righe/20 colonne, profilo1, proprietario corrispondente, sorgente non associata; content hash invariato. |
| Gateway/policy | 64 route e politica38; hash invariati rispetto al rapporto del14 ottobre. Pubblicazione delle nuove route/capability ancora da eseguire e qualificare. |

57 chiamate native. Nessuna mutazione DB/IAM/servizi, lifecycle, login interattivo,
reset budget o autorità runtime. Le lacune passano dalle10 del v1 alle4 dichiarate
dal v2, senza diventare accettazione end-to-end.

## Punti ancora aperti

Catalogo IAM: classificazione `IAM_CACHED_SESSION_UNAVAILABLE`, compatibile con
una sessione amministrativa non utilizzabile; non affermare scope o grant
effettivi. Ledger corrente: selezione esatta ancora necessaria. MCP corrente da
questa conversazione: non raccolto. Control plane Gateway: non disponibile,
da mantenere distinto dal perimetro file già documentato.

Nel codice emerge anche una condizione già determinabile senza nuovo tentativo:
`registry_database()` per semantic confronta la storia Flyway direttamente con
i soli file SQL e non gestisce il marker SCHEMA quotato, mentre il planner degli
altri moduli lo gestisce. La storia semantic corrente contiene proprio quel
marker. Questa omissione deve entrare nella stessa correzione verificata; non
farla scoprire all'operatore dopo un'altra autenticazione.

B01 resta preflight incompleto finché non confronta l'intero frame storico nel
canale appropriato prima di IAM. B03/B04 restano preparazione completa e
integrazione target di migrazioni/IAM/Gateway/THS. B05/B06 restano CSV reale con
ACK/commit/lineage/ricerca, preservazione Cinema e seconda sorgente.

## Prossimo lavoro

Correzione circoscritta al preparatore: confrontare il frame storico con lo
stesso canale CLI autenticato, mantenere integre le osservazioni API1.44 per i
nuovi intenti e le successive verifiche, controllare stabilità/corrispondenza
dei due canali e negare differenze non spiegate. Gestire il marker semantic
esatto senza alterare la storia conservata. Qualificare queste condizioni insieme
prima di pubblicare un nuovo launcher di consegna. I pin applicativi e l'archivio
1,7GB restano invariati. Nessun rollout è autorizzato da questo documento.

## Evidenze indipendenti raccolte dalla chat dopo l'inventario

La disponibilità di routing del connettore OUF per l'account `ouf-admin`,
corrispondente al proprietario selezionato, ha permesso una ricerca MCP fresca
del tipo canonico Cinema. Risultato completo:8 oggetti ACTIVE, revisione1,
stessi ID e property IRI della baseline del14 ottobre, nextCursor null e
partial false. [Evidenza redatta](../evidence/chatbot-cinema-read-20261015.json).
La lacuna di accesso MCP della conversazione è quindi superata per questa
lettura; il campo NOT_COLLECTED nell'output del processo VPS resta immutato.
Non è reingestion né prova CSV Teatri. La ricerca semantic.search(q=Teatri,
limit=10) ha restituito una lista vuota nell'ambito autorizzato: non è una
dimostrazione globale di assenza di ogni artefatto semantic.

Il confronto dei file SQL del commit semantic candidato eccef11a… con tutte
le colonne Flyway osservate conferma il prefisso completo:10 righe installate
(incluso SCHEMA),11 attese, sola V10__proposal_command_receipts.sql pendente.
[Confronto source-prefix](../evidence/semantic-target-source-prefix-20261015.json).
Il JAR dell'archivio non è stato riletto da questa sessione; il controllo dei byte
del pacchetto deve restare nel preparatore.

La correzione circoscritta è nella PR31, ramo
codex/retained-inspection-channel-20261015, distinto dalla baseline PR29.
Resta una bozza finché le prove native non passano. La qualificazione dei due
difetti non equivale alla qualificazione dell'intera consegna B03/B04.
