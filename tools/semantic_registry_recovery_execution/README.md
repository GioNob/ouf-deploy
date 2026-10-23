# Registry recovery dopo riavvio — percorso finito, target aperto

Il percorso concreto è `prepare → review → issue → install → bootstrap → owner → continue`; `status` legge soltanto gli artefatti privati. L'obiettivo è una nuova generazione ammessa dello stesso Registry e HTTP 200 per ogni riferimento semantico congelato, con la stessa identità SERVICE di Ingestion e stato esatto `ACTIVE`. Questa implementazione non attesta un'esecuzione sulla VPS, la risoluzione del 502 o continuità oltre la sessione. **Qualificazione CI della nuova chiusura: pending.**

La [ricevuta target di lineage](../../evidence/semantic-registry-bound-owner-lineage-target-20261023.json), fornita dall'operatore, collega tutti i 18 record all'output credenziali montato dal Registry: anchor 4, terminale 6, cumulativo controllato **319**. Il terminale è storico, `CANCELLED/BLOCKED`, di boot precedente; non è un owner corrente. Non rilanciare discovery o reader conclusi. La contabilità legacy sconosciuta resta tale.

## Entry concreta

`delivery.generate(root, case, source_commit, source_pins)` produce offline capsule e dichiarazione. `runtime.py` verifica l'intera chiusura prima di caricare `postboot_entry.execute(case, manifest, sources, argv)`, senza fallback a sorgenti installate. Il case esterno ha schema `ouf.semantic-registry-postboot-recovery-case.v1` e contiene soltanto `schema` e `preparation`. La capsule richiede root e Python isolato `-I -B -S`. Il pacchetto operatore deve legare commit qualificato, hash della capsule e case esatto; questo README non costituisce quel pacchetto.

| Modalità | Effetto e limite |
| --- | --- |
| `prepare` | Una preparazione privata per case/chiusura/boot: massimo 12 Engine GET, 1 Admin GET, 1 GET della configurazione congelata con il SERVICE originale. Usa bearer originale e credenziale Admin senza stamparli; per il client secret dell'owner verifica solo custodia. Nessun grant, autorità o runtime. |
| `review` | Review privata completa e `reviewHash`; 11 scope ricompilati. Propone massimo **1 nuovo tentativo SERVICE**, owner **≤900 s**, precedente 319 conservato. Nessuna firma o chiave aperta. |
| `issue REVIEW_SHA256` | Hash esatto e decisione fresca `/dev/tty`: `APPROVO REVIEW_SHA256`. Claim canonico consumato prima delle due firme dei ruoli esistenti. |
| `install REVIEW_SHA256` | Nuovi ledger canonici; nessun runtime/OAuth. |
| `bootstrap REVIEW_SHA256` | Verifica, start del gate in attesa, prova della nuova generazione, pause: stop al checkpoint 4. Nessun grant o rilascio Java. |
| `owner REVIEW_SHA256` | Successore del boot corrente legato al terminale storico e al nuovo gate; conserva prima ricevuta di grant e conteggi. Nessun OAuth. |
| `continue REVIEW_SHA256` | Worker finito e recovery nativo coordinati nello stesso processo: grant limitato, ammissioni complete, attestazione nuova, unpause, SIGUSR1 e GET originale. |
| `status` | Inventario dei soli artefatti. Non osserva salute, ammissione corrente o raggiungibilità. |

L'hash della review è obbligatorio per tutte e cinque le modalità `issue`, `install`, `bootstrap`, `owner`, `continue`. Ogni modalità deve produrre la ricevuta attesa prima della successiva. Directory, claim o esecuzioni parziali esistenti rimangono consumati: nessun reset, cancellazione o replay automatico.

## Ammissione e risultato

`bootstrap.py` separa l'avvio della shell in attesa dall'ammissione applicativa. `postboot_factory.py` connette al checkpoint 4 gli owner nativi reali. Restano obbligatori rootfs OCI indipendente completo, frame/mount, processo/namespace correnti, PostgreSQL/Flyway readonly, route complete ed endpoint, token owner corrente e attestazione fresca prima del rilascio Java. Un vecchio attestato o segnale non ammette un PID nuovo.

`postboot_controller.py` mantiene il lock d'invocazione del worker e coordina worker e passi nativi. Dopo una risposta Docker 204 al rilascio già registrata, ammette solo osservazioni aggiuntive ai checkpoint 9–11: finestra condivisa di 90 s per iniziarle, massimo 12, normalmente ogni 5 s, entro autorità e contatori già concessi. Un'osservazione in corso conserva il timeout del trasporto. ACK mancante, eccezione, cambio generazione o movimento concorrente del journal richiedono riconciliazione; non ridispatchano effetti.

HTTP 403 non distingue policy assente da diniego effettivo. Può essere osservato nuovamente entro il limite con lo stesso SERVICE; non è sano né classificato transitorio. Solo HTTP 200 con tutti i pin esatti e `ACTIVE` completa la verifica. Health/JVM avviata non bastano; nessun token HUMAN alternativo, policy stale o nuovo budget.

La ricevuta intermedia `ORIGINAL_SERVICE_GET_200_WITH_FINITE_OWNER` prova un successo nella finestra indicata. Il processo mantiene poi l'owner per il residuo consentito. La ricevuta finale riporta `ownerSessionEnded: true`, `currentOwnerAdmissionProven: false`, `continuousServiceRenewalEstablished: false`: non prova disponibilità durevole o resilienza al prossimo riavvio.

## Qualificazione e riferimenti

La precedente [qualificazione native path](../../evidence/semantic-registry-native-path-ci-20261023.json), a `f5937486fcfe1e461caed65abf45ca49887ca33f`, riguarda componenti precedenti con gate Alpine e owner simulati dichiarati; non qualifica automaticamente questa nuova chiusura. I test del controller hanno un [perimetro separato](tests/CONTROLLER_QUALIFICATION.md).

Il [nuovo handoff](../../docs/handoffs/OUF_REGISTRY_POSTBOOT_RECOVERY_20261023.md) descrive input, ricevute e arresto; il [dossier](../../docs/OUF_SEMANTIC_502_EVIDENCE_AND_REPAIR_20261023.md) distingue fatti storici e osservazioni correnti. Preservare contesti, log, budget, fence e claim. Nessuna activation, provider recovery, migrazione DB, modifica Gateway o deroga AUTHZ è implicita. Supervisor ed E2E di piattaforma sono lavori successivi e non sostituiscono la verifica mirata del 502.
