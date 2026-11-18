# R3 v17 — Budget di verifica del driver (D-053, R-030)

## Causa osservata

Il 18 novembre 2026 lo start v16 dell’adapter, epoca 19, ha registrato
`driverDenial` con fase `start` e codice `AUTHENTICATION_DEADLINE_MISSED`.
Gli start v13 e v15 avevano manifestato lo stesso problema intermittente
alle epoche 15 e 17. I dettagli del journal v3 sono descritti nella nota
[R3 v16 — Diniego del driver](OUF_SEMANTIC_PROVIDER_R3_V16_DRIVER_DENIAL.md).

In `start`, `Preexec.before_process` ed `EpochConsumption.consume_locked`
eseguono complessivamente quattro autorizzazioni nello stesso `VerificationBudget`,
che condivide la scadenza del backend nativo. Il template storico forniva
5 secondi. R3 v17 imposta **12 secondi** tramite l’input d’installazione
`driverBudget`, contenuto in `ops/vps/r3-driver-budget.json`.

## Contratto di composizione

`driverBudget` è un oggetto JSON canonico con il solo campo
`driverBudgetSeconds`, di tipo intero e compreso fra **5 e 15** inclusi.
Forma, tipo o valore fuori contratto producono `R3_DRIVER_BUDGET_INVALID`.
L’input separato preserva la forma esatta e i byte di `r3-settings.json`
e lascia riproducibili le composizioni v1–v16. Il compositore controlla il
template storico secondo il contratto originale `1..5` e applica il nuovo
valore alla copia emessa di `preparer-template.json` per entrambi i ruoli.
Ogni broker vincola per hash il proprio template e il preparer trasferisce
`budgetSeconds` nel `driver.json` della nuova epoca.

L’overlay v17 adegua i tre controlli del range nel Worker, nel driver e in
`NativeBackend`. `SOURCE_MAP_V17` mantiene i percorsi di v16 e il broker
vincola i digest dei byte emessi. `DATA_INPUTS_V17` aggiunge `driverBudget`.
I digest dell’input e dei risultati compaiono nelle rispettive mappe della
composizione. Il payload autorizzato vincola la configurazione del runtime
e i broker, che a loro volta vincolano template e sorgenti emessi.

Il limite di 15 s lascia almeno 5 s rispetto al tetto di 20 s per `start`.
Il tempo effettivamente disponibile continua a dipendere dal residuo della
sezione di ammissione di 60 s. Il tetto del subprocess `hook` rimane 10 s e
`VerificationBudget` mantiene il massimo generale di 18 s.

## Consegna da fissare nei runbook

Per la rigenerazione dell’issue e dell’upgrade v17, aggiungere
`files["driverBudget"]` con il percorso privato della copia di
`ops/vps/r3-driver-budget.json` e lo stesso digest in `PINS["driverBudget"]`.
Selezionare `C.DATA_INPUTS_V17` e `C.SOURCE_INPUTS_V17` per l’indice
`inputs.json`. Il modulo overlay serve nella consegna del compositore.
Il set dei percorsi `SOURCE_INPUTS_V17` coincide con quello v16.

| File della consegna | SHA-256 dei byte LF |
| --- | --- |
| `ops/vps/r3-driver-budget.json` | `2fc0921fd26cdb69adf6ab7dc683b3fea321bb59c5db24db95428d7ac59a1e16` |
| `tools/semantic_provider_r3/compose.py` | `4cfb90bc889673ea3ee1ee26ab1dc4921579f3e8d1096c66a1e928a621fac11b` |
| `tools/semantic_provider_r3/driver_budget_v17.py` | `086b695267ac94ce50053fe1c8f6c8bcec6f702d36e6d350fe74c319741a4f02` |
| `ops/vps/r3-settings.json` | `4b1aa5560a23657b92fe0a99915d747d02d272a0b765c5b719921f4007d5c150` |

Claude fissa `C` al commit della consegna approvata e verifica i digest
contro i blob Git del commit. Conservare i pin v16 dei sorgenti base,
incluso l’overlay del diniego, e quelli degli input D-052/D-053, delle
ricette B1 v4, dell’acceptance g7, del coordinatore e del kernel g2.
I digest dei sorgenti emessi derivano dalla composizione e sono verificati
nei manifest dei broker. Per eventuali manifest `operate` o autostart
rigenerati dalla stessa consegna, sincronizzare i pin dei file inclusi.

## Sequenza sul VPS

1. Verificare wrapper e head `OPERATE` v16, i due CID fermi, epoche assenti o
   terminali e coordinatore `QUIESCED` con lease/start a `false`. Se la
   coppia è in esecuzione, completare prima lo stop governato. Conservare
   journal e ricevute delle epoche precedenti.
2. Con i runbook v17 rigenerati, eseguire plan e apply dell’issue con
   `--supersede`, usando il digest del piano e la testa autenticata v16.
   Verificare `sequence=17`, `supersedes` uguale al digest dell’autorizzazione
   v16 e i binding agli stessi CID, ricette B1 v4 e acceptance g7.
3. Eseguire plan e apply dell’upgrade con gli stessi input dell’issue e il
   `planSha256` dell’upgrade. Dopo `SEMANTIC_PROVIDER_R3_UPGRADED_WAITING`,
   verificare il wrapper verso `versions/17`, il supervisore e il budget
   emesso nei due template. Coordinatore, kernel g2 e registry sono condivisi
   con v16. [Procedura di upgrade](OUF_SEMANTIC_PROVIDER_R3_UPGRADE.md).
4. Eseguire `operate start` con il nuovo wrapper tramite plan e apply.
   Registrare le nuove epoche dei due ruoli, il loro esito e l’eventuale
   `driverDenial` del journal v3. In caso di esito parziale, riconciliare la
   ricevuta e lo stato prima di un nuovo tentativo.

Le prove offline coprono la riproduzione v1–v16, la composizione e il
successore v17, i limiti del parametro e l’accettazione del valore 12
da parte dei sorgenti emessi su fixture per entrambi i ruoli. Lo start
v17 sul VPS resta da verificare con la nuova consegna.
