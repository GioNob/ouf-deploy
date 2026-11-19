# R3 v18 — Rinnovo e recupero del lease (D-054, R-022)

La v18 calcola l’avvio del rinnovo dal residuo nft verificato nelle famiglie
`inet` e `bridge`. Usa il minore dei TTL e lo ancora all’inizio della lettura.
Il rinnovo parte solo con il margine minimo configurato. Lo scheduler anticipa
il risveglio di un ulteriore secondo quando il residuo lo permette.

## Input e valori proposti

`leaseRenewal` è un oggetto JSON canonico a campi chiusi. Il file di consegna
è `ops/vps/r3-lease-renewal.json` ed entra in composizione dalla v18.

| Campo | Valore | Vincolo e motivazione |
| --- | ---: | --- |
| `renewalMarginSeconds` | 22 | Residuo minimo all’avvio del rinnovo. Intero da 1 a 300, ulteriormente vincolato dai budget e dalla durata effettiva. |
| `lockWaitSeconds` | 6 | Tetto per acquisizione nel percorso di rinnovo. Intero da 1 a 20. Il tentativo smette di attendere prima di esaurire la finestra se la contesa persiste. |
| `fastRetryCount` | 1 | Intero da 0 a 3. Una seconda raccolta DNS può assorbire un transitorio breve entro la stessa scadenza assoluta. |
| `fastRetryDelaysSeconds` | `[1]` | Un ritardo per retry, in ordine crescente o uguale, con valori interi da 1 a 5 s. Si rispetta anche l’eventuale `retry_after`. |
| `healthyResetSeconds` | 300 | Intero da 1 a 86.400. Cinque minuti di rinnovi sani abbassano il gradino dopo una sequenza di errori. |

La composizione riserva il maggiore fra `DNS + attesa lock` e budget del driver,
più 1 s di applicazione/readback, 2 s di soglia `denyOnly`, 1 s per il commit
e 1 s per i controlli. Con DNS a 10 s, lock a 6 s e driver a 12 s, la somma è
21 s e il valore proposto offre 1 s in più. Il driver conserva i suoi 12 s.
Se il driver occupa il lock per più di 6 s, il rinnovo può proseguire soltanto
se il percorso di retry riesce a riprovare il lease entro la finestra residua.

Il limite autorizzato resta 30 s. La composizione verifica il minore fra la
durata DNS al netto dell’applicazione e i `providerFlows[].leaseSeconds`,
lasciando margine per il TTL letto in secondi interi. Verifica inoltre il
limite di 30 s per tentativo e che i ritardi della corsia rapida possano
rientrare nella finestra disponibile. Un DNS lento o un TTL breve può ridurre
il lease effettivo e portare alla pausa. La corsia rapida richiede tempo
sufficiente per una nuova raccolta DNS e per pubblicare entro la scadenza
originaria. L’input viene rivalidato all’avvio contro il coordinatore sigillato.

## Deadline e percorsi di chiusura

Il rinnovo acquisisce il lock comune fino al primo di questi tre limiti.

1. Ora monotona più `lockWaitSeconds`.
2. Deadline del tentativo meno 1 s per il commit.
3. Prima scadenza dell’evidenza DNS meno `applyBudgetSeconds + 2 s`.

Dopo l’acquisizione ricontrolla subito la deadline e verifica sotto lock
autorità, generazione, ownership, journal e membership esatta del lease in
entrambe le famiglie. Ricompila con le stesse scadenze DNS assolute.
L’applicazione e il readback condividono il limite più stretto fra quello del
tentativo e `mustApplyByMonotonic`. `LEASE_READY` richiede readback e verifica
finale entro la finestra.

La corsia rapida ammette solo errori esplicitamente classificati prima della
prima mutazione. Prima e dopo il ritardo riprova il lease precedente sotto
lock. Il contatore del retry è persistito prima dell’attesa, la nuova query usa
evidenza fresca e la sua deadline può solo accorciarsi. Il budget cumulativo
conta l’intervallo di retry e il tetto di 128 tentativi comprende anche questi
tentativi. Il semplice flag storico `no_effect` da solo è insufficiente.

Scadenza nft a zero, perdita di prova e pubblicazione ambigua fanno scattare
la revoca. La revoca avviata dall’adapter dispone di 40 s indipendenti
dall’ammissione, con il tetto storico di 20 s per acquisizione e il budget
nft per comando. Il journal di recupero registra `BLOCKED / SAFE_PAUSE_UNPROVEN`
quando la revoca resta indimostrata. In quel caso vale la scadenza finita
già programmata nel kernel.

Il backoff dopo revoca usa `(5, 15, 60, 300, 900)` s con il jitter storico.
Dopo 300 s continui osservati su entrambi i clock, un rinnovo riuscito
riporta al primo gradino. Una pausa o un retry rapido interrompe il periodo
sano. I tetti di 128 tentativi, 86.400 s cumulativi per scope, 30 s per tentativo
e sei aperture in un’ora continuano a valere.

## Integrazione con l’osservabilità

La composizione applica prima il rinnovo e poi i marcatori di osservabilità
sugli stessi sorgenti emessi. Al termine sigilla una sola volta la chiusura
v18. I `PINS` del supervisore, la configurazione verificata dal bootstrap v3
e gli hash di consegna condividono i digest dei byte finali. Il bootstrap
verifica anche il proprio digest prima di eseguire i moduli.

L’ammissione al retry rapido registra `lastIncident` nello stesso checkpoint
che conta il tentativo. Il lease resta attivo durante l’attesa. Se il retry
pubblica `LEASE_READY`, il checkpoint di rinnovo valorizza `resumedAt` e
`pausedAt` resta nullo. Se segue una revoca, `pausedAt` viene valorizzato
solo dopo la verifica della quiescenza entro il budget separato di 40 s.
L’incidente conserva fase e codice del guasto iniziale. [Contratto di
osservabilità e proiezione in r3-status](OUF_SEMANTIC_PROVIDER_R3_V18_LEASE_OBSERVABILITY.md).

## Consegna da fissare nei runbook

Per issue e upgrade v18 aggiungere `files["leaseRenewal"]` con il percorso
privato della copia di `ops/vps/r3-lease-renewal.json`, il digest in
`PINS["leaseRenewal"]` e selezionare `C.DATA_INPUTS_V18` /
`C.SOURCE_INPUTS_V18` per `inputs.json`. L’insieme dei sorgenti aggiunge solo
`tools/semantic_provider_r3/lease_renewal_v18.py`. Il compositore richiede
anche i moduli host `lease_renewal_overlay_v18.py` e
`lease_observability_overlay_v18.py`.

| File della consegna | SHA-256 dei byte LF |
| --- | --- |
| `ops/vps/r3-lease-renewal.json` | `c35a9a6a22da6027ce3c07eccf1a4b8e21d4f697399de5e83ecab1f8340f403f` |
| `tools/semantic_provider_r3/lease_renewal_v18.py` | `c6fefa170903a92bcb706a061c91a3bfd5af560b51447f08dd0ac3135a5a7ecd` |

Fissare `C` al commit approvato e calcolare dai blob Git della consegna anche
gli hash di `compose.py` e dei due overlay. Allineare la consegna di
`r3-operate.sh` e il `MANIFEST` di `r3-autostart-install.sh` allo stesso
commit quando passano alla v18. I pin dei sorgenti base continuano a
identificare i blob storici. La composizione aggiorna invece i `PINS` interni
del supervisore sui byte emessi. Il bootstrap v3 emesso verifica la chiusura
nuova, incluso `tools/semantic_lease_recovery/lease_renewal_v18.py`, sotto
lo schema `ouf.semantic-provider-lease-supervisor.v2`. Il piano di upgrade
vincola configurazione, unità e manifest ai relativi byte emessi.

## Upgrade e qualifica

1. Eseguire `operate stop` plan/apply con il wrapper v17 e la testa `OPERATE`
   ancora allineata alla configurazione v17. Se i candidati sono già fermi,
   passare alle verifiche del punto seguente.
2. Verificare entrambi i CID fermi, tutte le epoche assenti o terminali e
   il coordinatore `QUIESCED` con lease e start a `false`. Per ogni epoca
   `FAILED` con `driverHash`, verificare la ricevuta `runtime-cleanup.json`
   del wrapper. Se il cleanup è pendente, completarlo mentre la testa
   è ancora allineata. Una ricevuta `STOPPED` da sola non prova il cleanup.
3. Eseguire issue plan/apply con `--supersede`. L’issuer blocca l’emissione
   prima della firma se rileva epoche aperte, binding incoerenti o cleanup
   pendente. Verificare `sequence=18` e
   `supersedes` pari al digest dell’autorizzazione v17. Usare gli stessi CID,
   coordinatore, kernel g2, ricette B1 v4, acceptance g7 e budget driver.
4. Eseguire upgrade plan/apply sulla stessa collezione di input. Verificare
   `SEMANTIC_PROVIDER_R3_UPGRADED_WAITING`, wrapper e unità verso `versions/18`
   e hash della configurazione supervisor. [Procedura di upgrade](OUF_SEMANTIC_PROVIDER_R3_UPGRADE.md).
5. Con il nuovo wrapper, usare `operate start` plan/apply e osservare i rinnovi
   e il recupero. Le prove offline usano clock e I/O controllati, incluse le
   decisioni di revoca. L’esecuzione sul VPS resta da qualificare.
