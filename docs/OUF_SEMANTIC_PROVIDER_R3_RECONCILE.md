# R3 v18 — Riconciliazione delle epoche FAILED preparate

Questa procedura attua il recupero umano descritto in [§R-012 di Operate](OUF_SEMANTIC_PROVIDER_R3_OPERATE.md#r-012--epoca-failed-già-preparata). Copre il guasto del 19 novembre 2026, in cui la testa 18 ha superato l'autorizzazione 17 prima dello stop dei due ruoli e il broker ha negato il cleanup con `CONSUMPTION_CONFIGURATION_DRIFT`.

## Condizioni verificate

Il tool seleziona il wrapper v18 e il registry dalla root R3 installata. Autentica l'intera catena con il ledger corrente. Per ciascun ruolo seleziona il digest registrato nell'epoca, verifica che corrisponda a un'entry `OPERATE` precedente alla testa e individua un'unica configurazione sigillata in `versions/<n>`. Il numero della versione deriva dai byte della configurazione. La chiusura storica di broker, driver e preparer viene verificata prima di caricarli.

Entrambi i Docker devono risultare `exited` con PID 0. Il puntatore deve ancora indicare un'epoca `FAILED` preparata, dello stesso boot, con `TWO_PHASE_BROKER_DENIED`, il diniego storico di cleanup e il preexec `ROLLED_BACK`. Il tool verifica il binding della generazione nei journal e nega anche il PID riciclato. Le tabelle dei ruoli devono essere assenti e il coordinatore deve attestare `QUIESCED` con set lease vuoti. Il mount residuo deve essere l'unico `nsfs` sul percorso `epochs/<n>/netns`, con device e inode di rete coerenti con l'admission e il driver.

## Plan e apply

Usare la consegna revisionata di [r3-reconcile.sh](../ops/vps/r3-reconcile.sh) con `C` fissato al commit che contiene i blob elencati nel runbook. Il valore iniziale a quaranta zeri inibisce l'esecuzione. Il runbook verifica i digest dei file scaricati e dell'interprete. La consegna vive in una directory temporanea privata distinta dallo stato R3.

```bash
sudo bash r3-reconcile.sh plan > reconcile-plan.json
sudo bash r3-reconcile.sh apply <planSha256> > reconcile-apply.json
```

Leggere i CID, le epoche, la testa, gli hash storici e le prove dei due ruoli nel JSON del plan. Sostituire `<planSha256>` con il digest appena verificato. Il plan legge lo stato installato sotto gli stessi lock dell'apply. L'apply ripete le letture sotto i due lock per CID in ordine lessicografico, il lock della directory delle autorizzazioni e il lock comune. Un digest diverso ferma l'apply prima del claim.

Il claim esclusivo `r3-reconcile-claim-<planSha256>.json` conserva il plan approvato nell'epoca adapter. Ogni ruolo registra `r3-reconcile-intent.json` prima della prima mutazione. Se runc è ancora presente e risulta `stopped` per il CID, bundle e root esatti, il tool esegue il delete runc senza forzatura e ne prova l'assenza. Il cleanup smonta il solo namespace provato, conserva il file sottostante e pubblica `CLEANED` nei journal admission e broker tramite CAS. Dopo il readback scrive `runtime-cleanup.json` nel formato del wrapper v18. Il tool conserva l'epoca `FAILED`, il consumo e il diniego storici. La catena è una fonte di sola lettura. Le operazioni sul task containerd spettano a Docker nel successivo percorso di avvio.

## Interruzioni

Un claim consumato resta nel registry. Se l'apply è caduto tra i due ruoli, fare un nuovo `plan`. Un ruolo completato compare come `CLEANED` solo quando l'intento, il claim originale, i digest dei journal, la ricevuta runtime e l'assenza di mount e runc concordano. Il nuovo hash autorizza la pulizia del solo ruolo ancora `PENDING`. Due ruoli già verificati producono `ALREADY_CLEANED` in apply.

Se l'interruzione è interna a un ruolo e la ricevuta manca o il readback diverge, il tool restituisce `HELD`. Conservare claim, intenti e journal e fermare la procedura su quell'epoca. Lo stesso vale se il claim è già stato creato e il plan restituisce ancora il medesimo hash. Un intervento su quel parziale richiede una nuova riconciliazione esplicita.

## Ritorno al percorso di avvio

1. Verificare l'apply `CLEANED` oppure `ALREADY_CLEANED`, il `readbackSha256` e le due ricevute. Un nuovo `plan` può confermare entrambi i ruoli prima dell'avvio.
2. Usare il runbook [r3-operate.sh v18](../ops/vps/r3-operate.sh). Produrre e leggere il nuovo plan di start, inclusi i gate ordinari del supervisore, del kernel lease g2 e del ripristino volatile.

   ```bash
   AZIONE=start bash r3-operate.sh plan > r3-start-plan.json
   AZIONE=start bash r3-operate.sh apply <startPlanSha256> > r3-start-apply.json
   ```

3. Se Docker richiede il delete del task obsoleto, il wrapper v18 vede la ricevuta e inoltra il delete a runc quando lo stato restituisce assenza esatta. Docker e containerd restano responsabili dell'esito del task e dell'avvio successivo. Verificare l'esito di Operate e le nuove epoche dei due ruoli. Se il delete è ancora negato o il task resta bloccato, conservare gli esiti e fermarsi prima di altre operazioni sul task.

Il test locale esercita il dispatch del wrapper v18 con runc simulato. L'esito di Docker/containerd e la disponibilità del provider vanno misurati sul VPS.
