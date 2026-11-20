# Conservazione delle istantanee di rilascio

Il punto di aggancio per la procedura di rilascio e per l’esecutore del task-17b è la conclusione di un rilascio riuscito, dopo la scrittura di tutti gli artefatti. Eseguire il comando sul nodo con lo stesso coordinamento esclusivo usato per i writer del rilascio, anche durante l’apply. La scansione comprende tutte le famiglie.

Distribuire insieme `retention.py` e `policy.json` dalla revisione approvata. Occorrono Python 3.9 o successivo, la CLI Docker locale con accesso in lettura ai container e il permesso di rimuovere i file selezionati. La procedura può passare `--root` e `--config` prima del sottocomando per usare i percorsi dell’installazione. La radice predefinita è `/etc/ouf/deploy-snapshots`.

1. Salvare lo stdout del plan fra le evidenze del rilascio, fuori dalla radice delle istantanee.

   ```sh
   python3 -I -B tools/snapshot_retention/retention.py plan > "$evidenze/retention-plan.json"
   ```

2. Acquisire il campo `planSha256` del piano approvato. Il campo `remove` elenca i percorsi relativi, i byte, la data di modifica Unix in nanosecondi, dispositivo e inode. L’esecutore passa il digest acquisito al passo successivo.

   ```sh
   python3 -I -B tools/snapshot_retention/retention.py apply "$planSha256" > "$evidenze/retention-apply.json"
   ```

3. Acquisire la ricevuta anche con codice di uscita diverso da zero. `APPLIED` elenca i file rimossi. `HELD` richiede la verifica della causa e un nuovo plan. L’apply rigenera il censimento prima della prima rimozione. Un errore durante la rimozione lascia nella ricevuta i percorsi già eliminati.

## Regola D-070

La configurazione distribuita conserva due istantanee per famiglia. Come nel censimento del 20 novembre, il nome della famiglia si ricava togliendo i suffissi di versione, data, hash e identificatore da otto caratteri. Si ordinano le istantanee con candidati per la massima data di modifica dei candidati e, a parità di data, per nome.

Sono candidati i file regolari `.jar`, `.tar` e i file oltre 64 MiB. La soglia di conservazione protegge tutti i file sotto 8 MiB. Restano le directory, i collegamenti e le famiglie comprese nell’espressione di protezione per provider semantico, R3, coorte M2, trust e lease. La corrispondenza fra un ID del manifest Docker in un tar e l’immagine di un container, anche fermo, conserva l’intera istantanea. Il confronto fra ID può non dare corrispondenze con Docker 29, come osservato nel censimento. Il numero di istantanee recenti si applica comunque.

## Registro della configurazione D-065

| Tipo di archivio | Responsabile e contenuto | Segreti | Cattura e ripristino | Prova |
|---|---|---|---|---|
| File JSON della politica di conservazione | Esecutore del rilascio. Contiene soglie in byte, numero di istantanee ed espressione delle famiglie protette | No | Per il default acquisire la revisione Git del rilascio e ridistribuire il file corrispondente. Per una configurazione locale acquisire e ripristinare i byte del file passato con `--config` | Eseguire `plan` e confrontare il campo `policy` con la configurazione catturata |
