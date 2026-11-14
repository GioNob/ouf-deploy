# Rilascio della sonda authority-mandates sul collector del gateway (sprint-01, task-32)

Riferimenti: D-030; `ouf-api-gateway` task-31 (`5b93e56`, `docs/OUF_GATEWAY_AUTHORITY_MANDATE_INCIDENTS.md`); modello: task-12 passo A.

## Cosa cambia sul VPS
- Nel checkout `/opt/ouf/gateway-r3-summary` (commit `1629652`) cambia **solo** `tools/gateway_operational_collector.py`, da `dd0edb44…` a `a0599016…` (byte di `5b93e56`). `tools/operational_incidents.py` è già `c0a8025c…`, identico a `5b93e56`, e non viene toccato.
- Si installano due unità nuove, sul modello delle unità etcd installate:
  - `ouf-gateway-authority-mandates-probe.service`: oneshot, `User=root`, `Group=10001`, `WorkingDirectory` sul checkout reale, store in scrittura, directory di stato del job in sola lettura e opzionale (`-/var/lib/ouf-authority-mandate-renewal`);
  - `ouf-gateway-authority-mandates-probe.timer`: ogni 15 minuti.
- Collector e sonda etcd restano invariati, salvo il riavvio del collector. Gli hash delle unità etcd sono verificati prima e dopo.

## Plan e apply
Il runbook `ops/vps/gateway-authority-probe.sh`:
- verifica `python3.13`;
- scarica lo script da `ouf-deploy` e il collector candidato da `ouf-api-gateway`, ciascuno fissato per commit e hash;
- crea il journal `/var/lib/ouf-gateway-authority-probe-20261114` (0700). La directory viene creata già in `plan`, vuota.

`plan` è in sola lettura e vincola:
- commit, porcelain e hash del checkout;
- owner e mode del file (`oufadmin` 0664);
- unità collector active;
- unità etcd;
- assenza delle unità nuove;
- store (`integrity_check`, indice degli episodi);
- byte delle unità nuove.

`apply <planSha256>` procede solo se il piano ricalcolato ha lo stesso hash. Poi:
1. journal `apply-<sha>` creato in modo esclusivo (nessun replay) e backup del file precedente;
2. sostituzione atomica, stessi owner e mode;
3. unità con `O_EXCL`, `daemon-reload`;
4. restart del collector, con attesa di una nuova invocazione active;
5. un `start` della sonda;
6. `enable --now` del timer;
7. riverifiche.

## Esito atteso
Finché il job di rinnovo (task-28) non è installato, `status.json` non esiste. La sonda esce quindi con 2 (`Result=exit-code`) e apre `AUTHORITY_MANDATE_STATUS_UNAVAILABLE` / `AUTHORITY_MANDATE_STATUS_MISSING`. È l'esito atteso, ed è accettato; è accettato anche `success/0`. L'incidente si risolve da solo dopo l'installazione del job.

## Ripristino manuale
Non c'è rollback automatico. Per tornare indietro:
1. `systemctl disable --now ouf-gateway-authority-mandates-probe.timer`;
2. rimuovere le due unità e fare `daemon-reload`;
3. rimettere `apply-<sha>/gateway_operational_collector.py.before` (oufadmin 0664) e riavviare il collector.
