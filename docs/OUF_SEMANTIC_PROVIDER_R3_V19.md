# R3 v19 — Pulizia del task containerd con runc assente (R-031)

Il 19 novembre 2026 la riconciliazione ha lasciato entrambe le epoche 21 in
`FAILED` con `driverHash` presente, journal broker e admission in `CLEANED`
e ricevuta `runtime-cleanup.json` con `runcStatusBefore: "absent"`. Al
successivo start, containerd ha tentato `kill` prima di eliminare il suo
task obsoleto. R3 v18 ha risposto con `FAILED_PREPARED_EPOCH_REQUIRES_RECOVERY`.
Containerd tollera l’errore runc con la stringa `does not exist` durante
`kill` e `delete`.

La v19 riprende dopo la [riconciliazione R3](OUF_SEMANTIC_PROVIDER_R3_RECONCILE.md)
prevista dal [§R-012 di Operate](OUF_SEMANTIC_PROVIDER_R3_OPERATE.md#r-012--epoca-failed-già-preparata).
Il wrapper verifica la ricevuta rispetto all’epoca corrente `FAILED` dello
stesso boot e prova l’assenza di runc sulla root registrata. La sonda deve
restituire exit 1 e il messaggio di assenza esatto, in forma semplice o
logfmt ammessa. Timeout, errori di permesso e altri esiti bloccano l’inoltro.

Dopo entrambe le verifiche il wrapper inoltra `kill` o `delete` a runc con
tutti gli argomenti originali di Docker, comprese le opzioni di log e
l’eventuale segnale. L’invocazione ha il tetto di 10 s. Il wrapper passa fino
a 16 KiB dello stderr originale e restituisce l’exit code di runc. Il
messaggio `container does not exist` con exit 1 è l’esito atteso del caso
osservato. Il wrapper lascia intatti i journal e le ricevute. Con cleanup
pendente il `kill` su runc assente resta negato e il `delete` segue la
procedura ordinaria. Se runc è presente dopo una ricevuta, il wrapper
mantiene il diniego.

Per un’epoca `DELETED` dello stesso boot si applica lo stesso inoltro dopo
la verifica della root registrata e la prova stretta di assenza in
`inactive()`. `DELETED` è pubblicata dopo il completamento del cleanup
ordinario, anche per le epoche preparate. Può quindi restare lo stesso tipo
di task containerd obsoleto. Per `state`, `ABANDONED`, l’assenza di epoca
e le epoche di un boot precedente valgono i percorsi già previsti.

Il successivo `create` usa la testa `OPERATE` corrente e apre una nuova
epoca. Il test riproduce `kill`, `delete` e `create` sul runtime composto,
con subprocess runc e I/O di custodia simulati. Partendo da `FAILED` 21 e
dai journal `CLEANED`, verifica il puntatore a `CREATED` 22, il nuovo
journal broker e la nuova consumption `CREATED` e i byte dell’epoca 21.

## Consegna da fissare nei runbook v19

- Usare `C.DATA_INPUTS_V19` e `C.SOURCE_INPUTS_V19` per issue, upgrade
  e operate. Gli insiemi restano quelli della v18, incluso
  `files["leaseRenewal"]` con la copia privata di
  `ops/vps/r3-lease-renewal.json` e il suo digest. Restano anche gli
  input del budget driver, del coordinatore, del kernel g2, delle ricette
  B1 v4 e dell’acceptance g7. I due ruoli mantengono gli stessi CID.
- Per issue, upgrade e operate aggiungere alla consegna del compositore
  `tools/semantic_provider_r3/runtime_absent_overlay_v19.py` e aggiornare
  il digest di `tools/semantic_provider_r3/compose.py`. Includere gli
  overlay e il modulo di rinnovo v18 già previsti. L’overlay v19 si usa
  durante la composizione e resta fuori da `inputs.json["sources"]`.
- Fissare `C` allo stesso commit approvato e calcolare i digest dei file
  dai blob Git della consegna. Allineare anche il `MANIFEST` di
  `r3-autostart-install.sh` ai file di operate v19. I pin dei blob base
  rimangono storici. Il sigillo finale esistente calcola gli hash dopo
  l’overlay. La configurazione runtime v19 pinna il sorgente emesso e
  l’autorizzazione pinna la configurazione. I sorgenti del supervisore e
  del bootstrap mantengono gli stessi digest.

## Upgrade v18 → v19

1. Verificare entrambi i CID fermi, epoche terminali e coordinatore
   `QUIESCED` con lease e start a `false`. Per ogni `FAILED` preparata,
   verificare la ricevuta di cleanup. Usare la procedura R-012 soltanto
   per i casi ancora pendenti che soddisfano le sue condizioni.
2. Eseguire issue plan/apply con `--supersede` e il gate dell’issuer
   esistente. Verificare `sequence=19` e il digest della testa
   `OPERATE` v18 in `supersedes`.
3. Eseguire [upgrade plan/apply](OUF_SEMANTIC_PROVIDER_R3_UPGRADE.md) con
   gli stessi input di issue. Verificare
   `SEMANTIC_PROVIDER_R3_UPGRADED_WAITING`, wrapper e unità con percorsi
   sotto `versions/19` e il digest della configurazione supervisor.
4. Usare operate start plan/apply con la consegna v19. Verificare per
   ciascun CID che containerd abbia rimosso il task obsoleto e che il
   `create` abbia aperto l’epoca successiva conservando l’epoca 21.
   Il test di upgrade qualifica il piano offline. L’upgrade e lo start
   sul VPS restano da verificare.
