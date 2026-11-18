# D-052 · Destinazione dichiarata delle route APISIX

R-028, sprint-01 / task-69. Il nome Docker dell'adapter compare su due reti. Il
southbound conserva quel nome come `upstream_host` per TLS e usa il nodo IP
del flusso `GATEWAY_ADAPTER` per la connessione. Il CID dei due ruoli e il
percorso della sorgente rimangono gli stessi.

## Sorgente e pin

| Input | SHA-256 atteso |
| --- | --- |
| `/etc/ouf/deploy-snapshots/semantic-provider-v2-inputs-XE7IwlGm/apisix.yaml` prima dell'apply e dopo il restore | `dd340bd652bd5c7763ea47fd53573626bc3541b0a2d97415a113c4877e2c7e80` |
| `southbound/historicalTemplate` | `7ac15676ff00e38e1ac5bf5bd2356e42c34dbe9b485a5ba38d562380dcb1a894` |
| `adapter/historicalTemplate` | `0a9a12a36b9f28eca2edcb3a2ad2c3d741559abb5d3699029bcc105c287dab53` |
| `g2-20261117T122656/coordinated-configuration.json` | `899f39c193b88017b88931dcd9713ed80d7f63b87594c2cd00636a695e06b02f` |
| Docker CLI, vista API 1.44 | `7f5b38163f9c5367f4b42d905c0505877eafa4c20abe49430c85a770aefacf40` |
| `successors.json` di Preparazione A2 | `394562b4162e8d1b615a6b61897446c8316b37e7a438fa99b389dbb5f119dfdb` |
| Risultato rootfs D-042 della g5 | `49a82a05f7f935e63b76cfacdda742f928c112a1de2a61353436ef1cdac3f2b8` |

La dichiarazione attesa è `172.21.0.2 → 172.21.0.3:9443/tcp`. Il codice estrae
IP e porta dai tre input vincolati per hash. Il piano deve mostrare due sole
modifiche `/routes/<indice>/upstream/nodes`, da
`{"ouf-semantic-provider-v2:9443":1}` a `{"172.21.0.3:9443":1}`.
La riserializzazione senza modifiche deve produrre un file identico, incluso
`#END\n`. Il nuovo SHA-256 si acquisisce da `plan.after.sha256` nella
custodia VPS e si confronta con `newSha256` nella ricevuta di apply.

La proiezione mostra URI, metodi, upstream e i soli endpoint host/porta di
discovery e issuer con i flag OIDC. Il parser rifiuta chiavi duplicate JSON e
configurazioni di uscita fuori dal profilo ammesso con
`R3_EGRESS_CONFIG_UNPROVEN`. I campi TLS e il segreto OIDC non transitano nelle
ricevute. Il file originale e il backup contengono materiale TLS privato.

## Ordine sul VPS

Dopo la review, Claude fissa il commit delle tre consegne. I runbook con il
segnaposto tutto zeri terminano prima del download.

1. Con il percorso R3 esistente fermare la coppia e verificare lease
   `QUIESCED` e testa `OPERATE` di v14. Conservare i CID
   `85b5302f…` e `622a1500…`. Coordinare ogni operazione Docker sui
   container che montano il file o una sua directory antenata. Il controller
   prende i lock già installati per i due CID, la guardia di boot/lease e la
   catena di autorizzazione. L'inventario degli altri container è una
   rilettura da Docker prima e dopo la sostituzione.
2. Eseguire `bash ops/vps/routes-d052.sh plan`. Verificare
   `plan.before.sha256`, `plan.after.sha256` e il diff. Il controller
   rifiuta anche una differenza di owner, modo o mount. Eseguire
   `bash ops/vps/routes-d052.sh apply <planSha256>` dopo la review. Verificare
   `ROUTES_D052_PUBLISHED` e il digest nuovo contro il piano. La claim
   privata è `/etc/ouf/deploy-snapshots/semantic-provider-routes-d052`.
3. Calcolare lo SHA-256 di `result.json` della claim senza esportarne il
   contenuto. Eseguire `bash ops/vps/b1-recipes-v3.sh plan <routesResultSha256>`.
   Verificare `routeSha256`, i digest delle ricette e il sigillo D-042 per
   entrambi i ruoli. La revisione confronta la configurazione Docker contro
   Preparazione A2, trattando a parte `State` e `RestartCount`. Il confronto
   conserva la presenza e il tipo di `Config.MacAddress` e confronta tutti
   gli endpoint. La verifica live del rootfs riusa la vista via export del
   container fermo e il sealer di D-042. A esito positivo eseguire
   `bash ops/vps/b1-recipes-v3.sh apply <planSha256> <routesResultSha256>`.
   Il risultato è sotto `semantic-provider-b1-recipes-20261118-v3`. I byte di
   `template` e `context` devono coincidere con v2 per entrambi i ruoli.
   Solo `launch.sources` e `policy.sources` del southbound portano il nuovo
   hash della sorgente.
4. Calcolare lo SHA-256 del risultato B1 v3 ed eseguire
   `bash ops/vps/acceptance-v51-g6.sh plan <b1ResultSha256>`. Controllare
   generazione 6, ricette B1 v3, rootfs D-042 e `payloadSha256`. Eseguire
   `bash ops/vps/acceptance-v51-g6.sh apply <planSha256> <b1ResultSha256>`.
   Verificare che il digest del manifest risultante coincida con
   `payloadSha256`. L'emettitore v5.1 scrive in
   `semantic-provider-acceptance-v51-g6`. Il runbook conserva lo stesso
   `issuedAt` e la stessa consegna tra plan e apply.
5. Mantenere ferma la coppia fino alla qualificazione R3 v15. Il nuovo
   hash della sorgente appartiene alle ricette v3, mentre v14 usa ancora
   i riferimenti precedenti.

## Restore e condizioni di arresto

`bash ops/vps/routes-d052.sh restore <planSha256>` ripristina il backup dal
medesimo claim, con i preflight di quiescenza e il confronto dei byte nuovi.
La procedura funziona anche se la sostituzione è riuscita ma manca
`result.json`, purché siano integri `plan.json` e il backup. Dopo
`ROUTES_D052_RESTORED`, il digest atteso è `dd340bd6…`. Conservare le
ricevute della claim e ritirare gli eventuali candidati B1 v3 e g6 dal
passaggio a R3 v15. Se l'originale è ancora presente dopo un apply parziale,
conservare la claim e riconciliare l'esito.

Il precedente D-047 documenta i volatili creati dall'avvio, incluso
`usr/local/apisix/conf/apisix.yaml`. Se il sigillo live diverge da D-042,
B1 v3 restituisce `RETAINED_ROOTFS_CHANGED_FROM_D042`. Il ripristino D-047
esistente è agganciato a `start` di R3, quindi per un'eventuale divergenza
serve una decisione dell'owner sul ripristino a coppia ferma. Preservare
il risultato D-042 e il confronto. Un diniego sulla configurazione Docker
richiede la qualifica dell'esatta transizione osservata in API 1.44.
Un diniego sulla proiezione richiede la revisione del profilo di uscita
in custodia. [Contratto D-047](OUF_SEMANTIC_PROVIDER_R3_VOLATILE_RESTORE.md)
