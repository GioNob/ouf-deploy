# R3 — avvio governato al boot (D-045, punti 2–5)

Implementazione task-61, 16 novembre 2026. Il driver usa la consegna locale di
`operate` e il ripristino D-047 della task-59. Non emette autorizzazioni, non
modifica epoche o policy Docker e non scarica codice. Installazione, reboot e
qualificazione sul VPS restano da eseguire; i test portabili usano un `operate`
finto e un clock simulato.

## Ordine con la piattaforma

L’unità R3 ha `After=ouf-platform-start.service`. Il driver accetta il campo facoltativo `platformReceipts` nella configurazione privata. Impostarlo al percorso assoluto di `receipts` del profilo piattaforma quando si installano insieme le due unità.

Prima del plan di ogni tentativo, dopo l’attesa, R3 legge `boot-<bootId senza trattini>.json` in quella directory sotto custodia root. Richiede schema `ouf.platform-restart-receipt.v1`, boot ID del kernel corrente, `mode=boot`, `action=start` e `status=SUCCEEDED`. L’assenza della prova produce `R3_PLATFORM_NOT_READY`. Al terzo diniego il driver scrive l’incidente D-045. Se il campo è omesso resta disponibile l’avvio autonomo di R3 dove manca la piattaforma. Il pin dell’installer R3 resta nullo e l’autostart resta da installare secondo D-048.

## Stato voluto dalle ricevute esistenti

Non viene introdotto un flag separato di autorità. Il driver cerca le directory
direttamente sotto `outputRoot` con i nomi prodotti dai runbook:

- `semantic-provider-r3-operate-start-*` e `semantic-provider-r3-operate-stop-*`;
- `semantic-provider-r3-autostart-start-<bootId>-<tentativo>`.

Contano solo i `result.json` con schema `ouf.semantic-provider-r3-operate.v1`,
azione `start`/`stop` e rispettivo esito riuscito
`SEMANTIC_PROVIDER_R3_STARTED`/`SEMANTIC_PROVIDER_R3_STOPPED`. Ogni successo deve
avere `operate-claim.json` della stessa azione/installazione: il driver ricalcola
l'hash canonico del claim senza `planSha256` e lo confronta anche con il risultato.
Directory, file e antenati devono essere root:root, senza scrittura di gruppo o
altri, senza symlink; i file devono essere regolari con un solo hard link.

L'ordine si ricava dalle due epoche in `lastObservation.candidates`, per CID,
senza usare timestamp, mtime, ordine lessicografico o orologio del boot:

1. Per la stessa coppia di CID, un risultato è successivo se entrambe le epoche
   sono maggiori o uguali a quelle dell'altro risultato.
2. A parità di entrambe le epoche, lo stop è successivo allo start: lo start apre
   nuove epoche, lo stop le termina. Il runtime v5.2 incrementa il contatore per
   CID durante `create` e conserva il registro fra le consegne.
3. Coppie di epoche incomparabili, CID cambiati, claim incoerenti o assenza di
   successi causano `HELD`, senza start. Occorre riconciliare lo storico; non
   viene scelto arbitrariamente un ordine. Le ricevute di altre installazioni
   vengono escluse tramite `installRoot` del claim.

Un `HELD`, un plan, un claim parziale o un `restart-one` non cambiano lo stato
voluto. L'ultimo successo `stop` produce exit 0 e `R3_AUTOSTART_NOT_DESIRED`, anche
se un successivo start è stato negato. Un nuovo start riuscito dopo lo stop apre
epoche maggiori e ripristina il desiderio di avvio. Il controllo viene ripetuto
dopo ogni attesa e subito prima dell'apply.

Presupposto operativo: conservare in questa radice tutte le ricevute start/stop
dell'installazione, con i nomi dei runbook. Ricevute spostate, cancellate o prodotte
con percorsi personalizzati richiedono riconciliazione preventiva. Il driver non
può attestare successi non presenti. Le operazioni manuali vanno serializzate con
l'avvio al boot: la rilettura del desiderio non introduce un lock condiviso con
`operate`.

## Configurazione installata

Percorsi fissi:

| Contenuto | Percorso |
|---|---|
| Consegna locale | `/etc/ouf/semantic-provider-r3-autostart/source` |
| JSON di configurazione | `/etc/ouf/semantic-provider-r3-autostart/config.json` |
| Unità | `/etc/systemd/system/ouf-semantic-r3-autostart.service` |
| Radice runtime e registro | `/etc/ouf/deploy-snapshots/semantic-provider-r3-install-v1` |
| Radice ricevute e incidenti | `/etc/ouf/deploy-snapshots` |

Schema JSON `ouf.semantic-provider-r3-autostart.v1`, campi ammessi:

- `bindings`: esattamente `docker`, `nft`, `systemctl`, `wrapper`, ognuno con
  `path` assoluto e `sha256`;
- `dockerSocket`: esclusivamente `unix:///...`; `installRoot` e `outputRoot`;
- `volatileRestore`: `result`, `sha256`, `source` storica D-042, passati senza
  modifiche agli argomenti `--volatile-*` di `operate`;
- `attempts`: default 3, valore ammesso 3; `waitSeconds`: default `[30,90,180]`,
  esattamente tre interi strettamente crescenti, fra 1 e 180 secondi.

Nessuna credenziale, chiave o token. Campi estranei, duplicati e socket TCP vengono
rifiutati. L'installer conserva i percorsi e i pin D-042 di `VOLATILE_ARGS` nel
runbook `r3-operate.sh`; wrapper e systemctl vengono rilevati durante il plan e
vincolati nel suo hash. Docker, nft e Python conservano i pin di quel runbook.

## Tentativi, interruzioni e incidente

Le attese precedono i tre tentativi: 30, 90 e 180 secondi, quindi in caso di
dinieghi immediati i plan avvengono a +30, +120 e +300 secondi. Non c'è attesa dopo
l'ultimo diniego. Ogni tentativo passa a `operate` una directory nuova:
`semantic-provider-r3-autostart-start-<bootId>-<1|2|3>`.

Ogni plan è nuovo. Solo `PLAN_READY` permette un apply, con il suo esatto
`planSha256`; `operate` mantiene il ricalcolo, il ripristino e tutte le sue
precondizioni. Un `HELD` prima del consumo può essere ritentato. Se la risposta
riporta `outputCreated` o `doNotRerunApply`, oppure l'output esiste dopo il
fallimento, l'incidente è immediato: `R3_AUTOSTART_APPLY_NOT_RETRYABLE`.
Timeout, eccezione o risposta indecifrabile durante apply sono parimenti incerti
e non consentono un nuovo apply, anche quando manca la ricevuta.

Dopo tre dinieghi si salva
`r3-autostart-incident-<bootId>.json`, con stato `R3_AUTOSTART_EXHAUSTED` e
`reason` di tutti i tentativi. Exit diverso da zero. Ogni tentativo negato
conserva `autostart-attempt.json` nella propria directory, senza sovrascrivere
claim o risultati di `operate`. Il JSON incidente viene scritto su stderr con
prefisso `<3>`: l'unità imposta `StandardError=journal` e `SyslogLevelPrefix=yes`,
quindi priorità `err`. Nessun invio a servizi esterni.

Il marcatore esclusivo `r3-autostart-<bootId>.json` viene salvato prima delle
attese: un riavvio dell'unità nello stesso boot non ricrea un budget. Il file
`.r3-autostart.lock` serializza i soli driver, senza occupare i lock del runtime
o del guard. Dopo un'interruzione si preservano marcatori e parziali e si usa
la procedura governata manuale, previa riconciliazione. Non cancellare marcatori
per forzare altri tentativi. Errori di configurazione/custodia/storico producono
`HELD` nel journal; se lo storage stesso non è scrivibile non è garantita la
persistenza del file incidente.

## Unità systemd

`Type=oneshot`, `Restart=no`; dipendenze `After` e `Wants` su Docker, rete online
e supervisore lease v2. Ogni invocazione figlia è limitata a 900 secondi, il poll
di `operate` conserva il default 180 secondi. Il massimo delle sei invocazioni
plan/apply più le attese è 5700 secondi; `TimeoutStartSec=6000` lascia margine per
letture e scritture locali. Nessun timer e nessun aggancio agli eventi di crash
dei container. Dopo il successo l'unità termina: un crash successivo non viene
riavviato automaticamente.

Il servizio usa root, Python 3.13 isolato senza bytecode, umask 0077,
`NoNewPrivileges`, protezione di sistema/home/kernel e soli address family
AF_UNIX/AF_NETLINK. Non imposta `PrivateNetwork`: nft deve osservare il namespace
host. `ReadWritePaths=/etc/ouf/deploy-snapshots` conserva la scrivibilità del
registro R3 e degli output sotto `ProtectSystem=full`; `/run` e `/var/lib` restano
disponibili ai contratti locali di runtime e ripristino. La compatibilità nativa
di questo indurimento resta da qualificare sul VPS.

## Installazione senza download

Il riferimento richiesto `r3-readers-install.sh` non è presente alla base
`8a3c4249`. Questo installer offre il contratto `plan`/`apply <planSha256>` con
ricalcolo completo, senza introdurre un lettore o rigenerare runbook esistenti.

1. Il reviewer fissa `C` al commit revisionato dopo il commit D-001. Il pin è
   intenzionalmente tutto zero nel materiale della task: lo script si arresta
   prima di qualsiasi effetto finché non viene fissato.
2. Trasferire tramite il canale operativo autorizzato una checkout locale di
   quel commit. L'installer usa la checkout che lo contiene, richiede `HEAD=C`,
   verifica i byte contro manifest SHA-256 e blob Git di `C` e non usa rete.
3. Eseguire come root:

   ```sh
   bash ops/vps/r3-autostart-install.sh plan
   bash ops/vps/r3-autostart-install.sh apply <planSha256>
   ```

Il manifest contiene gli stessi 87 file della consegna di `r3-operate.sh`, più
driver ed entrypoint, per 89 file. L'unità è verificata separatamente. Directory
installate 0700 root:root, file della consegna e config 0600, unità 0644. La
destinazione e l'unità devono essere assenti; un'installazione parziale non viene
riscritta. Il plan non scrive file e non esegue systemctl; l'apply ricalcola anche
i binding, crea esclusivamente i nuovi percorsi, verifica e stampa tutti gli
hash installati, esegue `daemon-reload` ed `enable`. Non esegue `start` o `--now`.
Un errore conserva i file parziali per la review. La ricevuta finale locale è
`installation-result.json`.

Per leggere il risultato dopo un boot autorizzato:

```sh
systemctl status ouf-semantic-r3-autostart.service
journalctl -u ouf-semantic-r3-autostart.service -b
journalctl -u ouf-semantic-r3-autostart.service -b -p err
```

## Limiti già verificati nel codice e domande aperte

- La v25 verifica l’identità stabile del peer Semantic e della sua generazione corrente.
- Il task 63d-b tratta due cause di diniego nello start governato. Una vecchia
  epoca aperta può avanzare se `operate` prova l’assenza runc, l’autorità
  invariata e l’ingresso chiuso. Il ripristino D-047 tratta il socket APISIX
  identificato nell’upper e verifica i sigilli originali. Il driver usa il plan
  e il readback ordinari per entrambi i casi.
- **R-025 resta aperto.** Il recupero del guard pre-Docker e quello del kernel
  del lease con nuovi handle spettano ai task successivi. L’installazione
  dell’autostart resta subordinata alla qualifica in esercizio dopo reboot e
  alla decisione umana D-048.

## Verifica riproducibile

```sh
python3 -I -B -m unittest discover -s tests -p test_semantic_provider_r3_autostart.py -v
bash -n ops/vps/r3-autostart-install.sh
```

Il workflow R3 installazione esistente aggiunge questi controlli su
`ubuntu-24.04`, senza runner self-hosted. I test coprono anche l'installer
incorporato, con filesystem temporaneo e comandi finti: plan in sola lettura,
apply vincolato, hash della consegna, destinazioni esclusive e soli reload/enable.
