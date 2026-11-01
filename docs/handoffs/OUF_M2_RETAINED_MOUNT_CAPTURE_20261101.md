> CONSUMATO — 1 novembre 2026: il comando seguente ha restituito
> `STOP_RECONCILE / EXACT_UNADMITTED_THIRTEEN_PEER_SEED_REQUIRED`.
> Non eseguirlo nuovamente e non cancellare la directory. Il lettore nuovo
> richiedeva erroneamente nomi di ruolo come etichette di inventario.
> Correzione separata qualificata: [nuovo comando](OUF_M2_RETAINED_MOUNT_ROLE_CORRECTION_20261101.md).
> Il comando storico resta qui soltanto come evidenza.

# M2 — input necessario dal VPS: soli metadati dei mount mantenuti

Il prossimo input concreto è la custodia attuale dei mount dei dieci servizi
mantenuti. In questa sessione non è disponibile un connettore shell/filesystem
del VPS; questo passaggio richiede l'operatore. Serve a completare la nuova
review privata, non autorizza installazione, pubblicazione o attivazione.

## Comando unico sul VPS

Il launcher verifica in memoria gli esatti byte della capsula prima dell'eventuale
esecuzione privilegiata. La verifica qui sotto fissa anche il launcher.

```bash
(
  set -e
  ouf_capture_tmp=$(mktemp -d)
  trap 'rm -rf -- "$ouf_capture_tmp"' EXIT
  curl -fsSL --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 \
    https://raw.githubusercontent.com/GioNob/ouf-deploy/ef664e159ea4bc6981d2799dae6c93a1d0a4c8c7/scripts/launch-m2-retained-mount-capture-20261101.sh \
    -o "$ouf_capture_tmp/run.sh"
  printf '%s  %s\n' fe722cf6b37b5789f2cafa799a1506aea8d49736349ae4bef1010428d8e93b6a "$ouf_capture_tmp/run.sh" | sha256sum --check --strict
  bash "$ouf_capture_tmp/run.sh"
)
```

Restituire soltanto il JSON pubblico finale. Se termina `STOP_RECONCILE`,
restituire quel JSON senza ripetere il comando o cancellare la directory consumata.
Nessuna credenziale o file privato deve essere allegato alla conversazione.

Il comando richiede root oppure sudo non interattivo già disponibile; scarica
soltanto codice pubblico. I dati raccolti rimangono nella directory root privata
`/etc/ouf/deploy-snapshots/m2-retained-mount-custody-14e42ac9-20261101-v1`.
Il risultato pubblico conserva hash/contatori e image ID runtime, distinguendoli
dal digest di configurazione registrato negli archivi Docker-save.

## Perimetro verificabile

- Selezione degli esatti dieci ID dal precedente record di tredici peer,
  `inputs.json` con hash14e42ac96293d342cd71b7386360b976882ac7ec75a18838d3960999430f3a13.
  Dati storici usati come selettori: boot, processi radice/peer e configurazioni
  devono corrispondere ancora; nessuna autorità storica viene riutilizzata.
- Venti tentativi GET sull'unico socket Engine con peer/custodia fissati,
  due osservazioni per ruolo; nessuna scoperta per nomi o altro endpoint.
- Soli metadati di proprietà, permessi, tipo, inode e tempi dei mount; albero
  dei mount readonly limitato a2048entry/profondità32. Zero byte letti dal
  contenuto dei file montati. FIFO/socket/dispositivi sono solo metadati;
  un mount readonly non prova diritti di protocollo readonly sul socket.
- Contenuti mutabili/effimeri non osservati. I metadati catturati sono candidati
  di review, non una politica attesa indipendente né ammissione della coorte.
- Un tentativo, budget90secondi; timeout del processo100secondi con kill dopo5.
  Output esclusivo, parziali conservati e nessun replay/ripristino di budget.
- Nessuna sessione SQL, OAuth, grant, signing, avvio/arresto di servizi,
  pubblicazione di capability, attivazione sorgente o accettazione.

## Codice e qualifica

[Launcher esatto](https://github.com/GioNob/ouf-deploy/blob/ef664e159ea4bc6981d2799dae6c93a1d0a4c8c7/scripts/launch-m2-retained-mount-capture-20261101.sh)
SHA256 `fe722cf6b37b5789f2cafa799a1506aea8d49736349ae4bef1010428d8e93b6a`.
[Implementazione leggibile](https://github.com/GioNob/ouf-deploy/blob/26b7fb1260ea72a67ae635019e21d8eedbc9c42b/tools/m2_discovery_installation_profile/retained_mount_capture.py).
[Capsula autonoma](https://github.com/GioNob/ouf-deploy/blob/d2020f17508fb7d5e14f6bc96a110f668ba6ee26/scripts/capture-m2-retained-mounts-20261101.py)
SHA256 `dfdedd2e038b524277d6db8ed9f00808798366e45552863b471f5d7de67014fa`,36422byte.
Due sorgenti chiuse; helper di custodia congelato conservato. `--inspect-source`
sul launcher verifica/compila solo le sorgenti senza leggere il target.

CI[41267871051](https://github.com/GioNob/ouf-deploy/actions/runs/41267871051):
**20test/4suite PASS**, log finali124734362848 e124734362635 letti,
zero failure/error/skip/ResourceWarning. Unit17, native3 con Docker29.8.1 reale,
dieci processi scratch, socket Unix, /proc, mount/FIFO/socket, drift e PID
riavviato respinti prima dell'I/O successivo. Non sono applicazioni OUF/E2E.
La prima qualifica41266955677 falliva soltanto perché il test negativo attendeva
ValueError mentre il vecchio PID sparito produceva FileNotFoundError, già negato
prima di ogni GET. Corretto il test, senza indebolire il guard di produzione.

Publisher push[41267257360](https://github.com/GioNob/ouf-deploy/actions/runs/41267257360),
artifact13068106546: CLI2.97.0, certificato/subject/source/ref/repository ID letti;
byte scaricati identici alla capsula commessa. ZIP SHA256
`5f2699aa39d7bda21da3aa795f004d2725265632ce8e1843b96fb05eb96eb603`.
Non è una firma di autorità runtime. [Dossier](../../evidence/m2-retained-mount-capture-qualified-20261101.json).

Dopo il risultato riprendere la composizione della custodia/private review e del
controller completo. Applicazione, bearer target, E2E/Farmacie→UDP con tutti61esiti,
boot/rotazione/due client restano aperti. M1/Teatri e la Farmacie già profilata
restano acquisiti; nessun nuovo upload/profiling/acquisizione.
