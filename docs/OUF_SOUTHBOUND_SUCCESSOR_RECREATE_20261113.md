# D-022 — ricreazione del southbound successor senza `noswap`

## Motivo e perimetro

Docker 29.8.1 rifiuta `noswap` durante lo start, nel percorso
`moby/sys/mount.MergeTmpfsOptions`. Il successor southbound creato l'11 novembre
non è mai stato avviato e la sua richiesta contiene questa opzione. D-022
autorizza a sostituirlo con la stessa richiesta salvo il valore tmpfs:

```text
/run/ouf-southbound-runtime
prima: rw,noexec,nosuid,nodev,uid=636,gid=636,mode=0700,size=1m,noswap
dopo:  rw,noexec,nosuid,nodev,uid=636,gid=636,mode=0700,size=1m
```

L'assenza di swap sul VPS è un fatto riportato dall'operatore il 13 novembre,
non una misura effettuata da questa implementazione. Non si avviano container,
non si cambiano runtime, reti o configurazioni e non si legge la chiave HMAC.
Il controller non esegue i vecchi reader, lo staging, il cutover o il precedente
creatore. I launcher di discovery sono eseguiti dall'umano (D-004, D-011.4).

## Ricostruzione e prova di identità

Il nuovo controller è autonomo. Replica `build_request` e le costanti dello
script `create-discovery-stopped-candidates-20261111.py`, lasciato invariato:

1. Legge entrambi i container storici con API Docker **1.44**. Il frame originale
   usa gli stessi campi e lo stesso hash canonico con newline finale, e deve
   coincidere con `HISTORICAL_FRAMES`.
2. Verifica immagine, variabili d'ambiente, isolamento e bind di sola lettura.
   Verifica metadati e hash di route/config, incluse le condizioni JWKS.
   Su `HMAC_SOURCE` chiama esclusivamente `protected_file` con UID/GID 636 e
   modo 0600: nessuna apertura né lettura dei byte della chiave. La stringa di
   startup conservata nella richiesta contiene il futuro caricamento della
   chiave, ma il controller non la esegue.
3. Ricompila **entrambi** i ruoli, con `noswap=True`, e calcola
   `sha256(canonical({ADAPTER: richiesta, SOUTHBOUND: richiesta}))`. Il digest
   deve iniziare con il prefisso CLI `52cfc4fb`. Il digest completo originale
   non è disponibile: il prefisso di 32 bit, da solo, non prova l'identità.
4. Per questo applica anche `inspect_created` adattato a entrambi i successor
   correnti: identità, transazione, mai avviati, processo, healthcheck, bind,
   IP/MAC/alias richiesti e assenza di endpoint attivi. Confronta **tutto**
   `HostConfig`, presenza dei campi e valori annidati compresi. È ammessa solo
   la normalizzazione dell'engine osservata sul VPS il 2026-11-13 per entrambi
   i ruoli: `OomKillDisable: null` nella richiesta deve risultare `false` nel
   readback. Vale per i successor correnti e per il nuovo container; la richiesta
   inviata in POST conserva `OomKillDisable: null`. `true`, la direzione inversa
   (`false` → `null`) e differenze in altri campi (anche `ShmSize`) restano
   `CANDIDATE_FULL_HOSTCONFIG_CHANGED`. Un campo aggiunto, omesso o diverso
   fuori da questa unica normalizzazione produce `HELD`, senza
   ignorarlo automaticamente. La prova di identità usa prefisso **e** readback
   completo del `HostConfig` richiesto; non pretende di recuperare il digest
   storico mancante da una fonte indipendente.
5. Preserva `Config.MacAddress` nei digest dei frame. Se presente deve essere
   una stringa esatta corrispondente a un endpoint del ruolo; null/vuoto/altro
   valore falliscono. Il profilo presenza/tipo/valore del nuovo southbound deve
   coincidere col precedente. Nessuna eccezione STOP/DETACH viene riusata.

I mismatch della ricostruzione producono
`CREATION_REQUEST_RECONSTRUCTION_MISMATCH`; quelli dei successor correnti
`CURRENT_SUCCESSOR_REQUEST_MISMATCH` con una causa sicura, senza dati privati.
Le condizioni non ricostruibili dal frame originale fermano prima il relativo
controllo storico. Non si cambiano gli hash per superare un `HELD`.

La nuova richiesta nasce da copia profonda. Il controller riapplica al contrario
l'unica modifica tmpfs e confronta la richiesta completa con l'originale.
Il test esegue anche un diff ricorsivo completo e richiede esattamente quel
percorso/valore. La nuova label è applicata separatamente al momento del POST,
come nel creatore originale: non fa parte del digest storico ricostruito.

## Piano e controlli di rete

Ogni modalità ricontrolla lo stato `created`, PID 0, `StartedAt` zero esatto,
`RestartCount` 0, restart `no`, runtime atteso, nome, label e reti di entrambi i
successor. Verifica che il runtime governato sia presente in `/info`.

Per le tre reti del southbound usa `GET /networks/<nome>`. Queste risposte
possono omettere le prenotazioni dei container fermi: integra quindi
`GET /containers/json?all=1` e gli inspect dell'unione dei container elencati e
dei peer di rete. Un terzo container con IP assegnato o richiesto, MAC o alias
del southbound impedisce l'operazione, anche se fermo. Nessuna assenza viene
dedotta da campi obbligatori omessi. Dopo DELETE ripete il controllo senza
escludere alcun CID; dopo CREATE esclude solo il nuovo CID.

`--plan` non crea directory/ricevute e non invia mutazioni. Stampa `PLAN_READY`,
`plan` e `planSha256 = sha256(canonical(plan))`, senza newline nel payload hash.
Il piano comprende input CLI, digest delle richieste ricostruite, prefisso
verificato, digest dei frame correnti e delle reti, profili MAC, nuova richiesta
completa, regola per la label casuale e conteggio previsto delle operazioni.
Non contiene i byte della chiave, solo il path del bind. I dati temporali di
delivery e la futura transazione casuale sono esclusi dal digest del piano.

## Sequenza per l'operatore

Prima della consegna Claude sostituisce `__PIN_COMMIT__` e
`__PIN_CONTROLLER_SHA256__` nel launcher con commit e hash del controller
revisionato. I segnaposto impediscono l'esecuzione. Il launcher scarica solo
quel controller in una directory root 0700, verifica SHA-256 del controller e
di `/usr/bin/python3.13` (`889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9`),
poi esegue `sudo /usr/bin/python3.13 -I -B`. Non importa codice locale.
La directory di delivery rimane disponibile anche in caso di errore.

L'umano esegue il launcher fissato. Gli argomenti sotto usano gli ID e la
transazione indicati nella task; runtime e socket sono espliciti, senza default.
La root di output già esistente deve essere directory root e non scrivibile da
gruppo/altri, come tutti i suoi antenati, senza symlink. Il nome di output è
una nuova destinazione scelta per D-022 e deve essere assente.

```bash
common=(
  --historical-adapter-id f3d59af93fc90162681cee3a7562bdff3bf2af8c05cbdb7e270d1508fff18f67
  --historical-southbound-id 1fc5ae6a0db4600e0124bb1f9d2998780d533fd2b4de7cb086d8675b6afb5916
  --current-adapter-id 85b5302f6dbc3e9a24ace904b8d8a2d43bc5185e340c1bfe5474c723a6b640ef
  --current-southbound-id 34adce783cba238c1954eb33e39c37a641ea4f0db212531951a2fd2b86290c52
  --creation-transaction 7ff12b95c3f70c5eaebb1d0a12ab931d
  --creation-plan-prefix 52cfc4fb
  --expected-runtime ouf-semantic-admitted-v2
  --docker-socket /var/run/docker.sock
  --output-root /etc/ouf/deploy-snapshots
  --output-name southbound-recreate-20261113-d022-v1
)
bash ./deliver-recreate-southbound-successor-20261113.sh --plan "${common[@]}"
```

Esaminare `PLAN_READY` e il piano, conservandone il digest esatto. Eseguire
sequenzialmente, senza altri writer Docker tra plan e apply. Non usare digest
dei vecchi piani di creazione, A o cutover. Nessun hash di piano futuro viene
inventato in questo documento. Per inserire quello appena revisionato:

```bash
read -r -p 'planSha256 del piano D-022 revisionato: ' approved_plan_sha
[[ "$approved_plan_sha" =~ ^[0-9a-f]{64}$ ]] || exit 1
bash ./deliver-recreate-southbound-successor-20261113.sh \
  --apply --plan-sha256 "$approved_plan_sha" "${common[@]}"
```

Apply riosserva e ricompila tutto. Se il digest cambia, nessuna DELETE/POST e
nessuna directory di output. Dopo l'approvazione del digest riserva il nome di
output con mkdir atomico 0700; una verifica finale di entrambi i frame e delle
reti precede la sola `DELETE /containers/<vecchio CID>`, senza `force` né `v`.
Solo dopo GET 404 del vecchio e verifica delle risorse libere invia una sola
`POST /containers/create?name=ouf-semantic-southbound-v2-successor`.
La nuova transazione è `os.urandom(16).hex()`; il POST aggiunge esclusivamente
la label di creazione alla richiesta senza `noswap` del piano.

Il risultato positivo è `SOUTHBOUND_RECREATED_STOPPED`: nuovo container
verificato mai avviato, adapter col frame esattamente invariato, reti
ricontrollate. La ricevuta è:

```text
/etc/ouf/deploy-snapshots/southbound-recreate-20261113-d022-v1/result.json
schema: ouf.semantic-southbound-successor-recreation.v1
```

È creata 0600 con `O_EXCL`, flush/fsync del file e fsync della directory.
Contiene piano/digest, vecchio e nuovo CID, nuova transazione,
`newRequestSha256` del **POST effettivo inclusa la label**, digest del nuovo
frame, `containerStarts: 0`, `createRequests: 1`, `deleteRequests: 1`,
`noswapRemoved: true`, `startAuthorized: false` e conferma adapter invariato.
I contatori contano richieste tentate, non successi dedotti. Root, umask 077 e
interprete isolato senza bytecode sono obbligatori nel percorso operativo.

## Errori e ripristino

Un errore prima delle mutazioni produce `HELD`. Dopo una DELETE tentata produce
`PARTIAL`, con `oldRemoved`, `newCreated`, CID se noto e
`doNotRerunApply: true`. `null` significa esito sconosciuto, per esempio una
risposta persa; `false` significa nessuna mutazione tentata o presenza del
vecchio ancora osservata. Nessuna risposta persa viene interpretata come
fallimento certo della mutazione. Il controller non riprova automaticamente.

Un readback nuovo non conforme lascia il nuovo container presente e fermo;
non esegue una seconda DELETE. Un errore di scrittura ricevuta è riportato su
stdout e non provoca replay. Se il processo viene terminato senza possibilità
di gestire l'errore, può restare la directory riservata senza `result.json`:
conservare directory e output di delivery, riconciliare in sola lettura gli
effetti, senza cancellare parziali né scegliere un altro nome per rilanciare.
Il nome già riservato è sempre rifiutato, anche dopo un `HELD` tardivo.

Non c'è rollback automatico o ripristino del vecchio container: il vecchio
conteneva una richiesta non avviabile. Qualunque recupero residuo richiede
review dello stato conservato e un percorso esplicito per quel residuo.

## Effetti a valle e verifica

Il nuovo CID invalida i binding al vecchio successor. Occorrono nuova
preparazione **A**, ricontrollo di **P**, nuove prove rootfs del southbound e
ricomposizione/ricontrollo delle ricette col nuovo CID e con la nuova transazione.
Non riusare claim, sigilli, digest o ricette consumati della generazione vecchia.
Il risultato D-022 non autorizza start, ammissione, discovery o traffico e non
prova E2E.

Comando CI, senza dipendenze aggiuntive:

```bash
python3 -I -B -m unittest discover -s tests -p test_recreate_southbound_successor.py -v
bash -n scripts/deliver-recreate-southbound-successor-20261113.sh
```

Il workflow PR filtra i cinque nuovi path. L'Engine è un finto iniettato al
posto di `engine()`. La suite copre parità con il compilatore originale per i
due ruoli, prefisso e frame errati, guard di entrambi i successor, conflitti
IP/MAC/alias di terzi attivi e fermi, digest cambiato senza mutazioni, controllo
finale, successo e ricevuta, errori dopo DELETE, nuovo readback non conforme,
adapter modificato, diff completo tmpfs, metadati HMAC e allowlist senza start
o DELETE forzate. Include Config legacy MAC presente/coerente e negativi senza
normalizzazioni. Le fixture e gli hash storici della suite sono sintetici.

In questa working tree Windows Python non è disponibile nel PATH e non è stato
trovato nei percorsi locali verificati; WSL rifiuta l'enumerazione con accesso
negato. I test Python non sono stati eseguiti localmente. Il launcher supera
`bash -n`; il PASS della CI resta da acquisire dopo la pubblicazione a cura di
Claude. Nessun risultato CI o VPS viene attestato da questa consegna. La suite
simulata non qualifica un lifecycle Docker nativo e non dimostra normalizzazioni
engine oltre all'unica eccezione documentata per `OomKillDisable`: qualsiasi
altro mismatch reale rimane `HELD`.
