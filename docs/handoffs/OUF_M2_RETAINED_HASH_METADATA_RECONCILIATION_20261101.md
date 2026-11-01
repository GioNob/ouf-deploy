> CONSUMED on target, 1 November2026. Receipt621124d2/private candidate050ba14d.
> Four current metadata differences recorded, zero Engine/content. Do not run
> the command below again. All four predecessor scopes remain preserved.
> Lifecycle correction and new static-only input are in qualification.

# M2 — riconciliazione mirata dei metadati di gateway-owner

1 novembre2026, Europe/Rome. Il comando hash ha restituito `STOP_RECONCILE /
READONLY_HASH_MOUNT_METADATA_DIFFERS_FROM_CAPTURE`:2GET, zero file e byte hashati.
Risultato canonico `a7a7601c5f78dd55ad43839c588cddaded3a61471517dbf6b7917ffbfd9f4319`.
Le tre directory precedenti restano consumate. Non ripetere il vecchio comando,
non cancellare scope e non modificare file per far superare il controllo.

Il punto del sorgente fissato identifica gateway-owner, secondo peer dopo caddy.
Le due configurazioni Docker osservate hanno superato il guard; la differenza
è nei metadati dei mount del secondo peer. Il vecchio risultato non ha salvato
il nodo/campo diverso. Non prova una rotazione prevista né una violazione dei
permessi: non si sceglie una causa per supposizione e non si allenta il controllo.

Il nuovo lettore confronta il candidato acquisito con i metadati **attuali** dei
soli mount di gateway-owner. Esegue **zero richieste Engine e zero letture di
contenuti montati**. Conserva un rapporto root privato e stampa soltanto categorie
di differenze, nomi dei campi e identificatori opachi. Non riavvia gli hash.
La sessione non ha shell/filesystem del VPS: serve questo input dell'operatore
per distinguere la variazione reale, dopo la preparazione e qualifica del codice.

## Comando sul VPS

```bash
(
  set -e
  sudo -v
  ouf_reconcile_tmp=$(mktemp -d)
  trap 'rm -rf -- "$ouf_reconcile_tmp"' EXIT
  curl -fsSL --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 \
    https://raw.githubusercontent.com/GioNob/ouf-deploy/9f8bf3517ec5de1cc75808556877938b4bfaed59/scripts/launch-m2-retained-hash-reconciliation-20261101.sh \
    -o "$ouf_reconcile_tmp/run.sh"
  printf '%s  %s\n' b171c4487372af68161150eb7a9f39f7f553f2e3432b2774ced9a5a2a33d9f0f "$ouf_reconcile_tmp/run.sh" | sha256sum --check --strict
  bash "$ouf_reconcile_tmp/run.sh"
)
```

Restituire soltanto il JSON pubblico. Su `STOP_RECONCILE` conservare tutto e non
ripetere. Nessun file privato o credenziale deve essere allegato. Il launcher
verifica in memoria gli esatti byte della capsula prima dell'esecuzione isolata.

Nuovo scope, creato una sola volta:
`/etc/ouf/deploy-snapshots/m2-retained-hash-reconciliation-a7a7601c-20261101-v1`.
Risultato atteso: `METADATA_DIFFERENCES_RECORDED_NOT_ADMITTED`. Percorsi, nomi e
frame numerici completi sono soltanto in `reconciliation.private.json`, root0600.
Il risultato pubblico distingue:

- `SIZE_OR_TIME_CHANGED`: dimensione/tempi diversi; non dimostra la causa.
- `KIND_OR_CUSTODY_CHANGED`: tipo, inode, proprietà, permessi o link diversi.
- `MEMBERSHIP_CHANGED`: nodo aggiunto/rimosso; i sottoalberi non osservabili
  sono indicati come tali, senza seguirne i collegamenti.
- `CHANGED_DURING_OBSERVATION`: metadati instabili durante la nuova lettura.

Un'eventuale classe di riferimento a token deriva esclusivamente da un percorso
esplicito in Config.Env del record già fissato; non legge token/configurazioni,
non ne pubblica il valore e non autentica il relativo owner. Anche zero differenze
attuali non annullano il precedente stop. `currentDiffIsNotHistoricalFailureTrace`
resta true: questo confronto non ricostruisce retroattivamente l'istante fallito.
Non osserva nuovamente la configurazione Docker, che viene dichiarata non fresca.
Se `observationIncomplete` è true, la non osservabilità prevale sulle categorie:
non permette attribuire una modifica o una causa ai discendenti non osservati.

## Vincoli e prove

Esatto fallimento/claim/profilo e vecchi frame degli scope obbligatori; candidati
46f6e635/risultato59935457/seed14e42 ancora hash-bound. Stesso boot/processi radice
e gateway prima/dopo. Solo O_PATH/nofollow e listing di directory, massimo2048nodi/
profondità32; nessun file regolare, FIFO/socket/device aperto per contenuti.
Link e nodi bloccati sono descritti senza seguirli. Radici RW non enumerate.
Un tentativo30s, timeout40s+kill5s, massimo128differenze pubbliche (flag di troncamento
se necessario), rapporto privato8MiB. Valori/percorsi/nomi non stampati.

La catena conserva2controlli metadati/20GET +1tentativo hash/2GET; il confronto
aggiunge1controllo/0GET. Totale4controlli/22GET nella catena, senza riarmare o
rinnovare il tentativo hash né resettare vecchi clock/budget. Nessuna ammissione,
nuova policy, OAuth, SQL, firma, lifecycle, activation, grant o accettazione.

[Sorgente0bea0b9c](https://github.com/GioNob/ouf-deploy/commit/0bea0b9c46f8fdd941b43d6f800a179f460456dd),
[capsula2332de54](https://github.com/GioNob/ouf-deploy/blob/2332de54f919512ea347d7fae3bbdabf1721d337/scripts/reconcile-m2-retained-hash-metadata-20261101.py),107738byte,
SHA256 `5e992de54d31657f0c2fa840cfb0ca2f6e2513c15520a302bec7e8ba22f9f403`.
[Launcher9f8bf351](https://github.com/GioNob/ouf-deploy/blob/9f8bf3517ec5de1cc75808556877938b4bfaed59/scripts/launch-m2-retained-hash-reconciliation-20261101.sh),
SHA256 `b171c4487372af68161150eb7a9f39f7f553f2e3432b2774ced9a5a2a33d9f0f`.
Sei sorgenti chiuse, vecchi lettori/produttori e235hash congelati invariati.
Import reale isolato della capsula verificato, senza invocare l'entrypoint target.

CI sorgente[41291236508](https://github.com/GioNob/ouf-deploy/actions/runs/41291236508):
16test/3suite PASS, log finali124802755709 e124802755419 letti, unit7/capsula5/
native4, zero failure/error/skip/ResourceWarning. Docker29.8.1 reale/dieci scratch
processes, riproduzione dello stop dopo2GET/zero hash con il vecchio lettore;
nuova riconciliazione zero Engine/contenuti, sostituzione atomica, symlink e PID
riavviato. Tre peer/parent/common hash sono fixture; non è OUF E2E né diagnosi target.

CI launcher[41291711507](https://github.com/GioNob/ouf-deploy/actions/runs/41291711507):
20test/4suite PASS (unit16/native4), log finali124804139125 e124804139324
letti, zero failure/error/skip/ResourceWarning. Include i quattro controlli
della consegna: byte alterati/vuoti/eccessivi e argomenti estranei respinti.

Publisher push[41291231946](https://github.com/GioNob/ouf-deploy/actions/runs/41291231946),
job124802743273/artifact13077082636, ZIP SHA256
`a9b8deb48bed165c45952d5f38b0a8459cda74b27cb8b314948a4f8284cc594b`.
Runner gh2.97.0 verifica bundle offline; log finale letto. Certificato/subject/source/
ref/workflow/repoID1409074354/owner96419716 riletti; byte scaricati identici alla
capsula commessa. Nessuna verifica crittografica locale aggiuntiva dichiarata.

[Dossier riconciliazione](../../evidence/m2-retained-hash-reconciliation-qualified-20261101.json),
[stop reale](../../evidence/m2-retained-readonly-hashes-target-stop-20261101.json).
Dopo il confronto classificare la variazione usando i contratti degli owner;
non trasformare metadati osservati in policy attesa. Full private custody,
artefatti runtime, bearer target, controller/checkpoint/package/review/autorità
correnti, E2E e due client restano aperti. M1/Teatri e stessa Farmacie61/10/10OPEN/
ministeriale STRING preservati; nessun replay upload/profiling/acquisizioni.
