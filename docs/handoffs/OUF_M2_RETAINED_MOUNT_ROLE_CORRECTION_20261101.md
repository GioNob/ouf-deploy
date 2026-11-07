> ESEGUITO CON SUCCESSO — 1 novembre2026: candidato46f6e635,
> risultato59935457,20GET/zero contenuti montati, predecessore preservato.
> Scope consumato: non ripetere il comando seguente e non cancellare le prove.
> [Ricevuta target](../../evidence/m2-retained-mount-role-correction-target-20261101.json).
> Ora prosegue la composizione sorgente; non è richiesta un'altra cattura.

# M2 — correzione del contratto di inventario, precedente conservato

1 novembre 2026. Il primo lettore ha restituito il risultato pubblico esatto
`STOP_RECONCILE / EXACT_UNADMITTED_THIRTEEN_PEER_SEED_REQUIRED` e consumato la
propria directory. **Non ripetere il vecchio comando e non cancellare la directory.**
La sessione non ha accesso shell/filesystem al VPS: l'operatore deve eseguire
soltanto il nuovo comando qui sotto e restituire il JSON pubblico finale.

Il difetto è nel lettore preparato dall'agente: pretendeva tredici etichette
uguali ai nomi logici dei ruoli. Il produttore originale ammette etichette di
inventario diverse; già il precedente `material_role_preparation.py` selezionava
per ID container univoco. Le fixture originali del nuovo lettore usavano solo
etichette uguali ai ruoli, quindi la CI non aveva verificato quella compatibilità.
Il JSON ricevuto non contiene contatori e non rivela quale componente del guard
composto fosse falso. La correzione verifica separatamente hash/schema/flag del
seed e richiede proprio il dominio di alias diverso; non presume veri gli altri
prerequisiti e non accetta un fallimento alternativo.

## Comando sul VPS

```bash
(
  set -e
  sudo -v
  ouf_correction_tmp=$(mktemp -d)
  trap 'rm -rf -- "$ouf_correction_tmp"' EXIT
  curl -fsSL --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 \
    https://raw.githubusercontent.com/GioNob/ouf-deploy/3bd586f072449eace15cbdf645e4e3cdd6a8b8d4/scripts/launch-m2-retained-mount-role-correction-20261101.sh \
    -o "$ouf_correction_tmp/run.sh"
  printf '%s  %s\n' 0db66081112fcc0ee82f62cf4fbc29c782b0eeb0606721185107d2a2e0ef7a60 "$ouf_correction_tmp/run.sh" | sha256sum --check --strict
  bash "$ouf_correction_tmp/run.sh"
)
```

Su `STOP_RECONCILE` conservare entrambe le directory e restituire soltanto il
JSON; nessun replay, cancellazione, aggiustamento del seed o file privato allegato.
`sudo -v` autentica l'operatore prima del bootstrap non interattivo. Il launcher
scarica codice pubblico e verifica in memoria gli esatti byte prima dell'esecuzione.

## Riconciliazione e limiti

- Il precedente deve avere solo `capture.claim.json` e `result.json`, root:root,
  directory0700/file0600 senza link, e risultato canonico
  `0922ad7330417ed9da7a472cad266174ace344c12fa7c5c420f8083ca1fe8d2c`.
  Qualunque candidato/partial extra, errore diverso o modifica fa fermare il
  correttivo. File e directory precedenti sono verificati ancora alla fine.
- Quel reason code ha un unico punto nel sorgente precedente fissato, prima di
  costruire il lettore Engine o leggere i mount: da qui deriva zero GET/letture
  metadati dei mount nel primo tentativo. È una deduzione dal codice esatto,
  non un contatore riportato o una lettura indipendente dei log del VPS.
- Stesso seed privato, hash14e42ac96293d342cd71b7386360b976882ac7ec75a18838d3960999430f3a13,
  schema/flag originali verificati separatamente. Roster pubblico già acquisito,
  hash a5161311451021f936692274c6ad91cecb7a40ca2e0017da533765905fd0f674:
  tredici ID univoci, intero binding originale e generazione. Nessuna selezione
  runtime per nomi/etichette; gli alias possono sembrare nomi di altri ruoli.
- Dieci peer mantenuti, due GET ciascuno sul solo Engine fissato. Boot, processi
  radice/peer, socket/credenziali Unix e configurazioni ancora uguali obbligatori.
  Il predecessore resta consumato; un solo tentativo del codice corretto,
  due tentativi di controllo cumulativi e al massimo20tentativi GET cumulativi.
  Il vecchio clock non era persistito e non viene presentato come ripreso.
  Nuovo limite esplicito del correttivo90s; timeout100s+kill5s. Nessun grant o
  reset di budget runtime, nessun retry automatico.
- Meccanica metadata-only originale invariata: O_PATH/no symlink, readonly
  tree2048entry/profondità32, zero contenuto di file montati. Mutabili/effimeri
  non osservati; metadati FIFO/socket non provano diritti di protocollo readonly.
  Nessuna sessione SQL/OAuth/signing/lifecycle o attivazione/pubblicazione.

Nuova directory privata, creata una sola volta:
`/etc/ouf/deploy-snapshots/m2-retained-mount-role-correction-0922ad73-20261101-v1`.
Il risultato atteso è `PRIVATE_MOUNT_CANDIDATES_CAPTURED_NOT_ADMITTED`:
metadati candidati alla review, custodia completa/ammissione/bearer target/E2E
restano da dimostrare. Nessuna autorizzazione runtime/apply/accettazione emessa.

## Codice e prove

Sorgente [fff3a2dc](https://github.com/GioNob/ouf-deploy/commit/fff3a2dc617d115a2849ae2a4c4f90a34e249a4e).
Capsula [c9aef7c9](https://github.com/GioNob/ouf-deploy/blob/c9aef7c914b3f5e56f9c82e2e88c1cf79999044d/scripts/correct-m2-retained-mount-roles-20261101.py),56865byte,
SHA256 `647945cd54d222044213ce7aa993c05477327f4e71d7b809309245fd03021e93`.
Launcher [3bd586f0](https://github.com/GioNob/ouf-deploy/blob/3bd586f072449eace15cbdf645e4e3cdd6a8b8d4/scripts/launch-m2-retained-mount-role-correction-20261101.sh),
SHA256 `0db66081112fcc0ee82f62cf4fbc29c782b0eeb0606721185107d2a2e0ef7a60`.
Tre sorgenti chiuse: vecchio lettore e helper congelato byte identici, nuovo
correttivo separato. Tutti235hash del compilatore corrente restano invariati.
`--inspect-source` verifica/compila soltanto il sorgente senza leggere il target.

Qualifica sorgente [41271213577](https://github.com/GioNob/ouf-deploy/actions/runs/41271213577):
16test/3suite PASS, log finali124744202756 e124744202698 letti. Unit8+capsula5,
native3 con Docker29.8.1, dieci veri processi scratch e tre record fixture,
/proc e socket Unix reali. Riproduzione del guard originale fallito prima dei GET,
alias eterogenei/ingannevoli, ID duplicati/estranei, intera configurazione e pin,
predecessore alterato, mount modificati e processo riavviato. Non è OUF E2E.

Qualifica launcher [41271390451](https://github.com/GioNob/ouf-deploy/actions/runs/41271390451):
20test/4suite PASS (unit17/native3), log finali124744708747 e124744708942
letti, zero failure/error/skip/ResourceWarning. Include i quattro casi del
launcher: byte alterati/vuoti/eccessivi, argomenti estranei e hash della consegna.

Publisher push [41271208231](https://github.com/GioNob/ouf-deploy/actions/runs/41271208231),
job124744187713/artifact13068424551; ZIP SHA256
`8beea6fd52ca2e2cd5e10efd667677d37764eccb0cabca4c1e7ce691943a665e`.
Verifica runner con gh2.97.0 e bundle offline, log finale letto; certificato e
subject scaricati: repoID1409074354/owner96419716, workflow/ref/sourcefff3a2dc e
SHA della capsula corrispondenti. Byte scaricati identici alla capsula commessa;
nessuna verifica crittografica locale aggiuntiva dichiarata. Gli URL raw immutabili
sono stati riletti e gli hash confrontati.

[Dossier del fallimento](../../evidence/m2-retained-mount-capture-target-failure-20261101.json)
e [dossier del correttivo](../../evidence/m2-retained-mount-role-correction-qualified-20261101.json).
Dopo l'input proseguire la composizione della custodia privata/review e controller.
M1/Teatri e Farmacie61/10/10OPEN/ministeriale STRING preservati; nessun replay di
upload/profiling/acquisizioni. Caricamento termina a UDP con tutti61esiti, poi
ricerca nel grafo, poi verticali/API e scheduler delta. Restano aperti ammissione,
bearer target, E2E, boot/rotazione/due client e autorità correnti.
