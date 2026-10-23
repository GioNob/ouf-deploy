# Registry 502: preparazione e revisione del recupero nel boot corrente

Questo passaggio costruisce gli input privati correnti e la revisione completa del recupero. Il launcher esegue soltanto `prepare` e, se la relativa receipt è valida, `review`. Non richiede una decisione HUMAN, non emette firme, non acquisisce nuovi token e non avvia Registry o token-worker. Il 502 resta aperto.

## Correzione del loader dopo il primo tentativo VPS

Il tentativo conservato in `/home/oufadmin/ouf-registry-postboot-review.ZHJtALt7/operator.log` è terminato con `INTERPRETER_STDLIB_SYSCONFIG_ORIGIN_REQUIRED`. Nel sorgente fissato il controllo avviene prima del caricamento dell'entry applicativa e di `entry.execute`: non è iniziata la preparazione privata. La receipt non stabilisce la versione Python o il layout effettivo della VPS. Il vecchio controllo accettava solo `sysconfig.py`; CPython 3.13 fornisce anche il layout pacchetto `sysconfig/__init__.py`.

Il nuovo loader verifica entrambi i layout tramite `PathFinder` limitato a `sys._stdlib_dir`, origine canonica esatta, loader sorgente e percorso del pacchetto. Restano negati gli override di build, la sostituzione da `sys.path` e symlink esterni. CI sorgente `39933894931`: 20 test su Python 3.12 e 20 su 3.13, inclusi preload completo dei 105 moduli senza esecuzione del controller. I tre artefatti aggiornati sono stati riletti esattamente dal commit indicato sotto. La prova dell'intera CLI e l'esito VPS restano non attestati.

Il prossimo tentativo usa questa consegna corretta, non il vecchio comando: conserva tutte le directory e non cancella o riutilizza claim. Se il nuovo comando trova un claim esistente, si arresta. Evidenza dell'errore: `evidence/semantic-registry-postboot-loader-target-20261023.json`.

## Riferimenti immutabili

| Elemento | Pin |
| --- | --- |
| Commit dei sorgenti applicativi | `47899a153f1e2c84f778b67564a8c952d8323c35` |
| Commit di pubblicazione della capsule | `05caff5cf8b75617b2d407a8f2eefdcf116a664f` |
| Capsule | `releases/semantic-registry-postboot-20261023.py` |
| SHA256 capsule | `75162f0e9f1e3848392b23c1754751b18a45c529ce139e0550c347de0c67b17a` |
| SHA256 dichiarazione | `552c027f549c9bbcd9912e7dce5aab69b1ffaa040092df0e9736cdeac45921ac` |
| Hash della chiusura dei sorgenti | `7d352295d288dce2e01dec1c3c558d7159513751765a448d93b7430a19b04993` |
| Launcher | [semantic-registry-postboot-prepare-review-20261023.sh](../../releases/semantic-registry-postboot-prepare-review-20261023.sh) |
| SHA256 launcher | `9813f601731c18d14eab34cc01435fcb991b43d4877924edbc6fcc11ac338327` |

La capsule contiene 105 moduli: i loro blob Git corrispondono al commit dei sorgenti. Rigenerazione deterministica, decodifica indipendente e rilettura degli artefatti pubblicati sono state verificate. Il launcher aggiornato ha nove test PASS, senza skip; cambia soltanto i tre pin della versione precedente sottoposta a revisione indipendente: trasporto GitHub, sudo e applicazione sono sostituti espliciti nelle prove del launcher. Le fixture native compongono direttamente bootstrap, owner e factory; non costituiscono una prova dell'intera CLI sul VPS. Evidenze: `evidence/semantic-registry-postboot-source-membership-20261023.json` e `evidence/semantic-registry-postboot-ci-20261023.json`.

## Comando operativo

Consegnare il file del launcher indicato sopra tramite il commit immutabile che lo pubblica. Nel terminale `oufadmin` già stabilito, dalla directory contenente il file locale esatto, eseguire una sola volta:

```bash
(
  set -euo pipefail
  printf '%s\n' '9813f601731c18d14eab34cc01435fcb991b43d4877924edbc6fcc11ac338327  semantic-registry-postboot-prepare-review-20261023.sh' | sha256sum --check -
  bash ./semantic-registry-postboot-prepare-review-20261023.sh prepare-review
)
```

Il launcher usa prima il client GitHub già installato in `$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh`, poi eventualmente quello in PATH. Riutilizza l'autenticazione esistente: nessun login o token negli argomenti. Scarica una sola volta la capsule dal commit indicato, verifica SHA256 e commit interno prima dell'esecuzione privilegiata, quindi usa due interpreti root distinti con `-I -B -S`. La password eventualmente richiesta da `sudo` è quella del sistema operativo.

`prepare` effettua letture correnti limitate di Engine, Gateway e della configurazione congelata tramite l'identità SERVICE esistente; conserva input e sorgenti in custodia privata. Crea il claim deterministico prima delle letture. `review` ricontrolla boot e custodia degli input conservati, ricompila gli undici scope e pubblica una nuova revisione esclusiva. Non ripete le osservazioni live di `prepare`.

L'esito atteso contiene prima `CURRENT_POSTBOOT_INPUTS_PREPARED`, poi `COMPLETE_PRIVATE_POSTBOOT_REVIEW_PREPARED`, con `reviewHash` e `signedScopeCount: 11`. Restano `runtimeAuthorityIssued: false`, `runtimeEffectsDispatched: 0`, `targetApplyAuthorized: false`, `automaticReplayAllowed: false`, `budgetReset: false` e `releaseAcceptance: false`. L'eventuale proposta di un tentativo SERVICE entro 900 secondi conserva il cumulativo 319: non è un'autorizzazione né prova di rinnovo continuo.

## Conservazione e arresto

Il launcher stampa sempre la directory privata conservata `$HOME/ouf-registry-postboot-review.XXXXXXXX` e il relativo `operator.log`. Conserva inoltre capsule, log di ogni fase e diagnostica stderr privata. Riportare il JSON pubblico e il percorso del log; non trasferire input privati, credenziali o stderr grezzo in chat.

Al primo download, controllo, comando o receipt non confermato si arresta senza tentativi automatici. Non cancellare directory, claim o revisioni per ripetere l'operazione. Se `prepare` è completato ma `review` no, l'unica modalità separata disponibile è `review`, da valutare sul motivo conservato; non viene scelta automaticamente e una revisione già pubblicata non viene sovrascritta. Il launcher rifiuta `issue`, `install`, `bootstrap`, `owner`, `continue` e ogni altro argomento.

La decisione runtime e l'esecuzione del recupero rimangono passaggi distinti, successivi alla valutazione della revisione corrente. Questo comando non dimostra il successo della richiesta semantica originale, la risoluzione permanente del 502 o l'accettazione della piattaforma. Supervisor ed E2E della piattaforma restano successivi.
