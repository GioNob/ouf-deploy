# Registry 502: preparazione e revisione del recupero nel boot corrente

Questo passaggio costruisce gli input privati correnti e la revisione completa del recupero. Il launcher esegue soltanto `prepare` e, se la relativa receipt è valida, `review`. Non richiede una decisione HUMAN, non emette firme, non acquisisce nuovi token e non avvia Registry o token-worker. Il 502 resta aperto.

## Riferimenti immutabili

| Elemento | Pin |
| --- | --- |
| Commit dei sorgenti applicativi | `2d860631ffaf837e15de0f8d5e285fe415fe0486` |
| Commit di pubblicazione della capsule | `03b995cf0da3ab93a30f82f5c1ee6080ab739ab7` |
| Capsule | `releases/semantic-registry-postboot-20261023.py` |
| SHA256 capsule | `6c76312c07e6eaffdafe22d885a10dce5f34cf93d7866153f0097619293decf5` |
| SHA256 dichiarazione | `64ec0b2040f2bd91793b4c43bebbf90369f0b1c39e9cfa31ba341593d199deeb` |
| Hash della chiusura dei sorgenti | `5f7c46a000f0500c5910fe8d505a6d4f5598091d5d7400660cc1c4c3b13716e6` |
| Launcher | [semantic-registry-postboot-prepare-review-20261023.sh](../../releases/semantic-registry-postboot-prepare-review-20261023.sh) |
| SHA256 launcher | `c36a48dba432e6befa4e3d7ff986f93532fedb99637cc8f68ca195e539620022` |

La capsule contiene 105 moduli: i loro blob Git corrispondono al commit dei sorgenti. Rigenerazione deterministica, decodifica indipendente e rilettura degli artefatti pubblicati sono state verificate. Il launcher ha nove test PASS, senza skip, e revisione indipendente: trasporto GitHub, sudo e applicazione sono sostituti espliciti nelle prove del launcher. Le fixture native compongono direttamente bootstrap, owner e factory; non costituiscono una prova dell'intera CLI sul VPS. Evidenze: `evidence/semantic-registry-postboot-source-membership-20261023.json` e `evidence/semantic-registry-postboot-ci-20261023.json`.

## Comando operativo

Consegnare il file del launcher indicato sopra tramite il commit immutabile che lo pubblica. Nel terminale `oufadmin` già stabilito, dalla directory contenente il file locale esatto, eseguire una sola volta:

```bash
(
  set -euo pipefail
  printf '%s\n' 'c36a48dba432e6befa4e3d7ff986f93532fedb99637cc8f68ca195e539620022  semantic-registry-postboot-prepare-review-20261023.sh' | sha256sum --check -
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
