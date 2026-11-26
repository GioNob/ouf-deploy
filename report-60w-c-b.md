# Report sprint-03 / task-60w-c-b — Ritmo del poll e scadenza del device flow

## Esito

`PARTIAL` — Entrambe le correzioni superano i test di regressione. Rimane aperta la verifica della suite in un container Linux come root.

## Sintesi

Prima di ripetere il poll, il client attende il maggiore fra l’intervallo corrente, il backoff e il ritardo richiesto da `Retry-After`.
Con intervallo iniziale di 7 secondi, `slow_down` seguito da HTTP 429 produce poll ai secondi 7, 19 e 31. Il successivo `authorization_pending` porta il quarto poll al secondo 43.
Una challenge con `expires_in=900` resta valida fino al secondo 900, entro la finestra della sessione HUMAN.
Su Windows sono passati 19 test su 20. Il test di custodia nativa richiede Linux root.

## Branch e commit

- Branch `sprint-03/task-60w-c-reader-args`, HEAD `ce36912c`.
- Modifiche non committate. Indice Git vuoto.

## File modificati

| File | Tipo (A/M/D) | Descrizione |
|---|---|---|
| `tools/chatbot_file_cohort/human_session.py` | M | Attesa minima dei retry del poll e durata della challenge. |
| `tests/test_installation_active_reader.py` | M | PET 19–20 con clock simulato e risposte HTTP in memoria. |
| `docs/STATE.md` | M | Esito corrente della verifica. |
| `docs/OUF_M2_CHECKPOINT_LOG.md` | M | Riproduzione dei difetti ed esiti dopo le correzioni. |
| `releases/storage-functional-status-20261107.json` | M | Qualificazione offline 60w-c-b. |
| `report-60w-c-b.md` | A | Report della review nella worktree. |

## Comandi eseguiti

I comandi Python locali usano Python 3.12.14 dalla radice della worktree.

| Comando | Esito |
|---|---|
| `python -I -B -m unittest discover -s tests -p 'test_installation_active_reader.py' -k test_poll_retry_after_slow_down -k test_provider_device_expiry` | Prima della correzione, riprodotti il poll anticipato al secondo 24 per HTTP 429 e 503 e l’arresto dei poll dopo il secondo 590. |
| `python -I -B -m unittest discover -s tests -p 'test_installation_active_reader.py' -v` | Windows, 19 superati, 1 saltato, 0 falliti. |
| `docker run --rm --user 0:0 --network none --mount "type=bind,source=$($PWD.Path),target=/src,readonly" -w /src python:3.13-slim python -I -B -m unittest discover -s tests -p 'test_installation_active_reader.py'` | PowerShell, uscita 1. Accesso negato a `npipe:////./pipe/docker_engine` prima dell’avvio del container. |
| `git diff --check` | Superato. |
| `python -I -B -m json.tool releases/storage-functional-status-20261107.json` | Registro JSON valido. |

## Criteri di accettazione

- [x] Il PET 19 verifica che HTTP 429 e HTTP 503 dopo `slow_down` mantengano l’intervallo di 12 secondi. Con `Retry-After: 20`, il terzo e il quarto poll partono ai secondi 39 e 51.
- [x] Il PET 20 verifica tutti gli 89 poll ai secondi da 10 a 890 e l’esito `LOGIN_FAILED:expired` al secondo 900.
- [ ] Suite completa in un container Linux come root. Il daemon Docker ha negato l’accesso. Il PET 09 è saltato su Windows.

## Decisioni prese

Il codice precedente limitava la challenge a 600 secondi, accorciando di 300 secondi la durata dichiarata nella prova. La nuova scadenza usa `expires_in` e si ferma alla scadenza della sessione HUMAN. Il contratto `validate_session_binding` in `tools/chatbot_file_cohort/authorization.py` ammette una finestra massima di 7.200 secondi dalla creazione della sessione e verifica il profilo finito di 128 tentativi.

## Domande aperte

Resta da acquisire l’esito della suite Linux root su questa worktree.

## Note per il reviewer

I test usano il percorso di login del lettore e registrano l’istante di ogni richiesta al token endpoint. Il PET 19 fissa il jitter per rendere riproducibile il backoff iniziale di 5 secondi. Le modifiche a `scripts/read_installation_active.py` visibili nel diff provengono dal 60w-c.
