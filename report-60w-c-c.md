# Report sprint-03 / task-60w-c-c — Intervallo di polling e diagnosi del token

## Esito

`DONE` — Entrambe le correzioni passano nelle prove offline del lettore.

## Sintesi

Con `interval=600` ed `expires_in=1900`, i poll partono ai secondi 600, 1205 e 1815. Ogni `slow_down` aggiunge 5 secondi e la challenge scade al secondo 1900.
Il lettore restituisce `LOGIN_FAILED:token` per un HTTP 200 dal token endpoint con JSON illeggibile, come per un token inutilizzabile.
Su Windows sono passati 21 test del lettore. Il PET 09 è stato saltato e la suite dedicata a `HumanSession` si è fermata all’import di `fcntl`.

## Branch e commit

- Branch `sprint-03/task-60w-c-reader-args`, HEAD `ce36912c`.
- Modifiche non committate. Indice Git vuoto.

## File modificati

| File | Tipo (A/M/D) | Descrizione |
|---|---|---|
| `tools/chatbot_file_cohort/human_session.py` | M | Incremento di 5 secondi per ogni `slow_down` e stato HTTP disponibile in caso di errore di decodifica. |
| `scripts/read_installation_active.py` | M | Classificazione del JSON illeggibile durante un poll con risposta HTTP 200. |
| `tests/test_installation_active_reader.py` | M | PET 21 e 22 con clock simulato e risposte HTTP in memoria. |
| `docs/STATE.md` | M | Esito corrente delle prove. |
| `docs/OUF_M2_CHECKPOINT_LOG.md` | M | Esiti prima e dopo le correzioni. |
| `releases/storage-functional-status-20261107.json` | M | Qualificazione offline 60w-c-c. |
| `report-60w-c-c.md` | A | Report nella worktree, come per 60w-c-b. |

## Comandi eseguiti

I comandi Python usano Python 3.12.14 su Windows.

| Comando | Esito |
|---|---|
| `python -I -B -m unittest discover -s tests -p 'test_installation_active_reader.py' -k test_slow_down_above_initial_interval_limit -k test_malformed_token_response` | Prima delle correzioni, entrambi i test hanno riprodotto i difetti. |
| `python -I -B -m unittest discover -s tests -p 'test_installation_active_reader.py'` | ✅ 22 test rilevati, 21 passati, 1 saltato (PET 09). |
| `python -I -B -m unittest discover -s tests -p 'test_chatbot_cohort_human_session.py' -v` | ❌ Import del modulo fallito per assenza di `fcntl` su Windows. Nessun caso della suite dedicata eseguito. |
| `docker version --format '{{.Server.Version}}'` | ❌ Accesso negato alla pipe del daemon Docker. |
| `wsl --list --quiet` | ❌ Accesso negato al servizio WSL. |
| `git diff --check` | ✅ Superato. |
| `python -I -B -m json.tool releases/storage-functional-status-20261107.json` | ✅ Registro JSON valido. |

## Criteri di accettazione

- [x] Il PET 21 verifica i poll a 600, 1205 e 1815 secondi e l’esito `LOGIN_FAILED:expired` al secondo 1900.
- [x] Il PET 22 verifica `LOGIN_FAILED:token` per il JSON illeggibile con HTTP 200 e `LOGIN_FAILED:poll` con HTTP 400.
- [x] Suite del lettore rilanciata e prove di `HumanSession` registrate con i rispettivi esiti.

## Decisioni prese

Il limite di 600 secondi resta nella validazione dell’intervallo iniziale ricevuto dal provider. Gli incrementi successivi seguono `slow_down` fino alla scadenza della challenge. L’eccezione di decodifica rende disponibile al lettore il solo stato HTTP, così il journal conserva il percorso di blocco già usato per gli esiti OAuth incerti.

## Domande aperte

Restano da verificare su Linux il PET 09 come root e la suite dedicata a `HumanSession`.

## Note per il reviewer

La suite portabile del lettore ha esercitato la macchina a stati di `HumanSession` con questi test:

- `test_automatic_poll`
- `test_poll_retry_after_slow_down`
- `test_provider_device_expiry`
- `test_slow_down_above_initial_interval_limit`
- `test_malformed_token_response`
- `test_login_failures`

Il PET 09, `test_human_session_device_login`, verifica il journal e i permessi nativi. L’esecuzione su Windows lo ha saltato.
