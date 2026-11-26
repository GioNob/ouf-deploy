# Report sprint-03 / task-60w-c-d — URL di verifica e risposte del token endpoint

## Esito

`DONE` — Entrambe le correzioni passano nelle prove offline del lettore.

## Sintesi

Una challenge che include il `device_code` in `verification_uri` o `verification_uri_complete` termina con `LOGIN_FAILED:device-start` prima di mostrare URL o codice e prima del primo poll.
Un HTTP 200 del token endpoint con corpo illeggibile, JSON non oggetto o oltre 65.536 byte termina con `LOGIN_FAILED:token`.
Su Windows sono passati 23 dei 24 test del lettore. Il PET 09 è stato saltato e la suite dedicata a `HumanSession` si è fermata all’import di `fcntl`.

## Branch e commit

- Branch `sprint-03/task-60w-c-reader-args`, HEAD `ce36912c`.
- Modifiche non committate. Indice Git vuoto.

## File modificati

| File | Tipo (A/M/D) | Descrizione |
|---|---|---|
| `tools/chatbot_file_cohort/human_session.py` | M | Controlla entrambi gli URL prima di salvare la challenge e conserva lo stato HTTP quando il corpo è inutilizzabile. |
| `tests/test_installation_active_reader.py` | M | Aggiunge i PET 23 e 24 al flusso offline con provider simulato. |
| `docs/STATE.md` | M | Aggiorna lo stato delle prove del lettore. |
| `docs/OUF_M2_CHECKPOINT_LOG.md` | M | Registra le due regressioni e gli esiti delle suite. |
| `releases/storage-functional-status-20261107.json` | M | Registra la qualifica offline 60w-c-d. |
| `report-60w-c-d.md` | A | Report nella stessa worktree dei report precedenti. |

## Comandi eseguiti

I comandi Python usano Python 3.12.12 di QGIS su Windows, aggiunto al PATH della shell dei test.

| Comando | Esito |
|---|---|
| `python -I -B -m unittest discover -s tests -p 'test_installation_active_reader.py' -k test_device_code_in_verification_urls -k test_invalid_token_response_body` | Prima della correzione, 11 sottocasi falliti. |
| `python -I -B -m unittest discover -s tests -p 'test_installation_active_reader.py'` | ✅ 23 passati, 1 saltato (PET 09). |
| `python -I -B -m unittest discover -s tests -p '*human_session*.py' -v` | ❌ Import del modulo fallito per assenza di `fcntl` su Windows. |
| `wsl --list --quiet` | ❌ Accesso negato al servizio WSL. |
| `docker version --format '{{.Server.Version}}'` | ❌ Accesso negato alla pipe del daemon Docker. |
| `git diff --check` | ✅ Superato. |
| `python -I -B -m json.tool releases/storage-functional-status-20261107.json` | ✅ Registro JSON valido. |

## Criteri di accettazione

- [x] Il PET 23 inserisce la sentinella nel percorso, nella query e nel frammento di ciascun URL, anche con percent-encoding nella query. Verifica `LOGIN_FAILED:device-start`, terminale vuoto e zero poll.
- [x] I PET 22 e 24 verificano `LOGIN_FAILED:token` per JSON malformato, array JSON, codifica non valida, errore di lettura e corpo di 65.537 byte con HTTP 200.
- [x] Entrambe le suite richieste sono state rilanciate e i relativi esiti sono riportati sopra.

## Decisioni prese

Il controllo confronta il codice con l’intero URL, sia così come ricevuto sia dopo una decodifica percentuale. Per i corpi inutilizzabili, il lettore usa lo stato HTTP attraverso l’eccezione già introdotta dal 60w-c-c.

## Domande aperte

Restano da eseguire su Linux il PET 09 come root e la suite dedicata a `HumanSession`.

## Note per il reviewer

I PET portabili esercitano la macchina a stati di `HumanSession` con clock, risposte HTTP e journal simulati. Il PET 22 verifica anche che il JSON malformato con HTTP 400 resti classificato come `LOGIN_FAILED:poll`.
