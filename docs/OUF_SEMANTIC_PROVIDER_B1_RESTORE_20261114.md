# Annullamento di B1: ripristino del wrapper del runtime (task-26)

Decisioni: D-025 (B1 si applica solo con l'annullamento pronto), D-026 (implementato da Claude).
Riferimento: nota B1 §7.

## Che cosa fa
`scripts/restore-semantic-provider-b1-wrapper.py` ripristina il wrapper del runtime
`ouf-semantic-admitted-v2` che c'era **prima** di B1. Usa i byte esatti salvati dalla primitiva
di switch in `<b1-root>/switch/prior-runtime-wrapper.sh`.

Il ripristino passa dalla stessa primitiva invariata (`switch_existing_wrapper`): claim, CAS e
rename atomico sotto il lock del guard, con i checkpoint `BEFORE_CLAIM`, `BEFORE_RENAME` e
`AFTER_RENAME`. Lavora in una **root di claim nuova**: il claim originale di B1 non viene
cancellato né riscritto.

## Quando è ammesso
Solo se B2 non ha fatto nulla. Ogni condizione viene ricontrollata in plan, in apply e a ogni
checkpoint:
- il claim di B1 esiste e lega esattamente l'hash del wrapper precedente e quello del wrapper installato;
- il backup `prior-runtime-wrapper.sh` ha l'hash del wrapper precedente;
- il wrapper corrente è esattamente quello installato da B1. Se è già quello precedente, l'esito è `NOTHING_TO_RESTORE`;
- i file a cui punta il wrapper precedente sono invariati: python, sorgente v4 e configurazione v4;
- `<b1-root>/arming` è vuota, cioè nessuna armatura B2 è stata pubblicata;
- i due successor sono `created`, con PID 0, mai avviati e `RestartCount` 0;
- il lock del guard è vuoto e ha la stessa identità del piano.

Se una condizione non è soddisfatta, il controller si ferma con `HELD` senza scritture. Se B2 ha già
fatto progressi, il ripristino richiede una riconciliazione B2: questo controller non ferma container.

## Sequenza per l'umano
Plan e apply si lanciano con lo script runbook `ops/vps/b1-restore.sh`, con le stesse 4 righe dei
passi precedenti. L'apply va eseguito solo se si decide di annullare B1, e dopo aver rivisto il plan.

## Cosa non fa
- non avvia, non ferma e non rimuove container;
- non legge chiavi e non scrive in nft;
- non riavvia il daemon;
- non riprova da solo: dopo un claim `doNotRerunApply` resta true.
