# OUF ops kit

Strumenti riusabili per diagnosticare ed evolvere una sorgente su OUF dal PC
dell'operatore. Sono nati dall'E2E Teatri v4 del 2026-11-10
(`docs/OUF_TEATRI_E2E_V4_20261110.md`) e sono parametrici: nessun ID è cablato.
Tutti richiedono solo Python 3.10+ e `ssh`. Non servono librerie esterne.

| Strumento | Cosa fa | Scrive su OUF? |
|---|---|---|
| `ro_psql.py` | Esegue un file SQL in sola lettura su `ouf_onboarding` o `ouf_udp` via ssh | No |
| `sql/*.sql` | Query parametriche (vedi sotto) | No |
| `onboarding_swap_asset.py` | Crea una nuova configurazione dalla versione padre sostituendo file gestito, profilo ed eventualmente etichetta | No (solo file locale) |
| `onboarding_clone_put.py` | Device login HUMAN, clone della versione padre, PUT della configurazione, diff | Sì: crea **una bozza** |
| `rebuild_csv_from_udp.py` | Ricostruisce il CSV originale dai payload canonici in UDP | No |

`onboarding_clone_put.py` non approva, non pubblica e non attiva: questi passi
restano nella UI di onboarding, a cura dell'utente.

## Prerequisiti sul VPS (temporanei)

La chiave SSH dev'essere caricata nell'ssh-agent (`ssh-add`). Passphrase e password
sudo non vanno mai scritte in chat o negli script.

`ro_psql.py` usa esattamente questi comandi. Il file sudoers va creato solo per la
sessione di diagnostica e rimosso subito dopo:

```
# /etc/sudoers.d/90-ouf-readonly-diagnostics  (visudo -f ...)
oufadmin ALL=(root) NOPASSWD: /usr/bin/docker ps *, /usr/bin/docker inspect *, /usr/bin/docker logs *, /usr/bin/systemctl show *
oufadmin ALL=(root) NOPASSWD: /usr/bin/docker exec -i -e PGOPTIONS=-cdefault_transaction_read_only=on ouf-postgres psql -X -w -q -P pager=off -v ON_ERROR_STOP=1 -h /var/run/postgresql -U ouf_onboarding -d ouf_onboarding
oufadmin ALL=(root) NOPASSWD: /usr/bin/docker exec -i -e PGOPTIONS=-cdefault_transaction_read_only=on ouf-postgres psql -X -w -q -P pager=off -v ON_ERROR_STOP=1 -h /var/run/postgresql -U ouf_udp -d ouf_udp
```

A fine lavoro: `sudo rm /etc/sudoers.d/90-ouf-readonly-diagnostics` sul VPS e
`ssh-add -D` sul PC.

Le transazioni sono doppiamente in sola lettura: lato server tramite `PGOPTIONS` e
lato client, perché `ro_psql.py` rifiuta i file senza `BEGIN READ ONLY` … `ROLLBACK`.
Sul database `ouf_ingestion` non esiste accesso: il run id si ricava da
`ouf_udp.handoff_intake`.

## Query disponibili

Le variabili si passano con `--var nome=valore` e nel SQL si usano come `:'nome'`.

| File | Variabili | Uso |
|---|---|---|
| `onb_source_versions.sql` | `source_id` | Versioni, pubblicazioni e metadati della sorgente |
| `onb_version_configuration.sql` | `version_id` | Configurazione completa in JSON |
| `onb_asset_profile.sql` | `asset_id`, `owner_subject` | File gestito e profilo: hash, dimensione, `staging_ref`, schema inferito |
| `udp_run_status.sql` | `source_id`, `run_id` | Run della sorgente e stato per record: intake, job, issue, revisione |
| `udp_issue_candidates.sql` | `run_id` | Issue aperte, candidato migliore, segnali in disaccordo; base per la pagina THS |
| `udp_issue_field_diff.sql` | `run_id`, `reference_source` | Proprietà in arrivo diverse da quelle già note da un'altra sorgente |
| `udp_materialization_check.sql` | `source_id`, `run_id` | Dopo la conferma THS: revisione, binding, etichette, contributi multi-sorgente |
| `udp_source_payloads.sql` | `source_id`, `run_id` | Payload canonici in JSON, input di `rebuild_csv_from_udp.py` |

Esempio:

```powershell
python tools/ops_kit/ro_psql.py --db ouf_udp --sql tools/ops_kit/sql/udp_issue_candidates.sql `
  --var run_id=f78029ff-e10a-4c7c-b1ad-902b223712dc --out candidates.txt
```

L'host è `oufadmin@62.83.33.202` di default; si cambia con `--host` o con la
variabile d'ambiente `OUF_VPS`. L'output viene scritto in UTF-8 su file, per evitare
i problemi di encoding della console PowerShell.

## Procedura: sostituire il file di una sorgente con una nuova versione

È il percorso seguito per la v4 Teatri. Ogni passo che scrive su OUF richiede un
"sì" esplicito dell'utente.

1. **Upload e profilazione** del nuovo file dalla UI di onboarding, a cura
   dell'utente. Annotare asset id e profile id.
   - Un file identico a uno già caricato viene deduplicato: per un vero re-test
     serve un contenuto diverso.
   - Controllare in `onb_asset_profile.sql` che i tipi inferiti siano quelli
     attesi, per esempio DECIMAL per le coordinate e DATE per le date. Un file
     corrotto da un foglio di calcolo li fa scendere a STRING senza alcun avviso.
2. **Configurazione padre:** `onb_version_configuration.sql` sulla versione ACTIVE.
3. **Nuova configurazione:** `onboarding_swap_asset.py --parent-config … --asset-id …
   --profile-id … --staging-ref … --content-hash … --size … [--label RESTRICTED]
   --out new.json`. Lo script fallisce se nella configurazione restano id del
   vecchio asset e stampa tutte le foglie cambiate. Rileggerle prima di proseguire.
4. **Bozza:** dopo il "sì" dell'utente, `onboarding_clone_put.py --source …
   --parent … --config new.json --correlation … --diff-out diff.json`. L'utente
   completa il device login nel browser. La bozza risultante è DRAFT.
5. **Approvazione, pubblicazione e attivazione** dalla UI, a cura dell'utente.
   Poi si avvia il run.
6. **Diagnosi UDP:** `udp_run_status.sql`, quindi `udp_issue_candidates.sql` e,
   se i candidati non combaciano, `udp_issue_field_diff.sql` contro la sorgente
   storica.
7. **Revisione THS** (vedi suggerimenti), poi `udp_materialization_check.sql`.
8. **Verifica MCP:** ricerca degli oggetti e confronto con l'insieme di UUID atteso.

Se la sorgente originale è andata persa, `udp_source_payloads.sql` seguito da
`rebuild_csv_from_udp.py --bom --crlf --expect-sha256 …` la ricostruisce a partire
dai payload canonici. Colonne, delimitatore e mapping vengono letti dalla
configurazione. Il 2026-11-10 il CSV Teatri è stato ricostruito identico byte per
byte.

## Suggerimenti per la pagina THS di risoluzione identità

- **Durata della sessione:** il token di sessione THS non viene rinnovato e dopo
  la scadenza la conferma risponde con un 403 "THS session unavailable or expired".
  Preparare le decisioni in anticipo con `udp_issue_candidates.sql` e lavorare per
  lotti brevi, oppure ricaricare la pagina subito prima di confermare.
- **Collegamento automatico:** con le regole attuali non avviene quasi mai. Tutti i
  segnali comuni devono essere AGREE e tutti gli altri candidati devono risultare
  esclusi, ma non esistono `distinctRules`. Ci si deve quindi aspettare una
  revisione umana per ogni record.
- **Significato delle voci del menu:**
  - "Collega a un oggetto" corrisponde ad APPROVE;
  - "Crea un oggetto distinto" corrisponde a CREATE_NEW;
  - "Chiudi il caso" corrisponde a DISMISS, cioè scarta il record in ingresso, ma
    il job resta QUARANTINED.
- **Run dello stesso oggetto in coda:** se lo stesso oggetto ha issue di più run
  in coda, distinguere le serie da un campo che le differenzia. Nel caso Teatri
  era il formato di `data_verifica`.

## Regole

- Sola lettura per default. Configurazioni, riavvii, IAM, scope, grant, policy e
  dati si toccano solo dopo un "sì" esplicito per quella singola azione.
- Mai stampare token, segreti o variabili d'ambiente complete. Sul database di
  Keycloak si interrogano solo client, scope, mapper e user id.
- Un solo operatore alla volta sul VPS.
- Le cartelle di lavoro temporanee create sul VPS vanno rimosse da chi le ha create.
