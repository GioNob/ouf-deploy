> **CONSUMATO — NON ESEGUIRE I BLOCCHI SOTTO.** La ricevuta15 è stata riconciliata:15 controlli/50 GET cumulativi,0 file/0 byte credenziali. [Unica nuova consegna: controllo16](OUF_SEAWEEDFS_INPUT_OBSERVATION_20261102.md). Nessun replay o cancellazione degli scope; quanto segue è storico.

> **CONSUMATO — NON ESEGUIRE IL BLOCCO SOTTO.** Controllo14 terminato con CANONICAL_PRIVATE_CREDENTIAL_REFERENCE_REQUIRED; cumulativi14controlli/49GET. I13snapshot sono conservati. Usare esclusivamente la [NUOVA continuazione qualificata](OUF_SEAWEEDFS_CREDENTIAL_CONTINUATION_20261102.md), controllo15 separato/max2GET, senza cancellare o ripetere nulla. Il contenuto seguente è storico.

# SeaweedFS — rilevazione correttiva dopo lo STOP di selezione

2 novembre 2026. Il primo controllo è terminato con `BOUNDED_NONEMPTY_OUF_CONTAINER_SET_REQUIRED`: scope13 consumato,13controlli/36GET Docker cumulativi. Il filtro per prefisso `/ouf-` era un'assunzione errata del reader. Lo STOP non prova assenza di container o dati. Dal punto preciso di arresto nel sorgente qualificato si deduce che non erano ancora stati aperti credenziali o richieste S3; questa è una deduzione dal codice, non un contatore S3 riportato dal target.

Il comando precedente resta consumato. Non ripeterlo, non cancellare scope o installazione e non sostituire manualmente nomi/ID.

## Unica azione necessaria

L'agente non dispone di shell VPS o API Docker/S3. Sul VPS OUF, dallo stesso account operativo usato prima, eseguire **una sola volta** questo nuovo blocco. È un controllo correttivo distinto, che richiede e conserva esattamente lo STOP già ricevuto.

```bash
(
  set -eu
  umask 077
  inventory_correction_dir="$(mktemp -d /tmp/ouf-storage-correction.XXXXXX)"
  trap 'rm -rf -- "$inventory_correction_dir"' EXIT
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 --max-time 60 \
    https://raw.githubusercontent.com/GioNob/ouf-deploy/4da291a42aa7951b3742fab5423a1fb40401f266/releases/seaweedfs-inventory-reconciliation-20261102/run-reconciliation.py \
    -o "$inventory_correction_dir/run-reconciliation.py"
  printf '%s  %s\n' a4d3173bd6e41943811c825acf95501ba898dd057ed698bb884b1d73bb375c77 "$inventory_correction_dir/run-reconciliation.py" | sha256sum --check --strict
  sudo /usr/bin/python3 -I -B -S "$inventory_correction_dir/run-reconciliation.py"
)
```

Restituire **solo il JSON finale**, anche in caso di STOP o esito parziale. Non inviare inventari privati, file di configurazione, nomi degli oggetti o credenziali. Non rilanciare il blocco in caso di errore e conservare tutti i file prodotti.

## Cosa cambia

Il reader corregge la selezione usando i13ID del roster già verificato e il seed privato hash-bound `14e42ac9…`. I nomi non selezionano più i ruoli: il nome osservato viene soltanto confrontato con quello già catturato per lo stesso ID. Sono ammessi esclusivamente13GET diretti `/v1.44/containers/<ID>/json`, senza richiesta di elenco, ricerca per prefisso o fallback verso altri container. Socket e credenziali peer del Docker Engine, boot/processi e identità MinIO vengono vincolati alle evidenze esistenti; se differiscono, il controllo si ferma.

È il controllo14, ancora da eseguire. Parte dai36GET già consumati e può arrivare a49, secondo le letture effettive. Conserva tutti13scope precedenti, compreso il fallimento; non riattiva clock o budget precedenti. Lo scope nuovo è `/etc/ouf/deploy-snapshots/seaweedfs-inventory-reconciliation-20261102-v1`.

Riusa senza reinstallarlo il reader statico già presente, SHA256 `430631fe4dfd1b844229637373ea176c2e84e81e1491919f4a25cc36c68359a8`. Installa soltanto la nuova capsula e il manifesto sotto `/usr/local/lib/ouf-storage-inventory-reconciliation-20261102` e scrive le nuove evidenze private. Credenziali esistenti solo in descrittori RAM anonimi sigillati.

I limiti S3 restano10000GET/HEAD,25000record/parti,300s di reader e64MiB di inventario privato. Controllo600s, sorveglianza esterna630s; obiettivo soft di memoria Go256MiB/GOMAXPROCS1. Zero corpi oggetto letti, scritture S3, SQL, lifecycle container, deploy o migrazione. Il risultato non prova una fotografia atomica o assenza di consumer esterni; feature UNSUPPORTED non sono dichiarate assenti.

## Qualifica e provenienza

- [CI41406925881](https://github.com/GioNob/ouf-deploy/actions/runs/41406925881), source `f53412947ab7b301e76083c27d11d93a9873df3d`:10nuovi test Python e12Java PASS, SDK originale identico e nuova scansione zero findings. Prova con13container Docker reali, tutti con nomi senza `/ouf-`, socket/peer reali e13inspect per ID; namespace e S3 reali,1010record sintetici. Lo storico dei13scope è MODELLATO; il ruolo MinIO nella prova è un processo sintetico su rete host, con server S3 reale separato. Non è osservazione del VPS o qualifica della topologia finale.
- Capsula chiusa24sorgenti,23storiche invariate, payload260304byte entro il limite originale; alterazione negata. Root install della sola capsula e conservazione dei byte del reader precedente PASS. Uno STOP alterato è respinto prima di Docker/S3.
- [CI41407543627](https://github.com/GioNob/ouf-deploy/actions/runs/41407543627): verifica indipendente di tutti18membri checksum, sorgenti, firma Sigstore del produttore/workflow/runner esatti, due file pubblicati confrontati byte per byte e launcher esattamente vincolato al template qualificato. Pubblicazione immutabile `7102638803484c7dcb7a61f398d442f5ccbe6203`; launcher immutabile `4da291a42aa7951b3742fab5423a1fb40401f266`.
- [Ricevuta target originale](../evidence/seaweedfs-inventory-selection-stop-target-20261102.json), [dossier della correzione](../evidence/seaweedfs-inventory-reconciliation-qualified-20261102.json).

La build server SeaweedFS mantiene il gate grezzo HELD per1UNKNOWN OpenPGP non importato. Questo comando non installa il server, non rimuove ancora le vulnerabilità del MinIO corrente e non concede ammissione runtime/release. SW-G0…G7 e21AT restano OPEN; Teatri e la stessa Farmacie sono preservati.
