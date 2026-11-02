> **CONSUMATO — NON ESEGUIRE I BLOCCHI SOTTO.** Inventario16 completo:2 bucket/120 record/203743 byte,16 controlli/52 GET cumulativi. [Unica nuova consegna: analisi offline17](OUF_SEAWEEDFS_OFFLINE_PLAN_20261102.md),senza nuove interrogazioni Docker/S3 o letture credenziali. Nessun replay/reset/cancellazione;quanto segue è storico.

> **CONSUMATO — NON ESEGUIRE I BLOCCHI SOTTO.** La ricevuta15 è stata riconciliata:15 controlli/50 GET cumulativi,0 file/0 byte credenziali. [Unica nuova consegna: controllo16](OUF_SEAWEEDFS_INPUT_OBSERVATION_20261102.md). Nessun replay o cancellazione degli scope; quanto segue è storico.

# SeaweedFS — completamento inventario dopo lo STOP sulle credenziali

2 novembre 2026. Ricevuto lo STOP `CANONICAL_PRIVATE_CREDENTIAL_REFERENCE_REQUIRED`: controllo14 consumato,14controlli e49GET Docker cumulativi. I13inspect sono riusciti e lo snapshot di container, RAM e capacità è già conservato. S3 non era ancora raggiunto; l'ambiente dei container era passato in RAM negli inspect, mentre non è provato se la successiva funzione di risoluzione abbia completato0o1letture. Nessun valore di credenziale va inviato all'agente.

Il reader richiedeva impropriamente riferimenti assoluti. La configurazione pubblica dell'immagine trattenuta contiene anche i default relativi `access_key`, `secret_key`, `config.env`. La correzione segue l'ordine della versione MinIO dichiarata: file legacy, file root, poi configurazione ambiente; file segreti mancanti o vuoti non sovrascrivono i valori espliciti. I riferimenti sono risolti nel root/cwd del processo MinIO vincolato, senza shell, senza credenziali predefinite e senza accettare traversal, symlink o file non privati. La fonte di riferimento non autentica il publisher dell'immagine corrente.

**I due comandi precedenti restano consumati.** Non ripeterli e non cancellare scope, installazioni o file prodotti.

## Una nuova esecuzione necessaria

L'agente non ha shell VPS o API di inventario. Sul VPS OUF, dallo stesso account operativo usato prima, eseguire **una sola volta** questo nuovo blocco:

```bash
(
  set -eu
  umask 077
  inventory_credentials_dir="$(mktemp -d /tmp/ouf-storage-credentials.XXXXXX)"
  trap 'rm -rf -- "$inventory_credentials_dir"' EXIT
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 --max-time 60 \
    https://raw.githubusercontent.com/GioNob/ouf-deploy/727dfedc1ca41c91f402149f441141bb17ea0fa3/releases/seaweedfs-inventory-credentials-20261102/run-credentials.py \
    -o "$inventory_credentials_dir/run-credentials.py"
  printf '%s  %s\n' 457fe76a6c2c7e71fc7d0488509254f9354e0f9b203931f3e5192a418111dac5 "$inventory_credentials_dir/run-credentials.py" | sha256sum --check --strict
  sudo /usr/bin/python3 -I -B -S "$inventory_credentials_dir/run-credentials.py"
)
```

Restituire **solo il JSON finale**, anche se parziale o STOP. Non inviare credenziali, inventari privati, configurazioni o nomi degli oggetti. Non rilanciare in caso di errore: il nuovo risultato conserva anche la fase e gli eventuali contatori S3 già osservati per evitare diagnosi alla cieca.

## Effetti e limiti

È il controllo15, ancora da eseguire. Verifica esattamente lo STOP del14 e conserva tutti14scope precedenti. Riusa lo snapshot dei13container già raccolto: **non ripete la scansione13GET**. Effettua al massimo due nuovi inspect del SOLO MinIO, prima e dopo S3, arrivando al massimo a51GET cumulativi. Le altre12configurazioni non sono rinfrescate; RAM e spazio restituiti restano esplicitamente osservazioni del controllo14, non una fotografia corrente o atomica.

Riusa senza reinstallarlo il reader SDK statico SHA256 `430631fe4dfd1b844229637373ea176c2e84e81e1491919f4a25cc36c68359a8`. Installa soltanto nuova capsula e manifesto in `/usr/local/lib/ouf-storage-inventory-credentials-20261102`; scrive le nuove evidenze private in `/etc/ouf/deploy-snapshots/seaweedfs-inventory-credentials-20261102-v1`. Nessun file attivo, permesso, container o endpoint viene modificato.

Sono ammessi solo i riferimenti dichiarati nella configurazione del MinIO già vincolato: fino a4file segreti e1configurazione ambiente,4096byte per segreto/65536per configurazione,81920byte totali. I default assenti richiedono soltanto verifiche metadata; i file condivisi sono deduplicati. Valori soltanto in memoria e descrittori anonimi sigillati; nessun valore o hash individuale di credenziale è pubblicato. Il parsing di `config.env` è letterale, senza esecuzione o espansione shell. La precedenza è verificata prima dell'unica esecuzione S3; assenze e metadati vengono ricontrollati dopo.

S3 resta limitato a10000GET/HEAD,25000record di oggetti/versioni,300s di reader,64MiB di inventario privato. Controllo600s, sorveglianza esterna630s; obiettivo soft Go256MiB/GOMAXPROCS1. **Zero corpi oggetto letti, scritture S3, SQL, lifecycle container, deploy o migrazione.** Namespace/processo/socket/peer e identità MinIO sono vincolati; cambiamenti reali interrompono la prova. Per confrontare le osservazioni dei mount si usa la destinazione unica, mantenendo ogni valore; gli snapshot grezzi e i contratti/hash runtime congelati non vengono normalizzati o modificati.

## Qualifica

- Source `6447b0f64616170cfa79e2d0e471c5f860fb6ec9`, [CI41429406938](https://github.com/GioNob/ouf-deploy/actions/runs/41429406938):28test Python e12Java PASS. Due casi con Docker reale riproducono prima lo STOP del vecchio reader dopo13GET, poi completano1010record con due soli nuovi GET MinIO: default relativi assenti con valori ENV, e file relativi che prevalgono su ENV diversi. Caso file con ordine dei mount variato appositamente; modifiche di sorgente/diritti o destinazioni duplicate restano negate.
- Kernel, socket/peer Docker e S3 sono reali; storico14scope MODELLATO. Il ruolo MinIO della fixture è un waiter sintetico su rete host con server S3 reale separato: non è prova della configurazione VPS o della topologia finale. Nessuna nuova operazione target dopo la ricevuta14.
- Stesso SDK originale riscan zero findings. Root install della sola capsula PASS.26sorgenti: tutte24precedenti, comprese le23storiche, restano byte per byte uguali. Nuovo limite del solo loader294912byte, payload279063byte; nessun vecchio loader o budget viene modificato.
- [CI41430471681](https://github.com/GioNob/ouf-deploy/actions/runs/41430471681): verifica indipendente di18membri checksum, sorgenti/loader, firma Sigstore del produttore e workflow esatti su runner hosted, due file pubblicati confrontati byte per byte, entry/bootstrap e launcher esatti. Pubblicazione `28eb67064492c802ff96b884dbe42deefb5bec00`, launcher `727dfedc1ca41c91f402149f441141bb17ea0fa3`.
- [Ricevuta14](../evidence/seaweedfs-inventory-credential-stop-target-20261102.json), [riferimenti MinIO](../evidence/minio-credential-reference-20261102.json), [dossier](../evidence/seaweedfs-credential-continuation-qualified-20261102.json).

La migrazione dei dati non è avviata. SeaweedFS server resta non installato e il suo gate grezzo HELD per1UNKNOWN; le vulnerabilità del MinIO corrente non sono ancora rimosse. Tutti8gate e21AT del MiniPET restano OPEN. Teatri e la stessa Farmacie sono preservati; nessun nuovo upload o profiling.
