> **CONSUMATO — NON ESEGUIRE QUESTO VECCHIO BLOCCO.** L'operatore ha restituito STOP_RECONCILE/BOUNDED_NONEMPTY_OUF_CONTAINER_SET_REQUIRED: scope13 consumato e36GET cumulativi. Usare esclusivamente la [nuova consegna correttiva qualificata](OUF_SEAWEEDFS_INVENTORY_RECONCILIATION_20261102.md), scope14 distinto; non cancellare o rilanciare nulla del vecchio controllo. Il contenuto seguente è storico.

# SeaweedFS — unica rilevazione privata sul VPS

2 novembre 2026. MiniPET OUF-MP-STORAGE-SW, SW-WP0/SW-G0. Consegna preparata e verificata; **non ancora eseguita sul target**. L'agente dispone di GitHub e OUF MCP, ma non di una shell VPS o di una funzione MCP per inventariare Docker/S3. Questo è l'intervento operativo necessario per proseguire.

## Cosa eseguire

Sul VPS OUF, come `ouf-admin`, eseguire una sola volta il blocco seguente. Sono necessari Python3 Linux AMD64 con memfd, `/usr/bin/nsenter`, curl e sudo già presenti; non installare pacchetti per aggirare uno STOP.

```bash
(
  set -eu
  umask 077
  inventory_task_dir="$(mktemp -d /tmp/ouf-storage-inventory.XXXXXX)"
  trap 'rm -rf -- "$inventory_task_dir"' EXIT
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 --max-time 60 \
    https://raw.githubusercontent.com/GioNob/ouf-deploy/4eb2505d77b2ced8df77b52ab3ee12df52642ffa/releases/seaweedfs-inventory-delivery-20261102/run-inventory.py \
    -o "$inventory_task_dir/run-inventory.py"
  printf '%s  %s\n' 4c0d2bd971b661a7352b480fbe14d48ea957db7835caddf14ad7bd88795221fd "$inventory_task_dir/run-inventory.py" | sha256sum --check --strict
  sudo /usr/bin/python3 -I -B -S "$inventory_task_dir/run-inventory.py"
)
```

Restituire all'agente **solo il JSON finale**, sia in caso di successo sia di esito parziale/STOP. Non inviare l'inventario privato, file di configurazione, variabili d'ambiente, nomi degli oggetti o credenziali. Non cancellare scope/installazione, non ripetere il comando e non rilanciare i precedenti controlli M2. Un esito parziale conserva le evidenze disponibili e richiede riconciliazione sul risultato, non un retry automatico.

## Effetti e limiti

La consegna scarica circa4MB pubblici con hash fissati e installa esclusivamente il reader statico, la capsula e il manifesto in `/usr/local/lib/ouf-storage-inventory-20261102`. Crea le nuove evidenze private root-only in `/etc/ouf/deploy-snapshots/seaweedfs-inventory-20261102-v1`; nessuna credenziale è copiata su disco. Le due credenziali MinIO già esistenti sono passate al reader tramite descrittori anonimi sigillati, dopo verifica dell'immagine nativa e del processo.

È un nuovo controllo monouso, il13º dopo i12 precedenti/35GET cumulativi. Legge al massimo64container OUF con65nuovi GET Docker; legge soltanto metadati S3, versioni/delete marker, tag, configurazioni bucket e parti di multipart incompleti. Massimi:10000richieste GET/HEAD,25000record/parti,300s di reader S3,64MiB di inventario privato; Go256MiB/GOMAXPROCS1. Il controllo completo ha600s, download fino240s e sorveglianza esterna630s per la fase reader. Richieste negate o limiti raggiunti producono STOP o parziale, senza dichiarare completezza.

**Zero corpi oggetto letti, scritture S3, SQL, lifecycle container, deploy o migrazione.** Le scritture filesystem sono l'installazione del reader e le nuove evidenze private. Nessun vecchio scope viene azzerato o rinnovato. Il wrapper verifica gli hash del checkpoint origin ca16/8cf e i12scope precedenti; root14cea è l'identità Docker nativa attesa di MinIO, non il config69b2.

L'esito non prova una fotografia atomica dei dati, l'assenza di consumer esterni o la completezza di feature dichiarate UNSUPPORTED. Serve per dimensionare e qualificare i passi successivi. Nessuna ammissione release o autorità runtime è prodotta.

## Evidenze della consegna

- Produttore: source `6cddeee707b67bd27568aa7a3890e28ebecf274f`, [CI41391421536](https://github.com/GioNob/ouf-deploy/actions/runs/41391421536).24test Python,7Go,11Java di contratto e1di recovery PASS; inventario1010record sintetici; credenziali sigillate e diniego con esito parziale PASS. Docker e storico del test nativo sono MODELLATI; namespace kernel e S3 sono reali. Non è osservazione del VPS.
- Verifica indipendente: [CI41391892653](https://github.com/GioNob/ouf-deploy/actions/runs/41391892653), checksum di tutti50membri,4390Gitblob/mode upstream, firma Sigstore del workflow/source esatti su runner hosted;8test bootstrap e installazione root dei byte esatti PASS.
- Pubblicazione immutabile `0f446ddb4a1ed19b2c139bb496d06f84edb6062a`:19parti, capsula chiusa24sorgenti,23storiche invariate. [CI41392147761](https://github.com/GioNob/ouf-deploy/actions/runs/41392147761) ha confrontato tutti21file/3.951.279byte pubblicati con l'artefatto attestato e verificato il launcher esatto.
- [Dossier](../evidence/seaweedfs-laboratory-byte-readback-20261102.json). Reader SHA256 `430631fe4dfd1b844229637373ea176c2e84e81e1491919f4a25cc36c68359a8`, scan zero findings. Il server SeaweedFS resta separato: rawgate HELD per1UNKNOWN, nessuna ammissione produzione.

## Dopo il risultato

L'agente analizza il riepilogo minimizzato e gli eventuali blocker. Poi qualifica layout/capacità, identità/policy, backup dati+filer, packaging e procedure di copia e verifica integrale. L'inventario da solo non chiude SW-G0 o gli altri gate. Nessuna copia dati o commutazione endpoint è inclusa in questo comando.
