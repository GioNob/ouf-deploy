# SeaweedFS — compilazione offline del piano privato di copia

2 novembre 2026. L'inventario del controllo 16 è acquisito: 2 bucket, 120 record oggetto, 203743 byte logici. Non ripetere nessuno dei quattro vecchi comandi. La raccolta è completa per le API supportate, ma resta non ammessa al cutover: 2 risposte sulle funzionalità non supportate, writer/DB e sicurezza del candidato sono ancora da riconciliare.

Questa nuova operazione usa soltanto evidenze già raccolte. Non ripete l'inventario, non legge credenziali, non interroga Docker/S3 o database e non copia oggetti. Il download del codice immutabile avviene da GitHub; il compilatore opera offline. Non cambia permessi o proprietario dei file esistenti.

## Unico passaggio sul VPS

L'agente non ha accesso al manifest privato conservato sul VPS. Eseguire **una sola volta**, dallo stesso account operativo:

```bash
(
  set -eu
  umask 077
  offline_plan_dir="$(mktemp -d /tmp/ouf-offline-plan.XXXXXX)"
  trap 'rm -rf -- "$offline_plan_dir"' EXIT
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 --max-time 60 \
    https://raw.githubusercontent.com/GioNob/ouf-deploy/835ffb7626ea1c6c95c1a87b0c674dbb7d57494b/releases/seaweedfs-offline-plan-20261102/run-plan.py \
    -o "$offline_plan_dir/run-plan.py"
  printf '%s  %s\n' bbb8ea975dbfd9978b753a27c3e21e448bdcabedcae50443650fbeb1deb5ae2a "$offline_plan_dir/run-plan.py" | sha256sum --check --strict
  sudo /usr/bin/python3 -I -B -S "$offline_plan_dir/run-plan.py"
)
```

Restituire **solo il JSON finale**, anche se STOP. Non inviare il piano privato, l'inventario, nomi degli oggetti, policy o credenziali. Non rilanciare in caso di errore e non cancellare scope, installazioni o vecchi file.

Risultato atteso: `PRIVATE_PLAN_PREPARED_NOT_ADMITTED`, con conteggi delle funzionalità PRESENT/ABSENT/UNSUPPORTED, attributi degli oggetti, riferimenti storage dei ruoli già osservati e hash del nuovo piano privato. È una preparazione, non una migrazione o un'autorizzazione al cutover.

## Input, output e limiti

- Legge soltanto `capture.claim.json`, `result.json`, `s3/inventory.private.json` del controllo 16 e `host-baseline.private.json` del controllo 14. Verifica ricevuta esatta, SHA256 dell'inventario `43571bb43921f74adfa5974a0903acb54ee1eadecbc9d5d0d70539ce5cadba55`, hash dello snapshot host `49aaea817bff55ff5ab901f2f54784e97ac85b7e2bbf2ec489055bab94c790c4`, owner/mode/link e stabilità dei file metadata. Non apre il file password non-root né la configurazione dei descrittori delle credenziali.
- Nuova sola installazione root protetta in `/usr/local/lib/ouf-storage-offline-plan-20261102`; nuovo scope `/etc/ouf/deploy-snapshots/seaweedfs-offline-plan-20261102-v1`. Claim, `migration-plan.private.json` e risultato con modo 0600 nella directory 0700. Codice/manifesto installati in directory 0500 con file 0400. Nessuna reinstallazione del vecchio SDK.
- Il piano privato mantiene ogni bucket/key/versione, metadato, tag e attributo originale, insieme alle funzionalità e al contesto trattenuto. Tutte le voci restano `PLANNED_NOT_COPIED`, con zero copie/verifiche, `executionEnabled:false` e nessuna authority. Il motore di copia e ripresa non è ancora implementato.
- Verifica futura dei corpi richiesta per tutti i 120 oggetti, inclusi i 110 con hash dichiarato. I 10 senza hash conservano i metadati originali: nuovi hash di migrazione nel manifest, senza inventare metadati storici. SHA-256, tag e attributi devono essere verificati anche rileggendo la destinazione.
- Il riepilogo espone tipi e conteggi, mai bucket/key, endpoint, valori dei tag, policy, KMS o hash individuali. UNSUPPORTED resta distinto da ABSENT. I riferimenti nel contesto 14 non provano writer correnti o assenza di consumer esterni; capacità e RAM non vengono rilette. Nessuno snapshot atomico o coerenza DB dichiarati.
- Controllo 17 distinto, un solo tentativo, 4 file metadata, inventario 64 MiB/host 2 MiB/ricevuta 32 KiB/claim 4 KiB, piano massimo 64 MiB, 45 s di worker e sorveglianza 60 s, limite memoria 512 MiB. Zero nuovi GET Docker/S3, zero corpi, SQL, lifecycle container, deploy o migrazione. Dopo l'analisi i controlli diventano 17 e i GET Docker restano 52; non è un reset dei budget precedenti.

## Qualifica

Source `969e45ee3bdbcb426aeaca2b93872b46c6932445`, [CI 41488131645](https://github.com/GioNob/ouf-deploy/actions/runs/41488131645): 33 test Python senza skip, filesystem root reale in un namespace rete isolato, installazione dei byte esatti e source inspection. I fixture hash/ricevuta/contesto sono MODELLATI e i dati sintetici; non è osservazione del VPS. Due sorgenti nel compilatore; tutte le 28 precedenti preservate byte per byte. Non è cambiato alcun componente attivo.

Sono provati: 120 record con 10 hash mancanti e 120 verifiche ancora richieste; sintesi senza dati privati; metadati/tag/retention/cifratura preservati nel piano privato; versioni/marker senza inventare ordine di copia; namespace problematico ancora HELD; file, ricevute e hash alterati negati; symlink/FIFO/hardlink/file non privati negati; nessuna sovrascrittura dell'output; file relativo alle credenziali non aperto. Compiler senza import di rete/subprocess o librerie esterne.

Il primo CI 41487826809 ha superato i test ma fallito nel salvataggio del bundle per permessi della directory root. Corretto il solo passaggio di raccolta della firma, poi ripetuta l'intera qualifica. Non viene presentato come successo completo.

[CI indipendente 41488523185](https://github.com/GioNob/ouf-deploy/actions/runs/41488523185) PASS: 6 membri checksum, ricostruzione esatta del compilatore dalle 2 sorgenti e dalla ricevuta, 28 sorgenti precedenti invariate, firma Sigstore del workflow/produttore/ref esatti su runner hosted, 2 file pubblicati/28089 byte confrontati byte per byte e launcher verificato. Pubblicazione `a8f767edd7e9cd8b043f4092c73279b1b1c2c052`, launcher `835ffb7626ea1c6c95c1a87b0c674dbb7d57494b`, SHA256 `bbb8ea975dbfd9978b753a27c3e21e448bdcabedcae50443650fbeb1deb5ae2a`. [Dossier e archivi originali](../evidence/seaweedfs-offline-plan-qualified-20261102.json). Nessuna esecuzione del controllo 17 sul VPS.

[Ricevuta 16](../evidence/seaweedfs-private-baseline-target-20261102.json) · [Valutazione](OUF_SEAWEEDFS_BASELINE_ASSESSMENT_20261102.md) · [MiniPET](OUF_MINIO_SEAWEEDFS_MINIPET_v1_0_20261102.md)

Tutti gli 8 gate/21 AT e M2 restano aperti. Server SeaweedFS raw HELD per 1 UNKNOWN, MinIO ancora in uso e vulnerabile. Nessuna nuova operazione VPS dopo la raccolta 16; nessuna copia, merge o runtime grant. Teatri/M1 e la stessa Farmacie sono preservati.
