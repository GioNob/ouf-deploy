# Cold recovery storage — risultato hosted circoscritto

La [CI 41696541366](https://github.com/GioNob/ouf-deploy/actions/runs/41696541366)
sul commit `041992eacd851d277cd049f03b9fe68a393e6df4` ha completato il drill
storage e i 15 test del runner. **Restore sintetico PASS; compatibilità MIME
octet-stream FAIL.** Non chiude G2, G3 o un test di accettazione target.

L'artifact `13262411150`, 30.548 byte e 31 membri, è stato scaricato e verificato
indipendentemente: SHA256
`73bcbb68624d16d044b106aa9c2a86bdfdd983d962e07f68e8d10f11fa9b843e`.
Tutti i 30 file coperti da `SHA256SUMS` coincidono con i checksum; il manifest
ha SHA256 `69a249518bcc159eb035f9a28973d4da4d6f52b30047f0acf715711012ef5a88`.
La CI ha pubblicato l'[attestazione 63247763](https://github.com/GioNob/ouf-deploy/attestations/63247763):
il readback non ne ha verificato nuovamente la firma. Retention temporanea
fino al 2027-02-01, non custodia durevole.

I **31 membri UTF-8 originali** sono inoltre preparati per conservazione nel
repository sotto
[`evidence/seaweedfs-452-cold-recovery-hosted-20261103/`](../evidence/seaweedfs-452-cold-recovery-hosted-20261103/).
Nomi e byte coincidono integralmente con l'artifact: nessuna riscrittura,
redazione o esclusione. La ricevuta elenca percorso, dimensione e SHA256 di
ogni file, compreso il manifest originale; i 30 checksum del manifest sono
stati verificati anche sui file materializzati. Non sono presenti chiavi
private, credenziali segrete o environment container popolati. I warning
filer citano genericamente il Bearer token, senza contenerne il valore.
Non vengono aggiunti ZIP, corpi GET o backup dati, assenti dall'artifact.
La conservazione dei log/prove nel repository non stabilisce custodia durevole
dell'immagine candidata né del backup operativo. Lo stato della ricevuta è
`PREPARED_FOR_REPOSITORY_PUBLICATION` fino alla pubblicazione del parent.

## Prove verificate

Il drill usa esclusivamente il candidato OCI a **15 patch**, manifest
`sha256:1bb1ff9d7a42e98f5c6a90903644ed5e18e83a89d76bccbc4d16ce6b8027c6b4`
e binario `85fa52c68a783f3cf4d54ae6064e7b46d022982c1bef4460616dd76cdc609033`.
Non si trasferisce questa prova a immagini successive ricompilate.

- Cinque oggetti sintetici, 8.388.702 byte: quattro fixture recovery e un probe
  MIME distinto. Corpo vuoto, Unicode/escaping, 8 MiB, overwrite e delete.
- LIST di due pagine prima/dopo; ricevute oggetti e probe uguali, escluso il
  nome dell'azione. Il runner ha confrontato i corpi GET con i byte fixture e
  i metadati hash GET/HEAD. Il readback ha ricalcolato gli hash delle fixture;
  i corpi HTTP grezzi non sono inclusi nell'artifact.
- Backup di 110 file, 8.417.419 byte: master 4, volume 65, filer 40, config 1.
  Il processo hosted ha confrontato gli inventari SHA256 di sorgente ferma,
  copia e nuova radice; l'artifact conserva inventario e checksum, non i file
  backup. Non si dichiara una seconda verifica locale dei loro byte.
- Otto container con identità distinte, quattro ruoli in ogni generazione;
  UID/GID 65532, root read-only, tutte le capability rimosse, no-new-privileges,
  512 MiB, una CPU e 128 processi per container, nessuna porta pubblicata.
- Inspect e route attestano namespace Docker `none` condiviso solo dai quattro
  ruoli della generazione e route esclusivamente `lo`. I nuovi container
  montano soltanto `/restored/<ruolo>` e `/restored/config` read-only.
- Tutti gli otto servizi: ExitCode 0, nessun OOM. L'ultimo originale si ferma
  alle 18:44:36.744156071Z; il primo ripristinato parte alle 18:44:37.028974556Z.
  Il codice eseguito richiede stop/rm e spostamento degli originali fuori dai
  mount; non è stata conservata una ricevuta `docker inspect` dopo la rimozione.

La durata osservata di 5,844 secondi appartiene a questo piccolo test hosted.
Non prova RTO, DB RPO ≤15 minuti, core RTO ≤4 ore o prestazioni rappresentative.

## Difetto MIME mantenuto aperto

Il probe `ouf-recovery-mime-fixture/octet-stream.txt`, scritto con
`application/octet-stream`, restituisce **`text/plain; charset=utf-8` sia su
GET sia su HEAD**, prima e dopo il restore. Entrambi i findings restano `FAIL`.
Il byte/hash del probe è invece corretto e identico; la conservazione del
difetto dopo restore non costituisce un PASS di compatibilità S3.

Le quattro fixture principali preservano rigorosamente il MIME esplicito
`application/x-ouf-recovery-fixture` su entrambi i metodi. La ricevuta finale
conserva `s3MetadataCompatibilityQualified=false` e `g2Closed=false`.
I due precedenti run negativi restano parte della cronologia delle prove.

## Limiti e stato delle autorità

La [ricevuta completa](../evidence/seaweedfs-452-cold-recovery-hosted-20261103.json)
separa osservazioni, verifiche locali e inferenze dal controllo di flusso.
Restano non provati PostgreSQL live coordinato, WAL/PITR, crash/perdita host,
TLS/rotazione in questo drill, carico rappresentativo e contratto completo
della fondazione G3. Il profilo dichiarativo non è materializzato letteralmente.

La foundation separata sullo stesso head ha eseguito 25 test hosted PASS
([run 41696541354](https://github.com/GioNob/ouf-deploy/actions/runs/41696541354));
questa informazione è stata verificata nei log, senza scaricare il suo artifact
in questo readback. Le librerie fixture non provano PostgreSQL live.

Restano 0/8 gate chiusi, 0/21 AT, 0/120 oggetti reali, zero operazioni target,
nessuna autorità runtime o release. MinIO attivo, Scope17/52 Engine GET,
Teatri/M1 8/8 tecniche e 6/6 funzionali e Farmacie 61/10 OPEN/STRING invariati.
