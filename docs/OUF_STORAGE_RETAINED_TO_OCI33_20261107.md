# Dalla copia storica a SeaweedFS OCI33

La [ricevuta MinIO](../evidence/storage-historical-minio-restored-operator-20261107.json) conferma 120 corpi da due bucket, 203.743 byte e zero marker. Il [ripristino PostgreSQL](../evidence/storage-historical-postgres-restored-operator-20261107.json) conferma 7 database e 7 letture campione. La copertura degli eventi e la consistenza della generazione comune restano aperte. MiniPET **39,78%**, zero corpi migrati.

## Primo passo VPS

Verificare se è già presente l'esatta immagine OCI33. Il comando è una lettura Docker; non carica immagini e non avvia servizi.

```bash
sudo docker image inspect --format '{{.Id}}' sha256:3b972a3ca20f98b73554f0772a2df4f1a5ef4441298299a443f0e605f10ec9b6
```

Se manca, il candidato esatto è l'[artefatto Actions OCI33](https://github.com/GioNob/ouf-deploy/actions/runs/41782068047/artifacts/13299559178), 174.223.468 byte, SHA-256 `4175ae9f0f5e4f6e71729084e0bfc2d9e8a2d39d3c5908dc51e5c4c695bd6121`, prodotto da `1a11295ad502a77dce76157423577b9766106bfe`. L'archivio Docker interno ha SHA-256 `5683622c9924be6192babb5a49588c7cb1ec53e5bf9257ed48225aa61ed26b12`. Il candidato va verificato prima di un eventuale caricamento. Il controllo immagine è distinto dall'ammissione al deploy.

## Perimetro del confronto

Riutilizzare la copia MinIO storica e l'inventario privato `historical-minio-restore-20261107-v1/s3-proof-v2/s3-bodies.private.json` con SHA-256 `c54d67b9ec8448e884a296c37e588845e3d128283af14e92c29b9bb3e3a8281f`. I nomi e i corpi restano sul VPS. L'ambiente SeaweedFS di rehearsal dovrà avere storage vuoto separato e rete isolata. Riprendere il [core di copia qualificato](OUF_SEAWEEDFS_COPY_CORE_20261102.md) e il [rehearsal OCI33](../evidence/storage-minio33-rehearsal-qualified-20261105.json), verificando sul materiale reale anche il profilo applicabile per versioni, metadati e tag. I conteggi osservati non dimostrano da soli la parità di identità e contenuti tra due inventari. La copia e la rilettura SeaweedFS restano da eseguire.
