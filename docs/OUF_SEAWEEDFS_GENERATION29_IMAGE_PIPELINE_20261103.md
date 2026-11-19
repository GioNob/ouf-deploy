# SeaweedFS 4.52 — pipeline immagine della generazione 29

**31 test locali PASS e packaging reale deterministico PASS; qualifica hosted
PENDING, NOT_ADMITTED.** La [patch MIME](OUF_SEAWEEDFS_CONTENT_TYPE_FIX_20261103.md)
cambia il binario: lock, artefatti e prove della coorte 15 restano immutati e
non qualificano automaticamente la 29.

Il [manifest build](../releases/seaweedfs-452-generation29-build-manifest-20261103.json)
fissa ordine e SHA256 delle 29 patch, toolchain, root lockfile, grafo,
inventario binario ed eseguibile. Non è un candidate lock di consegna e non
contiene ID di artefatti ancora inesistenti.

| Identità osservata localmente | Valore |
|---|---|
| Upstream | `984eac6a790be89e2a11de175a7413e1e3e32dd3` |
| Patch 29 SHA256 | `54982d752afc77e680cfa75b5ada1febc6680709bdb46f8d284f2090448849bc` |
| Git tree dopo 29 patch | `574ad42543851ffe58cc025e14b1011609ff83de` |
| Binario SHA256 | `a0c74718e584942f58c02214f6b3abe46b71cd47d4995b8da3aa002dcdadeef7` |
| Grafo 1811 SHA256 | `cb2536b10d73bc04e587c257a75a622c6b3cf855f1d232f26dba246b43b03f4a` |
| Inventario 262 moduli SHA256 | `dfedc0d9f4b48e3886dea9c072c329bbe2b297474d402a888a3d3ae0d2a5ebd3` |
| Manifest OCI locale | `sha256:f8679022d5baff88c33285b501317510ac4d1713cc4901f99999a1df937b18bd` |
| Config/image ID locale | `sha256:77fca36f4b76b0a35b84c3ec4391f129d191e0ef21e04a04798ff81bef57fbbd` |
| Layer locale | `sha256:71d9c727671a69b5211dcb91a1c1c32d18b70b2455a81adbc7043ded18e72fb4` |
| Docker archive SHA256 locale | `5445f54bb1aab0b3ad5e8f4aa8c759959b1e7554dda7330cc426de6be73d02c7` |

Il [workflow](../.github/workflows/storage-452-generation29-image.yml) ha
quattro job: test di confine; build e regressioni; packaging/scan/SPDX/
attestazione; readback indipendente. Trigger push limitato ai file della 29
e workflow_dispatch, concorrenza dedicata, cancel-in-progress:false. Nessuna
release, push registry o operazione target.

Il build applica la stessa lista committed usata per sigillare i sorgenti,
verificando SHA e `git apply --check`. Fissa il tree mediante indice Git,
rifiuta modifiche working-tree inattese, controlla tidy fixed point e root
module graph senza SDKv1, manager deprecato, elasticv7 e rclone. La suite
comprende i 20 package precedenti più `weed/filer`: conteggi osservati
6156 PASS/5 skip e presenza esplicita dei due nuovi test MIME. Ripete fixture
IAM root/nested e compile Kafka; i profili opzionali esclusi devono fallire
esplicitamente. Build Go1.27.3, CGO0, linux/amd64, trimpath, no tag: binario,
grafo e inventario devono coincidere con i pin locali.

Il packaging riusa `runtime_image.ImageProfile` e lifecycle immutati, con
qualifier e reader separati dalla 15. L'immagine scratch nonroot contiene
soltanto binario e licenza upstream ed è ricostruita deterministicamente.
Il job produce un nuovo scan Trivy0.70.0 completo, inclusi UNKNOWN e unfixed,
senza ignore; converte quello stesso scan in SPDX. Nessun risultato scan15
è copiato o riclassificato implicitamente per la 29.

Controlli aggiunti:

- Scan esattamente uguale ai 262 moduli del build-info più main e stdlib:
  omissioni, versioni diverse e duplicati negati.
- SPDX con lo stesso multinsieme di 264 componenti versionati e soli due
  nodi descrittivi APPLICATION/CONTAINER legati al binario e allo scan.
- Build-info, lockfile, module graph, patched tree e manifest legati per
  hash; nessun modfile alternativo o source glob non applicato.
- HIGH/CRITICAL/UNKNOWN irrisolti bloccano producer e readback CLI; il reader
  restituisce 2 senza creare output qualificato. L'assessment negativo resta
  nell'artefatto originale.
- Reader bounded: 22 membri ZIP, 20 checksum e 37 sorgenti esatti; rifiuto di
  path ambigui, traversal, duplicati, byte alterati e profili precedenti.

Il readback usa un runner separato, l'ID/digest ZIP effettivo del producer
nella stessa run, riproduzione OCI/assessment e verifica bundle Sigstore con
gh2.97.0 pinned, signer-workflow29, source commit/ref esatti e rifiuto dei
runner self-hosted. La sola funzione Python non asserisce verifica della
firma. Artefatto build conservato 3 giorni, evidence 90 giorni; custody
durevole OPEN. Download, test e job hanno budget espliciti e conservano
evidence del fallimento senza retry mutativi o nuova authority.

Qualifica locale: 12 test packaging precedenti +19 nuovi =31 PASS, ripetuti
da review indipendente. Copertura di round-trip ZIP/assessment, reject
profilo15, source tamper, grafo/moduli/tree, scan/SPDX incompleti o eccedenti,
severità irrisolte e CLI nonzero. YAML 4 job, 14 blocchi shell e 3 blocchi
Python validati. Parser JSONL esercitato sui log reali 6156 PASS mediante
stream, preservando i separatori Unicode nei payload. Packaging ripetuto
sul binario reale produce gli stessi digest OCI.

Per il solo smoke di packaging locale, module graph/list28 hosted sono
riusati previa uguaglianza esatta go.mod/go.sum29; non si rivendica un nuovo
`go mod graph` locale. Il workflow hosted li rigenera. Docker, scan fresco,
SPDX nuovo, firma e readback hosted29 restano **PENDING**.
[Ricevuta locale](../evidence/seaweedfs-generation29-image-local-20261103.json)
e [log test](../evidence/seaweedfs-generation29-image-local-tests-20261103.txt).

Dopo il PASS hosted servono nuovi binding licenze, candidate lock29,
coorte29 e prove cold-recovery/identity sulla 29. Octet-stream deve passare
prima e dopo restore; nessuna prova storica viene rinominata. Review
licenze, custody, autorità HUMAN/THS e accettazione restano separate.
Target 0, gate/AT chiusi 0, nessuna admission. Scope consumati e risultati
Teatri/Farmacie invariati.
