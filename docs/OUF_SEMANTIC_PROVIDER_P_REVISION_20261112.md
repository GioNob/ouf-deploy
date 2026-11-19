# Revisione governata del profilo P — 12 novembre 2026

## Contratto

`prepare-semantic-provider-installation.py` mantiene lo schema
`ouf.semantic-provider-installation.v1` e la serializzazione canonica esistente
(JSON ordinato e compatto, un LF finale). Pubblicazione iniziale e revisione
richiedono tre argomenti aggiuntivi, senza default:

| Argomento | Verifica | Campo P |
| --- | --- | --- |
| `--guard-service-unit` | Nome `.service` senza slash; systemd `LoadState=loaded`, `Type=oneshot`; Docker in `RequiredBy` e `Before` | `guardServiceUnit` |
| `--guard-service-file` | Path assoluto uguale al `FragmentPath` del guard | `paths.guard.unitFiles.guardService` |
| `--docker-drop-in-file` | Path assoluto presente nei `DropInPaths` di Docker; guard in `Requires` e `After` | `paths.guard.unitFiles.dockerDropIn` |

Si usa il binario systemctl verificato dal lettore. Entrambi i file devono
essere regolari, root:root 0600, con un solo hardlink, senza symlink e con
antenati root non scrivibili da gruppo/altri. Gli hash dei due file appartengono
solo agli `inputHashes` che determinano `planSha256`, non al profilo (D-008).
Gli altri drop-in, inclusi i `99-*`, non sono letti né confrontati (D-013).
Non vengono richiesti `ActiveState`, `UnitFileState` o l'assenza di altri drop-in.

Senza `--revise-from-sha256` la destinazione deve essere assente. Con questo
argomento deve esistere e superare custodia e SHA-256 dei byte esatti, inclusi
spazi e terminatori, altrimenti `REVISION_BASE_PROFILE_UNPROVEN`.
La revisione non crea directory installative mancanti.

Il piano espone `previousProfileSha256`, `previousProfileIdentity`
(`dev`, `inode`, `size`, `mtime_ns`) e `profileDiff`. Il diff è una lista ordinata
di oggetti `{"path": <JSON Pointer>, "change": "added"|"removed"|"changed"}`;
le aggiunte di contenitori sono espanse fino alle foglie. Sono ammesse
**esattamente** queste tre aggiunte:

```text
/guardServiceUnit
/paths/guard/unitFiles/dockerDropIn
/paths/guard/unitFiles/guardService
```

Qualsiasi altro delta, anche un sottoinsieme delle tre aggiunte o un profilo
già revisionato, produce `PROFILE_REVISION_UNEXPECTED_DELTA`: il report contiene
in `profileDiff` soltanto i percorsi diversi, senza i valori. Hash precedente,
identità e diff partecipano tutti al digest del piano.

Apply ripete l'osservazione e confronta `--plan-sha256` prima di scrivere
(`PLAN_DIGEST_CHANGED` se differisce). Riapre poi la base e ne ricontrolla
custodia, hash e identità. Crea esclusivamente con `os.link`:

```text
semantic-provider.json.superseded-<previousProfileSha256>
```

La copia deve essere assente (`REVISION_SUPERSEDED_ALREADY_EXISTS` altrimenti).
Il link esclusivo impedisce due revisioni concorrenti della stessa base.
Seguono verifica del link, fsync della directory, temporaneo `O_EXCL` nella
stessa directory, owner/mode root:root 0600, scrittura e fsync del file,
ulteriore confronto della base, `os.rename` atomico, fsync della directory e
readback di contenuto, hash e custodia. Durante la conservazione è previsto
`nlink=2`; dopo il rename entrambi i file devono tornare a `nlink=1`.
La directory è sotto custodia root: nessuna procedura concorrente deve mutare
il profilo durante apply. Il controllo prima del rename non è un CAS kernel
contro scrittori root estranei a questo protocollo.

Il successo è `SEMANTIC_PROVIDER_INSTALLATION_PROFILE_REVISED`, con
`previousProfileSha256`, `profileSha256`, `supersededFile`, `privateKeysRead: 0`.
Non vengono aperte chiavi private, emesse firme o mutate unità/container/reti.
Questa revisione non installa B1 e non attesta readiness o E2E.

## Sequenza umana tramite launcher

Prima dell'esecuzione, Claude deve fissare nel launcher commit e SHA del
controller revisionato, dopo review e commit D-001. Il launcher presente in
questa task conserva il pin precedente e **non consegna ancora questo codice**.
I comandi seguenti sono istruzioni per l'operatore, non operazioni eseguite
durante questa task. Il launcher usa rete per consegnare il sorgente fissato;
qui non è stato invocato.

In una shell Bash compilare tutti i valori `${...:?}` con i binding della
pubblicazione corrente. Gli hash di input sono forniti/verificati dall'umano;
non ricavarne nuovi per far passare un drift. Usare gli stessi argomenti in
plan e apply. Per l'attivazione socket usare `systemd-socket`, il vero nome
`.socket` e la proprietà prevista; per `daemon`, socket-unit e service-unit
devono coincidere. Percorsi e altri nomi non sono dedotti dagli esempi.

```bash
common=(
  --installation-ref "${INSTALLATION_REF:?}"
  --installation-root "${INSTALLATION_ROOT:?}"
  --a-root "${A_ROOT:?}"
  --a-plan-sha256 "${A_PLAN_SHA256:?}"
  --guard-pointer "${GUARD_POINTER:?}"
  --guard-service-unit ouf-semantic-boot-guard.service
  --guard-service-file /etc/systemd/system/ouf-semantic-boot-guard.service
  --docker-drop-in-file /etc/systemd/system/docker.service.d/90-ouf-semantic-boot-guard.conf
  --docker-socket "${DOCKER_SOCKET:?}"
  --docker-socket-activation "${DOCKER_SOCKET_ACTIVATION:?}"
  --docker-socket-unit "${DOCKER_SOCKET_UNIT:?}"
  --docker-service-unit "${DOCKER_SERVICE_UNIT:?}"
  --docker-socket-owner "${DOCKER_SOCKET_OWNER:?}"
  --docker-socket-group "${DOCKER_SOCKET_GROUP:?}"
  --docker-socket-mode "${DOCKER_SOCKET_MODE:?}"
  --dockerd "${DOCKERD:?}"
  --generation-receipt "${GENERATION_RECEIPT:?}"
  --generation-receipt-sha256 "${GENERATION_RECEIPT_SHA256:?}"
  --authority-profile "${AUTHORITY_PROFILE:?}"
  --authority-sha256 "${AUTHORITY_SHA256:?}"
  --trust-policy "${TRUST_POLICY:?}"
  --trust-policy-sha256 "${TRUST_POLICY_SHA256:?}"
  --revise-from-sha256 b956466521ca1f1cc887eeeaa321d66414a26f8c76e2d96eabc7fd4d84a74d5f
)
bash scripts/deliver-semantic-provider-installation.sh --plan "${common[@]}"
```

Verificare `PLAN_READY`, identità/hash della base e le sole tre aggiunte;
conservare il report in posizione privata root. Il valore di base sopra è quello
fornito nel mandato (4335 byte), non una nuova attestazione del VPS. Una base
diversa richiede riconciliazione, non un hash sostitutivo scelto alla cieca.
Dopo review del piano, impostare `APPROVED_PLAN_SHA256` al suo esatto digest:

```bash
bash scripts/deliver-semantic-provider-installation.sh \
  --apply --plan-sha256 "${APPROVED_PLAN_SHA256:?}" "${common[@]}"
```

Per una nuova pubblicazione omettere soltanto `--revise-from-sha256` e il suo
valore dalla lista: i tre argomenti guard restano obbligatori. La destinazione
deve essere assente e il successo resta
`SEMANTIC_PROVIDER_INSTALLATION_PROFILE_PUBLISHED`.

## Parziali e ripristino manuale

Nessun rollback automatico. In apply `revisionOutcome` riporta:

| Campo | Fatto attestato |
| --- | --- |
| `supersededFile`, `supersededLinked` | Percorso previsto; se il link è stato creato da questa invocazione |
| `temporaryFile` | Temporaneo ancora presente, oppure `null` dopo cleanup/rename |
| `renamed` | Il rename sulla destinazione è riuscito |
| `directorySynced` | È riuscito il fsync della directory **successivo al rename** |
| `readbackVerified` | Nuovo file e copia precedente hanno superato il readback finale |

Gli errori OS riportano tipo/errno, senza stderr o valori privati. Un errore
dopo link conserva sempre la copia; prima del rename base e copia possono
essere ancora lo stesso inode con due link. Un errore dopo rename conserva il
nuovo file: `HELD` non implica che sia ancora installato il precedente. Un
temporaneo creato viene rimosso se il cleanup riesce; se fallisce, il percorso
rimane nel report. Dopo un crash senza report occorre osservare i file prima
di qualsiasi decisione. Non ripetere apply e non cancellare la copia per
sbloccare il controller.

Ripristino solo manuale, dopo riconciliazione e decisione dell'owner:

1. Fermare gli scrittori concorrenti del profilo e sospendere il consumo da B1/B2.
   Leggere report, `stat` e SHA-256 dei byte esatti di destinazione, copia e
   eventuale temporaneo. Verificare root:root 0600, file regolari senza symlink,
   antenati sotto custodia e hash della copia uguale a `previousProfileSha256`.
   Riconciliare esplicitamente `nlink=2` se il rename non è avvenuto. Un terzo
   contenuto non riconosciuto richiede arresto e review.
2. Conservare separatamente contenuto e metadata della destinazione corrente
   con nome nuovo, senza sovrascrivere alcuna evidenza esistente. Non modificare
   in-place il profilo né fare chmod/chown sui file collegati per simulare custodia.
3. Copiare i byte della `superseded-*` in un **nuovo inode** temporaneo nella
   stessa directory (`O_CREAT|O_EXCL|O_NOFOLLOW`, root:root 0600). Verificarne
   hash e custodia e fare flush/fsync. Non rinominare direttamente il backup:
   con due hardlink allo stesso inode il rename potrebbe essere un no-op.
4. Ricontrollare che destinazione e copia coincidano con gli hash/identità
   appena riconciliati; quindi rinominare atomicamente il temporaneo sulla
   destinazione e fare fsync della directory. Rileggere il profilo ripristinato:
   hash precedente, root:root 0600 e un solo link. Conservare copia, evidenze e
   ricevuta del ripristino manuale. Nessuna ripresa automatica B1/B2.

## Verifica del codice

La suite comprende fixture systemd e prove filesystem root sotto `/run`,
inclusi fault dopo link/rename. Il comando CI già previsto è:

```bash
sudo -n env OUF_P_NATIVE=1 /usr/bin/python3 -I -B -m unittest discover -s tests -p test_semantic_provider_installation.py -v
```

Le prove native Docker esistenti usano un listener sintetico e unità systemd
temporanee nel runner; non attestano Docker o stato live del VPS.
