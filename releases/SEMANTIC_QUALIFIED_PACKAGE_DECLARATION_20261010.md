# Semantic: dichiarazione del pacchetto qualificato — 10 ottobre 2026

La receipt R10 ricevuta alle 22:35:54 CEST dichiara due flussi attivi e due rinnovi. [Receipt integrale](../evidence/finite-r10-active-renewed-target-20261010.json). R10 è consumata: non ripetere attivazione, reset claim o riavvio del worker. Questa osservazione non dimostra liveness continua o salute applicativa.

## Target receipt — compilation completed

Output received **10 October 2026 22:47:55 CEST** reports `QUALIFIED_PACKAGE_DECLARED_NOT_APPLY_READY`, exit0. [Complete operator-reported receipt](../evidence/semantic-qualified-package-declaration-target-20261010.json). Snapshot `/etc/ouf/deploy-snapshots/semantic-qualified-package-declaration-v7nhhm3o`, private declaration hash `78dc04694daf0dd8685b74eedddd64365c600c2303ac3fbaa47313bdb85b5d59`, candidate config hash `31d2dbbd8a286ac4123148f293e5732fc18f28aeccc28eef3ea061aca5d37193`.

The new declaration now binds Semantic e826bd… with exact qualified source/ZIP. HostConfig hash aee587… and original creation-frame hash ff9159… match the previous protected declaration. Application settings are retained and runtime defaults come from the new image. No R10 touch, lease lock, container lifecycle, image import, database/firewall mutation or key-file access was reported.

**Compilation is complete; the command in the historical delivery section below need not be rerun.** Production apply readiness, fresh runtime custody, complete realized OCI and application cutover remain unproven. Continue with coordinated R10-preserving cutover composition and the closures listed below. The reported timestamp is message receipt time, not independently verified execution time.

## Disallineamento trovato (risolto dalla compilazione target)

La [dichiarazione runtime protetta precedente](../evidence/replacement-runtime-declaration-target-20261010.json) riguarda l'immagine Semantic `sha256:b1a7956a673f88b5ee65d174c2eda7b9e448153e101348c06fdd53c0640e700b`. Il [pacchetto con publisher verificato sul target](../evidence/file-loop-provenance-trust-r9-target-20261010.json) riguarda invece `sha256:e826bd9769a72e930e356f72c1c244007f9a34d065db94ca8113b064d10d8b85`, sorgente `622614b0040cf11be2f6c7e3568733a488ca4ca8`. Il nome storico della receipt include R9: le sue prove su publisher e trust restano distinte dalla vecchia osservazione R9 fallita.

Il nuovo compilatore lega la dichiarazione ai byte dello ZIP qualificato già presenti in `/home/oufadmin/ouf-file-loop-offline-stage.LMawhAuO/semantic.zip`. Verifica SHA256 dello ZIP e del config Docker-save che definisce l'ImageId; verifica sorgente, linux/amd64 e utente10001:10001. Non ricostruisce né importa l'immagine. Conserva HostConfig completo, frame nativo, reti e mount storici. Riprende i default runtime dalla nuova immagine e conserva gli environment applicativi approvati OUF/SPRING/MANAGEMENT, PORT e opzioni Java. Altri setting non revisionati e differenze in comando, utente, working directory, porte, volumi, stop signal, healthcheck o shell bloccano la compilazione.

Il vecchio contratto e la vecchia dichiarazione sono letti solo dopo verifica dei loro hash, proprietà e metadati POSIX; riletti prima di pubblicare lo snapshot. Nessuna lettura di file credenziali o chiavi, nessun Docker, database, nft, DNS, provider o lock R10. Sono creati soltanto un nuovo snapshot root0700 con dichiarazione privata0600 e receipt pubblica. I valori privati non sono stampati. Le osservazioni rimangono storiche; la verifica di file mount e generazioni vive resta da fare all'applicazione.

## Prove

- Compilatore `eee3a3c240df53c30fd25fdb8c77f469c3f63fd7`: [CI38084825457](https://github.com/GioNob/ouf-deploy/actions/runs/38084825457) PASS,9 test e lettura dello ZIP reale. Config immagine SHA256 `573a79f23a7beaf2d3886ecc41e760181f67026c8dc0a6b8e14c36729a4c8e50`.
- Consegna `50c638d62fb4bf86faf9400172acb3a6f165dbb8`: [CI38084905986](https://github.com/GioNob/ouf-deploy/actions/runs/38084905986) PASS,13 test complessivi e lettura dello ZIP reale. I4 test di consegna provano entrambe le posizioni di errore download/hash prima di sudo, bootstrap isolato e rifiuto di entrambi i sorgenti alterati dopo download.
- [Receipt di qualificazione](../evidence/semantic-qualified-package-declaration-qualification-20261010.json). Queste prove non sono una compilazione sul VPS e non promuovono le vecchie attestazioni di startup, recovery, peer o installazione alla nuova immagine.

## Comando sul VPS

Eseguire come `oufadmin`. Il sudo serve per leggere gli snapshot privati root e creare il nuovo snapshot protetto. Non attiva R10 e non effettua cutover. Il launcher esterno, il compilatore e gli helper sono tutti vincolati a commit e SHA256; il bootstrap root ricontrolla i sorgenti prima di eseguirli.

```bash
(
  set -euo pipefail
  umask 077
  OUF_GH="$HOME/ouf-gh-2.102.0.PNoFbF/gh_2.102.0_linux_amd64/bin/gh"
  if [ ! -x "$OUF_GH" ]; then OUF_GH="$(command -v gh)"; fi
  OUF_LAUNCH="$(mktemp "$HOME/ouf-package-declaration-launch.XXXXXXXX")"
  "$OUF_GH" api -H 'Accept: application/vnd.github.raw' 'repos/GioNob/ouf-deploy/contents/releases/semantic-qualified-package-declaration-20261010.sh?ref=50c638d62fb4bf86faf9400172acb3a6f165dbb8' > "$OUF_LAUNCH"
  printf '%s  %s\n' '999333ae488356d0309772267a48416cfe70911f0ded97d00b2e42606528f4d8' "$OUF_LAUNCH" | sha256sum -c -
  /usr/bin/bash "$OUF_LAUNCH"
)
```

Restituire l'output fino a `OUF_PACKAGE_DECLARATION_EXIT`. Successo atteso: `QUALIFIED_PACKAGE_DECLARED_NOT_APPLY_READY`, exit0. Un errore di contratto/default va esaminato; non modificare hash o dichiarazioni storiche per aggirarlo.

## Continuazione ancora aperta

Dopo la receipt target: chiudere generazione/OCI e peer reciproco nuovi, trasporto governato e coordinamento del lease R10, fence writer e backup fresco con recovery consapevole delle migrazioni, custody privata aggiornata e readiness applicativa IAM/provider. Poi integrazione e accettazione file end-to-end. Gli8 Cinema acquisiti e i Teatri già caricati restano preservati. F10 e F11/installazione riusabile non sono chiusi; API PULLv2.3 segue il consolidamento file.

L'autorizzazione dell'utente a lavorare e aggiornare GitHub persiste. Non è un grant di dominio o una decisione HUMAN/THS applicativa e non viene codificata come tale. Il compilatore non emette autorità di installazione.
