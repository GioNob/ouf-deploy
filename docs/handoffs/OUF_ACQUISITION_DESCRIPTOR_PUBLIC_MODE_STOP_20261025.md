# STOP codice pubblico e continuazione esatta qualificata — 25 ottobre2026

## Risultato VPS acquisito

La consegna originale077065def9e06e743556c5e86f051238284b5a0d/SHA5af3e992... ha verificato i download e creato la copia protetta; il checksum come operatore ha ricevuto Permission denied e DeliveryExit1. Log originale: /home/oufadmin/ouf-acquisition-descriptor-read-delivery.XdyYVHv1/bootstrap.log; bootstrap originale: /home/oufadmin/ouf-descriptor-bootstrap.mIZy6zES. [Evidenza owner](../../evidence/acquisition-descriptor-public-code-read-stop-20261025.json).

Il flusso del wrapper dimostra che il diagnostico non è stato invocato: nessun login o ownerGET da quella esecuzione. Modo/ACL/ancestor attuali sul target NON sono stati ancora letti. Non chiamare successo la sola copiaRoot. NON rilanciare il comando del [precedente handoff](OUF_ACQUISITION_PERMISSION_DESCRIPTOR_PREFLIGHT_20261025.md), né cancellare/modificare directory per ripeterlo.

Difetto dell'assistente: os.open(...0444) senza fchmod esplicito lasciava che l'umaskroot restringesse i permessi a0400. La precedente CI verificava l'umaskdefault e ha mancato questa condizione. Il copier futuro ora forza il modo sullo stessoFD; questa correzione NON autorizza il replay della consegna originale. La lezione è permanente in AGENTS.

## Continuazione ammessa e qualifica reale

Wrapper pinned **c11d9ce029da431f9f9b225e9f06ea10264c7ecb**, SHA256 **24cdc955bf0fbe26818968ebdf2ac6f89c9a7572d69dd0d8baa2f60a53bc1528**.
File: releases/resume-acquisition-descriptor-read-mode-20261025.sh.
[Evidenza qualificazione](../../evidence/acquisition-descriptor-mode-continuation-qualified-20261025.json).

Il comando riusa i file ESATTI originali. Verifica hash/custodia/nlink1 dei due pubblici, bootstrap.log del preciso fallimento, assenza di operator.log originale e claimdiagnostica. Prova il traversal come identità Linux effettiva dell'operatore, con relativi gruppi e setuid reali: ACL dei parent sono rivalutate e preservate, non ignorate né rimosse. Richiede assenza di accessACL sul SOLO filecodice oggetto di chmod, rootdir0555, codiceRoot0400 e hash062b... esatto. Se codice già0444, altra causa/parent non attraversabile, ACLcodice, drift o scope già avviato: STOP senza riparazioni alternative.

Sotto childfisso XdyYVHv1/permission-mode-v1, conserva nuovi bootstrap/operator.log; non sovrascrive gli originali. FaseRoot massima60s, journalCLAIMEDroot0400/fsync PRIMA della singola fchmodFD0400→0444. Inode/byte/owner/nlink/mtime preservati. Non riscrive codice, non cambia parent/ACL/owner e non usa chiavi/Engine/IAMadmin/SQL. Esito ambiguo rimane CLAIMED e non si rilancia. Journal: /usr/local/lib/ouf-acquisition-permission-descriptor-read-062b1e201904b9fd/permission-mode-v1.json.

Dopo APPLIED e checksumcomeoperatore, avvia per la PRIMA volta il lettore già pinned d2e80980f7575ce1e71627632eeba515441d84be/SHA256062b1e201904b9fd7a10efcad371de17d4c0fbc3411710c310186aa7381c5cad. NON riscarica/ricopia il lettore e NON riapre una sua claim esistente. Restano600s/max52ownerGET/1metadataIAMGET/121IAMPOST/16MB e fixedclaim /home/oufadmin/ouf-acquisition-permission-descriptor-read-20261025. Loginbrowser ordinario HUMANouf-admin per leggere6descrittori, tokenmemoria; nessuna pubblicazione/grant/attivazione/acquisizione. La copiaRoot e il diagnostico sono fasi distinte, non accettazione E2E.

CI su sorgentec11d9ce029da431f9f9b225e9f06ea10264c7ecb: push40222432040 e PR40222436406, tutti i3job puntuali PASS/logdiretti letti:
- 15testprotocollo/0skip: rootumask077 e file0400 REALI, operatore nonroot DAVVERO negato prima e autorizzato dopo, setuid reale, inode/byte/owner/log preservati, negativehash/owner/hardlink/symlink/parent/ACLfile/claim/replay/ambiguità; ACLparent REALI sia positive sia negative e preservate. Jobpush121256690689/PR121256704384.
- Wrappercompleto sui file trattenuti della fixture: root400→444, checksumoperatore e primo invocazionelettore; STOP atteso senzaTTY PRIMA del login/claim, secondoavvio negato. Jobpush121256690725/PR121256704161.
- Copier futuro VERBATIM sotto rootumask077 e checksumoperatore reale, jobpush121256690522/PR121256704335.

Storia/datiowner sono SINTETICI, filesystemroot/umask/ACL/setuid reali. Nessuna approvazione production simulata. CI NON legge il target né prova il suo modo attuale o IAM. Il primo candidato9a8e0b6/runs40222206020/40222209880 si fermava nel guardACL troppo generale: corretto con verifica dell'attore effettivo e casiACLrealipositivi/negativi, nessuna modificaACL. Fallimenti conservati, mai consegnati. Il workspace locale non mappaUID1001 e chown davaEINVAL: nessun falsoPASS/skip locale, qualifica affidata alla CI reale.

## Comando unico: continuazione, NON replay del vecchio wrapper

Come oufadmin, nel terminale VPS interattivo, UNA volta:

```bash
(
  set -Eeuo pipefail
  umask 077
  ouf_mode_bootstrap=$(mktemp -d "$HOME/ouf-descriptor-mode-bootstrap.XXXXXXXX")
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-redirs 3 --connect-timeout 15 --max-time 60 \
    "https://raw.githubusercontent.com/GioNob/ouf-deploy/c11d9ce029da431f9f9b225e9f06ea10264c7ecb/releases/resume-acquisition-descriptor-read-mode-20261025.sh" \
    -o "$ouf_mode_bootstrap/run.sh"
  printf '%s  %s\n' '24cdc955bf0fbe26818968ebdf2ac6f89c9a7572d69dd0d8baa2f60a53bc1528' "$ouf_mode_bootstrap/run.sh" | sha256sum -c -
  bash "$ouf_mode_bootstrap/run.sh"
)
```

Sudo serve solo alla verifica root e al permesso del filecodice pubblico esatto; il lettore viene eseguito comeoperatore. Quando compaiono indirizzo/codice IAM, aprire quell'indirizzo nel browser e inserire il codice SOLO lì, con accountouf-admin. Non incollare token/codice in chat e non eseguire l'intero comando come root.

Attesi prima JSONpermission-mode/APPLIED con chmodOperations1 e zeroIAM/owner; poi DESCRIPTORS_OBSERVED_NO_AUTHORITY/complete=true, Exit0 e ContinuationExit0. Riportare entrambi i JSON, Exit/ContinuationExit e percorsi dei log; non il codice di login. Se STOP/interruzione, conserva file/journal/claim/log e NON rilanciare o creare altri child. Risultato di questa continuazione target ANCORA NON RICEVUTO.

## Dopo il risultato descrittori

Il [precedente handoff](OUF_ACQUISITION_PERMISSION_DESCRIPTOR_PREFLIGHT_20261025.md) resta riferimento per account, sei permission, due run, limiti e registrazione/ACTIVEpublicationHUMAN ADDITIVA se necessaria. Toolacquisizione disponibili, singola propostaREPLACE_ROLES rifiutata AUTH_ROLE_CAPABILITY_INVALID e prima IngestionREAD negata retryablefalse conservate e non ritentate. Solo dopo autorità nuova effettivamente pubblicata/verificata: temporanei2ruoli/2run e4READ con correlazioneCSV/contratto/ACK/watermark/13ID/20proprietà/provenance. Nessuna terza acquisizione/budgetfonte/reset/riavvio/reinstallRegistry.

Installazione VPS ACQUISITION_READ_PATH_INSTALLED_E2E_NOT_ACCEPTED resta positiva e tutti gli scope storiciCONSUMATI; nessun APPLY/recoveryworker va ripetuto. E2E/G4/F5/F6 OPEN, tecnico8/8 funzionale4/6, Supervisor dopo E2E. Nessun merge/release acceptance.
