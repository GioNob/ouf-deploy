# Successore materiali: associazione per identità — 29 ottobre 2026

Questo è l'unico comando operatore corrente. [Qualifica](../../evidence/m2-discovery-material-role-successor-qualified-20261029.json), [STOP precedente](../../evidence/m2-discovery-material-preparation-target-stop-20261029.json).

Il precedente tentativo è FALLITO e CONSUMATO: INSTALLATION_ROLES_OUTSIDE_REVIEWED_COHORT,3metadata/648347byte,zeroEngineGET,zero letture credenziali/chiavi e zero copie. Non è un problema di budget o un'ammissione IAM. L'errore era nel preparatore: assumeva nomi identici tra inventario13 e selezione4, mentre il reader originale seleziona per containerId e rinomina i ruoli.

La correzione associa ciascun ruolo selezionato a un solo ID nell'inventario originale, conserva i nomi originali e verifica interamente immagine/configurazione/mount/rete/pin. Rifiuta ID mancanti o duplicati, deriva anche con ID uguale, catena di provenienza/Engine/root diversa e qualsiasi peer corrente cambiato. Nessun guard viene disabilitato. I quattro moduli e il capsule già consegnati restano byte-esatti.

## Passaggio necessario sul VPS

Il connettore OUF di questa chat non dispone di esecuzione amministrativa sul VPS. Serve il solo accesso SSH interattivo già usato, come `oufadmin`. Non serve una nuova autorizzazione generale o login applicativo.

Il NUOVO scope `/etc/ouf/deploy-snapshots/m2-discovery-material-roles-2d133870-20261029-v1` non è stato eseguito. Il successore legge per prima la ricevuta protetta del fallimento e richiede esattamente SHA256 canonico `2d13387053ab8bc824f64183a1efb00d038a117b2a3d28547237be6eca7247ac`, con zero effetti/letture di segreti/copie. Una ricevuta diversa o con effetti blocca tutto. Non riparte, cancella o modifica il vecchio scope e non resetta alcun budget.

Poi legge i tre input originali esatti, ricontrolla tredici peer con27GET Engine al massimo e prepara due copie private root:10001/0440 più una copia del certificato pubblico root0600 nel nuovo contesto root0700, con tre riletture. Totale4metadata, massimo90secondi/16MiB. File storici, vecchia ricevuta e log conservati.

Nessun OAuth/IAM/login/grant/budget/SQL/nuova chiave/firma/import/lifecycle/apply applicativo/upload/job/resume/acquisizione. Il controllo del certificato riguarda SOLO l'involucro pubblico, non CA/validità/TLS. Truststore combinato IAM+provider, credenziali correnti e ammissione runtime restano da provare.

## Eseguire una sola volta

Usare questo NUOVO blocco in SSH, non il vecchio comando. L'eventuale password sudo va inserita solo nel terminale.

```bash
(
set -euo pipefail
umask 077
ouf_roles_bootstrap=$(mktemp -d "$HOME/ouf-m2-material-roles-bootstrap.XXXXXXXX")
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
  --max-redirs 3 --connect-timeout 15 --max-time 60 --max-filesize 131072 \
  'https://raw.githubusercontent.com/GioNob/ouf-deploy/8bfaafed1b23b79500a3b4867a4f75112d87ca9e/releases/prepare-m2-discovery-material-roles-20261029.sh' \
  -o "$ouf_roles_bootstrap/run.sh" &&
printf '%s  %s\n' '06ca017cd74cf3cc87a81c32787a1ea2ab3929453809599bc682067f14fdcb69' "$ouf_roles_bootstrap/run.sh" | sha256sum -c - &&
chmod 0400 "$ouf_roles_bootstrap/run.sh" &&
bash "$ouf_roles_bootstrap/run.sh"
)
```

Wrapper immutabile `8bfaafed1b23b79500a3b4867a4f75112d87ca9e`, SHA256 `06ca017cd74cf3cc87a81c32787a1ea2ab3929453809599bc682067f14fdcb69`. Scarica il nuovo capsule5moduli dal commit339f3ee1, SHA256 `3f213db3cc611490398a097ef334f874726af09c2f3de0344322ad604a108c65`, lo protegge root0400 e avvia Python -I/-B/-S con ambiente vuoto. Scope o log protetto preesistente impediscono un nuovo avvio.

Restituire SOLO JSON pubblico e footer OperatorExit/OperatorLog/DeliveryExit/DeliveryDirectory/DeliveryLog. Mai file privati, credenziali o chiavi.

Il successo previsto è `PRIVATE_MATERIAL_ROLE_COPIES_PREPARED_NOT_ADMITTED`, complete=true,4metadata/27GET/2copie private/1pubblica/3riletture, con preparedInputsHash, predecessorResultHash e installationRoleMapHash. Entrambi exit0; runtimeAuthorityIssued/targetApplyAuthorized/applicationE2EProven restano false.

Anche STOP consuma il nuovo scope: conservare tutto, NON rilanciare/cancellare/ricreare né sovrascrivere log. Prima riconciliare il risultato. Nessun ripristino automatico o riuso di authority.

## Evidenza

139PASS/0errori/0skip su push40864412321/job123415421260 e PR40864419812/job123415447362, più PR corrente40864636805/job123416176800; log letti. Sette nuovi test riproducono prima lo STOP originale, verificano il successore con alias diversi e rifiutano ambiguità/deriva/provenienza o predecessore con effetti. Cinque nuovi test del capsule; vecchio capsule ancora riproducibile byte-esatto.

Prova nativa Docker29.8.1: tredici container reali con etichette differenti, peer Unix root e pin kernel,27GET,2copie private/1pubblica; ricevuta precedente, fonti e peer invariati, replay nuovo scope e peer fermo rifiutati. Push40863972102/job123413909601 e PR40863982982/job123413944028 PASS/log letti. Input e provenienza sintetici, nessun target/IAM.

Consegna reale HTTPS/nonroot/sudo/root0400/checksum: quattro job push40864627473 e PR40864636679 PASS/log letti, con casi predecessor metadata assenti e log protetto preesistente. Il capsule produttivo byte-esatto si ferma prima dei segreti nel caso negativo; la prova positiva è separata.

Dopo il risultato continuare la preparazione coordinata da questo nuovo input privato: trust/ammissioni correnti, executor tredici fasi/worker distinto, backup/fencing/DB/cohort, reviewHUMAN/authority finite soloquando il percorso intero è pronto. Nessun token o finestra anticipata.

E2E e otto criteri stabilità OPEN; discovery non ancora esposta. Farmacie/decisioni confermate invariati. ChatGPT→MCP→Gateway→Registry→OntoPiA obbligatorio; no web/Turtle/ontologia sostitutiva, merge, acceptance, subagenti o automazioni.
